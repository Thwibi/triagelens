"""Alert-scoped IOC extraction and linking (spec 01 section 8, spec 05 section 7).

The parse worker extracts tier-1 indicators (network, hashes, CVEs) from every
event as it is ingested. Tier-2 indicators -- filenames, filepaths, registry
keys, commands and user agents -- are only meaningful once an alert exists, so
they are extracted here, from the events an alert points at, and every evidence
indicator (tier 1 already stored and tier 2 just stored) is then linked to its
alert in ``ioc_alerts``.

This is the "enrich + score" stage of the ingest pipeline (spec 01 section 8).
It runs inside the detection transaction, after alerts are recorded, and its
output is what the alert detail endpoint and the alert-evidence scoring modifier
read (spec 04 section 8). Linking is derived state: every run rebuilds the
case's ``ioc_alerts`` from the current evidence, so it is idempotent.
"""

from __future__ import annotations

import json
import sqlite3
from collections import Counter
from dataclasses import dataclass

from app.config import Settings
from app.db.connection import atomic
from app.db.repositories.iocs import IocRepository
from app.ingest.events import EVENT_COLUMNS, NormalizedEvent
from app.ioc import (
    BASE_STRUCTURED,
    TIER2_TYPES,
    Allowlist,
    IocCandidate,
    IocHit,
    IocType,
    Role,
    aggregate,
    canonical_value,
    default_allowlist,
    extract_fields,
)

#: The scanner/attack-tool user agents from spec 04 section 10. A user agent
#: matching one is kept even when it is seen only once.
SCANNER_USER_AGENTS: tuple[str, ...] = (
    "sqlmap",
    "nikto",
    "nmap scripting engine",
    "masscan",
    "gobuster",
    "dirbuster",
    "wpscan",
    "nuclei",
    "acunetix",
    "nessus",
    "zgrab",
    "feroxbuster",
)

#: Alert levels whose evidence commands are stored (spec 05 section 3).
_COMMAND_LEVELS: frozenset[str] = frozenset({"medium", "high", "critical"})

#: Severity ranking, so an event shared by several alerts keeps its loudest one.
_LEVEL_RANK: dict[str, int] = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

#: Command lines are truncated to this many characters (spec 05 section 3).
_COMMAND_MAX = 2000

#: Most tier-2 hits kept for one event, matching the tier-1 extraction bound.
_MAX_HITS_PER_EVENT = 100

#: A user agent seen at least this often in the evidence is kept (spec 05 section 3).
_USER_AGENT_MIN_OCCURRENCES = 2


@dataclass(frozen=True, slots=True)
class _Evidence:
    """One ``alert_events`` link with the alert's level."""

    alert_id: str
    event_id: int
    level: str


def link_alert_iocs(
    connection: sqlite3.Connection,
    *,
    case_id: str,
    settings: Settings,
) -> int:
    """Extract tier-2 IOCs from alert evidence and link every evidence IOC.

    Returns the number of tier-2 indicators seen in the evidence. Safe to run
    repeatedly: re-storing an already-seen occurrence does not change its count,
    and the case's ``ioc_alerts`` links are rebuilt from the current evidence.
    """
    evidence = _evidence(connection, case_id)
    if not evidence:
        return 0
    events = _load_events(connection, sorted({row.event_id for row in evidence}))
    groups = aggregate(
        _records(
            events,
            evidence,
            allowlist=default_allowlist(),
            decode_depth=settings.ioc.decode_depth,
        )
    )
    if groups:
        IocRepository(connection).store_alert_iocs(case_id, groups)
    _relink(connection, case_id)
    return len(groups)


def _evidence(connection: sqlite3.Connection, case_id: str) -> list[_Evidence]:
    """Every evidence event this case's alerts point at, with its alert level."""
    rows = connection.execute(
        "SELECT ae.alert_id AS alert_id, ae.event_id AS event_id, a.level AS level "
        "FROM alert_events ae JOIN alerts a ON a.id = ae.alert_id "
        "WHERE a.case_id = ? ORDER BY ae.alert_id, ae.event_id",
        (case_id,),
    ).fetchall()
    return [
        _Evidence(str(row["alert_id"]), int(row["event_id"]), str(row["level"])) for row in rows
    ]


def _load_events(
    connection: sqlite3.Connection, event_ids: list[int]
) -> dict[int, NormalizedEvent]:
    """The evidence events, rebuilt as :class:`NormalizedEvent` for extraction."""
    if not event_ids:
        return {}
    placeholders = ", ".join("?" * len(event_ids))
    rows = connection.execute(
        f"SELECT id, {', '.join(EVENT_COLUMNS)}, raw, fields_json FROM events "
        f"WHERE id IN ({placeholders})",
        event_ids,
    ).fetchall()
    return {int(row["id"]): _event_from_row(row) for row in rows}


def _event_from_row(row: sqlite3.Row) -> NormalizedEvent:
    """Rebuild one stored event so :meth:`NormalizedEvent.ioc_fields` applies."""
    values: dict[str, object] = {name: row[name] for name in EVENT_COLUMNS}
    values["raw"] = row["raw"]
    values["fields_json"] = json.loads(row["fields_json"] or "{}")
    return NormalizedEvent(**values)  # type: ignore[arg-type]


def _records(
    events: dict[int, NormalizedEvent],
    evidence: list[_Evidence],
    *,
    allowlist: Allowlist,
    decode_depth: int,
) -> list[tuple[int, int | None, list[IocHit]]]:
    """``(event_id, ts_ms, hits)`` for each evidence event, in id order."""
    levels = _levels_by_event(evidence)
    user_agents = _user_agent_counts(events)
    records: list[tuple[int, int | None, list[IocHit]]] = []
    for event_id in sorted(events):
        hits = _tier2_hits(
            events[event_id],
            level=levels.get(event_id, "informational"),
            allowlist=allowlist,
            decode_depth=decode_depth,
            user_agent_counts=user_agents,
        )
        records.append((event_id, events[event_id].ts_ms, hits))
    return records


def _levels_by_event(evidence: list[_Evidence]) -> dict[int, str]:
    """The loudest alert level per evidence event (an event can be shared)."""
    levels: dict[int, str] = {}
    for row in evidence:
        current = levels.get(row.event_id)
        if current is None or _LEVEL_RANK.get(row.level, -1) > _LEVEL_RANK.get(current, -1):
            levels[row.event_id] = row.level
    return levels


def _user_agent_counts(events: dict[int, NormalizedEvent]) -> Counter[str]:
    """How often each user agent appears across the case's evidence events."""
    counts: Counter[str] = Counter()
    for event in events.values():
        if event.user_agent:
            counts[event.user_agent] += 1
    return counts


def _tier2_hits(
    event: NormalizedEvent,
    *,
    level: str,
    allowlist: Allowlist,
    decode_depth: int,
    user_agent_counts: Counter[str],
) -> list[IocHit]:
    """Tier-2 indicators in one evidence event (spec 05 sections 3 and 4)."""
    hits = extract_fields(
        event.ioc_fields(),
        allowlist=allowlist,
        types=TIER2_TYPES,
        decode_depth=decode_depth,
        max_hits=_MAX_HITS_PER_EVENT,
    )
    if level in _COMMAND_LEVELS and event.process_cmdline:
        hits.append(
            _field_hit(
                IocType.COMMAND,
                event.process_cmdline[:_COMMAND_MAX],
                "process_cmdline",
                Role.PROCESS,
                allowlist,
            )
        )
    if event.user_agent and _keep_user_agent(event.user_agent, user_agent_counts):
        hits.append(
            _field_hit(
                IocType.USER_AGENT,
                event.user_agent,
                "user_agent",
                Role.MENTIONED,
                allowlist,
            )
        )
    return hits


def _keep_user_agent(value: str, counts: Counter[str]) -> bool:
    """A user agent from a known scanner, or one seen repeatedly in the case."""
    lowered = value.lower()
    if any(keyword in lowered for keyword in SCANNER_USER_AGENTS):
        return True
    return counts.get(value, 0) >= _USER_AGENT_MIN_OCCURRENCES


def _field_hit(
    ioc_type: IocType,
    value: str,
    field: str,
    role: Role,
    allowlist: Allowlist,
) -> IocHit:
    """A hit for a value read straight from a dedicated structured field."""
    value_norm = canonical_value(ioc_type, value)
    candidate = IocCandidate(
        type=ioc_type,
        value=value,
        value_norm=value_norm,
        base=BASE_STRUCTURED,
        is_private=False,
        is_allowlisted=allowlist.matches(ioc_type, value, value_norm),
    )
    return IocHit(candidate=candidate, field=field, role=role)


def _relink(connection: sqlite3.Connection, case_id: str) -> None:
    """Rebuild the case's ``ioc_alerts`` links from its stored evidence."""
    with atomic(connection):
        connection.execute(
            "DELETE FROM ioc_alerts WHERE alert_id IN (SELECT id FROM alerts WHERE case_id = ?)",
            (case_id,),
        )
        connection.execute(
            "INSERT OR IGNORE INTO ioc_alerts (ioc_id, alert_id) "
            "SELECT DISTINCT o.ioc_id, ae.alert_id "
            "FROM alert_events ae "
            "JOIN alerts a ON a.id = ae.alert_id "
            "JOIN ioc_occurrences o ON o.event_id = ae.event_id "
            "WHERE a.case_id = ?",
            (case_id,),
        )


__all__ = ["SCANNER_USER_AGENTS", "link_alert_iocs"]
