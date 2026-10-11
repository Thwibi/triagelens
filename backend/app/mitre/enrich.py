"""Per-alert ATT&CK resolution and storage (spec 04 sections 7.2-7.3).

Alerts carry their mapping in ``tactics_json``/``techniques_json``/
``groups_software_json``; this module computes those from the rule's sigma
tags, consulting the event-based fallback only when the tags map nothing
(rule 2 of section 7.2: alert tactics are the explicit tactic tags, or
else the union of the resolved techniques' tactics). Unresolved tags are
not stored - the alert detail recomputes them from the rule's tags.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import TypeVar

from app.db.connection import atomic
from app.mitre.catalogue import MitreCatalogue, resolve_rule_tags
from app.mitre.fallbacks import FallbackEntry, match_fallback
from app.models.rule import RuleRecord


@dataclass(frozen=True, slots=True)
class TechniqueRef:
    """A resolved technique as stored on an alert."""

    id: str
    name: str
    source: str


@dataclass(frozen=True, slots=True)
class EntityRef:
    """A resolved group/software as stored on an alert."""

    id: str
    name: str
    kind: str


@dataclass(frozen=True, slots=True)
class AlertMitre:
    """One alert's resolved ATT&CK mapping."""

    tactics: tuple[str, ...]
    techniques: tuple[TechniqueRef, ...]
    groups_software: tuple[EntityRef, ...]
    unresolved_tags: tuple[str, ...]
    source: str


_Ref = TypeVar("_Ref", TechniqueRef, EntityRef)


def resolve_alert_mitre(
    rule_tags: Sequence[str],
    *,
    catalogue: MitreCatalogue,
    fallback_entries: Sequence[FallbackEntry] = (),
    channel: str | None = None,
    event_id: int | None = None,
    event_action: str | None = None,
) -> AlertMitre:
    """Resolve one alert's mapping: rule tags first, event fallback second.

    Fallback techniques that the loaded bundle does not know are skipped
    (there is no name to show); they are not unresolved tags, because
    unresolved tracking is about what the *rule* claimed.
    """
    resolved = resolve_rule_tags(list(rule_tags), catalogue)
    techniques = _dedupe_refs(
        TechniqueRef(info.attack_id, info.name, "tag") for info in resolved.techniques
    )
    tactics = list(resolved.tactics)
    source = "tag" if techniques or tactics else "none"
    if not techniques and not tactics:
        known = [
            catalogue.techniques[attack_id]
            for attack_id in match_fallback(
                fallback_entries, channel=channel, event_id=event_id, event_action=event_action
            )
            if attack_id in catalogue.techniques
        ]
        techniques = _dedupe_refs(
            TechniqueRef(info.attack_id, info.name, "fallback") for info in known
        )
        if techniques:
            source = "fallback"
    if not tactics and techniques:
        tactics = list(
            dict.fromkeys(
                tactic for ref in techniques for tactic in catalogue.techniques[ref.id].tactics
            )
        )
    return AlertMitre(
        tactics=tuple(tactics),
        techniques=techniques,
        groups_software=_dedupe_refs(
            EntityRef(info.attack_id, info.name, info.kind) for info in resolved.groups_software
        ),
        unresolved_tags=resolved.unresolved_tags,
        source=source,
    )


def _dedupe_refs(references: Iterable[_Ref]) -> tuple[_Ref, ...]:
    """First occurrence per id wins, order preserved."""
    seen: set[str] = set()
    unique: list[_Ref] = []
    for ref in references:
        if ref.id in seen:
            continue
        seen.add(ref.id)
        unique.append(ref)
    return tuple(unique)


def enrich_run_alerts(
    connection: sqlite3.Connection,
    *,
    case_id: str,
    run_id: str,
    rules: Mapping[str, RuleRecord],
    fallback_entries: Sequence[FallbackEntry] = (),
    catalogue: MitreCatalogue | None = None,
) -> int:
    """Write the ATT&CK mapping onto every alert of one run; returns count.

    Fallback matching reads each alert's first linked evidence event, so
    this runs after the alert drafts have been recorded and linked.
    """
    loaded = catalogue if catalogue is not None else MitreCatalogue.load(connection)
    rows = connection.execute(
        "SELECT id, rule_id FROM alerts WHERE case_id = ? AND run_id = ? ORDER BY id",
        (case_id, run_id),
    ).fetchall()
    if not rows:
        return 0
    with atomic(connection):
        for row in rows:
            rule = rules.get(str(row["rule_id"]))
            channel, event_id, event_action = _first_event(connection, str(row["id"]))
            mapping = resolve_alert_mitre(
                list(rule.tags) if rule is not None else [],
                catalogue=loaded,
                fallback_entries=fallback_entries,
                channel=channel,
                event_id=event_id,
                event_action=event_action,
            )
            connection.execute(
                "UPDATE alerts SET tactics_json = ?, techniques_json = ?, "
                "groups_software_json = ? WHERE id = ?",
                (
                    json.dumps(list(mapping.tactics)),
                    json.dumps(
                        [
                            {"id": ref.id, "name": ref.name, "source": ref.source}
                            for ref in mapping.techniques
                        ]
                    ),
                    json.dumps(
                        [
                            {"id": ref.id, "name": ref.name, "kind": ref.kind}
                            for ref in mapping.groups_software
                        ]
                    ),
                    str(row["id"]),
                ),
            )
    return len(rows)


def _first_event(
    connection: sqlite3.Connection, alert_id: str
) -> tuple[str | None, int | None, str | None]:
    """The evidence event's channel, event_id and event_action."""
    row = connection.execute(
        "SELECT e.channel, e.event_id, e.event_action FROM alert_events ae "
        "JOIN events e ON e.id = ae.event_id WHERE ae.alert_id = ? ORDER BY e.id LIMIT 1",
        (alert_id,),
    ).fetchone()
    if row is None:
        return None, None, None
    return (
        str(row["channel"]) if row["channel"] is not None else None,
        int(row["event_id"]) if row["event_id"] is not None else None,
        str(row["event_action"]) if row["event_action"] is not None else None,
    )


__all__ = [
    "AlertMitre",
    "EntityRef",
    "TechniqueRef",
    "enrich_run_alerts",
    "resolve_alert_mitre",
]
