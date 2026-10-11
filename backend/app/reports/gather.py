"""Assemble one case's report data from a read connection (spec 08 section 1).

Everything here is a deterministic read: the same case with the same options
produces the same data except for ``generated_at``. Rendering is deliberately
kept out of this module, matching its docstring in :mod:`app.reports.model`.

The alert statuses driving section 3/4 come from the report options; every
other section follows its ``include_*`` flag, and the cover plus the
integrity/methodology section are always present (spec 08 section 1).
"""

from __future__ import annotations

import json
import sqlite3
from collections import Counter
from collections.abc import Sequence
from typing import Any

from app.db.repositories.alerts import AlertRepository
from app.db.repositories.audit import AuditRepository
from app.db.repositories.cases import CaseRepository
from app.db.repositories.events import EventFilters, EventRepository
from app.db.repositories.iocs import IocRepository
from app.db.repositories.rules import RuleRepository
from app.db.repositories.runs import DetectionRunRepository, attack_version
from app.detect.scoring import score_alert
from app.errors import ApiError, ErrorCode
from app.ioc.refang import defang
from app.mitre.catalogue import MitreCatalogue
from app.mitre.matrix import matrix_for_case
from app.mitre.navigator import build_layer
from app.mitre.tactics import TACTIC_NAMES
from app.models.alert import AlertRecord
from app.reports.model import (
    ReportAlert,
    ReportData,
    ReportIoc,
    ReportMeta,
    ReportRun,
    ReportSource,
    ReportSummary,
)
from app.reports.options import ReportOptions
from app.util.ids import new_id
from app.util.time import iso_from_ms, utc_now_iso
from app.version import APP_VERSION

#: How many external indicators the executive summary names.
_TOP_IOC_LIMIT = 5
#: How many techniques the executive summary names.
_TOP_TECHNIQUE_LIMIT = 3

_PAGE = 1000


def gather_report(
    connection: sqlite3.Connection,
    *,
    case_id: str,
    options: ReportOptions,
) -> ReportData:
    """Build the neutral report data for one case under ``options``."""
    case = CaseRepository(connection).get(case_id)
    if case is None:
        raise ApiError(ErrorCode.NOT_FOUND, "case not found", id=case_id)
    alerts = _alert_records(connection, case_id, options.alert_statuses)
    rules = RuleRepository(connection)
    catalogue = MitreCatalogue.load(connection)
    runs = DetectionRunRepository(connection).list_for_case(case_id, limit=1)
    latest = runs[0] if runs else None
    alerts_payload = [
        _alert_detail(connection, record, catalogue, rules, options.events_per_alert)
        for record in alerts
    ]
    iocs = _external_iocs(connection, case_id) if options.include_iocs else []
    summary = _summary(connection, case_id, alerts_payload, iocs)
    generated_at = utc_now_iso()
    parent_of, own_tactics = _technique_graph(connection)
    mappings = _alert_mappings(connection, case_id)
    navigator = (
        build_layer(
            case_name=case.name,
            attack_version=latest.attack_version if latest else attack_version(connection),
            mappings=mappings,
            parent_of=parent_of,
            own_tactics=own_tactics,
            ruleset_hash=latest.ruleset_hash if latest else "0" * 64,
            generated_at=generated_at,
        )
        if options.include_mitre
        else None
    )
    events = EventRepository(connection)
    timeline = (
        events.timeline(EventFilters(case_id=case_id), bucket="auto")
        if options.include_timeline
        else {}
    )
    entities = IocRepository(connection).entities(case_id) if options.include_entities else []
    appendix = (
        _appendix(connection, alerts_payload, options.events_per_alert)
        if options.include_appendix_raw
        else []
    )
    runs_payload = [_run_detail(connection, run) for run in runs]
    audit = AuditRepository(connection).verify(case_id=case_id).as_dict()
    meta = ReportMeta(
        report_id=new_id(),
        case_id=case_id,
        case_name=case.name,
        title=options.title or f"{case.name} report",
        analyst=options.analyst or "unassigned",
        generated_at=generated_at,
        timezone=case.default_timezone,
        tool_version=latest.tool_version if latest else APP_VERSION,
        attack_version=latest.attack_version if latest else attack_version(connection),
        ruleset_hash=latest.ruleset_hash if latest else "0" * 64,
        detection_profile=latest.profile if latest else "",
    )
    return ReportData(
        meta=meta,
        summary=summary,
        alerts=alerts_payload,
        iocs=iocs,
        mitre={
            "matrix": matrix_for_case(connection, case_id=case_id),
            "navigator_layer": navigator,
        }
        if options.include_mitre
        else {},
        timeline=timeline,
        entities=entities,
        sources=[_source_detail(connection, source.id) for source in _sources(connection, case_id)],
        runs=runs_payload,
        audit_verification=audit,
        include={
            "summary": True,
            "alerts": bool(alerts_payload),
            "iocs": options.include_iocs,
            "mitre": options.include_mitre,
            "timeline": options.include_timeline,
            "entities": options.include_entities,
            "integrity": True,
            "appendix": options.include_appendix_raw,
        },
        appendix_raw=appendix,
    )


def _alert_records(
    connection: sqlite3.Connection, case_id: str, statuses: Sequence[str]
) -> list[AlertRecord]:
    """Every alert of the case whose status is in ``statuses``, highest score first.

    An empty ``statuses`` means the alert section is switched off (spec 08 1).
    """
    repository = AlertRepository(connection)
    wanted = set(statuses)
    if not wanted:
        return []
    rows: list[AlertRecord] = []
    offset = 0
    while True:
        page, _total = repository.search(case_id, limit=_PAGE, offset=offset)
        if not page:
            break
        rows.extend(record for record in page if record.status in wanted)
        offset += len(page)
        if len(page) < _PAGE:
            break
    return sorted(rows, key=lambda record: (-record.score, record.id))


def _alert_detail(
    connection: sqlite3.Connection,
    record: AlertRecord,
    catalogue: Any,
    rules: RuleRepository,
    events_per_alert: int,
) -> ReportAlert:
    """One included alert with detail sections (spec 08 sections 1.3/1.4)."""
    rule = rules.get(record.rule_id)
    tactics = [
        {
            "shortname": shortname,
            "name": catalogue.tactics.get(shortname, TACTIC_NAMES.get(shortname, shortname)),
        }
        for shortname in json.loads(record.tactics_json)
    ]
    techniques = [
        _technique_payload(item)
        for item in (json.loads(record.techniques_json) or [])
        if isinstance(item, dict) and item.get("id")
    ]
    breakdown = score_alert(
        connection,
        record,
        rule_status=rule.status if rule is not None else None,
    )
    evidence_ids = AlertRepository(connection).event_ids(record.id)[:events_per_alert]
    events = _event_briefs(connection, evidence_ids, with_raw=False)
    iocs = _alert_iocs(connection, record.id)
    return ReportAlert(
        id=record.id,
        rule_id=record.rule_id,
        rule_title=record.rule_title,
        rule_kind=record.rule_kind,
        rule_type=record.rule_type,
        level=record.level,
        score=record.score,
        status=record.status,
        description=_rule_description(rule.yaml if rule is not None else None),
        tactics=tactics,
        techniques=techniques,
        host=record.host,
        user_name=record.user_name,
        first_seen_ms=record.first_seen_ms,
        last_seen_ms=record.last_seen_ms,
        match_count=record.match_count,
        false_positives=json.loads(record.false_positives_json),
        references=json.loads(record.references_json),
        analyst_notes=record.analyst_notes,
        score_breakdown=[
            {"label": label, "delta": delta} for label, delta in breakdown.breakdown.items()
        ],
        events=events,
        iocs=iocs,
    )


def _external_iocs(connection: sqlite3.Connection, case_id: str) -> list[ReportIoc]:
    """External, non-allowlisted indicators with defanged display values."""
    repository = IocRepository(connection)
    rows = []
    offset = 0
    while True:
        page, _total = repository.search(
            case_id,
            include_private=False,
            include_allowlisted=False,
            limit=_PAGE,
            offset=offset,
        )
        if not page:
            break
        rows.extend(page)
        offset += len(page)
        if len(page) < _PAGE:
            break
    rows.sort(key=lambda record: (-record.confidence, record.type, record.value))
    return [
        ReportIoc(
            id=record.id,
            type=record.type,
            value=record.value,
            defanged=defang(record.value),
            confidence=record.confidence,
            occurrences=record.occurrences,
            first_seen_ms=record.first_seen_ms,
            last_seen_ms=record.last_seen_ms,
            first_seen=iso_from_ms(record.first_seen_ms),
            last_seen=iso_from_ms(record.last_seen_ms),
            analyst_state=record.analyst_state,
            is_private=record.is_private,
            allowlisted=record.is_allowlisted,
            tags=record.tags,
        )
        for record in rows
    ]


def _summary(
    connection: sqlite3.Connection,
    case_id: str,
    alerts: Sequence[ReportAlert],
    iocs: Sequence[ReportIoc],
) -> ReportSummary:
    """The deterministic executive summary (spec 08 section 1.2)."""
    first_values = [alert.first_seen_ms for alert in alerts if alert.first_seen_ms is not None]
    last_values = [alert.last_seen_ms for alert in alerts if alert.last_seen_ms is not None]
    first_ms = min(first_values) if first_values else None
    last_ms = max(last_values) if last_values else None
    counts = _case_counts(connection, case_id)
    level_counts: Counter[str] = Counter()
    for alert in alerts:
        level_counts[alert.level] += 1
    technique_counts: Counter[str] = Counter()
    technique_names: dict[str, str] = {}
    for alert in alerts:
        for item in alert.techniques:
            attack_id = str(item.get("id", ""))
            if attack_id:
                technique_counts[attack_id] += 1
                technique_names[attack_id] = str(item.get("name") or attack_id)
    top_techniques = [
        {"id": attack_id, "name": technique_names[attack_id], "alerts": count}
        for attack_id, count in technique_counts.most_common(_TOP_TECHNIQUE_LIMIT)
    ]
    top_iocs = [
        {"type": ioc.type, "value": ioc.value, "confidence": ioc.confidence}
        for ioc in iocs[:_TOP_IOC_LIMIT]
    ]
    hosts = sorted({a.host for a in alerts if a.host})
    users = sorted({a.user_name for a in alerts if a.user_name})
    paragraph = _executive_paragraph(
        case_id=case_id,
        first_ms=first_ms,
        last_ms=last_ms,
        sources=counts["sources"],
        events=counts["events"],
        errors=counts["errors"],
        alerts_by_level=dict(level_counts),
        top_techniques=top_techniques,
        top_iocs=top_iocs,
        hosts=hosts,
        users=users,
    )
    return ReportSummary(
        first_seen_ms=first_ms,
        last_seen_ms=last_ms,
        first_seen=iso_from_ms(first_ms),
        last_seen=iso_from_ms(last_ms),
        source_count=counts["sources"],
        event_count=counts["events"],
        error_count=counts["errors"],
        alert_total=len(alerts),
        alerts_by_level=dict(level_counts),
        top_techniques=top_techniques,
        top_iocs=top_iocs,
        hosts=hosts,
        users=users,
        paragraph=paragraph,
    )


def _executive_paragraph(
    *,
    case_id: str,
    first_ms: int | None,
    last_ms: int | None,
    sources: int,
    events: int,
    errors: int,
    alerts_by_level: dict[str, int],
    top_techniques: list[dict[str, Any]],
    top_iocs: list[dict[str, Any]],
    hosts: list[str],
    users: list[str],
) -> str:
    """A factual, template-driven summary with no free-form AI text."""
    span = "unknown time span"
    if first_ms is not None and last_ms is not None:
        span = f"{iso_from_ms(first_ms)} to {iso_from_ms(last_ms)}"
    levels = ", ".join(f"{count} {level}" for level, count in sorted(alerts_by_level.items()))
    if not levels:
        levels = "none"
    techniques = (
        ", ".join(f"{item['name']} ({item['alerts']})" for item in top_techniques) or "none"
    )
    indicators = ", ".join(f"{item['type']} {item['value']}" for item in top_iocs) or "none"
    host_text = ", ".join(hosts) or "none"
    user_text = ", ".join(users) or "none"
    return (
        f"Case {case_id} spans {span}. {sources} source(s) produced {events} event(s) "
        f"with {errors} parse error(s). {sum(alerts_by_level.values())} alert(s) by level: "
        f"{levels}. Top techniques: {techniques}. Top external indicators: {indicators}. "
        f"Affected hosts: {host_text}. Affected users: {user_text}. "
        "All logs were processed locally on the analysing workstation."
    )


def _case_counts(connection: sqlite3.Connection, case_id: str) -> dict[str, int]:
    """Sources, events and parse errors for one case."""
    sources = connection.execute(
        "SELECT COUNT(*) FROM sources WHERE case_id = ?", (case_id,)
    ).fetchone()
    errors = connection.execute(
        "SELECT COUNT(*) FROM parse_errors WHERE source_id IN "
        "(SELECT id FROM sources WHERE case_id = ?)",
        (case_id,),
    ).fetchone()
    events = connection.execute(
        "SELECT COUNT(*) FROM events WHERE case_id = ?", (case_id,)
    ).fetchone()
    return {
        "sources": int(sources[0]) if sources else 0,
        "events": int(events[0]) if events else 0,
        "errors": int(errors[0]) if errors else 0,
    }


def _sources(connection: sqlite3.Connection, case_id: str) -> list[Any]:
    """Every source row of the case, oldest first."""
    from app.db.repositories.sources import SourceRepository

    return SourceRepository(connection).list_by_case(case_id, limit=1000)


def _source_detail(connection: sqlite3.Connection, source_id: str) -> ReportSource:
    """One source with parse-error and time-span figures."""
    from app.db.repositories.sources import ParseErrorRepository, SourceRepository

    source = SourceRepository(connection).get(source_id)
    if source is None:  # pragma: no cover - ids come from a live list
        raise ApiError(ErrorCode.NOT_FOUND, "source not found", id=source_id)
    parse_errors = ParseErrorRepository(connection).count_for_source(source_id)
    return ReportSource(
        id=source.id,
        filename=source.filename,
        size_bytes=source.size_bytes,
        sha256=source.sha256,
        log_type=source.log_type,
        status=str(source.status),
        event_count=source.event_count,
        error_count=parse_errors,
        first_seen=iso_from_ms(source.first_event_ms),
        last_seen=iso_from_ms(source.last_event_ms),
    )


def _run_detail(connection: sqlite3.Connection, run: Any) -> ReportRun:
    """Per-status rule counts for one detection run."""
    counts: Counter[str] = Counter()
    for row in DetectionRunRepository(connection).rule_runs(run.id):
        counts[row.status] += 1
    return ReportRun(
        id=run.id,
        profile=run.profile,
        tool_version=run.tool_version,
        ruleset_hash=run.ruleset_hash,
        attack_version=run.attack_version,
        started_at=run.started_at,
        finished_at=run.finished_at,
        status=run.status,
        rules_ok=counts["ok"],
        rules_skipped=counts["skipped_no_data"],
        rules_timeout=counts["timeout"],
        rules_error=counts["error"],
    )


def _technique_payload(item: Any) -> dict[str, Any]:
    """One technique dict with its ATT&CK reference URL."""
    attack_id = str(item["id"])
    name = str(item.get("name") or attack_id)
    return {
        "id": attack_id,
        "name": name,
        "url": f"https://attack.mitre.org/techniques/{attack_id.replace('.', '/')}/",
        **({} if "tactic" not in item else {"tactic": str(item["tactic"])}),
    }


def _rule_description(yaml_text: str | None) -> str | None:
    """The rule's own ``description``, when it has one."""
    if yaml_text is None:
        return None
    import yaml

    try:
        parsed = yaml.safe_load(yaml_text)
    except Exception:
        return None
    if isinstance(parsed, dict):
        text = parsed.get("description")
        return str(text) if text is not None else None
    return None


def _event_briefs(
    connection: sqlite3.Connection, ids: Sequence[int], *, with_raw: bool
) -> list[dict[str, Any]]:
    """Event rows for ``ids``, with ``raw`` optional."""
    if not ids:
        return []
    placeholders = ", ".join("?" for _ in ids)
    rows = connection.execute(
        f"SELECT * FROM events WHERE id IN ({placeholders}) ORDER BY ts_ms, id",
        tuple(ids),
    ).fetchall()
    return [_brief(row, with_raw=with_raw) for row in rows]


def _brief(row: Any, *, with_raw: bool) -> dict[str, Any]:
    """An event row as a JSONable brief."""
    brief = {
        "id": row["id"],
        "source_id": string_or_none(row["source_id"]),
        "record_ref": string_or_none(row["record_ref"]),
        "ts_ms": row["ts_ms"],
        "ts_iso": string_or_none(row["ts_iso"]),
        "log_type": string_or_none(row["log_type"]),
        "ls_category": string_or_none(row["ls_category"]),
        "host": string_or_none(row["host"]),
        "channel": string_or_none(row["channel"]),
        "app_name": string_or_none(row["app_name"]),
        "event_id": string_or_none(row["event_id"]),
        "level": string_or_none(row["level"]),
        "event_action": string_or_none(row["event_action"]),
        "user_name": string_or_none(row["user_name"]),
        "src_ip": string_or_none(row["src_ip"]),
        "dst_ip": string_or_none(row["dst_ip"]),
        "message": string_or_none(row["message"]),
    }
    if with_raw:
        brief["raw"] = string_or_none(row["raw"])
    return brief


def string_or_none(value: Any) -> str | None:
    """Render a row value as text, ``None`` passthrough."""
    return str(value) if value is not None else None


def _alert_iocs(connection: sqlite3.Connection, alert_id: str) -> list[dict[str, Any]]:
    """Linked indicators of one alert (ids and values)."""
    rows = connection.execute(
        "SELECT iocs.id, iocs.type, iocs.value, iocs.confidence "
        "FROM ioc_alerts JOIN iocs ON iocs.id = ioc_alerts.ioc_id "
        "WHERE ioc_alerts.alert_id = ? ORDER BY iocs.id",
        (alert_id,),
    ).fetchall()
    return [
        {
            "id": str(row["id"]),
            "type": str(row["type"]),
            "value": str(row["value"]),
            "confidence": int(row["confidence"]),
        }
        for row in rows
    ]


def _appendix(
    connection: sqlite3.Connection,
    alerts: Sequence[ReportAlert],
    events_per_alert: int,
) -> list[dict[str, Any]]:
    """Raw events for each included alert (spec 08 section 1.10)."""
    appendix: list[dict[str, Any]] = []
    for alert in alerts:
        ids = AlertRepository(connection).event_ids(alert.id)[:events_per_alert]
        rows = _event_briefs(connection, ids, with_raw=True)
        appendix.append({"alert_id": alert.id, "events": rows})
    return appendix


def _alert_mappings(connection: sqlite3.Connection, case_id: str) -> Any:
    """ATT&CK mappings for the navigator layer."""
    from app.mitre.matrix import load_alert_mappings

    return load_alert_mappings(connection, case_id=case_id)


def _technique_graph(
    connection: sqlite3.Connection,
) -> tuple[dict[str, str], dict[str, tuple[str, ...]]]:
    """``(parent_of, own_tactics)`` from ``mitre_techniques`` (navigator feed)."""
    parent_of: dict[str, str] = {}
    own_tactics: dict[str, tuple[str, ...]] = {}
    for row in connection.execute(
        "SELECT attack_id, tactics_json, is_subtechnique, parent_id FROM mitre_techniques"
    ):
        attack_id = str(row["attack_id"])
        own_tactics[attack_id] = tuple(json.loads(str(row["tactics_json"])))
        if bool(row["is_subtechnique"]) and row["parent_id"] is not None:
            parent_of[attack_id] = str(row["parent_id"])
    return parent_of, own_tactics


__all__ = ["gather_report"]
