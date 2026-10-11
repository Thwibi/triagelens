"""Alert endpoints (spec 06 "Alerts").

Reads run on a request-scoped read connection; ``PATCH`` and ``bulk`` run on
the single writer thread and append to the audit hash chain just like every
other analyst mutation. The MITRE mapping stored on each alert is served back
verbatim; ``unresolved_tags`` and the score breakdown are recomputed on
demand from the same stored state (spec 04 sections 7 and 8).
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from fastapi import APIRouter, Depends, Query
from fastapi import Request as FastAPIRequest
from pydantic import BaseModel, Field

from app.api.deps import alert_repository, get_settings, rule_repository, write_in
from app.config import Settings
from app.db.repositories.alerts import AlertRepository
from app.db.repositories.audit import AuditRepository
from app.db.repositories.rules import RuleRepository
from app.detect.engine import EventMatch, execute_rules
from app.detect.routing import load_logsource_map
from app.detect.scoring import score_alert as compute_score
from app.errors import ApiError, ErrorCode, validation_error
from app.mitre.catalogue import MitreCatalogue
from app.mitre.enrich import resolve_alert_mitre
from app.mitre.tactics import TACTIC_NAMES
from app.models.alert import ALERT_ANALYST_STATUSES, ALERT_STATUSES, AlertRecord
from app.models.rule import RuleRecord

router = APIRouter(tags=["alerts"])

_LEVELS: frozenset[str] = frozenset({"informational", "low", "medium", "high", "critical"})
_SORTS: frozenset[str] = frozenset(
    {"score", "first_seen", "last_seen", "created_at", "rule_title", "match_count"}
)


class AlertPatchBody(BaseModel):
    """Body of ``PATCH /alerts/{id}``: any subset may be provided."""

    status: str | None = None
    analyst_notes: str | None = Field(default=None, max_length=20_000)


class AlertBulkBody(BaseModel):
    """Body of ``POST /alerts/bulk``."""

    ids: list[str] = Field(min_length=1, max_length=1000)
    status: str


@router.get("/cases/{case_id}/alerts")
def list_alerts(  # noqa: PLR0917 - one parameter per documented API field
    case_id: str,
    level: str | None = Query(None),
    status: str | None = Query(None),
    rule_id: str | None = Query(None, max_length=200),
    host: str | None = Query(None, max_length=255),
    user_name: str | None = Query(None, max_length=255),
    min_score: int | None = Query(None, ge=0, le=100),
    q: str | None = Query(None, max_length=200),
    tactic: str | None = Query(None, max_length=80),
    technique: str | None = Query(None, max_length=20),
    unmapped: bool = Query(False),  # noqa: FBT001, FBT003 - FastAPI query flag
    sort: str = Query("-score"),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    alerts: AlertRepository = Depends(alert_repository),
    rules: RuleRepository = Depends(rule_repository),
) -> dict[str, Any]:
    """Alerts of one case, spec 06 filters, default ``-score`` order."""
    if level is not None and level not in _LEVELS:
        raise validation_error("unsupported alert level", level=level, allowed=sorted(_LEVELS))
    if status is not None and status not in ALERT_STATUSES:
        raise validation_error(
            "unsupported alert status", status=status, allowed=sorted(ALERT_STATUSES)
        )
    _require_sort(sort)
    try:
        items, total = alerts.search(
            case_id,
            level=level,
            status=status,
            rule_id=rule_id,
            host=host,
            user_name=user_name,
            min_score=min_score,
            q=q,
            tactic=tactic,
            technique=technique,
            unmapped=unmapped,
            sort=sort,
            limit=limit,
            offset=offset,
        )
    except ValueError as error:
        raise validation_error(str(error)) from error
    catalogue = MitreCatalogue.load(alerts.connection)
    unresolved = _unresolved_by_rule(alerts.connection, rules)
    return {
        "items": [_alert_payload(record, catalogue, unresolved) for record in items],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/alerts/{alert_id}")
def get_alert(
    alert_id: str,
    alerts: AlertRepository = Depends(alert_repository),
    rules: RuleRepository = Depends(rule_repository),
) -> dict[str, Any]:
    """One alert plus its scoring breakdown, evidence, IOCs and rule (spec 06)."""
    record = alerts.get(alert_id)
    if record is None:
        raise ApiError(ErrorCode.NOT_FOUND, "alert not found", id=alert_id)
    connection = alerts.connection
    catalogue = MitreCatalogue.load(connection)
    rule = rules.get(record.rule_id)
    payload = _alert_payload(
        record,
        catalogue,
        _unresolved_by_rule(connection, rules),
    )
    breakdown = compute_score(
        connection,
        record,
        rule_status=rule.status if rule is not None else None,
    )
    payload["score_breakdown"] = [
        {"label": label, "delta": delta} for label, delta in breakdown.breakdown.items()
    ]
    payload["events"] = [
        _event_brief(row) for row in _events_by_id(connection, alerts.event_ids(alert_id)).values()
    ]
    payload["iocs"] = _alert_iocs(connection, alert_id)
    if rule is not None:
        payload["rule"] = {
            "id": rule.id,
            "title": rule.title,
            "description": _rule_description(rule),
            "yaml": rule.yaml,
        }
    return payload


@router.patch("/alerts/{alert_id}")
def patch_alert(
    alert_id: str,
    body: AlertPatchBody,
    request: FastAPIRequest,
) -> dict[str, Any]:
    """Set an analyst verdict and/or notes; audit-logged (spec 06)."""

    def work(conn: sqlite3.Connection) -> dict[str, Any]:
        repository = AlertRepository(conn)
        record = repository.get(alert_id)
        if record is None:
            raise ApiError(ErrorCode.NOT_FOUND, "alert not found", id=alert_id)
        if body.status is not None and body.status not in ALERT_ANALYST_STATUSES:
            raise validation_error(
                "status not settable by an analyst",
                status=body.status,
                allowed=sorted(ALERT_ANALYST_STATUSES),
            )
        notes = record.analyst_notes if body.analyst_notes is None else body.analyst_notes
        new_status = record.status if body.status is None else body.status
        updated = repository.set_status(alert_id, status=new_status, analyst_notes=notes)
        audit = AuditRepository(conn)
        if body.status is not None:
            audit.append(
                "alert_status",
                case_id=record.case_id,
                detail={"alert_id": alert_id, "status": new_status},
            )
        if body.analyst_notes is not None and notes != record.analyst_notes:
            audit.append("alert_notes", case_id=record.case_id, detail={"alert_id": alert_id})
        if updated is None:
            raise ApiError(ErrorCode.NOT_FOUND, "alert not found", id=alert_id)
        return {
            "item": _alert_payload(
                updated,
                MitreCatalogue.load(conn),
                {},
            )
        }

    return write_in(request, work)


@router.post("/alerts/bulk")
def bulk_update_alerts(
    body: AlertBulkBody,
    request: FastAPIRequest,
) -> dict[str, Any]:
    """Set the same verdict on many alerts; audit-logged (spec 06)."""
    if body.status not in ALERT_ANALYST_STATUSES:
        raise validation_error(
            "status not settable by an analyst",
            status=body.status,
            allowed=sorted(ALERT_ANALYST_STATUSES),
        )

    def work(conn: sqlite3.Connection) -> dict[str, Any]:
        repository = AlertRepository(conn)
        updated: list[dict[str, Any]] = []
        audit = AuditRepository(conn)
        for alert_id in body.ids:
            record = repository.set_status(alert_id, status=body.status)
            if record is None:
                raise ApiError(ErrorCode.NOT_FOUND, "alert not found", id=alert_id)
            updated.append(_alert_payload(record, MitreCatalogue.load(conn), {}))
        audit.append(
            "alert_status",
            detail={"alert_ids": list(body.ids), "count": len(body.ids), "status": body.status},
        )
        return {"items": updated, "updated": len(updated)}

    return write_in(request, work)


@router.get("/alerts/{alert_id}/events")
def alert_evidence_events(  # noqa: PLR0917 - one parameter per documented API field
    alert_id: str,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    alerts: AlertRepository = Depends(alert_repository),
    rules: RuleRepository = Depends(rule_repository),
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    """Evidence beyond the stored sample: re-queries the rule (spec 06)."""
    record = alerts.get(alert_id)
    if record is None:
        raise ApiError(ErrorCode.NOT_FOUND, "alert not found", id=alert_id)
    event_ids = _evidence_event_ids(
        alerts.connection,
        record,
        rules.get(record.rule_id),
        load_logsource_map(settings.rules_dir / "logsource_map.yaml"),
        settings,
    )
    page = event_ids[offset : offset + limit]
    return {
        "items": list(_events_by_id(alerts.connection, page).values()),
        "total": len(event_ids),
        "limit": limit,
        "offset": offset,
    }


def _evidence_event_ids(
    connection: sqlite3.Connection,
    alert: AlertRecord,
    rule: RuleRecord | None,
    logsource_map: dict[str, dict[str, str]],
    settings: Settings,
) -> list[int]:
    """All evidence events of the cluster window.

    Re-runs the single rule and keeps the matches whose host/user and
    timestamp fall inside the alert's stored window; when the rule no longer
    compiles the stored sample is the best evidence left.
    """
    if rule is None or rule.compile_error is not None or rule.unroutable:
        return AlertRepository(connection).event_ids(alert.id)
    try:
        result = execute_rules(
            connection,
            case_id=alert.case_id,
            rules=[rule],
            logsource_map=logsource_map,
            timeout_seconds=settings.detection.rule_timeout_seconds,
        )
    except Exception:
        return AlertRepository(connection).event_ids(alert.id)
    matches = result.executions[0].matches if result.executions else ()
    return [match.event_id for match in matches if _inside_alert(alert, match)]


def _inside_alert(alert: AlertRecord, match: EventMatch) -> bool:
    """True when the match belongs to this alert's cluster."""
    if match.ts_ms is None or alert.first_seen_ms is None or alert.last_seen_ms is None:
        return False
    if not (alert.first_seen_ms <= match.ts_ms <= alert.last_seen_ms):
        return False
    if alert.host is not None and match.host != alert.host:
        return False
    return not (alert.user_name is not None and match.user_name != alert.user_name)


def _alert_payload(
    record: AlertRecord,
    catalogue: Any,
    unresolved: dict[str, tuple[str, ...]],
) -> dict[str, Any]:
    """An ``alerts`` row as the API returns it (spec 06 ``Alert``)."""
    tactics = [str(item) for item in json.loads(record.tactics_json)]
    return {
        "id": record.id,
        "case_id": record.case_id,
        "rule_id": record.rule_id,
        "rule_title": record.rule_title,
        "rule_kind": record.rule_kind,
        "rule_type": record.rule_type,
        "level": record.level,
        "score": record.score,
        "status": record.status,
        "analyst_notes": record.analyst_notes,
        "tactics": [
            {
                "shortname": shortname,
                "name": catalogue.tactics.get(shortname, TACTIC_NAMES.get(shortname, shortname)),
            }
            for shortname in tactics
        ],
        "techniques": json.loads(record.techniques_json),
        "groups_software": json.loads(record.groups_software_json),
        "unresolved_tags": list(unresolved.get(record.rule_id, ())),
        "host": record.host,
        "user_name": record.user_name,
        "group_key": record.group_key,
        "first_seen_ms": record.first_seen_ms,
        "last_seen_ms": record.last_seen_ms,
        "match_count": record.match_count,
        "false_positives": json.loads(record.false_positives_json),
        "references": json.loads(record.references_json),
    }


def _unresolved_by_rule(
    connection: sqlite3.Connection, rules: RuleRepository
) -> dict[str, tuple[str, ...]]:
    """Unresolved ATT&CK tags per rule, recomputed from the rule's own tags."""
    catalogue = MitreCatalogue.load(connection)
    result: dict[str, tuple[str, ...]] = {}
    for rule in rules.list(limit=100_000):
        if rule.tags:
            result[rule.id] = resolve_alert_mitre(rule.tags, catalogue=catalogue).unresolved_tags
    return result


def _require_sort(sort: str) -> None:
    column = sort[1:] if sort.startswith("-") else sort
    if column not in _SORTS:
        raise validation_error("unsupported sort", sort=sort, allowed=sorted(_SORTS))


def _rule_description(rule: RuleRecord) -> str | None:
    import yaml

    try:
        description = yaml.safe_load(rule.yaml)
    except Exception:
        return None
    if isinstance(description, dict):
        text = description.get("description")
        return str(text) if text is not None else None
    return None


def _events_by_id(
    connection: sqlite3.Connection, event_ids: list[int]
) -> dict[int, dict[str, Any]]:
    """Event rows (no raw) for the given ids, each keyed by id."""
    if not event_ids:
        return {}
    # Placeholders are only "?", never caller text; the ids are bound values.
    placeholders = ", ".join("?" for _ in event_ids)
    rows = connection.execute(
        f"SELECT * FROM events WHERE id IN ({placeholders}) ORDER BY ts_ms, id",  # noqa: S608 - count is bound, ids are parameters
        tuple(event_ids),
    ).fetchall()
    return {int(row["id"]): _event_brief(row) for row in rows}


def _event_brief(row: Any) -> dict[str, Any]:
    """An event row as the alert detail shows it: metadata, no raw."""
    return {
        "id": row["id"],
        "source_id": row["source_id"],
        "record_ref": row["record_ref"],
        "ts_ms": row["ts_ms"],
        "ts_iso": row["ts_iso"],
        "log_type": row["log_type"],
        "ls_category": row["ls_category"],
        "host": row["host"],
        "channel": row["channel"],
        "app_name": row["app_name"],
        "event_id": row["event_id"],
        "level": row["level"],
        "event_action": row["event_action"],
        "user_name": row["user_name"],
        "src_ip": row["src_ip"],
        "dst_ip": row["dst_ip"],
        "message": row["message"],
    }


def _alert_iocs(connection: sqlite3.Connection, alert_id: str) -> list[dict[str, Any]]:
    """Linked indicators of one alert (spec 06 ``AlertDetail.iocs``)."""
    rows = connection.execute(
        "SELECT iocs.id, iocs.type, iocs.value, iocs.value_norm, iocs.confidence "
        "FROM ioc_alerts JOIN iocs ON iocs.id = ioc_alerts.ioc_id "
        "WHERE ioc_alerts.alert_id = ? ORDER BY iocs.id",
        (alert_id,),
    ).fetchall()
    return [
        {
            "id": row["id"],
            "type": row["type"],
            "value": row["value"],
            "value_norm": row["value_norm"],
            "confidence": row["confidence"],
        }
        for row in rows
    ]


__all__ = ["AlertBulkBody", "AlertPatchBody", "router"]
