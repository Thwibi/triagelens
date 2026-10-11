"""Event endpoints (spec 06 "Events").

Browsing is read-only; analyst mutations live in their own endpoints. The
list, count and facets endpoints share one filter set: ``q`` runs against the
FTS index, ranges apply to ``ts_ms`` and ``ioc_id``/``alert_id`` select events
linked through the IOC/alerts junction tables. Listing uses keyset pagination
on ``(ts_ms, id)``, so ``next_cursor`` stays valid when new events land
between pages (no offset drift; spec 06).
"""

from __future__ import annotations

import base64
import json
import sqlite3
from collections.abc import Iterator
from typing import Any

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse

from app.api.deps import case_repository, event_repository, get_database, rule_repository
from app.db.connection import Database
from app.db.repositories.cases import CaseRepository
from app.db.repositories.events import EventFilters, EventRepository
from app.db.repositories.rules import RuleRepository
from app.errors import ApiError, ErrorCode, validation_error
from app.mitre.catalogue import MitreCatalogue
from app.mitre.enrich import resolve_alert_mitre
from app.mitre.tactics import TACTIC_NAMES
from app.models.alert import AlertRecord
from app.reports.export import EXPORT_FORMATS, EXPORT_MEDIA_TYPE, MAX_ROWS, iter_events_export

router = APIRouter(tags=["events"])

_LEVELS: frozenset[str] = frozenset({"informational", "low", "medium", "high", "critical"})
#: Events page on ``(ts_ms, id)``; those are the only sound keyset orders.
_SORTS: frozenset[str] = frozenset({"-ts", "ts"})
#: ``/timeline`` bucket names (spec 06); ``auto`` picks one from the data span.
_BUCKETS: frozenset[str] = frozenset({"auto", "1m", "5m", "1h", "1d"})


@router.get("/cases/{case_id}/events")
def list_events(  # noqa: PLR0917 - one parameter per documented API filter
    case_id: str,
    q: str | None = Query(None, max_length=200),
    from_ms: int | None = Query(None),
    to_ms: int | None = Query(None),
    host: str | None = Query(None, max_length=255),
    source_id: str | None = Query(None, max_length=255),
    log_type: str | None = Query(None, max_length=80),
    channel: str | None = Query(None, max_length=255),
    event_id: int | None = Query(None),
    ls_category: str | None = Query(None, max_length=80),
    user_name: str | None = Query(None, max_length=255),
    src_ip: str | None = Query(None, max_length=45),
    dst_ip: str | None = Query(None, max_length=45),
    ioc_id: str | None = Query(None, max_length=200),
    alert_id: str | None = Query(None, max_length=200),
    level: str | None = Query(None, max_length=20),
    include: str | None = Query(None, max_length=20),
    sort: str = Query("-ts"),
    limit: int = Query(100, ge=1, le=1000),
    cursor: str | None = Query(None),
    events: EventRepository = Depends(event_repository),
    cases: CaseRepository = Depends(case_repository),
) -> dict[str, Any]:
    """Events of one case, spec 06 filters, newest first by default."""
    _require_case(cases, case_id)
    _validate_common(level=level, include=include, sort=sort)
    filters = _filters(
        case_id,
        q=q,
        from_ms=from_ms,
        to_ms=to_ms,
        host=host,
        source_id=source_id,
        log_type=log_type,
        channel=channel,
        event_id=event_id,
        ls_category=ls_category,
        user_name=user_name,
        src_ip=src_ip,
        dst_ip=dst_ip,
        ioc_id=ioc_id,
        alert_id=alert_id,
        level=level,
    )
    position = _decode_cursor(cursor) if cursor is not None else None
    include_raw = include == "raw"
    try:
        rows, next_cursor = events.search(
            filters, sort=sort, cursor=position, limit=limit, include_raw=include_raw
        )
    except ValueError as error:
        raise validation_error(str(error)) from error
    return {
        "items": [_event_payload(row, include_raw=include_raw) for row in rows],
        "next_cursor": _encode_cursor(next_cursor) if next_cursor is not None else None,
        "total": None,
    }


@router.get("/cases/{case_id}/events/count")
def count_events(  # noqa: PLR0917 - one parameter per documented API filter
    case_id: str,
    q: str | None = Query(None, max_length=200),
    from_ms: int | None = Query(None),
    to_ms: int | None = Query(None),
    host: str | None = Query(None, max_length=255),
    source_id: str | None = Query(None, max_length=255),
    log_type: str | None = Query(None, max_length=80),
    channel: str | None = Query(None, max_length=255),
    event_id: int | None = Query(None),
    ls_category: str | None = Query(None, max_length=80),
    user_name: str | None = Query(None, max_length=255),
    src_ip: str | None = Query(None, max_length=45),
    dst_ip: str | None = Query(None, max_length=45),
    ioc_id: str | None = Query(None, max_length=200),
    alert_id: str | None = Query(None, max_length=200),
    level: str | None = Query(None, max_length=20),
    events: EventRepository = Depends(event_repository),
    cases: CaseRepository = Depends(case_repository),
) -> dict[str, Any]:
    """Total events matching the filters (spec 06; list ``total`` is null)."""
    _require_case(cases, case_id)
    _validate_common(level=level, include=None, sort="ts")
    filters = _filters(
        case_id,
        q=q,
        from_ms=from_ms,
        to_ms=to_ms,
        host=host,
        source_id=source_id,
        log_type=log_type,
        channel=channel,
        event_id=event_id,
        ls_category=ls_category,
        user_name=user_name,
        src_ip=src_ip,
        dst_ip=dst_ip,
        ioc_id=ioc_id,
        alert_id=alert_id,
        level=level,
    )
    try:
        total = events.count(filters)
    except ValueError as error:
        raise validation_error(str(error)) from error
    return {"count": total}


@router.get("/cases/{case_id}/events/facets")
def event_facets(  # noqa: PLR0917 - one parameter per documented API filter
    case_id: str,
    q: str | None = Query(None, max_length=200),
    from_ms: int | None = Query(None),
    to_ms: int | None = Query(None),
    host: str | None = Query(None, max_length=255),
    source_id: str | None = Query(None, max_length=255),
    log_type: str | None = Query(None, max_length=80),
    channel: str | None = Query(None, max_length=255),
    event_id: int | None = Query(None),
    ls_category: str | None = Query(None, max_length=80),
    user_name: str | None = Query(None, max_length=255),
    src_ip: str | None = Query(None, max_length=45),
    dst_ip: str | None = Query(None, max_length=45),
    ioc_id: str | None = Query(None, max_length=200),
    alert_id: str | None = Query(None, max_length=200),
    level: str | None = Query(None, max_length=20),
    limit: int = Query(20, ge=1, le=100),
    events: EventRepository = Depends(event_repository),
    cases: CaseRepository = Depends(case_repository),
) -> dict[str, Any]:
    """Top values per facet column under the current filters (spec 06)."""
    _require_case(cases, case_id)
    _validate_common(level=level, include=None, sort="ts")
    filters = _filters(
        case_id,
        q=q,
        from_ms=from_ms,
        to_ms=to_ms,
        host=host,
        source_id=source_id,
        log_type=log_type,
        channel=channel,
        event_id=event_id,
        ls_category=ls_category,
        user_name=user_name,
        src_ip=src_ip,
        dst_ip=dst_ip,
        ioc_id=ioc_id,
        alert_id=alert_id,
        level=level,
    )
    try:
        facets = events.facets(filters, limit=limit)
    except ValueError as error:
        raise validation_error(str(error)) from error
    return {"facets": facets}


@router.get("/cases/{case_id}/timeline")
def event_timeline(  # noqa: PLR0917 - one parameter per documented API filter
    case_id: str,
    q: str | None = Query(None, max_length=200),
    from_ms: int | None = Query(None),
    to_ms: int | None = Query(None),
    host: str | None = Query(None, max_length=255),
    source_id: str | None = Query(None, max_length=255),
    log_type: str | None = Query(None, max_length=80),
    channel: str | None = Query(None, max_length=255),
    event_id: int | None = Query(None),
    ls_category: str | None = Query(None, max_length=80),
    user_name: str | None = Query(None, max_length=255),
    src_ip: str | None = Query(None, max_length=45),
    dst_ip: str | None = Query(None, max_length=45),
    ioc_id: str | None = Query(None, max_length=200),
    alert_id: str | None = Query(None, max_length=200),
    level: str | None = Query(None, max_length=20),
    bucket: str = Query("auto", max_length=8),
    events: EventRepository = Depends(event_repository),
    cases: CaseRepository = Depends(case_repository),
) -> dict[str, Any]:
    """Bucketed event volume under the same filters as the list (spec 06)."""
    _require_case(cases, case_id)
    _validate_common(level=level, include=None, sort="ts")
    if bucket not in _BUCKETS:
        raise validation_error("unsupported bucket", bucket=bucket, allowed=sorted(_BUCKETS))
    filters = _filters(
        case_id,
        q=q,
        from_ms=from_ms,
        to_ms=to_ms,
        host=host,
        source_id=source_id,
        log_type=log_type,
        channel=channel,
        event_id=event_id,
        ls_category=ls_category,
        user_name=user_name,
        src_ip=src_ip,
        dst_ip=dst_ip,
        ioc_id=ioc_id,
        alert_id=alert_id,
        level=level,
    )
    try:
        timeline = events.timeline(filters, bucket=bucket)
    except ValueError as error:
        raise validation_error(str(error)) from error
    return timeline


@router.get("/cases/{case_id}/events/export")
def export_events(  # noqa: PLR0917 - one parameter per documented API filter
    case_id: str,
    format_: str = Query("csv", alias="format", max_length=8),
    q: str | None = Query(None, max_length=200),
    from_ms: int | None = Query(None),
    to_ms: int | None = Query(None),
    host: str | None = Query(None, max_length=255),
    source_id: str | None = Query(None, max_length=255),
    log_type: str | None = Query(None, max_length=80),
    channel: str | None = Query(None, max_length=255),
    event_id: int | None = Query(None),
    ls_category: str | None = Query(None, max_length=80),
    user_name: str | None = Query(None, max_length=255),
    src_ip: str | None = Query(None, max_length=45),
    dst_ip: str | None = Query(None, max_length=45),
    ioc_id: str | None = Query(None, max_length=200),
    alert_id: str | None = Query(None, max_length=200),
    level: str | None = Query(None, max_length=20),
    sort: str = Query("-ts"),
    limit: int = Query(MAX_ROWS, ge=1, le=MAX_ROWS),
    database: Database = Depends(get_database),
) -> StreamingResponse:
    """Stream the current filter result as CSV or JSONL (spec 08 4, 07 3.7).

    The filters match ``GET /cases/{id}/events`` exactly, so the download is the
    current result set. Rows are walked in keyset pages and yielded as text, so a
    multi-million-row case is never assembled in memory (spec 06 section 5); the
    scan stops at ``limit`` rows (the UI's 1M ceiling). Invalid FTS syntax is
    rejected with ``422`` before the body starts, matching the list endpoint.
    """
    if format_ not in EXPORT_FORMATS:
        raise validation_error(
            "unsupported export format", format=format_, allowed=sorted(EXPORT_FORMATS)
        )
    _validate_common(level=level, include=None, sort=sort)
    filters = _filters(
        case_id,
        q=q,
        from_ms=from_ms,
        to_ms=to_ms,
        host=host,
        source_id=source_id,
        log_type=log_type,
        channel=channel,
        event_id=event_id,
        ls_category=ls_category,
        user_name=user_name,
        src_ip=src_ip,
        dst_ip=dst_ip,
        ioc_id=ioc_id,
        alert_id=alert_id,
        level=level,
    )
    with database.read_connection() as connection:
        _require_case(CaseRepository(connection), case_id)
        try:
            EventRepository(connection).search(filters, sort=sort, limit=1)
        except ValueError as error:
            raise validation_error(str(error)) from error

    def stream() -> Iterator[str]:
        with database.read_connection() as connection:
            yield from iter_events_export(
                EventRepository(connection), filters, fmt=format_, sort=sort, max_rows=limit
            )

    return StreamingResponse(
        stream(),
        media_type=EXPORT_MEDIA_TYPE[format_],
        headers={
            "Content-Disposition": f'attachment; filename="events-{case_id}.{format_}"',
            "Cache-Control": "no-store",
        },
    )


@router.get("/events/{event_id}")
def get_event(
    event_id: int,
    events: EventRepository = Depends(event_repository),
    rules: RuleRepository = Depends(rule_repository),
) -> dict[str, Any]:
    """One event with its full record, linked alerts and IOCs (spec 06)."""
    row = events.get(event_id)
    if row is None:
        raise ApiError(ErrorCode.NOT_FOUND, "event not found", id=event_id)
    payload = _event_payload(row, include_raw=True)
    connection = events.connection
    catalogue = MitreCatalogue.load(connection)
    payload["alerts"] = _event_alerts(connection, event_id, rules, catalogue)
    payload["iocs"] = _event_iocs(connection, event_id)
    return payload


def _filters(
    case_id: str,
    *,
    q: str | None,
    from_ms: int | None,
    to_ms: int | None,
    host: str | None,
    source_id: str | None,
    log_type: str | None,
    channel: str | None,
    event_id: int | None,
    ls_category: str | None,
    user_name: str | None,
    src_ip: str | None,
    dst_ip: str | None,
    ioc_id: str | None,
    alert_id: str | None,
    level: str | None,
) -> EventFilters:
    return EventFilters(
        case_id=case_id,
        q=_blank_to_none(q),
        from_ms=from_ms,
        to_ms=to_ms,
        host=host,
        source_id=source_id,
        log_type=log_type,
        channel=channel,
        event_id=event_id,
        ls_category=ls_category,
        user_name=user_name,
        src_ip=src_ip,
        dst_ip=dst_ip,
        ioc_id=ioc_id,
        alert_id=alert_id,
        level=level,
    )


def _require_case(cases: CaseRepository, case_id: str) -> None:
    if cases.get(case_id) is None:
        raise ApiError(ErrorCode.NOT_FOUND, "case not found", id=case_id)


def _validate_common(*, level: str | None, include: str | None, sort: str) -> None:
    if level is not None and level not in _LEVELS:
        raise validation_error("unsupported event level", level=level, allowed=sorted(_LEVELS))
    if include is not None and include != "raw":
        raise validation_error("unsupported include", include=include, allowed=["raw"])
    if sort not in _SORTS:
        raise validation_error("unsupported sort", sort=sort, allowed=sorted(_SORTS))


def _blank_to_none(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _encode_cursor(position: tuple[int, int]) -> str:
    """Opaque url-safe cursor for one keyset position (spec 06)."""
    return base64.urlsafe_b64encode(f"{position[0]}:{position[1]}".encode()).decode().rstrip("=")


def _decode_cursor(cursor: str) -> tuple[int, int]:
    """Decode an ``(ts_ms, id)`` keyset cursor, rejecting malformed input."""
    padded = cursor + "=" * (-len(cursor) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode()).decode()
        ts_s, event_s = raw.split(":", 1)
        return int(ts_s), int(event_s)
    except (ValueError, UnicodeDecodeError) as error:
        raise validation_error("invalid event cursor", cursor=cursor) from error


def _event_payload(row: Any, *, include_raw: bool) -> dict[str, Any]:
    """One event row as the API returns it (spec 06 ``Event``)."""
    payload = {
        "id": row["id"],
        "case_id": row["case_id"],
        "source_id": row["source_id"],
        "record_ref": row["record_ref"],
        "ts_ms": row["ts_ms"],
        "ts_iso": row["ts_iso"],
        "log_type": row["log_type"],
        "ls_category": row["ls_category"],
        "host": row["host"],
        "channel": row["channel"],
        "provider": row["provider"],
        "app_name": row["app_name"],
        "event_id": row["event_id"],
        "level": row["level"],
        "event_action": row["event_action"],
        "event_outcome": row["event_outcome"],
        "user_name": row["user_name"],
        "target_user_name": row["target_user_name"],
        "domain": row["domain"],
        "src_ip": row["src_ip"],
        "src_port": row["src_port"],
        "dst_ip": row["dst_ip"],
        "dst_port": row["dst_port"],
        "protocol": row["protocol"],
        "process_pid": row["process_pid"],
        "process_path": row["process_path"],
        "process_cmdline": row["process_cmdline"],
        "parent_process_path": row["parent_process_path"],
        "parent_process_cmdline": row["parent_process_cmdline"],
        "file_path": row["file_path"],
        "registry_key": row["registry_key"],
        "registry_value": row["registry_value"],
        "url": row["url"],
        "url_path": row["url_path"],
        "url_query": row["url_query"],
        "http_method": row["http_method"],
        "http_status": row["http_status"],
        "user_agent": row["user_agent"],
        "bytes_out": row["bytes_out"],
        "message": row["message"],
        "fields": json.loads(row["fields_json"]),
    }
    if include_raw:
        payload["raw"] = row["raw"]
    return payload


def _event_alerts(
    connection: sqlite3.Connection,
    event_id: int,
    rules: RuleRepository,
    catalogue: MitreCatalogue,
) -> list[dict[str, Any]]:
    """Linked alerts of one event, in the same shape as alert detail."""
    rows = connection.execute(
        "SELECT a.* FROM alert_events ae JOIN alerts a ON a.id = ae.alert_id "
        "WHERE ae.event_id = ? ORDER BY a.id",
        (event_id,),
    ).fetchall()
    records = [AlertRecord.from_row(row) for row in rows]
    unresolved = _unresolved_by_rule(rules, records, catalogue)
    return [
        _alert_summary(record, catalogue, unresolved.get(record.rule_id, ())) for record in records
    ]


def _unresolved_by_rule(
    rules: RuleRepository,
    records: list[AlertRecord],
    catalogue: MitreCatalogue,
) -> dict[str, tuple[str, ...]]:
    """Unresolved ATT&CK tags per rule, resolved once per linked rule."""
    result: dict[str, tuple[str, ...]] = {}
    seen: set[str] = set()
    for record in records:
        rule_id = record.rule_id
        if rule_id in seen:
            continue
        seen.add(rule_id)
        rule = rules.get(rule_id)
        result[rule_id] = (
            resolve_alert_mitre(rule.tags, catalogue=catalogue).unresolved_tags
            if rule is not None
            else ()
        )
    return result


def _alert_summary(
    record: AlertRecord, catalogue: MitreCatalogue, unresolved: tuple[str, ...]
) -> dict[str, Any]:
    """Mirrors the alert router's payload so both call sites agree."""
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
        "unresolved_tags": list(unresolved),
        "host": record.host,
        "user_name": record.user_name,
        "group_key": record.group_key,
        "first_seen_ms": record.first_seen_ms,
        "last_seen_ms": record.last_seen_ms,
        "match_count": record.match_count,
        "false_positives": json.loads(record.false_positives_json),
        "references": json.loads(record.references_json),
    }


def _event_iocs(connection: sqlite3.Connection, event_id: int) -> list[dict[str, Any]]:
    """Indicators that occurred in this event (deduplicated per IOC)."""
    rows = connection.execute(
        "SELECT i.id, i.type, i.value, i.value_norm, i.confidence "
        "FROM ioc_occurrences io JOIN iocs i ON i.id = io.ioc_id "
        "WHERE io.event_id = ? GROUP BY i.id ORDER BY i.id",
        (event_id,),
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
