"""IOC and entity endpoints (spec 06 "Indicators and entities").

Reads run on a request-scoped read connection; the PATCH mutation and the
allowlist insert run on the single writer thread like every other write in the
process.
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, Query, Request, Response
from pydantic import BaseModel, Field

from app.api.deps import ioc_repository, write_in
from app.db.repositories.allowlist import AllowlistRepository
from app.db.repositories.iocs import IocRecord, IocRepository
from app.errors import ApiError, ErrorCode, validation_error
from app.ioc.export import MEDIA_TYPES, render_csv, render_json, render_stix, render_txt
from app.models.ioc import AnalystState, Entity

router = APIRouter(tags=["iocs"])

#: The schema CHECK constraint's IOC type list, also used to 422 bad ``type`` filters.
IOC_TYPES: frozenset[str] = frozenset(
    {
        "ipv4",
        "ipv6",
        "domain",
        "url",
        "email",
        "md5",
        "sha1",
        "sha256",
        "filename",
        "filepath",
        "registry",
        "cve",
        "user_agent",
        "command",
    }
)

_SORTS: frozenset[str] = frozenset(
    {"last_seen", "first_seen", "confidence", "occurrences", "value"}
)


class IocPatchBody(BaseModel):
    """Body of ``PATCH /iocs/{id}``: any subset may be provided."""

    analyst_state: AnalystState | None = None
    tags: list[str] | None = Field(default=None, max_length=50)
    allowlist: bool = False


class IocExportBody(BaseModel):
    """Body of ``POST /cases/{id}/iocs/export``."""

    format: str
    ids: list[str] | None = None
    filters: dict[str, Any] | None = None
    defang: bool = False


def _ioc_detail(record: IocRecord) -> dict[str, Any]:
    """An ``iocs`` row as the API returns it."""
    return {
        "id": record.id,
        "case_id": record.case_id,
        "type": record.type,
        "value": record.value,
        "value_norm": record.value_norm,
        "first_seen_ms": record.first_seen_ms,
        "last_seen_ms": record.last_seen_ms,
        "occurrences": record.occurrences,
        "confidence": record.confidence,
        "is_private": record.is_private,
        "is_allowlisted": record.is_allowlisted,
        "analyst_state": record.analyst_state,
        "tags": record.tags,
    }


def _entity_detail(entity: Entity) -> dict[str, Any]:
    return {
        "kind": entity.kind,
        "name": entity.name,
        "event_count": entity.event_count,
        "alert_count": entity.alert_count,
    }


@router.get("/cases/{case_id}/iocs")
def list_iocs(  # noqa: PLR0917 - one parameter per documented API field
    case_id: str,
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    ioc_type: str | None = Query(None, alias="type"),
    min_confidence: int | None = Query(None, ge=0, le=100),
    q: str | None = Query(None, max_length=200),
    host: str | None = Query(None, max_length=255),
    state: AnalystState | None = Query(None),
    include_private: bool = Query(False),  # noqa: FBT001, FBT003 - FastAPI query flag
    include_allowlisted: bool = Query(False),  # noqa: FBT001, FBT003 - FastAPI query flag
    sort: str = Query("last_seen"),
    order: str = Query("desc"),
    iocs: IocRepository = Depends(ioc_repository),
) -> dict[str, Any]:
    """Indicators of a case, with the spec 06 filters and the unpaginated total."""
    if ioc_type is not None and ioc_type not in IOC_TYPES:
        raise validation_error(
            "unsupported IOC type",
            type=ioc_type,
            allowed=sorted(IOC_TYPES),
        )
    if sort not in _SORTS:
        raise validation_error("unsupported sort", sort=sort, allowed=sorted(_SORTS))
    if order not in ("asc", "desc"):
        raise validation_error("unsupported order", order=order)
    items, total = iocs.search(
        case_id,
        ioc_type=ioc_type,
        min_confidence=min_confidence,
        q=q,
        host=host,
        state=state.value if state is not None else None,
        include_private=include_private,
        include_allowlisted=include_allowlisted,
        sort=sort,
        order=order,
        limit=limit,
        offset=offset,
    )
    return {
        "items": [_ioc_detail(record) for record in items],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/iocs/{ioc_id}")
def get_ioc(ioc_id: str, iocs: IocRepository = Depends(ioc_repository)) -> dict[str, Any]:
    """One indicator with an ``occurrences`` preview (newest first)."""
    record = iocs.get(ioc_id)
    if record is None:
        raise ApiError(ErrorCode.NOT_FOUND, "ioc not found", id=ioc_id)
    detail = _ioc_detail(record)
    detail["occurrences_preview"] = iocs.occurrences(ioc_id, limit=50)
    return detail


@router.get("/iocs/{ioc_id}/occurrences")
def list_ioc_occurrences(
    ioc_id: str,
    limit: int = Query(500, ge=1, le=5000),
    iocs: IocRepository = Depends(ioc_repository),
) -> dict[str, Any]:
    """Where one indicator was seen, newest event first (spec 06)."""
    if iocs.get(ioc_id) is None:
        raise ApiError(ErrorCode.NOT_FOUND, "ioc not found", id=ioc_id)
    occurrences = iocs.occurrences(ioc_id, limit=limit)
    return {"items": occurrences, "total": len(occurrences), "limit": limit}


@router.patch("/iocs/{ioc_id}")
def patch_ioc(
    ioc_id: str,
    body: IocPatchBody,
    request: Request,
) -> dict[str, Any]:
    """Set an analyst verdict, tags, and optionally allowlist a benign IOC."""

    def work(conn: Any) -> dict[str, Any]:
        iocs = IocRepository(conn)
        record = iocs.get(ioc_id)
        if record is None:
            raise ApiError(ErrorCode.NOT_FOUND, "ioc not found", id=ioc_id)
        if body.allowlist and body.analyst_state != AnalystState.BENIGN:
            raise validation_error("allowlist requires analyst_state=benign")
        state = record.analyst_state if body.analyst_state is None else body.analyst_state.value
        if body.tags is not None:
            iocs.set_analyst_state(ioc_id, analyst_state=state, tags=body.tags)
        else:
            iocs.set_analyst_state(ioc_id, analyst_state=state)
        if body.allowlist and body.analyst_state == AnalystState.BENIGN:
            entry = AllowlistRepository(conn).entry_for_ioc(record)
            if entry is not None:
                AllowlistRepository(conn).add_case_entry(
                    case_id=record.case_id,
                    kind=entry[0],
                    value=entry[1],
                    note=f"mark benign from IOC {ioc_id}",
                )
        updated = iocs.get(ioc_id)
        return _ioc_detail(updated or record)

    return write_in(request, work)


@router.post("/cases/{case_id}/iocs/export")
def export_iocs(
    case_id: str,
    body: IocExportBody,
    iocs: IocRepository = Depends(ioc_repository),
) -> Response:
    """Download the case's indicators in csv, txt, stix or json (spec 05 section 8)."""
    fmt = body.format
    if fmt not in MEDIA_TYPES:
        raise validation_error("unsupported export format", format=fmt, allowed=sorted(MEDIA_TYPES))

    def _fetch() -> list[IocRecord]:
        if body.ids:
            records: list[IocRecord] = []
            for ioc_id in body.ids:
                record = iocs.get(ioc_id)
                if record is None or record.case_id != case_id:
                    raise validation_error("ioc not in case", case_id=case_id, ioc_id=ioc_id)
                records.append(record)
            return records
        filters = body.filters or {}
        records, _ = iocs.search(
            case_id,
            ioc_type=_str_or_none(filters.get("type")),
            min_confidence=_int_or_none(filters.get("min_confidence")),
            q=_str_or_none(filters.get("q")),
            host=_str_or_none(filters.get("host")),
            state=_str_or_none(filters.get("state")),
            include_private=bool(filters.get("include_private", False)),
            include_allowlisted=bool(filters.get("include_allowlisted", False)),
            sort=str(filters.get("sort") or "last_seen"),
            order=str(filters.get("order") or "desc"),
            limit=100_000,
            offset=0,
        )
        return records

    records = _fetch()
    defanged = body.defang
    if fmt == "csv":
        content = render_csv(records, defanged=defanged)
    elif fmt == "txt":
        content = render_txt(records, defanged=defanged)
    elif fmt == "stix":
        content = json.dumps(render_stix(records, defanged=defanged), indent=2)
    else:
        content = render_json(records, defanged=defanged, occurrences_of=iocs.occurrences)
    return Response(
        content=content,
        media_type=MEDIA_TYPES[fmt],
        headers={"Content-Disposition": f'attachment; filename="iocs-{case_id}.{fmt}"'},
    )


@router.get("/cases/{case_id}/entities")
def list_entities(
    case_id: str,
    iocs: IocRepository = Depends(ioc_repository),
) -> list[dict[str, Any]]:
    """Hosts and users seen in the case, with event counts (spec 06)."""
    return [_entity_detail(Entity(**row)) for row in iocs.entities(case_id)]


def _str_or_none(value: Any) -> str | None:
    return str(value) if value is not None else None


def _int_or_none(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise validation_error("invalid integer filter", value=value)
    return value


__all__ = ["router"]
