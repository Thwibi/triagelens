"""Case endpoints (spec 06 section 3).

Cases are the unit of work an analyst opens. The list endpoint is not in the spec
but the UI cannot offer a case switcher without it, so it exists here and returns
the same envelope as the spec's paginated endpoints.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from app.api.deps import case_repository
from app.db.repositories.cases import CaseRepository
from app.errors import ApiError, ErrorCode

router = APIRouter(prefix="/cases", tags=["cases"])


class CasePatch(BaseModel):
    """Body of ``PATCH /cases/{id}``: any subset may be provided."""

    name: str | None = Field(default=None, min_length=1)
    description: str | None = None
    default_timezone: str | None = None


@router.get("")
def list_cases(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    cases: CaseRepository = Depends(case_repository),
) -> dict[str, Any]:
    """Cases, newest first, with the unpaginated total."""
    rows = cases.list(limit=limit, offset=offset)
    return {
        "items": [_detail(row) for row in rows],
        "total": cases.count(),
        "limit": limit,
        "offset": offset,
    }


@router.post("", status_code=201)
def create_case(
    body: dict[str, Any],
    cases: CaseRepository = Depends(case_repository),
) -> dict[str, Any]:
    """Create a case."""
    name = body.get("name")
    if not isinstance(name, str) or not name.strip():
        raise ApiError(ErrorCode.VALIDATION_ERROR, "name is required")
    timezone = body.get("default_timezone") or "UTC"
    if not isinstance(timezone, str):
        raise ApiError(ErrorCode.VALIDATION_ERROR, "default_timezone must be a string")
    description = body.get("description")
    if description is not None and not isinstance(description, str):
        raise ApiError(ErrorCode.VALIDATION_ERROR, "description must be a string")
    record = cases.create(name=name, description=description, default_timezone=timezone)
    return _detail(record)


@router.get("/{case_id}")
def get_case(case_id: str, cases: CaseRepository = Depends(case_repository)) -> dict[str, Any]:
    """One case with its rollup counts."""
    record = cases.get(case_id)
    if record is None:
        raise ApiError(ErrorCode.NOT_FOUND, "case not found", case_id=case_id)
    return _detail(record)


@router.patch("/{case_id}")
def patch_case(
    case_id: str,
    update: CasePatch,
    cases: CaseRepository = Depends(case_repository),
) -> dict[str, Any]:
    """Rename a case, edit its description, or move its default timezone."""
    record = cases.get(case_id)
    if record is None:
        raise ApiError(ErrorCode.NOT_FOUND, "case not found", case_id=case_id)

    changes: dict[str, Any] = {}
    if update.name is not None and update.name.strip() != record.name:
        changes["name"] = update.name.strip()
    if update.description is not None and update.description != record.description:
        changes["description"] = update.description
    if update.default_timezone is not None and update.default_timezone != record.default_timezone:
        changes["default_timezone"] = update.default_timezone
    if changes:
        cases.update(case_id, **changes)
    return _detail(cases.get(case_id) or record)


@router.delete("/{case_id}")
def delete_case(case_id: str, cases: CaseRepository = Depends(case_repository)) -> dict[str, Any]:
    """Delete a case and everything under it."""
    if cases.get(case_id) is None:
        raise ApiError(ErrorCode.NOT_FOUND, "case not found", case_id=case_id)
    cases.delete(case_id)
    return {"id": case_id, "deleted": True}


def _detail(record: Any) -> dict[str, Any]:
    """A case row as the API returns it."""
    return {
        "id": record.id,
        "name": record.name,
        "description": record.description,
        "default_timezone": record.default_timezone,
        "created_at": record.created_at,
        "updated_at": record.updated_at,
        "counts": record.counts.as_dict(),
    }


__all__ = ["router"]
