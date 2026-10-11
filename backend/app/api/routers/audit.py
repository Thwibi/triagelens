"""Audit-log endpoints (spec 10 section 2, spec 06 "Reports").

``GET /cases/{id}/audit-log`` serves the append-only, hash-chained audit rows of
one case, newest first, and verifies the whole chain in the same request. The
verification covers rows of every case (not just the requested one): a row of
another case sitting between two of ours would change our own hashes and go
unnoticed, so a case-scoped page can only be trusted after the full walk. The
immutability itself is enforced by storage triggers, not by this module.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query

from app.api.deps import audit_repository, case_repository
from app.db.repositories.audit import AuditEntry, AuditRepository
from app.db.repositories.cases import CaseRepository
from app.errors import ApiError, ErrorCode, validation_error

router = APIRouter(tags=["audit"])

_ORDERS: frozenset[str] = frozenset({"asc", "desc"})


@router.get("/cases/{case_id}/audit-log")
def case_audit_log(  # noqa: PLR0917 - one parameter per documented API field
    case_id: str,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    order: str = Query("desc", max_length=10),
    audit: AuditRepository = Depends(audit_repository),
    cases: CaseRepository = Depends(case_repository),
) -> dict[str, Any]:
    """Audit entries of one case with the chain verification result."""
    if cases.get(case_id) is None:
        raise ApiError(ErrorCode.NOT_FOUND, "case not found", id=case_id)
    if order not in _ORDERS:
        raise validation_error("unsupported order", order=order, allowed=sorted(_ORDERS))
    payload: dict[str, Any] = {
        "items": [
            _entry_payload(entry)
            for entry in audit.list_page(case_id=case_id, limit=limit, offset=offset, order=order)
        ],
        "total": audit.count(case_id=case_id),
        "limit": limit,
        "offset": offset,
    }
    payload.update(audit.verify(case_id=case_id).as_dict())
    return payload


def _entry_payload(entry: AuditEntry) -> dict[str, Any]:
    """One chain row as the API returns it.

    The hashes ride along so an analyst can re-verify the chain offline from a
    page dump; they are deterministic functions of the row, not secrets.
    """
    return {
        "id": entry.id,
        "ts": entry.ts,
        "case_id": entry.case_id,
        "action": entry.action,
        "detail": entry.detail,
        "prev_hash": entry.prev_hash,
        "hash": entry.hash,
    }


__all__ = ["router"]
