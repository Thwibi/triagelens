"""Settings endpoints (spec 06 "Health and settings").

``GET /settings`` returns the effective configuration - the deployment config
from ``config.toml`` with the auth token masked (spec 10 section 1), the small
set of analyst overrides laid on top, and the global allowlist. ``PUT /settings``
validates a partial update against the editable schema and appends a
``settings_changed`` row to the audit chain.

The allowlist sub-resource is the global half of the ``allowlist`` table (spec 05
section 5): entries there suppress an indicator for every case, unlike the
case-scoped entries the IOC table writes. Every mutation runs on the writer
thread so the write and its audit row commit together.
"""

from __future__ import annotations

import sqlite3
from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from app.api.deps import (
    allowlist_repository,
    get_settings,
    settings_repository,
    write_in,
)
from app.config import Settings
from app.db.repositories.allowlist import (
    ALLOWLIST_KINDS,
    AllowlistRepository,
)
from app.db.repositories.audit import AuditRepository
from app.db.repositories.settings import SettingsRepository
from app.errors import ApiError, ErrorCode, validation_error
from app.models.allowlist import AllowlistRecord
from app.settings_schema import overlay, validate_overrides

router = APIRouter(prefix="/settings", tags=["settings"])


class SettingsUpdateBody(BaseModel):
    """Body of ``PUT /settings``: dotted keys mapped to their new values."""

    values: dict[str, Any] = Field(default_factory=dict)


class AllowlistBody(BaseModel):
    """Body of ``POST /settings/allowlist``."""

    kind: str
    value: str = Field(min_length=1, max_length=2000)
    note: str | None = Field(default=None, max_length=2000)


@router.get("")
def get_settings_endpoint(
    settings: Settings = Depends(get_settings),
    stored: SettingsRepository = Depends(settings_repository),
    allowlist: AllowlistRepository = Depends(allowlist_repository),
) -> dict[str, Any]:
    """Effective configuration, analyst overrides and the global allowlist."""
    return _settings_payload(settings, stored.get_all(), allowlist.list_global())


@router.put("")
def update_settings_endpoint(
    body: SettingsUpdateBody,
    request: Request,
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    """Validate and persist a partial settings update; audit-logged (spec 06)."""
    validated = validate_overrides(body.values)

    def work(connection: sqlite3.Connection) -> dict[str, Any]:
        stored = SettingsRepository(connection)
        stored.update_many(validated)
        AuditRepository(connection).append(
            "settings_changed",
            detail={"keys": sorted(validated), "values": validated},
        )
        return _settings_payload(
            settings, stored.get_all(), AllowlistRepository(connection).list_global()
        )

    return write_in(request, work)


@router.get("/allowlist")
def list_allowlist(
    allowlist: AllowlistRepository = Depends(allowlist_repository),
) -> dict[str, Any]:
    """Every global allowlist entry, oldest first."""
    items = [_allowlist_payload(entry) for entry in allowlist.list_global()]
    return {"items": items, "total": len(items)}


@router.post("/allowlist", status_code=201)
def create_allowlist(body: AllowlistBody, request: Request) -> dict[str, Any]:
    """Add a global allowlist entry; audit-logged (spec 06)."""
    if body.kind not in ALLOWLIST_KINDS:
        raise validation_error(
            "unsupported allowlist kind",
            kind=body.kind,
            allowed=list(ALLOWLIST_KINDS),
        )
    value = body.value.strip()
    if not value:
        raise validation_error("allowlist value must not be blank")
    kind = body.kind
    note = body.note

    def work(connection: sqlite3.Connection) -> dict[str, Any]:
        entry, created = AllowlistRepository(connection).add_global_entry(
            kind=kind, value=value, note=note
        )
        if created:
            AuditRepository(connection).append(
                "allowlist_changed",
                detail={"action": "add", "id": entry.id, "kind": kind, "value": value},
            )
        return _allowlist_payload(entry)

    return write_in(request, work)


@router.delete("/allowlist/{entry_id}")
def delete_allowlist(entry_id: int, request: Request) -> dict[str, Any]:
    """Remove a global allowlist entry; audit-logged (spec 06)."""

    def work(connection: sqlite3.Connection) -> dict[str, Any]:
        repository = AllowlistRepository(connection)
        entry = repository.get(entry_id)
        if entry is None:
            raise ApiError(ErrorCode.NOT_FOUND, "allowlist entry not found", id=entry_id)
        repository.delete(entry_id)
        AuditRepository(connection).append(
            "allowlist_changed",
            detail={
                "action": "delete",
                "id": entry.id,
                "kind": entry.kind,
                "value": entry.value,
            },
        )
        return {"id": entry_id, "deleted": True}

    return write_in(request, work)


def _settings_payload(
    settings: Settings,
    overrides: dict[str, Any],
    allowlist: list[AllowlistRecord],
) -> dict[str, Any]:
    """The shared response of ``GET`` and ``PUT /settings``."""
    return {
        "settings": overlay(settings.redacted(), overrides),
        "overrides": overrides,
        "allowlist": [_allowlist_payload(entry) for entry in allowlist],
    }


def _allowlist_payload(entry: AllowlistRecord) -> dict[str, Any]:
    """One allowlist row as the API returns it."""
    return {
        "id": entry.id,
        "scope": entry.scope,
        "case_id": entry.case_id,
        "kind": entry.kind,
        "value": entry.value,
        "note": entry.note,
    }


__all__ = ["AllowlistBody", "SettingsUpdateBody", "router"]
