"""``GET /api/health`` (spec 06 section 3, spec 01 section 7).

Reports versions, SQLite capabilities, worker configuration, database size and
free disk. This is the only endpoint the Docker ``HEALTHCHECK`` calls, and it is
never cached.
"""

from __future__ import annotations

import importlib.util
import shutil
import sqlite3
from pathlib import Path
from typing import TypedDict

from fastapi import APIRouter, Depends

from app.api.deps import get_database, get_settings
from app.config import Settings
from app.db.connection import Database
from app.db.repositories.rules import RuleRepository
from app.db.repositories.runs import attack_version
from app.util.hashing import hash_mapping
from app.version import APP_VERSION

router = APIRouter(prefix="/api", tags=["health"])


class HealthResponse(TypedDict):
    """Body of ``GET /api/health``."""

    app_version: str
    attack_version: str
    ruleset_hash: str
    sqlite_version: str
    fts5: bool
    json1: bool
    workers: int
    db_bytes: int
    free_disk_bytes: int
    pdf_available: bool


def _ruleset_hash(connection: sqlite3.Connection) -> str:
    """SHA-256 over the sorted hashes of enabled rules (spec 01 section 9)."""
    try:
        return RuleRepository(connection).ruleset_hash()
    except sqlite3.Error:
        # Pre-migration databases have no rules table; the empty-set hash
        # is well defined, so the field is always populated.
        return hash_mapping({})


def _pdf_available() -> bool:
    """True when the optional WeasyPrint extra is importable (spec 08 section 2)."""
    try:
        return importlib.util.find_spec("weasyprint") is not None
    except (ImportError, ValueError):  # pragma: no cover - defensive
        return False


@router.get("/health", response_model=None)
def health(
    settings: Settings = Depends(get_settings),
    database: Database = Depends(get_database),
) -> HealthResponse:
    """Report process, database and storage health."""
    capabilities = database.capabilities
    with database.read_connection() as connection:
        resolved_attack_version = attack_version(connection)
        resolved_ruleset_hash = _ruleset_hash(connection)
    probe_path = settings.data_dir if settings.data_dir.exists() else Path.cwd()
    usage = shutil.disk_usage(probe_path)
    return HealthResponse(
        app_version=APP_VERSION,
        attack_version=resolved_attack_version,
        ruleset_hash=resolved_ruleset_hash,
        sqlite_version=capabilities.sqlite_version,
        fts5=capabilities.fts5,
        json1=capabilities.json1,
        workers=settings.effective_worker_processes,
        db_bytes=database.db_bytes(),
        free_disk_bytes=usage.free,
        pdf_available=_pdf_available(),
    )


__all__ = ["HealthResponse", "health", "router"]
