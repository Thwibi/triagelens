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


def _attack_version(connection: sqlite3.Connection) -> str:
    """ATT&CK bundle version, or empty until one is imported."""
    try:
        row = connection.execute(
            "SELECT value FROM mitre_meta WHERE key = 'attack_version'"
        ).fetchone()
    except sqlite3.Error:
        return ""
    return str(row[0]) if row and row[0] is not None else ""


def _ruleset_hash(connection: sqlite3.Connection) -> str:
    """SHA-256 over the sorted hashes of enabled rules (spec 01 section 9).

    Empty until the rule loader of Phase 6 populates ``rules``; the hash of the
    empty set is well defined, so the field is always populated.
    """
    try:
        rows = connection.execute(
            "SELECT id, sha256 FROM rules WHERE enabled = 1 ORDER BY id"
        ).fetchall()
    except sqlite3.Error:
        return hash_mapping({})
    return hash_mapping({str(row["id"]): str(row["sha256"]) for row in rows})


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
        attack_version = _attack_version(connection)
        ruleset_hash = _ruleset_hash(connection)
    probe_path = settings.data_dir if settings.data_dir.exists() else Path.cwd()
    usage = shutil.disk_usage(probe_path)
    return HealthResponse(
        app_version=APP_VERSION,
        attack_version=attack_version,
        ruleset_hash=ruleset_hash,
        sqlite_version=capabilities.sqlite_version,
        fts5=capabilities.fts5,
        json1=capabilities.json1,
        workers=settings.effective_worker_processes,
        db_bytes=database.db_bytes(),
        free_disk_bytes=usage.free,
        pdf_available=_pdf_available(),
    )


__all__ = ["HealthResponse", "health", "router"]
