"""Data-maintenance endpoints (spec 10 section 5, spec 07 section 3.13).

The Settings screen's Data pane exposes four operations, none of which is in the
spec 06 endpoint table because spec 06 predates it: vacuum the database, rebuild
the FTS index, verify every stored original still hashes to its intake-time
digest, and verify the audit hash chain. The first two mutate the database and so
run on the writer thread (VACUUM without a surrounding transaction, since SQLite
forbids it inside one); the last two are read-only and run on a short-lived read
connection.

These are maintenance actions, not part of the request path: a large database can
make VACUUM or an FTS rebuild slow, so they use a longer timeout than the normal
writer hand-off.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Request

from app.api.deps import get_database, get_writer, read_connection
from app.db.connection import Database
from app.db.repositories.audit import AuditRepository
from app.db.repositories.events import EventRepository
from app.db.repositories.sources import SourceRepository
from app.util.hashing import verify_sha256

router = APIRouter(prefix="/maintenance", tags=["maintenance"])

#: Maintenance work can be slow on a large database; block this long for the
#: writer thread before treating it as wedged.
MAINTENANCE_TIMEOUT = 300.0


@router.post("/vacuum")
def vacuum(request: Request, database: Database = Depends(get_database)) -> dict[str, Any]:
    """Reclaim free pages and compact the database file (spec 10 section 5).

    ``VACUUM`` cannot run inside a transaction, so it is submitted to the writer
    thread without one. Read connections are closed for the request, so no other
    statement is mid-flight on this connection.
    """
    before = database.db_bytes()

    def work(connection: sqlite3.Connection) -> None:
        connection.execute("VACUUM")

    get_writer(request).run(work, transactional=False).result(timeout=MAINTENANCE_TIMEOUT)
    return {"ok": True, "db_bytes_before": before, "db_bytes_after": database.db_bytes()}


@router.post("/rebuild-fts")
def rebuild_fts(request: Request) -> dict[str, Any]:
    """Rebuild the event FTS index from its content table (spec 10 section 5)."""

    def work(connection: sqlite3.Connection) -> int:
        return EventRepository(connection).rebuild_fts()

    indexed = get_writer(request).run(work).result(timeout=MAINTENANCE_TIMEOUT)
    return {"ok": True, "indexed": int(indexed)}


@router.post("/verify-hashes")
def verify_hashes(
    connection: sqlite3.Connection = Depends(read_connection),
) -> dict[str, Any]:
    """Recompute every original's SHA-256 and compare with the stored digest.

    Forensic integrity (spec 10 section 2): a mismatch means the stored evidence
    changed after intake; a missing file means it is no longer on disk. Both are
    reported with the source id and case so an analyst can act, and the response
    is ``ok`` only when every source passes.
    """
    sources = SourceRepository(connection).all_for_hash_check()
    mismatched: list[dict[str, Any]] = []
    missing: list[dict[str, Any]] = []
    for source_id, case_id, stored_path, expected in sources:
        path = Path(stored_path)
        if not path.is_file():
            missing.append({"source_id": source_id, "case_id": case_id, "path": stored_path})
        elif not verify_sha256(path, expected):
            mismatched.append({"source_id": source_id, "case_id": case_id, "path": stored_path})
    return {
        "ok": not mismatched and not missing,
        "checked": len(sources),
        "mismatched": mismatched,
        "missing": missing,
    }


@router.post("/verify-audit")
def verify_audit(
    connection: sqlite3.Connection = Depends(read_connection),
) -> dict[str, Any]:
    """Walk the whole audit hash chain and report the first broken row."""
    return AuditRepository(connection).verify().as_dict()


__all__ = ["router"]
