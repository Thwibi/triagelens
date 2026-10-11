"""Source repository (spec 02 section 4, ``sources``, ``parse_errors``,
``source_inventory``).

Intake itself lives in ``app.ingest`` (Phase 1); this repository is the typed
persistence surface those stages and the API use.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable, Sequence
from typing import Any

from app.db.connection import atomic
from app.models.source import (
    InventoryRow,
    ParseErrorRecord,
    SourceRecord,
    SourceStatus,
)
from app.util.ids import new_id
from app.util.time import utc_now_iso

#: Hard cap on a stored raw excerpt (spec 01 section 3, stage 3: "<= 2 KB").
MAX_RAW_EXCERPT_CHARS = 2048

#: Columns a caller may change on a source.
_UPDATABLE: frozenset[str] = frozenset(
    {"log_type", "detect_confidence", "timezone", "assumed_year", "filename"}
)

_SELECT = "SELECT * FROM sources"


class SourceRepository:
    """Create, read, update and delete ingested files."""

    __slots__ = ("_conn",)

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._conn = connection

    @property
    def connection(self) -> sqlite3.Connection:
        """The underlying connection."""
        return self._conn

    def create(
        self,
        *,
        case_id: str,
        filename: str,
        stored_path: str,
        size_bytes: int,
        sha256: str,
        status: SourceStatus = SourceStatus.QUEUED,
        parent_source_id: str | None = None,
        log_type: str | None = None,
        detect_confidence: float | None = None,
        timezone: str | None = None,
        assumed_year: int | None = None,
        source_id: str | None = None,
    ) -> SourceRecord:
        """Insert a source row and return it."""
        identifier = source_id or new_id()
        self._conn.execute(
            "INSERT INTO sources (id, case_id, filename, parent_source_id, stored_path, "
            "size_bytes, sha256, log_type, detect_confidence, timezone, assumed_year, "
            "status, ingested_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                identifier,
                case_id,
                filename,
                parent_source_id,
                stored_path,
                size_bytes,
                sha256,
                log_type,
                detect_confidence,
                timezone,
                assumed_year,
                str(status),
                utc_now_iso(),
            ),
        )
        created = self.get(identifier)
        if created is None:  # pragma: no cover - the INSERT above always produces a row
            raise RuntimeError(f"source {identifier} vanished immediately after insert")
        return created

    def get(self, source_id: str) -> SourceRecord | None:
        """One source by id, or ``None``."""
        row = self._conn.execute(f"{_SELECT} WHERE id = ?", (source_id,)).fetchone()
        return SourceRecord.from_row(row) if row is not None else None

    def list_by_case(
        self,
        case_id: str,
        *,
        limit: int = 100,
        offset: int = 0,
        status: SourceStatus | None = None,
    ) -> list[SourceRecord]:
        """Sources of one case, oldest first."""
        if status is None:
            rows = self._conn.execute(
                f"{_SELECT} WHERE case_id = ? ORDER BY ingested_at, id LIMIT ? OFFSET ?",
                (case_id, limit, offset),
            ).fetchall()
        else:
            rows = self._conn.execute(
                f"{_SELECT} WHERE case_id = ? AND status = ? "
                "ORDER BY ingested_at, id LIMIT ? OFFSET ?",
                (case_id, str(status), limit, offset),
            ).fetchall()
        return [SourceRecord.from_row(row) for row in rows]

    def count_by_case(self, case_id: str) -> int:
        """Number of sources in a case."""
        row = self._conn.execute(
            "SELECT COUNT(*) FROM sources WHERE case_id = ?", (case_id,)
        ).fetchone()
        return int(row[0]) if row else 0

    def update(self, source_id: str, **changes: Any) -> bool:
        """Update the supplied columns. Unknown keys are rejected, not ignored."""
        unknown = set(changes) - _UPDATABLE
        if unknown:
            raise ValueError(f"columns not updatable on sources: {sorted(unknown)}")
        if not changes:
            return self.get(source_id) is not None
        assignments = ", ".join(f"{column} = ?" for column in changes)
        values: list[Any] = [changes[column] for column in changes]
        values.append(source_id)
        cursor = self._conn.execute(f"UPDATE sources SET {assignments} WHERE id = ?", values)
        return cursor.rowcount > 0

    def set_status(
        self,
        source_id: str,
        status: SourceStatus,
        *,
        error_detail: str | None = None,
    ) -> bool:
        """Move a source to a new lifecycle state."""
        cursor = self._conn.execute(
            "UPDATE sources SET status = ?, error_detail = ? WHERE id = ?",
            (str(status), error_detail, source_id),
        )
        return cursor.rowcount > 0

    def set_counters(
        self,
        source_id: str,
        *,
        event_count: int,
        error_count: int,
        first_event_ms: int | None,
        last_event_ms: int | None,
    ) -> bool:
        """Store the final event and error counts and the observed time span."""
        cursor = self._conn.execute(
            "UPDATE sources SET event_count = ?, error_count = ?, first_event_ms = ?, "
            "last_event_ms = ? WHERE id = ?",
            (event_count, error_count, first_event_ms, last_event_ms, source_id),
        )
        return cursor.rowcount > 0

    def delete(self, source_id: str) -> bool:
        """Delete a source; events, parse errors and inventory cascade."""
        cursor = self._conn.execute("DELETE FROM sources WHERE id = ?", (source_id,))
        return cursor.rowcount > 0

    def stored_path(self, source_id: str) -> str | None:
        """On-disk path of the original file, or ``None`` when unknown."""
        row = self._conn.execute(
            "SELECT stored_path FROM sources WHERE id = ?", (source_id,)
        ).fetchone()
        return str(row["stored_path"]) if row else None

    def all_for_hash_check(self) -> list[tuple[str, str, str, str]]:
        """Every source's ``(id, case_id, stored_path, sha256)`` for verification.

        Used by the maintenance "verify all hashes" action (spec 10 section 5),
        which recomputes each stored original's digest and compares it with the
        intake-time value.
        """
        rows = self._conn.execute(
            "SELECT id, case_id, stored_path, sha256 FROM sources ORDER BY case_id, id"
        ).fetchall()
        return [
            (str(row["id"]), str(row["case_id"]), str(row["stored_path"]), str(row["sha256"]))
            for row in rows
        ]


class ParseErrorRepository:
    """Malformed records recorded during parsing."""

    __slots__ = ("_conn",)

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._conn = connection

    @property
    def connection(self) -> sqlite3.Connection:
        """The underlying connection."""
        return self._conn

    def add(
        self,
        *,
        source_id: str,
        record_ref: str,
        reason: str,
        raw_excerpt: str | None = None,
    ) -> int:
        """Record one malformed record and return its row id.

        The excerpt is clipped to :data:`MAX_RAW_EXCERPT_CHARS` so a hostile
        multi-megabyte line cannot bloat the database.
        """
        excerpt = raw_excerpt[:MAX_RAW_EXCERPT_CHARS] if raw_excerpt else None
        cursor = self._conn.execute(
            "INSERT INTO parse_errors (source_id, record_ref, reason, raw_excerpt) "
            "VALUES (?, ?, ?, ?)",
            (source_id, record_ref, reason, excerpt),
        )
        return int(cursor.lastrowid or 0)

    def list_for_source(
        self,
        source_id: str,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> list[ParseErrorRecord]:
        """One page of malformed records for a source."""
        rows = self._conn.execute(
            "SELECT * FROM parse_errors WHERE source_id = ? ORDER BY id LIMIT ? OFFSET ?",
            (source_id, limit, offset),
        ).fetchall()
        return [ParseErrorRecord.from_row(row) for row in rows]

    def count_for_source(self, source_id: str) -> int:
        """Number of malformed records for a source."""
        row = self._conn.execute(
            "SELECT COUNT(*) FROM parse_errors WHERE source_id = ?", (source_id,)
        ).fetchone()
        return int(row[0]) if row else 0

    def clear_for_source(self, source_id: str) -> int:
        """Drop malformed records before a re-parse replaces them."""
        cursor = self._conn.execute("DELETE FROM parse_errors WHERE source_id = ?", (source_id,))
        return cursor.rowcount


class InventoryRepository:
    """What each source actually contained, used to prune rules."""

    __slots__ = ("_conn",)

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._conn = connection

    @property
    def connection(self) -> sqlite3.Connection:
        """The underlying connection."""
        return self._conn

    def replace_for_source(
        self,
        source_id: str,
        rows: Iterable[tuple[str, str, str, str, int]],
    ) -> int:
        """Atomically replace a source's inventory with the given tuples.

        Tuples are ``(log_type, channel, app_name, ls_category, event_count)``;
        empty strings stand in for NULL so the composite primary key stays
        well-defined.
        """
        payload: Sequence[tuple[str, str, str, str, int]] = [
            (log_type, channel or "", app_name or "", ls_category or "", int(count))
            for log_type, channel, app_name, ls_category, count in rows
        ]
        with atomic(self._conn):
            self._conn.execute("DELETE FROM source_inventory WHERE source_id = ?", (source_id,))
            if payload:
                self._conn.executemany(
                    "INSERT INTO source_inventory "
                    "(source_id, log_type, channel, app_name, ls_category, event_count) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    [(source_id, *row) for row in payload],
                )
        return len(payload)

    def for_case(self, case_id: str) -> list[tuple[str, str]]:
        """Distinct ``(channel, ls_category)`` pairs present in a case."""
        rows = self._conn.execute(
            "SELECT DISTINCT i.channel, i.ls_category FROM source_inventory i "
            "JOIN sources s ON s.id = i.source_id WHERE s.case_id = ?",
            (case_id,),
        ).fetchall()
        return [(str(row["channel"]), str(row["ls_category"])) for row in rows]

    def for_source(self, source_id: str) -> list[InventoryRow]:
        """A source's inventory rows."""
        rows = self._conn.execute(
            "SELECT log_type, channel, app_name, ls_category, event_count "
            "FROM source_inventory WHERE source_id = ? ORDER BY log_type, channel",
            (source_id,),
        ).fetchall()
        return [InventoryRow.from_row(row) for row in rows]


__all__ = [
    "MAX_RAW_EXCERPT_CHARS",
    "InventoryRepository",
    "ParseErrorRepository",
    "SourceRepository",
]
