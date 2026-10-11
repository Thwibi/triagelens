"""Report repository (spec 02 section 4, ``reports``).

One row per generated report file. The file itself lives under
``data/reports/<case_id>/<report_id>.<ext>``; this table records its format, the
options it was generated with, its path and its SHA-256 so a download can be
verified against what was written (spec 08 sections 1 and 2).
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Any

from app.util.ids import new_id
from app.util.time import utc_now_iso

#: Formats a report may be written in (mirrors the schema CHECK).
REPORT_FORMATS: frozenset[str] = frozenset({"html", "pdf", "md", "json"})

_SELECT = "SELECT id, case_id, format, options_json, path, sha256, created_at FROM reports"


@dataclass(frozen=True, slots=True)
class ReportRecord:
    """One row of ``reports``."""

    id: str
    case_id: str
    format: str
    options_json: str
    path: str
    sha256: str
    created_at: str

    @classmethod
    def from_row(cls, row: Any) -> ReportRecord:
        """Build a record from a ``sqlite3.Row``-like mapping."""
        return cls(
            id=str(row["id"]),
            case_id=str(row["case_id"]),
            format=str(row["format"]),
            options_json=str(row["options_json"]),
            path=str(row["path"]),
            sha256=str(row["sha256"]),
            created_at=str(row["created_at"]),
        )


class ReportRepository:
    """Create and read generated reports."""

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
        fmt: str,
        options_json: str,
        path: str,
        sha256: str,
        report_id: str | None = None,
    ) -> ReportRecord:
        """Insert a report row and return it."""
        if fmt not in REPORT_FORMATS:
            raise ValueError(f"unsupported report format: {fmt!r}")
        identifier = report_id or new_id()
        self._conn.execute(
            "INSERT INTO reports (id, case_id, format, options_json, path, sha256, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (identifier, case_id, fmt, options_json, path, sha256, utc_now_iso()),
        )
        created = self.get(identifier)
        if created is None:  # pragma: no cover - the INSERT above always produces a row
            raise RuntimeError(f"report {identifier} vanished immediately after insert")
        return created

    def get(self, report_id: str) -> ReportRecord | None:
        """One report by id, or ``None``."""
        row = self._conn.execute(f"{_SELECT} WHERE id = ?", (report_id,)).fetchone()
        return ReportRecord.from_row(row) if row is not None else None

    def list_by_case(
        self, case_id: str, *, limit: int = 100, offset: int = 0
    ) -> list[ReportRecord]:
        """Reports of one case, newest first."""
        rows = self._conn.execute(
            f"{_SELECT} WHERE case_id = ? ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
            (case_id, limit, offset),
        ).fetchall()
        return [ReportRecord.from_row(row) for row in rows]

    def count_by_case(self, case_id: str) -> int:
        """Number of reports in a case."""
        row = self._conn.execute(
            "SELECT COUNT(*) FROM reports WHERE case_id = ?", (case_id,)
        ).fetchone()
        return int(row[0]) if row else 0

    def delete(self, report_id: str) -> bool:
        """Delete one report row (the file is removed by the caller)."""
        cursor = self._conn.execute("DELETE FROM reports WHERE id = ?", (report_id,))
        return cursor.rowcount > 0


__all__ = ["REPORT_FORMATS", "ReportRecord", "ReportRepository"]
