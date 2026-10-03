"""Case repository (spec 02 section 4, ``cases``).

Every statement is parameterised. Where a column name has to be built into SQL
it comes from the module-level ``_UPDATABLE`` allowlist, never from caller input
(spec 10 section 1, "SQL injection").
"""

from __future__ import annotations

import sqlite3
from typing import Any

from app.models.case import CaseRecord
from app.util.ids import new_id
from app.util.time import utc_now_iso

#: Columns a caller may change, and the only names ever interpolated into SQL.
_UPDATABLE: dict[str, str | None] = {
    "name": "str",
    "description": "str?",
    "default_timezone": "str",
}

_COUNT_COLUMNS = (
    "(SELECT COUNT(*) FROM sources s WHERE s.case_id = c.id) AS sources_count, "
    "(SELECT COUNT(*) FROM events e WHERE e.case_id = c.id) AS events_count, "
    "(SELECT COUNT(*) FROM alerts a WHERE a.case_id = c.id) AS alerts_count, "
    "(SELECT COUNT(*) FROM iocs i WHERE i.case_id = c.id) AS iocs_count"
)

_SELECT = f"SELECT c.*, {_COUNT_COLUMNS} FROM cases c"


class CaseRepository:
    """Create, read, update and delete cases with their rollup counts."""

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
        name: str,
        description: str | None = None,
        default_timezone: str = "UTC",
        case_id: str | None = None,
    ) -> CaseRecord:
        """Insert a case and return it with zeroed counts."""
        identifier = case_id or new_id()
        now = utc_now_iso()
        self._conn.execute(
            "INSERT INTO cases (id, name, description, default_timezone, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (identifier, name, description, default_timezone, now, now),
        )
        created = self.get(identifier)
        if created is None:  # pragma: no cover - the INSERT above always produces a row
            raise RuntimeError(f"case {identifier} vanished immediately after insert")
        return created

    def get(self, case_id: str) -> CaseRecord | None:
        """One case by id, or ``None``."""
        row = self._conn.execute(f"{_SELECT} WHERE c.id = ?", (case_id,)).fetchone()
        return CaseRecord.from_row(row) if row is not None else None

    def list(self, *, limit: int = 100, offset: int = 0, order: str = "desc") -> list[CaseRecord]:
        """One page of cases, newest first by default."""
        direction = "ASC" if order.lower() == "asc" else "DESC"
        rows = self._conn.execute(
            f"{_SELECT} ORDER BY c.updated_at {direction}, c.id {direction} LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
        return [CaseRecord.from_row(row) for row in rows]

    def count(self) -> int:
        """Total number of cases."""
        row = self._conn.execute("SELECT COUNT(*) FROM cases").fetchone()
        return int(row[0]) if row else 0

    def update(
        self,
        case_id: str,
        *,
        name: str | None = None,
        description: str | None = None,
        default_timezone: str | None = None,
        clear_description: bool = False,
    ) -> bool:
        """Update the supplied fields and bump ``updated_at``.

        Returns ``False`` when the case does not exist. Passing
        ``clear_description=True`` sets the description back to NULL; leaving
        ``description`` as ``None`` leaves it untouched.
        """
        changes: dict[str, str | None] = {}
        if name is not None:
            changes["name"] = name
        if clear_description:
            changes["description"] = None
        elif description is not None:
            changes["description"] = description
        if default_timezone is not None:
            changes["default_timezone"] = default_timezone
        if not changes:
            return self.get(case_id) is not None

        unknown = set(changes) - set(_UPDATABLE)
        if unknown:  # pragma: no cover - guards against a future edit slipping through
            raise ValueError(f"columns not updatable on cases: {sorted(unknown)}")

        assignments = ", ".join(f"{column} = ?" for column in changes)
        values: list[Any] = [changes[column] for column in changes]
        values.append(utc_now_iso())
        values.append(case_id)
        cursor = self._conn.execute(
            f"UPDATE cases SET {assignments}, updated_at = ? WHERE id = ?", values
        )
        return cursor.rowcount > 0

    def touch(self, case_id: str) -> bool:
        """Bump ``updated_at`` without changing any other field."""
        cursor = self._conn.execute(
            "UPDATE cases SET updated_at = ? WHERE id = ?", (utc_now_iso(), case_id)
        )
        return cursor.rowcount > 0

    def delete(self, case_id: str) -> bool:
        """Delete a case; sources, events, alerts and IOCs cascade."""
        cursor = self._conn.execute("DELETE FROM cases WHERE id = ?", (case_id,))
        return cursor.rowcount > 0

    def names(self) -> dict[str, str]:
        """``{case_id: name}`` for every case, used in log context."""
        rows = self._conn.execute("SELECT id, name FROM cases").fetchall()
        return {str(row["id"]): str(row["name"]) for row in rows}


__all__ = ["CaseRepository"]
