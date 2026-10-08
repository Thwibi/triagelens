"""Event repository (spec 02 section 4, `events` + FTS)."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import Any

from app.ingest.events import EVENT_COLUMNS, NormalizedEvent

_FTS_COLUMNS = (
    "message",
    "process_cmdline",
    "parent_process_cmdline",
    "url",
    "user_agent",
    "file_path",
    "raw",
)

_INSERT_SQL = (
    f"INSERT INTO events ({', '.join((*EVENT_COLUMNS, 'fields_json', 'raw'))}) "
    f"VALUES ({', '.join('?' * (len(EVENT_COLUMNS) + 2))})"
)
_FTS_DELETE_SQL = "INSERT INTO events_fts(events_fts, rowid) VALUES('delete', ?)"
_FTS_INSERT_SQL = (
    f"INSERT INTO events_fts(rowid, {', '.join(_FTS_COLUMNS)}) VALUES(?, ?, ?, ?, ?, ?, ?, ?)"
)

BATCH_SIZE = 5000


@dataclass(slots=True)
class EventBatch:
    events: list[NormalizedEvent]
    event_ids: list[int]


class EventRepository:
    __slots__ = ("_conn",)

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._conn = connection

    @property
    def connection(self) -> sqlite3.Connection:
        return self._conn

    def add(self, event: NormalizedEvent) -> int:
        cursor = self._conn.execute(_INSERT_SQL, event.values())
        return int(cursor.lastrowid or 0)

    def add_fts(self, event_id: int, event: NormalizedEvent) -> None:
        row = (
            event_id,
            event.message or "",
            event.process_cmdline or "",
            event.parent_process_cmdline or "",
            event.url or "",
            event.user_agent or "",
            event.file_path or "",
            event.raw or "",
        )
        self._conn.execute(_FTS_INSERT_SQL, row)

    def delete_for_source(self, source_id: str) -> int:
        rows = self._conn.execute(
            "SELECT id FROM events WHERE source_id = ?", (source_id,)
        ).fetchall()
        ids = [int(r[0]) for r in rows]
        for eid in ids:
            self._conn.execute(_FTS_DELETE_SQL, (eid,))
        cursor = self._conn.execute("DELETE FROM events WHERE source_id = ?", (source_id,))
        return cursor.rowcount

    def count_for_source(self, source_id: str) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) FROM events WHERE source_id = ?", (source_id,)
        ).fetchone()
        return int(row[0]) if row else 0

    def time_range_for_source(self, source_id: str) -> tuple[int | None, int | None]:
        row = self._conn.execute(
            "SELECT MIN(ts_ms), MAX(ts_ms) FROM events WHERE source_id = ?", (source_id,)
        ).fetchone()
        if row is None:
            return None, None
        minv = row[0]
        maxv = row[1]
        return (int(minv) if minv is not None else None, int(maxv) if maxv is not None else None)

    def insert_many(self, events: Sequence[NormalizedEvent]) -> list[int]:
        """Insert a batch and return their rowids."""
        ids: list[int] = []
        for event in events:
            ids.append(self.add(event))
        return ids


def _chunks(items: Sequence[Any]) -> Iterator[Sequence[Any]]:
    for i in range(0, len(items), BATCH_SIZE):
        yield items[i : i + BATCH_SIZE]


__all__ = ["BATCH_SIZE", "EventBatch", "EventRepository"]
