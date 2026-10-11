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

#: Event columns served by list endpoints (never ``raw`` by default). Qualified
#: so the FTS join (whose columns share names) cannot turn them ambiguous.
#: ``id`` is the autoincrement primary key, not part of ``EVENT_COLUMNS``.
_EVENT_COLS = ", ".join(f"events.{column}" for column in ("id", *EVENT_COLUMNS, "fields_json"))
_EVENT_COLS_RAW = f"{_EVENT_COLS}, events.raw"

#: Columns the ``events/facets`` endpoint buckets (spec 06).
_FACET_COLUMNS: tuple[str, ...] = (
    "host",
    "log_type",
    "channel",
    "event_id",
    "user_name",
    "src_ip",
)

#: Two link filters are expressed as ``EXISTS`` against the junction tables;
#: the column constants are what make the SQL safe to interpolate.
_EXISTS_IOC = (
    "EXISTS (SELECT 1 FROM ioc_occurrences io WHERE io.event_id = events.id AND io.ioc_id = ?)"
)
_EXISTS_ALERT = (
    "EXISTS (SELECT 1 FROM alert_events ae WHERE ae.event_id = events.id AND ae.alert_id = ?)"
)

#: Event columns with an exact-match filter; every value is bound, never text.
_EQUALS_COLUMNS: tuple[str, ...] = (
    "host",
    "source_id",
    "log_type",
    "channel",
    "event_id",
    "ls_category",
    "user_name",
    "src_ip",
    "dst_ip",
    "level",
)

#: Timeline bucket sizes in milliseconds (spec 06); ``auto`` picks one from
#: the filtered data span, never below ``1m``.
_BUCKET_MS: dict[str, int] = {
    "1m": 60_000,
    "5m": 300_000,
    "1h": 3_600_000,
    "1d": 86_400_000,
}

#: Span thresholds that drive the ``auto`` bucket choice (<= -> bucket).
_AUTO_BUCKET_SPANS: tuple[tuple[int, str], ...] = (
    (15 * 60_000, "1m"),
    (6 * 3_600_000, "5m"),
    (3 * 86_400_000, "1h"),
)

BATCH_SIZE = 5000


@dataclass(slots=True)
class EventBatch:
    events: list[NormalizedEvent]
    event_ids: list[int]


@dataclass(frozen=True, slots=True)
class EventFilters:
    """Filters shared by event list, count and facets (spec 06).

    ``q`` runs against the FTS index; ``ioc_id``/``alert_id`` select events
    linked through ``ioc_occurrences``/``alert_events``.
    """

    case_id: str
    q: str | None = None
    from_ms: int | None = None
    to_ms: int | None = None
    host: str | None = None
    source_id: str | None = None
    log_type: str | None = None
    channel: str | None = None
    event_id: int | None = None
    ls_category: str | None = None
    user_name: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    ioc_id: str | None = None
    alert_id: str | None = None
    level: str | None = None


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

    def rebuild_fts(self) -> int:
        """Rebuild the FTS index from the ``events`` content table.

        The index is normally maintained row by row, but a crash mid-delete or a
        restored database can leave it out of step with its content. ``rebuild``
        discards and re-derives it in one statement; returns the number of
        indexed events afterwards so the caller can report a figure.
        """
        self._conn.execute("INSERT INTO events_fts(events_fts) VALUES('rebuild')")
        row = self._conn.execute("SELECT COUNT(*) FROM events").fetchone()
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

    def search(
        self,
        filters: EventFilters,
        *,
        sort: str = "-ts",
        cursor: tuple[int, int] | None = None,
        limit: int = 100,
        include_raw: bool = False,
    ) -> tuple[list[Any], tuple[int, int] | None]:
        """One page of events for the filters, sorted by time (spec 06).

        Keyset pagination: ``cursor`` is the previous page's last ``(ts_ms, id)``
        and pages are ordered on ``(COALESCE(ts_ms, 0), id)``, so inserts between
        pages do not shift the window. Returns ``(rows, next_cursor)``; the
        cursor is ``None`` when no further rows exist. Raises ``ValueError`` when
        ``q`` is not valid FTS5 syntax.
        """
        params: list[Any] = []
        where = _filters_sql(filters, params)
        join = "JOIN events_fts ON events_fts.rowid = events.id" if filters.q else ""
        descending = sort == "-ts"
        key = "COALESCE(events.ts_ms, 0)"
        direction = "DESC" if descending else "ASC"
        order = f"ORDER BY {key} {direction}, events.id {direction}"
        if cursor is not None:
            ts_ord, event_id = cursor
            operator = "<" if descending else ">"
            where = f"{where} AND (({key} {operator} ?) OR ({key} = ? AND events.id {operator} ?))"
            params.extend([ts_ord, ts_ord, event_id])
        columns = _EVENT_COLS_RAW if include_raw else _EVENT_COLS
        params.append(limit + 1)
        sql = f"SELECT {columns} FROM events {join} WHERE {where} {order} LIMIT ?"
        try:
            rows = self._conn.execute(sql, params).fetchall()
        except sqlite3.OperationalError as error:
            raise ValueError(_simple_fts_error(str(error))) from error
        page = rows[:limit]
        next_cursor = None
        if len(rows) > limit:
            last = page[-1]
            next_cursor = (_zero_if_none(last["ts_ms"]), int(last["id"]))
        return page, next_cursor

    def count(self, filters: EventFilters) -> int:
        """Total events matching the filters (spec 06 ``/events/count``)."""
        params: list[Any] = []
        where = _filters_sql(filters, params)
        join = "JOIN events_fts ON events_fts.rowid = events.id" if filters.q else ""
        sql = f"SELECT COUNT(*) FROM events {join} WHERE {where}"
        try:
            row = self._conn.execute(sql, params).fetchone()
        except sqlite3.OperationalError as error:
            raise ValueError(_simple_fts_error(str(error))) from error
        return int(row[0])

    def facets(self, filters: EventFilters, *, limit: int = 20) -> dict[str, list[dict[str, Any]]]:
        """Top-N distinct values per facet column under the filters (spec 06)."""
        result: dict[str, list[dict[str, Any]]] = {}
        for column in _FACET_COLUMNS:
            params: list[Any] = []
            where = _filters_sql(filters, params)
            join = "JOIN events_fts ON events_fts.rowid = events.id" if filters.q else ""
            sql = (
                f"SELECT events.{column} AS value, COUNT(*) AS n FROM events {join} "
                f"WHERE {where} AND events.{column} IS NOT NULL "
                f"GROUP BY events.{column} ORDER BY n DESC, events.{column} LIMIT ?"
            )
            params.append(limit)
            try:
                rows = self._conn.execute(sql, params).fetchall()
            except sqlite3.OperationalError as error:
                raise ValueError(_simple_fts_error(str(error))) from error
            result[column] = [
                {"value": _facet_value(column, row["value"]), "count": int(row["n"])}
                for row in rows
            ]
        return result

    def get(self, event_id: int) -> Any | None:
        """One full event row (all columns incl. ``raw``), or ``None``."""
        return self._conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()

    def timeline(self, filters: EventFilters, *, bucket: str = "auto") -> dict[str, Any]:
        """Bucketed event counts under the filters (spec 06 ``/timeline``).

        Returns ``{bucket_ms, buckets:[{t_ms, count, by_log_type, alert_count}]}``.
        ``t_ms`` is the bucket's epoch-aligned start; ``by_log_type`` splits
        ``count`` by the event's stored ``log_type``; ``alert_count`` is the
        number of distinct events in the bucket that are linked to at least one
        alert through ``alert_events`` (so it honours the same filters). Only
        buckets holding at least one event are emitted; ``auto`` picks the
        bucket size from the filtered data span. Raises ``ValueError`` when
        ``q`` is not valid FTS5 syntax.
        """
        try:
            bucket_ms = _resolve_bucket_ms(self._conn, filters, bucket)
        except sqlite3.OperationalError as error:
            raise ValueError(_simple_fts_error(str(error))) from error
        join = "JOIN events_fts ON events_fts.rowid = events.id" if filters.q else ""
        bucket_expr = "((COALESCE(events.ts_ms, 0) / ?) * ?)"

        params: list[Any] = []
        where = _filters_sql(filters, params)
        try:
            rows = self._conn.execute(
                f"SELECT {bucket_expr} AS t_ms, events.log_type AS lt, COUNT(*) AS n "
                f"FROM events {join} WHERE {where} GROUP BY t_ms, lt",
                [bucket_ms, bucket_ms, *params],
            ).fetchall()
            alert_rows = self._conn.execute(
                f"SELECT {bucket_expr} AS t_ms, COUNT(DISTINCT events.id) AS n "
                f"FROM events JOIN alert_events ae ON ae.event_id = events.id {join} "
                f"WHERE {where} GROUP BY t_ms",
                [bucket_ms, bucket_ms, *params],
            ).fetchall()
        except sqlite3.OperationalError as error:
            raise ValueError(_simple_fts_error(str(error))) from error

        by_time: dict[int, dict[str, Any]] = {}
        for row in rows:
            t_ms = int(row["t_ms"])
            item = by_time.setdefault(
                t_ms, {"t_ms": t_ms, "count": 0, "by_log_type": {}, "alert_count": 0}
            )
            item["count"] += int(row["n"])
            item["by_log_type"][str(row["lt"] or "")] = int(row["n"])
        for row in alert_rows:
            bucket_item = by_time.get(int(row["t_ms"]))
            if bucket_item is not None:
                bucket_item["alert_count"] = int(row["n"])
        return {"bucket_ms": bucket_ms, "buckets": [by_time[t] for t in sorted(by_time)]}

    def insert_many(self, events: Sequence[NormalizedEvent]) -> list[int]:
        """Insert a batch and return their rowids."""
        ids: list[int] = []
        for event in events:
            ids.append(self.add(event))
        return ids


def _chunks(items: Sequence[Any]) -> Iterator[Sequence[Any]]:
    for i in range(0, len(items), BATCH_SIZE):
        yield items[i : i + BATCH_SIZE]


def _filters_sql(filters: EventFilters, params: list[Any]) -> str:
    """``WHERE`` text for the filters, appending bound values to ``params``.

    Only columns allowed by the spec are interpolated (constants); every value
    is a bound parameter, never caller text.
    """
    conds = ["events.case_id = ?"]
    params.append(filters.case_id)
    if filters.q:
        conds.append("events_fts MATCH ?")
        params.append(filters.q)
    if filters.from_ms is not None:
        conds.append("events.ts_ms >= ?")
        params.append(filters.from_ms)
    if filters.to_ms is not None:
        conds.append("events.ts_ms <= ?")
        params.append(filters.to_ms)
    for column in _EQUALS_COLUMNS:
        value = getattr(filters, column)
        if value is not None:
            conds.append(f"events.{column} = ?")
            params.append(value)
    if filters.ioc_id is not None:
        conds.append(_EXISTS_IOC)
        params.append(filters.ioc_id)
    if filters.alert_id is not None:
        conds.append(_EXISTS_ALERT)
        params.append(filters.alert_id)
    return " AND ".join(conds)


def _zero_if_none(value: Any) -> int:
    """``ts_ms`` may be NULL (ts-less rows sort as timestamp 0)."""
    return int(value) if value is not None else 0


def _resolve_bucket_ms(connection: sqlite3.Connection, filters: EventFilters, bucket: str) -> int:
    """The bucket size for the request: fixed for named buckets, span-driven for ``auto``.

    The min/max scan reuses the same filter set, so ``auto`` reflects what the
    response will show rather than the unbounded case; an empty filtered set has
    no span to judge and falls back to the finest bucket.
    """
    named = _BUCKET_MS.get(bucket)
    if named is not None:
        return named
    params: list[Any] = []
    where = _filters_sql(filters, params)
    join = "JOIN events_fts ON events_fts.rowid = events.id" if filters.q else ""
    row = connection.execute(
        f"SELECT MIN(COALESCE(events.ts_ms, 0)), MAX(COALESCE(events.ts_ms, 0)) "
        f"FROM events {join} WHERE {where}",
        params,
    ).fetchone()
    if row is None or row[0] is None or row[1] is None:
        return _BUCKET_MS["1m"]
    span = int(row[1]) - int(row[0])
    for threshold, name in _AUTO_BUCKET_SPANS:
        if span <= threshold:
            return _BUCKET_MS[name]
    return _BUCKET_MS["1d"]


def _facet_value(column: str, value: Any) -> Any:
    """Event ids are integers; every other facet value stays a string."""
    return int(value) if column == "event_id" and value is not None else str(value)


def _simple_fts_error(message: str) -> str:
    """Fold sqlite's error into a short client-facing message (spec 06)."""
    text = message.removeprefix("fts5: ")
    if text.endswith("."):
        text = text[:-1]
    return f"invalid search query: {text}"


__all__ = ["BATCH_SIZE", "EventBatch", "EventFilters", "EventRepository"]
