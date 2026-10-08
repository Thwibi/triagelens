"""IOC repository (spec 02 `iocs` + `ioc_occurrences`).

Two jobs, which is why this file is bigger than it looks:

**Store a batch.** The parse worker sends one group per indicator with a bounded
occurrence list. ``store`` upserts the indicator row and the occurrences, and
accumulates ``occurrences``/timestamps across batches so a source split into
twenty chunks still ends up with one correct count.

**Stay honest when events disappear.** ``ioc_occurrences`` cascades when an event
is deleted, but ``iocs.occurrences`` is a denormalized count. Deleting a source
(or a cancelled partial ingest) therefore snapshots the indicators that source
touched first, deletes, then recomputes exactly those rows. Orphaned indicators
-- no occurrence left anywhere -- are deleted, which is what "deleting a source
removes orphaned IOCs" means.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from typing import Any

from app.ioc.aggregate import AggregatedIoc

_INSERT_OR_UPDATE = """
INSERT INTO iocs (
    id, case_id, type, value, value_norm,
    first_seen_ms, last_seen_ms, occurrences, confidence,
    is_private, is_allowlisted
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(case_id, type, value_norm) DO UPDATE SET
    occurrences = iocs.occurrences + excluded.occurrences,
    first_seen_ms = MIN(
        COALESCE(iocs.first_seen_ms, excluded.first_seen_ms),
        COALESCE(excluded.first_seen_ms, iocs.first_seen_ms)
    ),
    last_seen_ms = MAX(
        COALESCE(iocs.last_seen_ms, excluded.last_seen_ms),
        COALESCE(excluded.last_seen_ms, iocs.last_seen_ms)
    ),
    confidence = MAX(iocs.confidence, excluded.confidence),
    is_private = MAX(iocs.is_private, excluded.is_private),
    is_allowlisted = MAX(iocs.is_allowlisted, excluded.is_allowlisted)
"""

_INSERT_OCCURRENCE = (
    "INSERT OR IGNORE INTO ioc_occurrences (ioc_id, event_id, field, role, decoded_from) "
    "VALUES (?, ?, ?, ?, ?)"
)

#: The columns every read in this repository returns, in model order.
_SELECT_COLUMNS = (
    "id, case_id, type, value, value_norm, first_seen_ms, last_seen_ms, "
    "occurrences, confidence, is_private, is_allowlisted, analyst_state, tags_json"
)


@dataclass(frozen=True, slots=True)
class IocRecord:
    """One ``iocs`` row, ready for the API layer."""

    id: str
    case_id: str
    type: str
    value: str
    value_norm: str
    first_seen_ms: int | None
    last_seen_ms: int | None
    occurrences: int
    confidence: int
    is_private: bool
    is_allowlisted: bool
    analyst_state: str
    tags: list[str]


def _record(row: sqlite3.Row) -> IocRecord:

    return IocRecord(
        id=str(row[0]),
        case_id=str(row[1]),
        type=str(row[2]),
        value=str(row[3]),
        value_norm=str(row[4]),
        first_seen_ms=row[5],
        last_seen_ms=row[6],
        occurrences=int(row[7]),
        confidence=int(row[8]),
        is_private=bool(row[9]),
        is_allowlisted=bool(row[10]),
        analyst_state=str(row[11]),
        tags=list(json.loads(row[12] or "[]")),
    )


class IocRepository:
    __slots__ = ("_conn",)

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._conn = connection

    @property
    def connection(self) -> sqlite3.Connection:
        return self._conn

    def store(self, case_id: str, groups: list[AggregatedIoc]) -> int:
        """Upsert one parse batch's indicators and their occurrences.

        Returns the number of indicator rows written. Failures are not swallowed:
        a transaction that cannot store evidence must roll the batch back.
        """
        written = 0
        for group in groups:
            ioc = group.ioc
            ioc_id = ioc.ioc_id(case_id)
            self._conn.execute(
                _INSERT_OR_UPDATE,
                (
                    ioc_id,
                    case_id,
                    ioc.type,
                    ioc.value,
                    ioc.value_norm,
                    group.first_seen_ms,
                    group.last_seen_ms,
                    group.occurrences,
                    group.confidence_score(),
                    int(ioc.is_private),
                    int(ioc.is_allowlisted),
                ),
            )
            written += 1
            for row in group.rows:
                self._conn.execute(
                    _INSERT_OCCURRENCE,
                    (ioc_id, row.event_id, row.field, row.role, row.decoded_from),
                )
        return written

    def recompute(self, ioc_ids: list[str]) -> int:
        """Recount the given indicators from their surviving occurrences.

        Deletes any that no longer have one. Cheap by construction: the id list
        is exactly the rows that could have changed.
        """
        removed = 0
        for ioc_id in ioc_ids:
            stats = self._conn.execute(
                "SELECT COUNT(*), MIN(e.ts_ms), MAX(e.ts_ms) FROM ioc_occurrences o "
                "JOIN events e ON e.id = o.event_id WHERE o.ioc_id = ?",
                (ioc_id,),
            ).fetchone()
            count = int(stats[0]) if stats else 0
            if count == 0:
                self._conn.execute("DELETE FROM iocs WHERE id = ?", (ioc_id,))
                removed += 1
                continue
            self._conn.execute(
                "UPDATE iocs SET occurrences = ?, first_seen_ms = ?, last_seen_ms = ? WHERE id = ?",
                (count, stats[1], stats[2], ioc_id),
            )
        return removed

    def snapshot_for_source(self, source_id: str) -> list[str]:
        """Indicators that have an occurrence on this source's events.

        Take this *before* the events are deleted: once the rows are gone the
        answer is unrecoverable, and guessing leaves stale counts behind.
        """
        rows = self._conn.execute(
            "SELECT DISTINCT o.ioc_id FROM ioc_occurrences o "
            "JOIN events e ON e.id = o.event_id WHERE e.source_id = ?",
            (source_id,),
        ).fetchall()
        return [str(row[0]) for row in rows]

    def get(self, ioc_id: str) -> IocRecord | None:
        """One indicator by id, or ``None``."""
        row = self._conn.execute(
            f"SELECT {_SELECT_COLUMNS} FROM iocs WHERE id = ?", (ioc_id,)
        ).fetchone()
        return _record(row) if row else None

    def list_for_case(self, case_id: str, *, limit: int = 200, offset: int = 0) -> list[IocRecord]:
        """Indicators for a case, most recently seen first."""
        rows = self._conn.execute(
            f"SELECT {_SELECT_COLUMNS} FROM iocs WHERE case_id = ? "
            "ORDER BY last_seen_ms DESC, confidence DESC LIMIT ? OFFSET ?",
            (case_id, limit, offset),
        ).fetchall()
        return [_record(row) for row in rows]

    def search(
        self,
        case_id: str,
        *,
        ioc_type: str | None = None,
        min_confidence: int | None = None,
        q: str | None = None,
        host: str | None = None,
        state: str | None = None,
        include_private: bool = False,
        include_allowlisted: bool = False,
        sort: str = "last_seen",
        order: str = "desc",
        limit: int = 200,
        offset: int = 0,
    ) -> tuple[list[IocRecord], int]:
        """Indicators for a case with the spec 06 filters.

        ``host`` filters to indicators seen on one event host. Private and
        allowlisted indicators are hidden unless explicitly included. Returns
        ``(items, total)`` where total ignores pagination.
        """
        where = ["case_id = ?"]
        params: list[Any] = [case_id]
        if ioc_type:
            where.append("type = ?")
            params.append(ioc_type)
        if min_confidence is not None:
            where.append("confidence >= ?")
            params.append(min_confidence)
        if q:
            where.append("(value LIKE ? OR value_norm LIKE ?)")
            like = f"%{q}%"
            params.extend([like, like])
        if host:
            where.append(
                "EXISTS (SELECT 1 FROM ioc_occurrences o JOIN events e ON e.id = o.event_id "
                "WHERE o.ioc_id = iocs.id AND e.host = ?)"
            )
            params.append(host)
        if state:
            where.append("analyst_state = ?")
            params.append(state)
        if not include_private:
            where.append("is_private = 0")
        if not include_allowlisted:
            where.append("is_allowlisted = 0")

        order_by = {
            "last_seen": "last_seen_ms",
            "first_seen": "first_seen_ms",
            "confidence": "confidence",
            "occurrences": "occurrences",
            "value": "value_norm",
        }.get(sort, "last_seen_ms")
        direction = "ASC" if order == "asc" else "DESC"
        where_sql = " AND ".join(where)
        count_row = self._conn.execute(
            f"SELECT COUNT(*) FROM iocs WHERE {where_sql}", params
        ).fetchone()
        total = int(count_row[0]) if count_row else 0
        rows = self._conn.execute(
            f"SELECT {_SELECT_COLUMNS} FROM iocs WHERE {where_sql} "
            f"ORDER BY {order_by} {direction}, value_norm ASC LIMIT ? OFFSET ?",
            [*params, limit, offset],
        ).fetchall()
        return [_record(row) for row in rows], total

    def entities(self, case_id: str) -> list[dict[str, Any]]:
        """Hosts and users seen in a case, with distinct event counts.

        Alert counts arrive with detection (phase 6); until then they are 0.
        Users are aggregated over both ``user_name`` and ``target_user_name``,
        which is how a username appears once whichever side of the event it was.
        """
        results: list[dict[str, Any]] = []
        for kind, column in (("host", "host"), ("user", "user_name"), ("user", "target_user_name")):
            if kind == "host":
                rows = self._conn.execute(
                    "SELECT host AS name, COUNT(*) AS events FROM events "
                    "WHERE case_id = ? AND host IS NOT NULL AND host != '' "
                    "GROUP BY host ORDER BY events DESC, host ASC",
                    (case_id,),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    f"SELECT {column} AS name, COUNT(*) AS events FROM events "
                    "WHERE case_id = ? AND {column} IS NOT NULL AND {column} != '' "
                    "GROUP BY {column} ORDER BY events DESC, {column} ASC".format(column=column),
                    (case_id,),
                ).fetchall()
            for row in rows:
                name = str(row[0])
                results.append(
                    {"kind": kind, "name": name, "event_count": int(row[1]), "alert_count": 0}
                )
        return results

    def count_for_case(self, case_id: str) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) FROM iocs WHERE case_id = ?", (case_id,)
        ).fetchone()
        return int(row[0]) if row else 0

    def set_analyst_state(
        self, ioc_id: str, *, analyst_state: str, tags: list[str] | None = None
    ) -> None:
        """Update an analyst's verdict and/or tags."""

        if tags is None:
            self._conn.execute(
                "UPDATE iocs SET analyst_state = ? WHERE id = ?", (analyst_state, ioc_id)
            )
            return
        self._conn.execute(
            "UPDATE iocs SET analyst_state = ?, tags_json = ? WHERE id = ?",
            (analyst_state, json.dumps(tags, ensure_ascii=False), ioc_id),
        )

    def occurrences(self, ioc_id: str, *, limit: int = 500) -> list[dict[str, Any]]:
        """Where an indicator was seen, newest event first."""
        rows = self._conn.execute(
            "SELECT o.event_id, o.field, o.role, o.decoded_from, e.ts_ms, e.host, e.log_type, "
            "e.source_id, e.message FROM ioc_occurrences o "
            "JOIN events e ON e.id = o.event_id WHERE o.ioc_id = ? "
            "ORDER BY e.ts_ms DESC LIMIT ?",
            (ioc_id, limit),
        ).fetchall()
        return [
            {
                "event_id": int(row[0]),
                "field": str(row[1]),
                "role": str(row[2]),
                "decoded_from": row[3],
                "ts_ms": row[4],
                "host": row[5],
                "log_type": row[6],
                "source_id": row[7],
                "message": row[8],
            }
            for row in rows
        ]


__all__ = ["IocRecord", "IocRepository"]
