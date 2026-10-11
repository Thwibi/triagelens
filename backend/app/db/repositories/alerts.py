"""Alert repository (spec 04 section 6, spec 02 section 4).

Persistence for ``alerts`` and their evidence links. The one piece of policy
it owns is the re-run replacement rule: a re-run replaces the previous run's
untouched (``new``) alerts, while analyst-touched alerts keep their status
and notes - and, when they do not re-appear, keep pointing at the old run,
which is what makes them read as stale (spec 04 section 6).

``tactics_json``/``techniques_json``/``groups_software_json`` are never
touched here: they belong to the ATT&CK mapping stage, and the upsert only
refreshes the fields detection itself produces.
"""

from __future__ import annotations

import json
import sqlite3

from app.db.connection import atomic
from app.models.alert import (
    ALERT_ANALYST_STATUSES,
    ALERT_STATUS_NEW,
    AlertDraft,
    AlertRecord,
)
from app.util.time import utc_now_iso

_SELECT_ALERT = "SELECT * FROM alerts"

#: Default page size for ``GET /cases/{id}/alerts`` (spec 06, sort ``-score``).
_DEFAULT_LIMIT = 50

#: Sortable alert columns; a leading ``-`` orders descending (spec 06).
_SORT_COLUMNS: frozenset[str] = frozenset(
    {"score", "first_seen", "last_seen", "created_at", "rule_title", "match_count"}
)

#: Columns the alerts router may not sort on; guarded inside :meth:`search`.
_ALERT_FILTER_COLUMNS: dict[str, str] = {
    "level": "level = ?",
    "status": "status = ?",
    "rule_id": "rule_id = ?",
    "host": "host = ?",
    "user_name": "user_name = ?",
    "min_score": "score >= ?",
}


class AlertRepository:
    """Create, replace and read alerts."""

    __slots__ = ("_conn",)

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._conn = connection

    @property
    def connection(self) -> sqlite3.Connection:
        """The underlying connection."""
        return self._conn

    def clear_previous_new(self, case_id: str, run_id: str) -> int:
        """Delete other runs' untouched ``new`` alerts for the case.

        Analyst-touched alerts (any other status) are left alone; an alert
        that re-appears is refreshed by :meth:`upsert`, one that does not
        keeps its old ``run_id`` and reads as stale.
        """
        cursor = self._conn.execute(
            "DELETE FROM alerts WHERE case_id = ? AND run_id != ? AND status = ?",
            (case_id, run_id, ALERT_STATUS_NEW),
        )
        return cursor.rowcount

    def upsert(
        self, draft: AlertDraft, *, score: int, created_at: str | None = None
    ) -> AlertRecord:
        """Insert the draft or refresh the existing alert with the same id.

        On refresh ``status`` and ``analyst_notes`` are carried over and
        ``created_at`` keeps the original timestamp; everything detection
        produces (window, counts, evidence metadata) is replaced.
        """
        with atomic(self._conn):
            self._conn.execute(
                "INSERT INTO alerts ("
                "id, case_id, run_id, rule_id, rule_title, rule_kind, rule_type, "
                "level, score, status, analyst_notes, host, user_name, group_key, "
                "first_seen_ms, last_seen_ms, match_count, "
                "false_positives_json, references_json, created_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET "
                "run_id = excluded.run_id, "
                "rule_title = excluded.rule_title, "
                "rule_kind = excluded.rule_kind, "
                "rule_type = excluded.rule_type, "
                "level = excluded.level, "
                "score = excluded.score, "
                "host = excluded.host, "
                "user_name = excluded.user_name, "
                "group_key = excluded.group_key, "
                "first_seen_ms = excluded.first_seen_ms, "
                "last_seen_ms = excluded.last_seen_ms, "
                "match_count = excluded.match_count, "
                "false_positives_json = excluded.false_positives_json, "
                "references_json = excluded.references_json",
                (
                    draft.id,
                    draft.case_id,
                    draft.run_id,
                    draft.rule_id,
                    draft.rule_title,
                    draft.rule_kind,
                    draft.rule_type,
                    draft.level,
                    score,
                    ALERT_STATUS_NEW,
                    draft.host,
                    draft.user_name,
                    draft.group_key,
                    draft.first_seen_ms,
                    draft.last_seen_ms,
                    draft.match_count,
                    json.dumps(list(draft.false_positives)),
                    json.dumps(list(draft.references)),
                    created_at or utc_now_iso(),
                ),
            )
        record = self.get(draft.id)
        if record is None:  # pragma: no cover - just upserted
            raise RuntimeError("alert vanished after upsert")
        return record

    def link_events(self, alert_id: str, event_ids: tuple[int, ...]) -> None:
        """Replace the alert's evidence sample (``alert_events``)."""
        with atomic(self._conn):
            self._conn.execute("DELETE FROM alert_events WHERE alert_id = ?", (alert_id,))
            self._conn.executemany(
                "INSERT INTO alert_events (alert_id, event_id) VALUES (?, ?)",
                [(alert_id, event_id) for event_id in event_ids],
            )

    def event_ids(self, alert_id: str) -> list[int]:
        """Evidence event ids linked to the alert, in id order."""
        rows = self._conn.execute(
            "SELECT event_id FROM alert_events WHERE alert_id = ? ORDER BY event_id",
            (alert_id,),
        ).fetchall()
        return [int(row["event_id"]) for row in rows]

    def set_score(self, alert_id: str, score: int) -> None:
        """Store the computed score (the breakdown is recomputed on demand)."""
        self._conn.execute("UPDATE alerts SET score = ? WHERE id = ?", (score, alert_id))

    def get(self, alert_id: str) -> AlertRecord | None:
        """One alert by id, or ``None``."""
        row = self._conn.execute(f"{_SELECT_ALERT} WHERE id = ?", (alert_id,)).fetchone()
        return AlertRecord.from_row(row) if row is not None else None

    def set_status(
        self,
        alert_id: str,
        *,
        status: str,
        analyst_notes: str | None = None,
    ) -> AlertRecord | None:
        """Set an analyst verdict, optionally with notes (spec 06).

        Raises:
            ValueError: if ``status`` is not one an analyst may set - a client
                cannot manufacture the ``new`` state a re-run owns.
        """
        if status not in ALERT_ANALYST_STATUSES:
            raise ValueError(f"alert status not settable: {status!r}")
        if analyst_notes is not None:
            self._conn.execute(
                "UPDATE alerts SET status = ?, analyst_notes = ?, "
                "created_at = created_at WHERE id = ?",
                (status, analyst_notes, alert_id),
            )
        else:
            self._conn.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id))
        return self.get(alert_id)

    def search(
        self,
        case_id: str,
        *,
        level: str | None = None,
        status: str | None = None,
        rule_id: str | None = None,
        tactic: str | None = None,
        technique: str | None = None,
        host: str | None = None,
        user_name: str | None = None,
        min_score: int | None = None,
        q: str | None = None,
        unmapped: bool = False,
        sort: str = "-score",
        limit: int = _DEFAULT_LIMIT,
        offset: int = 0,
    ) -> tuple[list[AlertRecord], int]:
        """One page of alerts matching every supplied filter (spec 06).

        ``tactic``/``technique`` read the stored ATT&CK mapping JSON with the
        JSON1 extension; ``q`` searches the rule title. Sorting is a column
        name, descending when prefixed with ``-`` (default ``-score``).
        """
        where: list[str] = ["case_id = ?"]
        params: list[object] = [case_id]
        if level is not None:
            where.append("level = ?")
            params.append(level)
        if status is not None:
            where.append("status = ?")
            params.append(status)
        if rule_id is not None:
            where.append("rule_id = ?")
            params.append(rule_id)
        if host is not None:
            where.append("host = ?")
            params.append(host)
        if user_name is not None:
            where.append("user_name = ?")
            params.append(user_name)
        if min_score is not None:
            where.append("score >= ?")
            params.append(min_score)
        if tactic is not None:
            where.append("EXISTS (SELECT 1 FROM json_each(alerts.tactics_json) WHERE value = ?)")
            params.append(tactic)
        if technique is not None:
            where.append(
                "EXISTS (SELECT 1 FROM json_each(alerts.techniques_json) "
                "WHERE json_extract(value, '$.id') = ?)"
            )
            params.append(technique)
        if q is not None:
            where.append("rule_title LIKE ? ESCAPE '\\'")
            params.append(f"%{_like_pattern(q)}%")
        if unmapped:
            where.append("techniques_json = '[]'")

        clause = " WHERE " + " AND ".join(where)

        column = sort[1:] if sort.startswith("-") else sort
        if column not in _SORT_COLUMNS:
            raise ValueError(f"unsupported alert sort: {sort!r}")
        direction = "DESC" if sort.startswith("-") else "ASC"
        order_sql = f"{column} {direction}, id {'DESC' if sort.startswith('-') else 'ASC'}"

        count_row = self._conn.execute(f"SELECT COUNT(*) FROM alerts{clause}", params).fetchone()
        total = int(count_row[0]) if count_row else 0

        rows = self._conn.execute(
            f"{_SELECT_ALERT}{clause} ORDER BY {order_sql} LIMIT ? OFFSET ?",
            (*params, limit, offset),
        ).fetchall()
        return [AlertRecord.from_row(row) for row in rows], total

    def list_for_case(
        self, case_id: str, *, limit: int = _DEFAULT_LIMIT, offset: int = 0
    ) -> list[AlertRecord]:
        """Alerts for one case, highest score first (spec 06)."""
        rows = self._conn.execute(
            f"{_SELECT_ALERT} WHERE case_id = ? ORDER BY score DESC, id ASC LIMIT ? OFFSET ?",
            (case_id, limit, offset),
        ).fetchall()
        return [AlertRecord.from_row(row) for row in rows]


def _like_pattern(value: str) -> str:
    """Escape LIKE wildcards so a search for ``50%`` is literal."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


__all__ = ["AlertRepository"]
