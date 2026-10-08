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
from app.models.alert import ALERT_STATUS_NEW, AlertDraft, AlertRecord
from app.util.time import utc_now_iso

_SELECT_ALERT = "SELECT * FROM alerts"

#: Default page size for ``GET /cases/{id}/alerts`` (spec 06, sort ``-score``).
_DEFAULT_LIMIT = 50


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

    def list_for_case(
        self, case_id: str, *, limit: int = _DEFAULT_LIMIT, offset: int = 0
    ) -> list[AlertRecord]:
        """Alerts for one case, highest score first (spec 06)."""
        rows = self._conn.execute(
            f"{_SELECT_ALERT} WHERE case_id = ? ORDER BY score DESC, id ASC LIMIT ? OFFSET ?",
            (case_id, limit, offset),
        ).fetchall()
        return [AlertRecord.from_row(row) for row in rows]


__all__ = ["AlertRepository"]
