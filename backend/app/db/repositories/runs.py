"""Detection run repositories (spec 04 section 2, spec 01 section 9).

``detection_runs`` carries one row per engine pass - the versions a report
embeds - and ``rule_runs`` carries one row per evaluated rule. Recording is
deliberately dumb: the engine decides outcomes, the repository persists them
and enforces the schema's status vocabulary before SQLite ever sees a value.

``attack_version`` lives here because both the health endpoint and a run row
need the same ATT&CK bundle version; one query, one spelling.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence

from app.db.connection import atomic
from app.detect.engine import RuleOutcome
from app.models.run import (
    RULE_RUN_STATUSES,
    RUN_STATUS_RUNNING,
    RUN_TERMINAL_STATUSES,
    DetectionRunRecord,
    RuleRunRecord,
)
from app.util.ids import new_id
from app.util.time import utc_now_iso

_SELECT_RUN = "SELECT * FROM detection_runs"
_SELECT_RULE_RUN = "SELECT * FROM rule_runs"

#: Default page size for ``GET /cases/{id}/detection-runs`` (spec 06).
_DEFAULT_LIMIT = 50


def attack_version(connection: sqlite3.Connection) -> str:
    """ATT&CK bundle version from ``mitre_meta``, or empty until one is imported."""
    try:
        row = connection.execute(
            "SELECT value FROM mitre_meta WHERE key = 'attack_version'"
        ).fetchone()
    except sqlite3.Error:
        return ""
    return str(row[0]) if row and row[0] is not None else ""


class DetectionRunRepository:
    """Create, finish and read detection runs and their per-rule rows."""

    __slots__ = ("_conn",)

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._conn = connection

    @property
    def connection(self) -> sqlite3.Connection:
        """The underlying connection."""
        return self._conn

    def start(
        self,
        *,
        case_id: str,
        profile: str,
        tool_version: str,
        ruleset_hash: str,
        attack_version: str,
    ) -> DetectionRunRecord:
        """Open a ``running`` run for ``case_id``; versions are caller-supplied.

        The caller collects them once per run (app version, enabled-rule hash,
        ATT&CK bundle) so the row is a self-contained reproduction record
        (spec 01 section 9) even if the catalogue changes afterwards.
        """
        run_id = new_id()
        self._conn.execute(
            "INSERT INTO detection_runs ("
            "id, case_id, profile, tool_version, ruleset_hash, attack_version, "
            "started_at, finished_at, status"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?)",
            (
                run_id,
                case_id,
                profile,
                tool_version,
                ruleset_hash,
                attack_version,
                utc_now_iso(),
                RUN_STATUS_RUNNING,
            ),
        )
        created = self.get(run_id)
        if created is None:  # pragma: no cover - just inserted
            raise RuntimeError("detection run vanished after insert")
        return created

    def finish(self, run_id: str, *, status: str) -> bool:
        """Close a still-running run; ``False`` when already finished.

        Raises:
            ValueError: if ``status`` is not a terminal run status - a run
                can only ever leave ``running`` once.
        """
        if status not in RUN_TERMINAL_STATUSES:
            raise ValueError(f"invalid terminal run status: {status!r}")
        cursor = self._conn.execute(
            "UPDATE detection_runs SET status = ?, finished_at = ? WHERE id = ? AND status = ?",
            (status, utc_now_iso(), run_id, RUN_STATUS_RUNNING),
        )
        return cursor.rowcount > 0

    def record_rules(self, run_id: str, outcomes: Sequence[RuleOutcome]) -> int:
        """Upsert one ``rule_runs`` row per outcome; returns the row count.

        Raises:
            ValueError: if any outcome carries a status outside the schema's
                ``rule_runs`` vocabulary.
        """
        for outcome in outcomes:
            if outcome.status not in RULE_RUN_STATUSES:
                raise ValueError(f"invalid rule run status: {outcome.status!r}")
        if not outcomes:
            return 0
        rows = [
            (
                run_id,
                outcome.rule_id,
                outcome.status,
                outcome.match_count,
                outcome.duration_ms,
                outcome.error,
            )
            for outcome in outcomes
        ]
        with atomic(self._conn):
            self._conn.executemany(
                "INSERT INTO rule_runs ("
                "run_id, rule_id, status, match_count, duration_ms, error"
                ") VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(run_id, rule_id) DO UPDATE SET "
                "status = excluded.status, "
                "match_count = excluded.match_count, "
                "duration_ms = excluded.duration_ms, "
                "error = excluded.error",
                rows,
            )
        return len(rows)

    def get(self, run_id: str) -> DetectionRunRecord | None:
        """One run by id, or ``None``."""
        row = self._conn.execute(f"{_SELECT_RUN} WHERE id = ?", (run_id,)).fetchone()
        return DetectionRunRecord.from_row(row) if row is not None else None

    def list_for_case(
        self, case_id: str, *, limit: int = _DEFAULT_LIMIT, offset: int = 0
    ) -> list[DetectionRunRecord]:
        """Runs for one case, newest first (``started_at`` then id)."""
        rows = self._conn.execute(
            f"{_SELECT_RUN} WHERE case_id = ? ORDER BY started_at DESC, id DESC LIMIT ? OFFSET ?",
            (case_id, limit, offset),
        ).fetchall()
        return [DetectionRunRecord.from_row(row) for row in rows]

    def rule_runs(self, run_id: str) -> list[RuleRunRecord]:
        """Every per-rule row of one run, in stable rule-id order."""
        rows = self._conn.execute(
            f"{_SELECT_RULE_RUN} WHERE run_id = ? ORDER BY rule_id", (run_id,)
        ).fetchall()
        return [RuleRunRecord.from_row(row) for row in rows]


__all__ = ["DetectionRunRepository", "attack_version"]
