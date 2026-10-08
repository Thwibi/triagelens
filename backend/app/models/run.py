"""Detection run records (spec 04 section 2, ``detection_runs`` / ``rule_runs``).

A detection run is one pass of the engine over a case: ``detection_runs``
carries the versions and profile reports embed, and ``rule_runs`` carries the
per-rule outcome. The status values mirror the schema CHECK constraints
exactly, so an invalid one is rejected here before SQLite sees it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

#: ``detection_runs.status`` values.
RUN_STATUS_RUNNING = "running"
RUN_STATUS_DONE = "done"
RUN_STATUS_FAILED = "failed"
RUN_STATUS_CANCELLED = "cancelled"
RUN_STATUSES = frozenset(
    {RUN_STATUS_RUNNING, RUN_STATUS_DONE, RUN_STATUS_FAILED, RUN_STATUS_CANCELLED}
)
#: Statuses a run may finish with; ``running`` is only ever the opening state.
RUN_TERMINAL_STATUSES = frozenset({RUN_STATUS_DONE, RUN_STATUS_FAILED, RUN_STATUS_CANCELLED})

#: ``rule_runs.status`` values: a row for every evaluated rule, never a skip.
RULE_RUN_OK = "ok"
RULE_RUN_SKIPPED_NO_DATA = "skipped_no_data"
RULE_RUN_TIMEOUT = "timeout"
RULE_RUN_ERROR = "error"
RULE_RUN_STATUSES = frozenset(
    {RULE_RUN_OK, RULE_RUN_SKIPPED_NO_DATA, RULE_RUN_TIMEOUT, RULE_RUN_ERROR}
)


@dataclass(frozen=True, slots=True)
class DetectionRunRecord:
    """One row of ``detection_runs``."""

    id: str
    case_id: str
    profile: str
    tool_version: str
    ruleset_hash: str
    attack_version: str
    started_at: str
    finished_at: str | None
    status: str

    @classmethod
    def from_row(cls, row: Any) -> DetectionRunRecord:
        """Build a record from a ``sqlite3.Row``-like mapping."""
        return cls(
            id=str(row["id"]),
            case_id=str(row["case_id"]),
            profile=str(row["profile"]),
            tool_version=str(row["tool_version"]),
            ruleset_hash=str(row["ruleset_hash"]),
            attack_version=str(row["attack_version"]),
            started_at=str(row["started_at"]),
            finished_at=str(row["finished_at"]) if row["finished_at"] is not None else None,
            status=str(row["status"]),
        )


@dataclass(frozen=True, slots=True)
class RuleRunRecord:
    """One row of ``rule_runs``."""

    run_id: str
    rule_id: str
    status: str
    match_count: int
    duration_ms: int
    error: str | None

    @classmethod
    def from_row(cls, row: Any) -> RuleRunRecord:
        """Build a record from a ``sqlite3.Row``-like mapping."""
        return cls(
            run_id=str(row["run_id"]),
            rule_id=str(row["rule_id"]),
            status=str(row["status"]),
            match_count=int(row["match_count"]),
            duration_ms=int(row["duration_ms"]),
            error=str(row["error"]) if row["error"] is not None else None,
        )


__all__ = [
    "RULE_RUN_ERROR",
    "RULE_RUN_OK",
    "RULE_RUN_SKIPPED_NO_DATA",
    "RULE_RUN_STATUSES",
    "RULE_RUN_TIMEOUT",
    "RUN_STATUSES",
    "RUN_STATUS_CANCELLED",
    "RUN_STATUS_DONE",
    "RUN_STATUS_FAILED",
    "RUN_STATUS_RUNNING",
    "RUN_TERMINAL_STATUSES",
    "DetectionRunRecord",
    "RuleRunRecord",
]
