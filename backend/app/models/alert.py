"""Alert records and drafts (spec 04 section 6, ``alerts``).

An :class:`AlertRecord` is one row of ``alerts``: the persisted outcome of
grouping a rule's matches for one host/user within one time cluster. An
:class:`AlertDraft` is its construction-time twin - built by
:mod:`app.detect.alerts` from engine matches, carrying the evidence sample
that has not been linked yet. Status values mirror the schema CHECK exactly,
so an invalid one is rejected here before SQLite sees it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

#: ``alerts.status`` values.
ALERT_STATUS_NEW = "new"
ALERT_STATUS_TRIAGED = "triaged"
ALERT_STATUS_TRUE_POSITIVE = "true_positive"
ALERT_STATUS_FALSE_POSITIVE = "false_positive"
ALERT_STATUS_BENIGN = "benign"
ALERT_STATUSES = frozenset(
    {
        ALERT_STATUS_NEW,
        ALERT_STATUS_TRIAGED,
        ALERT_STATUS_TRUE_POSITIVE,
        ALERT_STATUS_FALSE_POSITIVE,
        ALERT_STATUS_BENIGN,
    }
)
#: Statuses an analyst can set. ``new`` is the untouched default a re-run
#: replaces; anything else survives the next run (spec 04 section 6).
ALERT_ANALYST_STATUSES = frozenset(
    {
        ALERT_STATUS_TRIAGED,
        ALERT_STATUS_TRUE_POSITIVE,
        ALERT_STATUS_FALSE_POSITIVE,
        ALERT_STATUS_BENIGN,
    }
)


@dataclass(frozen=True, slots=True)
class AlertRecord:
    """One row of ``alerts``.

    The ``tactics_json``/``techniques_json``/``groups_software_json`` fields
    are stored as raw JSON text exactly as written by the ATT&CK mapping
    stage; this module deliberately does not interpret them.
    """

    id: str
    case_id: str
    run_id: str
    rule_id: str
    rule_title: str
    rule_kind: str
    rule_type: str
    level: str
    score: int
    status: str
    analyst_notes: str | None
    tactics_json: str
    techniques_json: str
    groups_software_json: str
    host: str | None
    user_name: str | None
    group_key: str
    first_seen_ms: int | None
    last_seen_ms: int | None
    match_count: int
    false_positives_json: str
    references_json: str
    created_at: str

    @classmethod
    def from_row(cls, row: Any) -> AlertRecord:
        """Build a record from a ``sqlite3.Row``-like mapping."""
        return cls(
            id=str(row["id"]),
            case_id=str(row["case_id"]),
            run_id=str(row["run_id"]),
            rule_id=str(row["rule_id"]),
            rule_title=str(row["rule_title"]),
            rule_kind=str(row["rule_kind"]),
            rule_type=str(row["rule_type"]),
            level=str(row["level"]),
            score=int(row["score"]),
            status=str(row["status"]),
            analyst_notes=(str(row["analyst_notes"]) if row["analyst_notes"] is not None else None),
            tactics_json=str(row["tactics_json"]),
            techniques_json=str(row["techniques_json"]),
            groups_software_json=str(row["groups_software_json"]),
            host=str(row["host"]) if row["host"] is not None else None,
            user_name=str(row["user_name"]) if row["user_name"] is not None else None,
            group_key=str(row["group_key"]),
            first_seen_ms=(int(row["first_seen_ms"]) if row["first_seen_ms"] is not None else None),
            last_seen_ms=(int(row["last_seen_ms"]) if row["last_seen_ms"] is not None else None),
            match_count=int(row["match_count"]),
            false_positives_json=str(row["false_positives_json"]),
            references_json=str(row["references_json"]),
            created_at=str(row["created_at"]),
        )


@dataclass(frozen=True, slots=True)
class AlertDraft:
    """A constructed alert before persistence.

    ``event_ids`` is the evidence sample (already capped by the caller's
    ``max_sample_events_per_alert``); the repository links it to
    ``alert_events`` on insert.
    """

    id: str
    case_id: str
    run_id: str
    rule_id: str
    rule_title: str
    rule_kind: str
    rule_type: str
    level: str
    host: str | None
    user_name: str | None
    group_key: str
    first_seen_ms: int
    last_seen_ms: int
    match_count: int
    event_ids: tuple[int, ...]
    false_positives: tuple[str, ...]
    references: tuple[str, ...]


__all__ = [
    "ALERT_ANALYST_STATUSES",
    "ALERT_STATUSES",
    "ALERT_STATUS_BENIGN",
    "ALERT_STATUS_FALSE_POSITIVE",
    "ALERT_STATUS_NEW",
    "ALERT_STATUS_TRIAGED",
    "ALERT_STATUS_TRUE_POSITIVE",
    "AlertDraft",
    "AlertRecord",
]
