"""Severity scoring (spec 04 section 8).

``score = base(level) + modifiers`` clamped to 0-100. Every modifier is a
deterministic function of stored state - the alert itself, its siblings in
the case, its linked IOCs and its rule's status - so two runs over the same
data always agree.

The breakdown always sums to the final score: when clamping fires, the
difference lands under the ``clamp`` key. It is never stored; the alert
detail endpoint recomputes it on demand (spec 04 section 8).

The IOC modifier reads links that the enrichment stage creates *after*
detection (spec 01 section 8), so scoring at detection time sees none of
them; re-scoring later picks the modifier up without any special casing.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from app.models.alert import ALERT_STATUS_FALSE_POSITIVE, AlertRecord

#: ``score = base(level) + modifiers`` (spec 04 section 8).
_BASE_SCORES = {
    "critical": 90,
    "high": 70,
    "medium": 50,
    "low": 30,
    "informational": 10,
}
#: Unknown levels are treated as informational rather than crashing a run.
_FALLBACK_BASE = 10

_HOST_OVERLAP = 10
_IOC_EVIDENCE = 5
_MATCH_VOLUME = ((10, 5), (100, 5))
_EXPERIMENTAL_PENALTY = -10
_SIBLING_FALSE_POSITIVE = -10

#: Another alert on the same host overlapping within +/- this window (spec 04
#: section 8) - 15 minutes in milliseconds.
_OVERLAP_WINDOW_MS = 15 * 60 * 1000
#: An evidence IOC must reach this confidence to boost the score.
_IOC_CONFIDENCE = 70
#: Rule statuses that weaken a rule's alerts.
_DEGRADED_STATUSES = frozenset({"experimental", "unsupported"})


@dataclass(frozen=True, slots=True)
class ScoreResult:
    """A score plus the modifier breakdown that produced it.

    ``sum(breakdown.values()) == score`` holds for every result.
    """

    score: int
    breakdown: dict[str, int]


def base_score(level: str) -> int:
    """The level's base points before any modifier."""
    return _BASE_SCORES.get(level, _FALLBACK_BASE)


def score_alert(
    connection: sqlite3.Connection,
    alert: AlertRecord,
    *,
    rule_status: str | None,
    overlap_window_ms: int = _OVERLAP_WINDOW_MS,
) -> ScoreResult:
    """Score one alert from stored state; see the module docstring.

    ``rule_status`` is passed in because the caller already holds the rule
    catalogue row; ``None`` means the rule carries no Sigma status.
    """
    breakdown: dict[str, int] = {"base": base_score(alert.level)}

    if _overlaps_another_alert(connection, alert, overlap_window_ms):
        breakdown["host_overlap"] = _HOST_OVERLAP
    if _has_confident_ioc(connection, alert.id):
        breakdown["ioc_evidence"] = _IOC_EVIDENCE
    for threshold, points in _MATCH_VOLUME:
        if alert.match_count >= threshold:
            breakdown[f"match_volume_{threshold}"] = points
    if rule_status is not None and rule_status in _DEGRADED_STATUSES:
        breakdown["rule_status"] = _EXPERIMENTAL_PENALTY
    if _sibling_marked_false_positive(connection, alert):
        breakdown["sibling_false_positive"] = _SIBLING_FALSE_POSITIVE

    raw = sum(breakdown.values())
    score = max(0, min(100, raw))
    if score != raw:
        breakdown["clamp"] = score - raw
    return ScoreResult(score=score, breakdown=breakdown)


def _overlaps_another_alert(
    connection: sqlite3.Connection, alert: AlertRecord, window_ms: int
) -> bool:
    """True when another alert on the same host overlaps within the window.

    A ``NULL`` host or window never compares equal in SQL, so alerts without
    one simply never match - the modifier stays off rather than guessing.
    """
    row = connection.execute(
        "SELECT 1 FROM alerts "
        "WHERE case_id = ? AND id != ? AND host = ? "
        "AND last_seen_ms + ? >= ? AND first_seen_ms - ? <= ? "
        "LIMIT 1",
        (
            alert.case_id,
            alert.id,
            alert.host,
            window_ms,
            alert.first_seen_ms,
            window_ms,
            alert.last_seen_ms,
        ),
    ).fetchone()
    return row is not None


def _sibling_marked_false_positive(connection: sqlite3.Connection, alert: AlertRecord) -> bool:
    """True when another alert of the same rule on the same host was dismissed."""
    row = connection.execute(
        "SELECT 1 FROM alerts "
        "WHERE case_id = ? AND rule_id = ? AND host = ? AND id != ? AND status = ? "
        "LIMIT 1",
        (alert.case_id, alert.rule_id, alert.host, alert.id, ALERT_STATUS_FALSE_POSITIVE),
    ).fetchone()
    return row is not None


def _has_confident_ioc(connection: sqlite3.Connection, alert_id: str) -> bool:
    """True when evidence carries a non-private, non-allowlisted IP/domain IOC."""
    row = connection.execute(
        "SELECT 1 FROM ioc_alerts "
        "JOIN iocs ON iocs.id = ioc_alerts.ioc_id "
        "WHERE ioc_alerts.alert_id = ? "
        "AND iocs.type IN ('ipv4', 'ipv6', 'domain') "
        "AND iocs.confidence >= ? "
        "AND iocs.is_private = 0 AND iocs.is_allowlisted = 0 "
        "LIMIT 1",
        (alert_id, _IOC_CONFIDENCE),
    ).fetchone()
    return row is not None


__all__ = ["ScoreResult", "base_score", "score_alert"]
