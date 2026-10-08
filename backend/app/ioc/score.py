"""Confidence scoring (spec 05 section 5).

The score is deterministic: a base value from how the indicator was found, plus
small bonuses for corroboration, minus penalties for private addresses and
allowlisted infrastructure. It is a triage *rank*, never a verdict, so the
formula is deliberately simple and reproducible.
"""

from __future__ import annotations

#: The three base scores, from how the indicator was found.
BASE_STRUCTURED = 80
BASE_DECODED = 60
BASE_MENTION = 50

#: Adjustments.
BONUS_ALERT = 15
BONUS_OCCURRENCES = 10
OCCURRENCES_THRESHOLD = 5
BONUS_DISTINCT_HOSTS = 5
DISTINCT_HOSTS_THRESHOLD = 3
PENALTY_PRIVATE = 20
PENALTY_ALLOWLISTED = 40
PENALTY_AMBIGUOUS = 30


def clamp(score: int) -> int:
    """Keep a score inside 0..100."""
    return max(0, min(100, score))


def confidence(
    base: int,
    *,
    in_alert: bool = False,
    occurrences: int = 1,
    distinct_hosts: int = 1,
    is_private: bool = False,
    is_allowlisted: bool = False,
    ambiguous: bool = False,
) -> int:
    """Compute a clamped confidence score from a base and its adjustments."""
    score = base
    if in_alert:
        score += BONUS_ALERT
    if occurrences >= OCCURRENCES_THRESHOLD:
        score += BONUS_OCCURRENCES
    if distinct_hosts >= DISTINCT_HOSTS_THRESHOLD:
        score += BONUS_DISTINCT_HOSTS
    if is_private:
        score -= PENALTY_PRIVATE
    if is_allowlisted:
        score -= PENALTY_ALLOWLISTED
    if ambiguous:
        score -= PENALTY_AMBIGUOUS
    return clamp(score)


__all__ = [
    "BASE_DECODED",
    "BASE_MENTION",
    "BASE_STRUCTURED",
    "BONUS_ALERT",
    "BONUS_DISTINCT_HOSTS",
    "BONUS_OCCURRENCES",
    "PENALTY_ALLOWLISTED",
    "PENALTY_PRIVATE",
    "clamp",
    "confidence",
]
