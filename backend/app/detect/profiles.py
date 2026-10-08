"""Detection profiles (spec 04 section 2).

A profile decides which loaded rules a run executes: ``fast`` trades
coverage for latency, ``standard`` is the default, ``full`` runs everything
that is enabled. Selection is a pure function over rule metadata, so the
API can preview it without touching the database.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Protocol, TypeVar

from app.models.rule import KIND_BUILTIN, KIND_CUSTOM

#: Level ranking for ``level >= medium`` style selection.
LEVEL_ORDER: dict[str, int] = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

#: Statuses the ``fast`` profile trusts for non-built-in sigma rules.
_FAST_STATUSES = frozenset({"stable", "test"})


class RuleSelection(Protocol):
    """What profile selection reads off a rule record.

    Members are read-only properties so frozen records like ``RuleRecord``
    satisfy the protocol structurally (mypy treats frozen dataclass fields
    as read-only).
    """

    @property
    def kind(self) -> str: ...

    @property
    def level(self) -> str: ...

    @property
    def status(self) -> str | None: ...

    @property
    def enabled(self) -> bool: ...


RuleT = TypeVar("RuleT", bound=RuleSelection)


def level_at_least(level: str, minimum: str) -> bool:
    """True when ``level`` ranks at or above ``minimum``.

    Unknown levels (either side) never match, so a corrupted row cannot
    sneak into a narrow profile.
    """
    have = LEVEL_ORDER.get(level.lower())
    floor = LEVEL_ORDER.get(minimum.lower())
    if have is None or floor is None:
        return False
    return have >= floor


def select_for_profile(rules: Sequence[RuleT], profile: str) -> list[RuleT]:
    """The rules a run with ``profile`` executes; input order is preserved.

    Disabled rules are excluded for every profile; the profile tables of
    spec 04 section 2 only ever describe *enabled* rules.

    Raises:
        ValueError: for an unknown profile name.
    """
    keep: Callable[[RuleSelection], bool]
    if profile == "fast":
        keep = _fast
    elif profile == "standard":
        keep = _standard
    elif profile == "full":
        keep = _full
    else:
        raise ValueError(f"unknown detection profile: {profile!r}")
    return [rule for rule in rules if rule.enabled and keep(rule)]


def _fast(rule: RuleSelection) -> bool:
    """Builtins, plus high/critical rules that are stable or in test."""
    if rule.kind == KIND_BUILTIN:
        return True
    return (
        rule.level in {"high", "critical"}
        and rule.status is not None
        and rule.status in _FAST_STATUSES
    )


def _standard(rule: RuleSelection) -> bool:
    """Builtins, every custom rule, and sigma rules at medium or above."""
    if rule.kind in {KIND_BUILTIN, KIND_CUSTOM}:
        return True
    return level_at_least(rule.level, "medium")


def _full(_rule: RuleSelection) -> bool:
    """Everything enabled, including experimental and informational."""
    return True


__all__ = [
    "LEVEL_ORDER",
    "RuleSelection",
    "level_at_least",
    "select_for_profile",
]
