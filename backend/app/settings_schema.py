"""Analyst-editable settings (spec 06 "Health and settings").

Deployment configuration lives in ``config.toml`` and is read-only through the
API. A small, explicit set of keys may also be adjusted by an analyst at runtime;
those are stored in the ``settings`` table under their dotted config path and
overlaid on the effective configuration that ``GET /settings`` returns. Only
declared keys are accepted, each with its own validator, so a typo or an
out-of-range value becomes a validation error instead of a value that is
persisted and then ignored.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from app.errors import validation_error

#: Accepted detection profiles (spec 04 section 2).
PROFILE_VALUES: tuple[str, ...] = ("fast", "standard", "full")


def _profile(value: Any) -> str:
    """Coerce ``detection.profile``, rejecting anything but a known name."""
    if not isinstance(value, str) or value not in PROFILE_VALUES:
        raise validation_error(
            "unsupported detection profile",
            value=value,
            allowed=list(PROFILE_VALUES),
        )
    return value


#: Dotted key -> validator that returns the stored value or raises ``ApiError``.
EDITABLE_KEYS: dict[str, Callable[[Any], Any]] = {
    "detection.profile": _profile,
}


def editable_keys() -> tuple[str, ...]:
    """The sorted names an analyst is allowed to change."""
    return tuple(sorted(EDITABLE_KEYS))


def validate_overrides(values: Mapping[str, Any]) -> dict[str, Any]:
    """Validate a partial settings update, returning the coerced values.

    Rejects an empty update, an unknown or read-only key, and any value its
    key's validator refuses. The result keeps the caller's key order.
    """
    if not values:
        raise validation_error("no settings were provided")
    validated: dict[str, Any] = {}
    for key, value in values.items():
        validator = EDITABLE_KEYS.get(key)
        if validator is None:
            raise validation_error(
                "unknown or read-only setting",
                key=key,
                allowed=list(editable_keys()),
            )
        validated[key] = validator(value)
    return validated


def overlay(config: dict[str, Any], overrides: Mapping[str, Any]) -> dict[str, Any]:
    """Apply dotted overrides onto a config mapping, in place.

    A key whose section is missing from the config is skipped rather than
    inventing a section, so a stale stored key can never deform the response.
    """
    for key, value in overrides.items():
        section, _, leaf = key.partition(".")
        target = config.get(section)
        if leaf and isinstance(target, dict):
            target[leaf] = value
    return config


def detection_profile(overrides: Mapping[str, Any], default: str) -> str:
    """The effective detection profile: a valid stored override, else ``default``."""
    value = overrides.get("detection.profile")
    if isinstance(value, str) and value in PROFILE_VALUES:
        return value
    return default


__all__ = [
    "EDITABLE_KEYS",
    "PROFILE_VALUES",
    "detection_profile",
    "editable_keys",
    "overlay",
    "validate_overrides",
]
