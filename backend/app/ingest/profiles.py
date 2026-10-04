"""Mapping profiles for the generic JSON and CSV parsers (spec 03 section 6).

A profile is a YAML file describing where the interesting values live inside an
otherwise unremarkable record, so the parser can stay generic. This module owns
loading and validating them; the profile editor and import API arrive with the
Phase 4 UI, but the loader is strict now because the alternative is a typo in a
YAML file silently producing events with every column NULL.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

#: A path segment: a plain key, or ``[*]`` for "first element of this array".
#: ``@`` is allowed because Elastic names its timestamp field ``@timestamp``.
_SEGMENT = re.compile(r"[A-Za-z0-9_@\-]+|\[\*\]")


class ProfileError(ValueError):
    """A profile that cannot be used, with the reason."""


def _value_matches(actual: Any, expected: Any) -> bool:
    """Compare a record value to a rule value.

    Elastic models some fields as arrays even when only one value is expected -
    ``event.category`` is the common one - so a rule matches when the expected
    value appears anywhere in the list rather than only when the list equals it.
    """
    if actual == expected:
        return True
    return isinstance(actual, list) and expected in actual


@dataclass(slots=True)
class CategoryRule:
    """One ``category_rules`` entry: field equality tests, first match wins."""

    conditions: dict[str, Any]
    ls_category: str

    def matches(self, record: dict[str, Any]) -> bool:
        """True when every condition holds against the flattened record."""
        flat = flatten(record)
        return all(_value_matches(flat.get(key), value) for key, value in self.conditions.items())


@dataclass(slots=True)
class Profile:
    """One loaded mapping profile."""

    name: str
    timestamp_path: str
    timestamp_format: str
    timezone: str | None
    #: Normalized field name to dot-notation path in the record.
    fields: dict[str, str]
    category_rules: list[CategoryRule] = field(default_factory=list)
    #: Substrings of any key that make this profile plausible for a record.
    applies_when_keys: frozenset[str] = frozenset()

    def applies_to(self, record: dict[str, Any]) -> bool:
        """True when this profile claims the record.

        With no ``applies_when`` the profile is unconditional, which is the right
        default for a format whose records all look the same.
        """
        if not self.applies_when_keys:
            return True
        keys = set(flatten(record))
        return bool(keys & self.applies_when_keys)

    def path_for(self, field_name: str) -> str | None:
        """The record path a normalized field maps to, or ``None``."""
        return self.fields.get(field_name)

    def category_for(self, record: dict[str, Any]) -> str | None:
        """First matching category rule, or ``None``."""
        for rule in self.category_rules:
            if rule.matches(record):
                return rule.ls_category
        return None


def flatten(record: Any, prefix: str = "") -> dict[str, Any]:
    """Flatten nested dicts to dot-notation keys (spec 03 section 6).

    Arrays are *not* flattened into indexed keys; a path addresses them with
    ``[*]`` instead, and the original array is left intact so nothing is lost.
    """
    if not isinstance(record, dict):
        return {}
    result: dict[str, Any] = {}
    for key, value in record.items():
        path = f"{prefix}{key}"
        if isinstance(value, dict):
            result.update(flatten(value, f"{path}."))
        else:
            result[path] = value
    return result


def _tokenize(path: str) -> list[str]:
    """Split a dot path into segments, keeping ``[*]`` as its own segment.

    ``a.b[*]`` yields ``['a', 'b', '[*]']`` rather than ``['a', 'b[*]']``, which
    is what makes ``[*]`` usable as an array step.
    """
    return path.replace("[*]", ".[*]").split(".")


def resolve(record: dict[str, Any], path: str) -> Any:
    """Read a dot-notation path out of a record, or ``None``.

    ``[*]`` takes the first element of an array. A path that walks into a
    non-object returns ``None`` rather than raising, because a profile describes
    records whose shape varies and a missing key is normal.
    """
    if not path:
        return None
    current: Any = record
    for segment in _tokenize(path):
        if segment == "[*]":
            if isinstance(current, list):
                current = current[0] if current else None
            else:
                return None
            continue
        if not isinstance(current, dict):
            return None
        current = current.get(segment)
        if current is None:
            return None
    return current


def validate_path(path: str) -> str:
    """Check a dot-notation path, returning it unchanged.

    Raises:
        ProfileError: when a segment is empty or not a plain key or ``[*]``.
    """
    if not path or path.startswith(".") or path.endswith("."):
        raise ProfileError(f"invalid path {path!r}")
    for segment in _tokenize(path):
        if not _SEGMENT.fullmatch(segment):
            raise ProfileError(f"invalid path segment {segment!r} in {path!r}")
    return path


def load_profile(path: Path) -> Profile:
    """Load and validate one profile file."""
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as error:
        raise ProfileError(f"{path.name} is not valid YAML: {error}") from error
    if not isinstance(document, dict):
        raise ProfileError(f"{path.name} must be a YAML mapping")

    name = document.get("name")
    if not isinstance(name, str) or not name:
        raise ProfileError(f"{path.name} needs a non-empty name")

    timestamp = document.get("timestamp")
    if not isinstance(timestamp, dict) or "path" not in timestamp:
        raise ProfileError(f"{path.name} needs a timestamp mapping with a path")
    timestamp_path = validate_path(str(timestamp["path"]))
    timestamp_format = str(timestamp.get("format", "iso8601"))
    builtin = {"iso8601", "epoch_s", "epoch_ms"}
    if timestamp_format not in builtin and not timestamp_format.startswith("strptime:"):
        raise ProfileError(f"{path.name} has an unsupported timestamp format {timestamp_format!r}")

    raw_fields = document.get("fields", {})
    if not isinstance(raw_fields, dict):
        raise ProfileError(f"{path.name} fields must be a mapping")
    fields = {
        str(key): validate_path(str(value))
        for key, value in raw_fields.items()
        if isinstance(value, str)
    }

    rules: list[CategoryRule] = []
    for entry in document.get("category_rules", []) or []:
        if not isinstance(entry, dict):
            raise ProfileError(f"{path.name} category_rules entries must be mappings")
        conditions = entry.get("when")
        ls_category = entry.get("ls_category")
        if not isinstance(conditions, dict) or not isinstance(ls_category, str):
            raise ProfileError(f"{path.name} category rule needs a when mapping and ls_category")
        rules.append(
            CategoryRule(
                conditions={str(key): value for key, value in conditions.items()},
                ls_category=ls_category,
            )
        )

    applies_when = document.get("applies_when") or {}
    if not isinstance(applies_when, dict):
        raise ProfileError(f"{path.name} applies_when must be a mapping")
    keys = applies_when.get("any_key", [])
    if not isinstance(keys, list):
        raise ProfileError(f"{path.name} applies_when.any_key must be a list")

    return Profile(
        name=name,
        timestamp_path=timestamp_path,
        timestamp_format=timestamp_format,
        timezone=(str(document["timezone"]) if document.get("timezone") else None),
        fields=fields,
        category_rules=rules,
        applies_when_keys=frozenset(str(key) for key in keys),
    )


def load_profiles(directory: Path) -> dict[str, Profile]:
    """Every ``*.yaml`` profile in ``directory``, keyed by name.

    A malformed file raises rather than being skipped: silently ingesting with
    fewer profiles than the operator believes are installed is worse than
    refusing to start.
    """
    loaded: dict[str, Profile] = {}
    if not directory.is_dir():
        return loaded
    for candidate in sorted(directory.glob("*.y*ml")):
        profile = load_profile(candidate)
        loaded[profile.name] = profile
    return loaded


__all__ = [
    "CategoryRule",
    "Profile",
    "ProfileError",
    "flatten",
    "load_profile",
    "load_profiles",
    "resolve",
    "validate_path",
]
