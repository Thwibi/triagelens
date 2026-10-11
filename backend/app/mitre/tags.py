"""Sigma tag -> ATT&CK parsing (spec 04 section 7.2).

Purely syntactic: ids and tactic names are classified here and checked
against the loaded catalogue by :mod:`app.mitre.catalogue`, so an unknown
ID stays a raw tag instead of an invented name.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

_PREFIX = "attack."
_TECHNIQUE = re.compile(r"^t\d{4}(?:\.\d{3})?$")
_GROUP = re.compile(r"^g\d{4}$")
_SOFTWARE = re.compile(r"^s\d{4}$")
_TACTIC_NAME = re.compile(r"^[a-z][a-z0-9-]*$")


@dataclass(frozen=True, slots=True)
class ParsedTags:
    """ATT&CK-shaped sigma tags, split by kind, order preserved."""

    technique_ids: tuple[str, ...]
    tactic_names: tuple[str, ...]
    tactic_raw: tuple[str, ...]
    group_ids: tuple[str, ...]
    software_ids: tuple[str, ...]
    other: tuple[str, ...]


def parse_sigma_tags(tags: Iterable[str]) -> ParsedTags:
    """Classify ``attack.*`` sigma tags; non-ATT&CK tags are ignored.

    Underscores in tactic names become hyphens (``attack.defense_evasion``
    -> ``defense-evasion``); technique and entity ids are uppercased. The
    pre-normalization tactic token is kept in ``tactic_raw`` so an unknown
    tactic keeps its exact authored tag. Anything that fits no known shape
    lands in ``other`` untouched.
    """
    techniques: list[str] = []
    tactics: list[str] = []
    tactic_raw: list[str] = []
    groups: list[str] = []
    software: list[str] = []
    other: list[str] = []
    for tag in tags:
        text = str(tag).strip().lower()
        if not text.startswith(_PREFIX):
            continue
        rest = text[len(_PREFIX) :]
        if not rest:
            continue
        if _TECHNIQUE.match(rest):
            techniques.append(rest.upper())
        elif _GROUP.match(rest):
            groups.append(rest.upper())
        elif _SOFTWARE.match(rest):
            software.append(rest.upper())
        else:
            normalized = rest.replace("_", "-")
            if _TACTIC_NAME.match(normalized):
                tactics.append(normalized)
                tactic_raw.append(rest)
            else:
                other.append(str(tag).strip())
    return ParsedTags(
        technique_ids=_ordered(techniques),
        tactic_names=_ordered(tactics),
        tactic_raw=_ordered(tactic_raw),
        group_ids=_ordered(groups),
        software_ids=_ordered(software),
        other=tuple(other),
    )


def _ordered(values: list[str]) -> tuple[str, ...]:
    """Deduplicate preserving first-seen order."""
    return tuple(dict.fromkeys(values))


__all__ = ["ParsedTags", "parse_sigma_tags"]
