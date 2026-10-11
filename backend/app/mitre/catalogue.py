"""The loaded ATT&CK catalogue and tag resolution (spec 04 section 7.2).

Resolution rule 1: tags that reference an unknown ID keep their raw tag
under ``unresolved_tags``; a name is never invented for them.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass

from app.mitre.tags import ParsedTags, parse_sigma_tags


@dataclass(frozen=True, slots=True)
class TechniqueInfo:
    """One row of ``mitre_techniques`` as the resolver sees it."""

    attack_id: str
    name: str
    tactics: tuple[str, ...]
    is_subtechnique: bool
    parent_id: str | None


@dataclass(frozen=True, slots=True)
class GroupSoftwareInfo:
    """One row of ``mitre_groups_software`` as the resolver sees it."""

    attack_id: str
    name: str
    kind: str


@dataclass(frozen=True, slots=True)
class MitreCatalogue:
    """Everything the resolver needs, loaded once per enrichment run."""

    tactics: dict[str, str]
    techniques: dict[str, TechniqueInfo]
    groups_software: dict[str, GroupSoftwareInfo]

    @classmethod
    def load(cls, connection: sqlite3.Connection) -> MitreCatalogue:
        """Read the MITRE tables into memory."""
        tactics = {
            str(row["shortname"]): str(row["name"])
            for row in connection.execute("SELECT shortname, name FROM mitre_tactics")
        }
        techniques: dict[str, TechniqueInfo] = {}
        for row in connection.execute(
            "SELECT attack_id, name, tactics_json, is_subtechnique, parent_id FROM mitre_techniques"
        ):
            techniques[str(row["attack_id"])] = TechniqueInfo(
                attack_id=str(row["attack_id"]),
                name=str(row["name"]),
                tactics=tuple(json.loads(str(row["tactics_json"]))),
                is_subtechnique=bool(row["is_subtechnique"]),
                parent_id=(str(row["parent_id"]) if row["parent_id"] is not None else None),
            )
        entities = {
            str(row["attack_id"]): GroupSoftwareInfo(
                attack_id=str(row["attack_id"]),
                name=str(row["name"]),
                kind=str(row["kind"]),
            )
            for row in connection.execute("SELECT attack_id, name, kind FROM mitre_groups_software")
        }
        return cls(tactics=tactics, techniques=techniques, groups_software=entities)


@dataclass(frozen=True, slots=True)
class ResolvedTags:
    """Parsed tags checked against a catalogue."""

    techniques: tuple[TechniqueInfo, ...]
    tactics: tuple[str, ...]
    groups_software: tuple[GroupSoftwareInfo, ...]
    unresolved_tags: tuple[str, ...]


def resolve_rule_tags(tags: list[str] | tuple[str, ...], catalogue: MitreCatalogue) -> ResolvedTags:
    """Parse sigma tags and resolve them against the loaded catalogue."""
    return resolve_parsed(parse_sigma_tags(tags), catalogue)


def resolve_parsed(parsed: ParsedTags, catalogue: MitreCatalogue) -> ResolvedTags:
    """Resolve already-parsed tags; unknown ids become raw unresolved tags."""
    techniques: list[TechniqueInfo] = []
    tactics: list[str] = []
    entities: list[GroupSoftwareInfo] = []
    unresolved: list[str] = []
    for attack_id in parsed.technique_ids:
        info = catalogue.techniques.get(attack_id)
        if info is None:
            unresolved.append(f"attack.{attack_id.lower()}")
        else:
            techniques.append(info)
    for index, normalized in enumerate(parsed.tactic_names):
        if normalized in catalogue.tactics:
            tactics.append(normalized)
        else:
            raw = parsed.tactic_raw[index]
            unresolved.append(f"attack.{raw}")
    for attack_id in (*parsed.group_ids, *parsed.software_ids):
        entity = catalogue.groups_software.get(attack_id)
        if entity is None:
            unresolved.append(f"attack.{attack_id.lower()}")
        else:
            entities.append(entity)
    unresolved.extend(parsed.other)
    return ResolvedTags(
        techniques=tuple(techniques),
        tactics=tuple(tactics),
        groups_software=tuple(entities),
        unresolved_tags=tuple(dict.fromkeys(unresolved)),
    )


__all__ = [
    "GroupSoftwareInfo",
    "MitreCatalogue",
    "ResolvedTags",
    "TechniqueInfo",
    "resolve_parsed",
    "resolve_rule_tags",
]
