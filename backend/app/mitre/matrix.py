"""Case MITRE matrix aggregation (spec 06 ``GET /cases/{id}/mitre``).

Folds a case's alerts into the canonical tactic order. Rule 3 of spec 04
section 7.2: a technique appears under the tactic(s) the rule declared,
or under all of the technique's own tactics when it declared none.
Rule 4: a sub-technique alert also credits its parent in the rollup.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from typing import Any

from app.db.repositories.runs import attack_version
from app.detect.profiles import LEVEL_ORDER
from app.mitre.tactics import CANONICAL_TACTICS, TACTIC_NAMES


@dataclass(frozen=True, slots=True)
class AlertMapping:
    """One alert's stored ATT&CK mapping, as the rollups read it."""

    id: str
    rule_title: str
    level: str
    tactics: tuple[str, ...]
    techniques: tuple[str, ...]


@dataclass(slots=True)
class _TechniqueRow:
    attack_id: str
    name: str
    tactics: tuple[str, ...]
    is_subtechnique: bool
    parent_id: str | None


@dataclass(slots=True)
class _Cell:
    alert_ids: list[str]
    levels: list[str]

    def add(self, mapping: AlertMapping) -> None:
        if mapping.id not in self.alert_ids:
            self.alert_ids.append(mapping.id)
            self.levels.append(mapping.level)

    def max_level(self) -> str:
        return max(self.levels, key=lambda level: LEVEL_ORDER.get(level, 0))


def load_alert_mappings(
    connection: sqlite3.Connection, *, case_id: str
) -> tuple[AlertMapping, ...]:
    """Every alert of one case, oldest id first."""
    mappings: list[AlertMapping] = []
    for row in connection.execute(
        "SELECT id, rule_title, level, tactics_json, techniques_json "
        "FROM alerts WHERE case_id = ? ORDER BY id",
        (case_id,),
    ):
        techniques = tuple(
            str(item.get("id"))
            for item in json.loads(str(row["techniques_json"]))
            if isinstance(item, dict) and item.get("id") is not None
        )
        mappings.append(
            AlertMapping(
                id=str(row["id"]),
                rule_title=str(row["rule_title"]),
                level=str(row["level"]),
                tactics=tuple(json.loads(str(row["tactics_json"]))),
                techniques=techniques,
            )
        )
    return tuple(mappings)


def matrix_static(connection: sqlite3.Connection) -> dict[str, Any]:
    """The full ATT&CK matrix, independent of any case (spec 06 ``/mitre/matrix``).

    Every technique the bundle knows, nested under the tactic row whose
    shortname appears in the technique's own ``tactics_json`` (not the
    per-case alert fold - this is the static reference, before detection).
    """
    rows = _technique_rows(connection)
    tactic_names = _tactic_names(connection)
    tactics: list[dict[str, Any]] = []
    for tactic in CANONICAL_TACTICS:
        techniques = [
            _static_technique(attack_id, rows, tactic.shortname)
            for attack_id in sorted(rows)
            if _is_static_top(rows, attack_id) and tactic.shortname in rows[attack_id].tactics
        ]
        tactics.append(
            {
                "shortname": tactic.shortname,
                "name": tactic_names.get(tactic.shortname, tactic.name),
                "techniques": techniques,
            }
        )
    return {"attack_version": attack_version(connection), "tactics": tactics}


def _is_static_top(rows: dict[str, _TechniqueRow], attack_id: str) -> bool:
    """Top-level in a static matrix: not a nested sub-technique."""
    info = rows[attack_id]
    return not (info.is_subtechnique and info.parent_id in rows)


def _static_technique(
    attack_id: str, rows: dict[str, _TechniqueRow], shortname: str
) -> dict[str, Any]:
    """One static technique row with its nested sub-techniques."""
    info = rows[attack_id]
    children = [
        _static_technique(child_id, rows, shortname)
        for child_id in sorted(rows)
        if rows[child_id].is_subtechnique
        and rows[child_id].parent_id == attack_id
        and shortname in rows[child_id].tactics
    ]
    return {"id": attack_id, "name": info.name, "subtechniques": children}


def matrix_for_case(connection: sqlite3.Connection, *, case_id: str) -> dict[str, Any]:
    """The ``GET /api/cases/{id}/mitre`` payload."""
    mappings = load_alert_mappings(connection, case_id=case_id)
    rows = _technique_rows(connection)
    tactic_names = _tactic_names(connection)
    cells = _fold(mappings, rows)
    tactics: list[dict[str, Any]] = []
    for tactic in CANONICAL_TACTICS:
        tactics.append(
            {
                "shortname": tactic.shortname,
                "name": tactic_names.get(tactic.shortname, tactic.name),
                "techniques": _tactic_techniques(tactic.shortname, cells, rows),
            }
        )
    unmapped = sum(1 for mapping in mappings if not mapping.techniques)
    return {
        "attack_version": attack_version(connection),
        "tactics": tactics,
        "unmapped_alert_count": unmapped,
    }


def _technique_rows(connection: sqlite3.Connection) -> dict[str, _TechniqueRow]:
    rows: dict[str, _TechniqueRow] = {}
    for row in connection.execute(
        "SELECT attack_id, name, tactics_json, is_subtechnique, parent_id FROM mitre_techniques"
    ):
        rows[str(row["attack_id"])] = _TechniqueRow(
            attack_id=str(row["attack_id"]),
            name=str(row["name"]),
            tactics=tuple(json.loads(str(row["tactics_json"]))),
            is_subtechnique=bool(row["is_subtechnique"]),
            parent_id=(str(row["parent_id"]) if row["parent_id"] is not None else None),
        )
    return rows


def _tactic_names(connection: sqlite3.Connection) -> dict[str, str]:
    return {
        str(row["shortname"]): str(row["name"])
        for row in connection.execute("SELECT shortname, name FROM mitre_tactics")
    }


def _fold(
    mappings: tuple[AlertMapping, ...], rows: dict[str, _TechniqueRow]
) -> dict[tuple[str, str], _Cell]:
    """(tactic, technique) -> accumulated alerts, parent credit included."""
    cells: dict[tuple[str, str], _Cell] = {}
    for mapping in mappings:
        for attack_id in mapping.techniques:
            info = rows.get(attack_id)
            if info is None:
                continue
            for tactic in _mapping_tactics(mapping, info.tactics):
                cells.setdefault((tactic, attack_id), _Cell([], [])).add(mapping)
            parent = rows.get(info.parent_id) if info.parent_id else None
            if parent is not None:
                for tactic in _mapping_tactics(mapping, parent.tactics):
                    cells.setdefault((tactic, parent.attack_id), _Cell([], [])).add(mapping)
    return cells


def _mapping_tactics(mapping: AlertMapping, own_tactics: tuple[str, ...]) -> tuple[str, ...]:
    """Declared tactics when there are any, else all of the technique's."""
    declared = tuple(name for name in mapping.tactics if name in TACTIC_NAMES)
    return declared or own_tactics


def _tactic_techniques(
    shortname: str,
    cells: dict[tuple[str, str], _Cell],
    rows: dict[str, _TechniqueRow],
) -> list[dict[str, Any]]:
    """Top-level technique rows of one tactic, sub-techniques nested."""
    under = sorted(attack_id for (tactic, attack_id) in cells if tactic == shortname)
    top_level = [attack_id for attack_id in under if not _is_sub(rows, attack_id)]
    return [_technique_payload(attack_id, cells, rows, shortname) for attack_id in top_level]


def _is_sub(rows: dict[str, _TechniqueRow], attack_id: str) -> bool:
    info = rows.get(attack_id)
    return bool(info is not None and info.is_subtechnique and info.parent_id in rows)


def _technique_payload(
    attack_id: str,
    cells: dict[tuple[str, str], _Cell],
    rows: dict[str, _TechniqueRow],
    shortname: str,
) -> dict[str, Any]:
    info = rows.get(attack_id)
    payload: dict[str, Any] = {
        "id": attack_id,
        "name": info.name if info is not None else attack_id,
        "alert_count": 0,
        "max_level": "",
        "alert_ids": [],
        "subtechniques": [],
    }
    children = [
        child_id
        for (tactic, child_id) in sorted(cells)
        if tactic == shortname
        and rows.get(child_id) is not None
        and rows[child_id].is_subtechnique
        and rows[child_id].parent_id == attack_id
    ]
    for child_id in children:
        payload["subtechniques"].append(_technique_payload(child_id, cells, rows, shortname))
    cell = cells.get((shortname, attack_id))
    if cell is not None:
        # ``_fold`` already credited sub-technique alerts onto the parent
        # cell, so the parent's own ids cover the whole rollup.
        payload["alert_ids"] = sorted(cell.alert_ids)
        payload["max_level"] = cell.max_level()
    payload["alert_count"] = len(payload["alert_ids"])
    return payload


__all__ = [
    "AlertMapping",
    "load_alert_mappings",
    "matrix_for_case",
    "matrix_static",
]
