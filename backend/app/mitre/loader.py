"""Offline ATT&CK STIX 2.1 loader (spec 04 section 7.1).

``load_bundle`` replaces the MITRE tables from a bundle in one transaction
and records the version, load time and bundle hash in ``mitre_meta``.
Nothing here touches the network: the bundle is a local file handed over
by ``scripts/update_attack.py`` or the Settings import endpoint.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.db.connection import atomic
from app.mitre.tactics import CANONICAL_TACTICS, TACTIC_ORDER, Tactic
from app.util.time import utc_now_iso


class AttackBundleError(ValueError):
    """The document is not a usable ATT&CK STIX 2.1 bundle."""


@dataclass(slots=True)
class _Pattern:
    """One ``attack-pattern`` object, pre-table."""

    stix_id: str
    attack_id: str | None
    name: str
    description: str | None
    is_subtechnique: bool
    tactics: list[str]
    platforms: list[str]
    url: str | None
    deprecated: bool
    revoked: bool


def load_bundle(
    connection: sqlite3.Connection,
    source: Path | str | Mapping[str, Any],
    *,
    attack_version: str | None = None,
    loaded_at: str | None = None,
) -> str:
    """Replace the MITRE tables from ``source``; return the attack version.

    ``attack_version`` overrides the version detected in the bundle. The
    replace is atomic: either the new catalogue is fully visible or the old
    one is untouched.
    """
    document, sha256 = _read(source)
    patterns, tactics, entities, parent_of = _extract(document)
    version = attack_version or _detect_version(document, patterns)
    with atomic(connection):
        connection.execute("DELETE FROM mitre_groups_software")
        connection.execute("DELETE FROM mitre_techniques")
        connection.execute("DELETE FROM mitre_tactics")
        _insert_tactics(connection, tactics)
        _insert_patterns(connection, patterns, parent_of)
        _insert_entities(connection, entities)
        _write_meta(connection, version, loaded_at or utc_now_iso(), sha256)
    return version


def _read(source: Path | str | Mapping[str, Any]) -> tuple[dict[str, Any], str]:
    """The parsed bundle and the SHA-256 of its bytes (or canonical form)."""
    if isinstance(source, Mapping):
        document = _ensure_bundle(dict(source))
        payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        return document, hashlib.sha256(payload).hexdigest()
    path = Path(source)
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise AttackBundleError(f"cannot read bundle: {exc}") from exc
    return _parse(data), hashlib.sha256(data).hexdigest()


def _parse(data: bytes) -> dict[str, Any]:
    try:
        document: object = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AttackBundleError(f"bundle is not valid JSON: {exc}") from exc
    return _ensure_bundle(document)


def _ensure_bundle(document: object) -> dict[str, Any]:
    if not isinstance(document, dict) or document.get("type") != "bundle":
        raise AttackBundleError("document is not a STIX bundle")
    if not isinstance(document.get("objects"), list):
        raise AttackBundleError("bundle has no objects list")
    return document


def _extract(
    document: Mapping[str, Any],
) -> tuple[
    list[_Pattern],
    list[Mapping[str, Any]],
    list[tuple[str, str, str, str | None]],
    dict[str, str],
]:
    """Patterns, tactic objects, group/software rows and parent links."""
    patterns: list[_Pattern] = []
    tactics: list[Mapping[str, Any]] = []
    entities: list[tuple[str, str, str, str | None]] = []
    by_stix: dict[str, _Pattern] = {}
    for obj in document.get("objects") or []:
        if not isinstance(obj, dict):
            continue
        kind = obj.get("type")
        if kind == "x-mitre-tactic":
            shortname = obj.get("x_mitre_shortname")
            if isinstance(shortname, str) and shortname:
                tactics.append(obj)
        elif kind == "attack-pattern":
            attack_id, url = _mitre_ref(obj)
            pattern = _Pattern(
                stix_id=str(obj.get("id", "")),
                attack_id=attack_id,
                name=str(obj.get("name", "")),
                description=(
                    str(obj["description"]) if isinstance(obj.get("description"), str) else None
                ),
                is_subtechnique=bool(obj.get("x_mitre_is_subtechnique", False)),
                tactics=_phases(obj),
                platforms=[
                    str(p) for p in obj.get("x_mitre_platforms") or [] if isinstance(p, str)
                ],
                url=url,
                deprecated=bool(obj.get("x_mitre_deprecated", False)),
                revoked=bool(obj.get("revoked", False)),
            )
            patterns.append(pattern)
            if pattern.stix_id:
                by_stix[pattern.stix_id] = pattern
        elif kind == "intrusion-set":
            attack_id, url = _mitre_ref(obj)
            if attack_id is not None:
                entities.append((attack_id, "group", str(obj.get("name", "")), url))
        elif kind in {"malware", "tool"}:
            attack_id, url = _mitre_ref(obj)
            if attack_id is not None:
                entities.append((attack_id, "software", str(obj.get("name", "")), url))
    return patterns, tactics, entities, _parent_links(document, by_stix)


def _parent_links(document: Mapping[str, Any], by_stix: Mapping[str, _Pattern]) -> dict[str, str]:
    """Child STIX id -> parent ATT&CK id, from ``subtechnique-of`` links."""
    links: dict[str, str] = {}
    for obj in document.get("objects") or []:
        if not isinstance(obj, dict) or obj.get("relationship_type") != "subtechnique-of":
            continue
        source = obj.get("source_ref")
        target = obj.get("target_ref")
        if not isinstance(source, str) or not isinstance(target, str):
            continue
        child = by_stix.get(source)
        parent = by_stix.get(target)
        if child is None or parent is None or parent.attack_id is None:
            continue
        child.is_subtechnique = True
        links[source] = parent.attack_id
    return links


def _mitre_ref(obj: Mapping[str, Any]) -> tuple[str | None, str | None]:
    """The ``(attack_id, url)`` of the first ``mitre-attack`` reference."""
    references = obj.get("external_references")
    if not isinstance(references, list):
        return None, None
    for ref in references:
        if isinstance(ref, dict) and ref.get("source_name") == "mitre-attack":
            external_id = ref.get("external_id")
            url = ref.get("url")
            return (
                str(external_id) if external_id is not None else None,
                str(url) if isinstance(url, str) else None,
            )
    return None, None


def _phases(obj: Mapping[str, Any]) -> list[str]:
    """Kill-chain phase names of the ``mitre-attack`` chain, in order."""
    phases: list[str] = []
    raw = obj.get("kill_chain_phases")
    if not isinstance(raw, list):
        return phases
    for phase in raw:
        if isinstance(phase, dict) and phase.get("kill_chain_name") == "mitre-attack":
            name = phase.get("phase_name")
            if isinstance(name, str) and name:
                phases.append(name)
    return phases


def _detect_version(document: Mapping[str, Any], patterns: list[_Pattern]) -> str:
    """``attack_version`` argument, bundle ``x_mitre_version``, or newest date."""
    bundle_version = document.get("x_mitre_version")
    if isinstance(bundle_version, str) and bundle_version.strip():
        return bundle_version.strip()
    modified = [
        str(obj.get("modified", ""))[:10]
        for obj in document.get("objects") or []
        if isinstance(obj, dict) and obj.get("type") == "attack-pattern"
    ]
    dated = sorted(day for day in modified if day)
    if not dated and not patterns:
        raise AttackBundleError("cannot determine attack version (pass attack_version=)")
    return dated[-1] if dated else "unknown"


def _insert_tactics(connection: sqlite3.Connection, tactics: list[Mapping[str, Any]]) -> None:
    shortnames = sorted(
        {str(obj["x_mitre_shortname"]) for obj in tactics} - set(TACTIC_ORDER),
    )
    extra_rank = {
        shortname: len(CANONICAL_TACTICS) + index for index, shortname in enumerate(shortnames)
    }

    def _rank(shortname: str) -> int:
        ranked = TACTIC_ORDER.get(shortname)
        if ranked is not None:
            return ranked
        return extra_rank[shortname]

    rows: dict[str, tuple[str, str, str, int]] = {}
    for obj in tactics:
        shortname = str(obj["x_mitre_shortname"])
        if shortname in rows:
            continue
        attack_id, _ = _mitre_ref(obj)
        canonical = _canonical_tactic(shortname)
        rows[shortname] = (
            shortname,
            attack_id or (canonical.attack_id if canonical else ""),
            str(obj.get("name", "")) or (canonical.name if canonical else shortname),
            _rank(shortname),
        )
    connection.executemany(
        "INSERT OR IGNORE INTO mitre_tactics (shortname, attack_id, name, order_idx) "
        "VALUES (?, ?, ?, ?)",
        [rows[shortname] for shortname in sorted(rows, key=lambda name: rows[name][3])],
    )


def _canonical_tactic(shortname: str) -> Tactic | None:
    for tactic in CANONICAL_TACTICS:
        if tactic.shortname == shortname:
            return tactic
    return None


def _insert_patterns(
    connection: sqlite3.Connection,
    patterns: list[_Pattern],
    parent_of: Mapping[str, str],
) -> None:
    connection.executemany(
        "INSERT OR REPLACE INTO mitre_techniques ("
        "attack_id, stix_id, name, description, is_subtechnique, parent_id, "
        "tactics_json, platforms_json, url, deprecated, revoked"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (
                pattern.attack_id,
                pattern.stix_id,
                pattern.name,
                pattern.description,
                1 if pattern.is_subtechnique else 0,
                parent_of.get(pattern.stix_id),
                json.dumps(pattern.tactics),
                json.dumps(pattern.platforms),
                pattern.url,
                1 if pattern.deprecated else 0,
                1 if pattern.revoked else 0,
            )
            for pattern in patterns
            if pattern.attack_id is not None
        ],
    )


def _insert_entities(
    connection: sqlite3.Connection, entities: list[tuple[str, str, str, str | None]]
) -> None:
    connection.executemany(
        "INSERT OR IGNORE INTO mitre_groups_software (attack_id, kind, name, url) "
        "VALUES (?, ?, ?, ?)",
        entities,
    )


def _write_meta(connection: sqlite3.Connection, version: str, loaded_at: str, sha256: str) -> None:
    connection.executemany(
        "INSERT OR REPLACE INTO mitre_meta (key, value) VALUES (?, ?)",
        [("attack_version", version), ("loaded_at", loaded_at), ("sha256", sha256)],
    )


__all__ = ["AttackBundleError", "load_bundle"]
