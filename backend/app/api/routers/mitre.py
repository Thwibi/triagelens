"""MITRE ATT&CK endpoints (spec 06 "MITRE" and the attack import).

Reads run on the request-scoped read connection; the bundle import writes
through the single writer thread and audit-logs the replacement.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from fastapi import APIRouter, Depends, File, UploadFile
from fastapi import Request as FastAPIRequest

from app.api.deps import case_repository, read_connection, write_in
from app.db.repositories.audit import AuditRepository
from app.db.repositories.cases import CaseRepository
from app.db.repositories.runs import attack_version
from app.errors import ApiError, ErrorCode, validation_error
from app.mitre.loader import AttackBundleError, load_bundle
from app.mitre.matrix import (
    load_alert_mappings,
    matrix_for_case,
    matrix_static,
)
from app.mitre.navigator import build_layer
from app.mitre.tactics import CANONICAL_TACTICS, TACTIC_NAMES

router = APIRouter(tags=["mitre"])

_MAX_BUNDLE_BYTES = 250 * 1024 * 1024


@router.get("/mitre/matrix")
def mitre_matrix(conn: sqlite3.Connection = Depends(read_connection)) -> dict[str, Any]:
    """The static reference matrix (spec 06)."""
    return matrix_static(conn)


@router.get("/cases/{case_id}/mitre")
def case_mitre(
    case_id: str,
    conn: sqlite3.Connection = Depends(read_connection),
) -> dict[str, Any]:
    """One case's ATT&CK coverage in canonical tactic order (spec 06)."""
    return matrix_for_case(conn, case_id=case_id)


@router.get("/cases/{case_id}/mitre/navigator-layer")
def case_mitre_layer(
    case_id: str,
    conn: sqlite3.Connection = Depends(read_connection),
    cases: CaseRepository = Depends(case_repository),
) -> dict[str, Any]:
    """ATT&CK Navigator layer for one case (spec 08 section 3)."""
    case = cases.get(case_id)
    if case is None:
        raise ApiError(ErrorCode.NOT_FOUND, "case not found", id=case_id)
    mappings = load_alert_mappings(conn, case_id=case_id)
    parent_of, own_tactics = _technique_graph(conn)
    return build_layer(
        case_name=case.name,
        attack_version=attack_version(conn),
        mappings=mappings,
        parent_of=parent_of,
        own_tactics=own_tactics,
    )


@router.get("/mitre/techniques/{attack_id}")
def mitre_technique(
    attack_id: str,
    conn: sqlite3.Connection = Depends(read_connection),
) -> dict[str, Any]:
    """One technique from the loaded bundle (spec 06)."""
    row = conn.execute(
        "SELECT * FROM mitre_techniques WHERE attack_id = ?", (attack_id.upper(),)
    ).fetchone()
    if row is None:
        raise ApiError(ErrorCode.NOT_FOUND, "technique not found", id=attack_id)
    tactics = [str(item) for item in json.loads(str(row["tactics_json"]))]
    return {
        "attack_id": str(row["attack_id"]),
        "name": str(row["name"]),
        "description": row["description"],
        "tactics": [
            {
                "shortname": shortname,
                "name": TACTIC_NAMES.get(shortname, shortname),
            }
            for shortname in tactics
        ],
        "platforms": json.loads(str(row["platforms_json"])),
        "url": row["url"],
        "is_subtechnique": bool(row["is_subtechnique"]),
        "parent_id": row["parent_id"],
        "deprecated": bool(row["deprecated"]),
        "revoked": bool(row["revoked"]),
    }


@router.get("/mitre/tactics")
def mitre_tactics() -> dict[str, Any]:
    """The tactic shortnames in canonical order (spec 06)."""
    return {
        "tactics": [
            {"shortname": tactic.shortname, "name": tactic.name} for tactic in CANONICAL_TACTICS
        ]
    }


@router.post("/settings/attack/import")
async def import_attack_bundle(
    request: FastAPIRequest,
    bundle: UploadFile = File(...),
) -> dict[str, Any]:
    """Replace the ATT&CK catalogue from an uploaded STIX 2.1 bundle (spec 06)."""

    async def _read_bundle() -> dict[str, Any]:
        data = await bundle.read()
        if not data:
            raise validation_error("bundle is empty")
        if len(data) > _MAX_BUNDLE_BYTES:
            raise validation_error("bundle exceeds the size limit", max_bytes=_MAX_BUNDLE_BYTES)
        try:
            document = json.loads(data)
        except ValueError as exc:
            raise validation_error("bundle is not valid JSON", error=str(exc)) from exc
        if not isinstance(document, dict):
            raise validation_error("bundle must be a JSON object")
        return document

    document = await _read_bundle()

    def work(conn: sqlite3.Connection) -> dict[str, Any]:
        try:
            version = load_bundle(conn, document)
        except AttackBundleError as exc:
            raise validation_error("bundle rejected", error=str(exc)) from exc
        techniques = conn.execute("SELECT COUNT(*) FROM mitre_techniques").fetchone()
        technique_count = int(techniques[0]) if techniques else 0
        AuditRepository(conn).append(
            "attack_imported",
            detail={
                "attack_version": version,
                "technique_count": technique_count,
            },
        )
        return {
            "attack_version": version,
            "techniques": technique_count,
        }

    return write_in(request, work)


def _technique_graph(conn: sqlite3.Connection) -> tuple[dict[str, str], dict[str, tuple[str, ...]]]:
    """``(parent_of, own_tactics)`` from ``mitre_techniques`` (navigator feed)."""
    parent_of: dict[str, str] = {}
    own_tactics: dict[str, tuple[str, ...]] = {}
    for row in conn.execute(
        "SELECT attack_id, tactics_json, is_subtechnique, parent_id FROM mitre_techniques"
    ):
        attack_id = str(row["attack_id"])
        own_tactics[attack_id] = tuple(json.loads(str(row["tactics_json"])))
        if bool(row["is_subtechnique"]) and row["parent_id"] is not None:
            parent_of[attack_id] = str(row["parent_id"])
    return parent_of, own_tactics


__all__ = ["router"]
