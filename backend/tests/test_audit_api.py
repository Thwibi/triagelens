"""Audit-log API tests (spec 10 section 2, spec 06 "Reports").

The suite appends hash-chained rows through ``AuditRepository`` on the writer
connection (the same one-statement INSERT the real endpoints use) and reads the
page through the app. One test forges a row with a wrong ``prev_hash`` to prove
``GET /cases/{id}/audit-log`` reports the first broken link.
"""

from __future__ import annotations

from typing import Any

from app.db.connection import Database
from app.db.repositories.audit import AuditEntry, AuditRepository, canonical_detail

_ISO = "2026-01-01T00:00:00.000Z"


def _seed_case(database: Database, case_id: str = "case-1") -> None:
    database.writer.execute(
        "INSERT INTO cases (id, name, description, default_timezone, created_at, updated_at) "
        "VALUES (?, 'case', NULL, 'UTC', ?, ?)",
        (case_id, _ISO, _ISO),
    )


def _append(database: Database, case_id: str, action: str, detail: dict[str, Any]) -> AuditEntry:
    repository = AuditRepository(database.writer)
    return repository.append(action, case_id=case_id, detail=detail)


def _seed_log(database: Database, *, rows: int = 3) -> list[AuditEntry]:
    _seed_case(database)
    return [
        _append(database, "case-1", "source_ingested", {"source_id": f"src-{index}"})
        for index in range(rows)
    ]


def test_audit_log_newest_first_with_verification(client: Any, database: Database) -> None:
    entries = _seed_log(database, rows=3)
    response = client.get("/api/cases/case-1/audit-log")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["total"] == 3
    assert payload["limit"] == 100
    assert payload["offset"] == 0
    assert [item["id"] for item in payload["items"]] == [
        entries[2].id,
        entries[1].id,
        entries[0].id,
    ]
    first = payload["items"][0]
    assert first["ts"] == entries[2].ts
    assert first["case_id"] == "case-1"
    assert first["action"] == "source_ingested"
    assert first["detail"] == {"source_id": "src-2"}
    assert first["prev_hash"] == entries[1].hash
    assert first["hash"] == entries[2].hash
    assert payload["chain_ok"] is True
    assert payload["rows_checked"] == 3


def test_audit_log_pagination_and_order(client: Any, database: Database) -> None:
    entries = _seed_log(database, rows=5)
    response = client.get("/api/cases/case-1/audit-log?limit=2&offset=1")
    assert response.status_code == 200, response.text
    assert [item["id"] for item in response.json()["items"]] == [entries[3].id, entries[2].id]
    response = client.get("/api/cases/case-1/audit-log?limit=10&order=asc")
    assert response.status_code == 200, response.text
    assert [item["id"] for item in response.json()["items"]] == [
        entries[index].id for index in range(5)
    ]
    response = client.get("/api/cases/case-1/audit-log?order=sideways")
    assert response.status_code == 422, response.text
    body = response.json()["error"]
    assert body["code"] == "VALIDATION_ERROR"
    assert "unsupported order" in body["message"]


def test_audit_log_scopes_to_the_case(client: Any, database: Database) -> None:
    _seed_log(database, rows=2)
    _seed_case(database, case_id="case-2")
    _append(database, "case-2", "case_created", {})
    response = client.get("/api/cases/case-1/audit-log")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["total"] == 2
    assert payload["chain_ok"] is True
    assert all(item["case_id"] == "case-1" for item in payload["items"])


def test_audit_log_reports_a_broken_chain(client: Any, database: Database) -> None:
    _seed_log(database, rows=2)
    forged = {
        "ts": _ISO,
        "case_id": "case-1",
        "action": "tampered",
        "detail": canonical_detail({}),
    }
    fake_prev = "deadbeef"
    cursor = database.writer.execute(
        "INSERT INTO audit_log (ts, case_id, action, detail_json, prev_hash, hash) "
        "VALUES (?, ?, ?, ?, ?, audit_hash(?, ?, ?, ?))",
        (
            forged["ts"],
            forged["case_id"],
            forged["action"],
            forged["detail"],
            fake_prev,
            fake_prev,
            forged["ts"],
            forged["action"],
            forged["detail"],
        ),
    )
    forged_id = int(cursor.lastrowid or 0)
    response = client.get("/api/cases/case-1/audit-log")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["total"] == 3
    assert payload["chain_ok"] is False
    assert payload["broken_at"] == forged_id
    assert "prev_hash does not match" in payload["broken_reason"]
    assert payload["items"][0]["id"] == forged_id


def test_audit_log_reports_recomputed_hash_mismatch(client: Any, database: Database) -> None:
    (entry,) = _seed_log(database, rows=1)
    cursor = database.writer.execute(
        "INSERT INTO audit_log (ts, case_id, action, detail_json, prev_hash, hash) "
        "VALUES (?, 'case-1', 'tampered', '{}', ?, '00000000')",
        (_ISO, entry.hash),
    )
    forged_id = int(cursor.lastrowid or 0)
    payload = client.get("/api/cases/case-1/audit-log").json()
    assert payload["chain_ok"] is False
    assert payload["broken_at"] == forged_id


def test_audit_log_missing_case_404(client: Any, database: Database) -> None:
    response = client.get("/api/cases/nope/audit-log")
    assert response.status_code == 404, response.text
    assert response.json()["error"]["code"] == "NOT_FOUND"
