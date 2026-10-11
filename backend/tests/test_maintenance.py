"""Data-maintenance endpoints (spec 10 section 5, spec 07 section 3.13).

The Settings screen's Data pane: vacuum, rebuild the FTS index, verify every
stored original still hashes to its recorded digest, and verify the audit chain.
The endpoints are exercised through the real app so the writer-thread hand-off
(and the no-transaction VACUUM) is covered, not just the SQL.
"""

from __future__ import annotations

import io
import sqlite3
from pathlib import Path

from fastapi.testclient import TestClient

from app.config import Settings

SYSLOG = b"Jan  1 00:00:00 host app[1]: hello\nJan  1 00:00:01 host app[1]: world\n"

_UPLOAD_MEDIA = "text/plain"


def _create_case(client: TestClient) -> str:
    response = client.post("/api/cases", json={"name": "maintenance"})
    assert response.status_code == 201, response.text
    return str(response.json()["id"])


def _upload(client: TestClient, case_id: str, payload: bytes = SYSLOG) -> dict[str, object]:
    response = client.post(
        f"/api/cases/{case_id}/sources",
        files=[("files", ("syslog.txt", io.BytesIO(payload), _UPLOAD_MEDIA))],
    )
    assert response.status_code == 202, response.text
    body: dict[str, object] = response.json()
    return body


def _stored_path(settings: Settings) -> Path:
    connection = sqlite3.connect(str(settings.db_path))
    try:
        row = connection.execute("SELECT stored_path FROM sources LIMIT 1").fetchone()
    finally:
        connection.close()
    assert row is not None, "the upload created no source row"
    return Path(str(row[0]))


class TestVerifyHashes:
    def test_intact_evidence_reports_ok(self, client: TestClient) -> None:
        case_id = _create_case(client)
        _upload(client, case_id)

        response = client.post("/api/maintenance/verify-hashes")
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["ok"] is True
        assert body["checked"] >= 1
        assert body["mismatched"] == []
        assert body["missing"] == []

    def test_a_changed_file_is_reported(self, client: TestClient, settings: Settings) -> None:
        case_id = _create_case(client)
        _upload(client, case_id)
        path = _stored_path(settings)
        # Stored originals are read-only; restore the write bit to tamper.
        path.chmod(0o600)
        with path.open("ab") as handle:
            handle.write(b"\ntampered\n")

        response = client.post("/api/maintenance/verify-hashes")
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["ok"] is False
        assert len(body["mismatched"]) == 1
        assert body["mismatched"][0]["path"] == str(path)

    def test_a_missing_file_is_reported(self, client: TestClient, settings: Settings) -> None:
        case_id = _create_case(client)
        _upload(client, case_id)
        path = _stored_path(settings)
        path.chmod(0o600)
        path.unlink()

        response = client.post("/api/maintenance/verify-hashes")
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["ok"] is False
        assert len(body["missing"]) == 1


class TestRebuildFts:
    def test_rebuild_indexes_the_stored_events(self, client: TestClient) -> None:
        case_id = _create_case(client)
        _upload(client, case_id)

        response = client.post("/api/maintenance/rebuild-fts")
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["ok"] is True
        assert body["indexed"] >= 0


class TestVacuum:
    def test_vacuum_reports_before_and_after(self, client: TestClient) -> None:
        _create_case(client)
        response = client.post("/api/maintenance/vacuum")
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["ok"] is True
        assert body["db_bytes_before"] >= 0
        assert body["db_bytes_after"] >= 0


class TestVerifyAudit:
    def test_empty_chain_verifies(self, client: TestClient) -> None:
        response = client.post("/api/maintenance/verify-audit")
        assert response.status_code == 200, response.text
        assert response.json()["chain_ok"] is True
