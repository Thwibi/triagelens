"""Case and source deletion: audit rows, tombstone, and file removal.

Spec 06 says ``DELETE /cases/{id}`` cascades and returns ``204``; spec 10 section
2 requires the case's chain head to be anchored in ``audit_tombstones`` and spec
02 section 4 requires the case directory to be removed; deleting a source writes
a ``source_deleted`` audit row.
"""

from __future__ import annotations

import io
import sqlite3
from pathlib import Path

from fastapi.testclient import TestClient

from app.config import Settings

SYSLOG = b"Jan  1 00:00:00 host app[1]: hello\n"


def _create_case(client: TestClient) -> str:
    response = client.post("/api/cases", json={"name": "to delete"})
    assert response.status_code == 201, response.text
    return str(response.json()["id"])


def _upload(client: TestClient, case_id: str) -> dict[str, object]:
    response = client.post(
        f"/api/cases/{case_id}/sources",
        files=[("files", ("syslog.txt", io.BytesIO(SYSLOG), "text/plain"))],
    )
    assert response.status_code == 202, response.text
    body: dict[str, object] = response.json()
    return body


def _rows(settings: Settings, sql: str, params: tuple[object, ...] = ()) -> list[sqlite3.Row]:
    connection = sqlite3.connect(str(settings.db_path))
    connection.row_factory = sqlite3.Row
    try:
        return list(connection.execute(sql, params).fetchall())
    finally:
        connection.close()


class TestDeleteCase:
    def test_delete_returns_204_and_the_case_is_gone(self, client: TestClient) -> None:
        case_id = _create_case(client)
        response = client.delete(f"/api/cases/{case_id}")
        assert response.status_code == 204, response.text
        assert client.get(f"/api/cases/{case_id}").status_code == 404

    def test_delete_writes_an_audit_entry_and_a_tombstone(
        self, client: TestClient, settings: Settings
    ) -> None:
        case_id = _create_case(client)
        client.delete(f"/api/cases/{case_id}")

        entries = _rows(
            settings,
            "SELECT action, case_id FROM audit_log WHERE action = 'case_deleted'",
        )
        assert len(entries) == 1
        assert entries[0]["case_id"] == case_id

        tombstones = _rows(
            settings,
            "SELECT case_id, last_hash, row_count FROM audit_tombstones WHERE case_id = ?",
            (case_id,),
        )
        assert len(tombstones) == 1
        assert len(str(tombstones[0]["last_hash"])) == 64
        # One row: the case_deleted entry written just before the tombstone.
        assert tombstones[0]["row_count"] >= 1

    def test_delete_removes_the_case_directory(
        self, client: TestClient, settings: Settings
    ) -> None:
        case_id = _create_case(client)
        case_dir = settings.cases_dir / case_id
        case_dir.mkdir(parents=True, exist_ok=True)
        (case_dir / "original.bin").write_bytes(b"evidence")

        client.delete(f"/api/cases/{case_id}")
        assert not case_dir.exists()

    def test_delete_of_an_unknown_case_is_404(self, client: TestClient) -> None:
        assert client.delete("/api/cases/does-not-exist").status_code == 404


class TestDeleteSource:
    def test_delete_writes_a_source_deleted_audit_entry(
        self, client: TestClient, settings: Settings
    ) -> None:
        case_id = _create_case(client)
        body = _upload(client, case_id)
        sources = body["sources"]
        assert isinstance(sources, list)
        assert sources
        source_id = str(sources[0]["id"])

        response = client.delete(f"/api/sources/{source_id}")
        assert response.status_code == 200, response.text

        entries = _rows(
            settings,
            "SELECT action, case_id FROM audit_log WHERE action = 'source_deleted'",
        )
        assert len(entries) == 1
        assert entries[0]["case_id"] == case_id
        assert not Path(str(settings.cases_dir / case_id / "sources" / source_id)).exists()
