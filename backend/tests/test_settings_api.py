"""Settings API tests (spec 06 "Health and settings", spec 05 section 5).

Covers the effective-config read, the analyst override update with its audit row,
and the global allowlist CRUD. The audit rows are read straight off the writer
connection because a ``settings_changed`` row is global (``case_id`` is NULL) and
so never appears in a case-scoped audit page.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from app.config import Settings
from app.db.connection import Database
from app.main import create_app


def _audit_actions(database: Database) -> list[tuple[str, dict[str, Any]]]:
    rows = database.writer.execute(
        "SELECT action, detail_json FROM audit_log ORDER BY id"
    ).fetchall()
    return [(row["action"], json.loads(row["detail_json"])) for row in rows]


def test_get_settings_is_the_effective_config(client: TestClient) -> None:
    response = client.get("/api/settings")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["overrides"] == {}
    assert payload["allowlist"] == []
    effective = payload["settings"]
    assert effective["detection"]["profile"] == "standard"
    assert effective["limits"]["max_upload_gb"] == 10
    assert effective["server"]["auth_token"] == ""
    assert effective["server"]["host"] == "127.0.0.1"


def test_get_settings_masks_a_configured_token(data_dir: Path) -> None:
    settings = Settings(
        server={"host": "127.0.0.1", "port": 8787, "auth_token": "0123456789abcdef"},
        storage={"data_dir": str(data_dir)},
        logging={"console": False, "level": "CRITICAL"},
        detection={"sync_rules_on_startup": False},
    )
    with TestClient(create_app(settings), base_url="http://127.0.0.1:8787") as client:
        response = client.get("/api/settings")
        assert response.status_code == 200, response.text
        assert response.json()["settings"]["server"]["auth_token"] == "***redacted***"


def test_put_settings_persists_an_override_and_audits(
    client: TestClient, database: Database
) -> None:
    response = client.put("/api/settings", json={"values": {"detection.profile": "full"}})
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["overrides"] == {"detection.profile": "full"}
    assert payload["settings"]["detection"]["profile"] == "full"
    actions = _audit_actions(database)
    assert [action for action, _ in actions] == ["settings_changed"]
    assert actions[0][1]["keys"] == ["detection.profile"]

    follow_up = client.get("/api/settings").json()
    assert follow_up["settings"]["detection"]["profile"] == "full"


def test_put_settings_rejects_an_unknown_key(client: TestClient, database: Database) -> None:
    response = client.put("/api/settings", json={"values": {"detection.nope": 1}})
    assert response.status_code == 422, response.text
    body = response.json()["error"]
    assert body["code"] == "VALIDATION_ERROR"
    assert body["details"]["key"] == "detection.nope"
    assert _audit_actions(database) == []


def test_put_settings_rejects_an_empty_update(client: TestClient) -> None:
    response = client.put("/api/settings", json={"values": {}})
    assert response.status_code == 422, response.text
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


def test_put_settings_rejects_an_invalid_profile(client: TestClient) -> None:
    response = client.put("/api/settings", json={"values": {"detection.profile": "nope"}})
    assert response.status_code == 422, response.text
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


def test_detect_uses_a_stored_profile_override(client: TestClient, database: Database) -> None:
    database.writer.execute(
        "INSERT INTO cases (id, name, description, default_timezone, created_at, updated_at) "
        "VALUES ('case-1', 'case', NULL, 'UTC', '2026-01-01T00:00:00.000Z', "
        "'2026-01-01T00:00:00.000Z')"
    )
    client.put("/api/settings", json={"values": {"detection.profile": "fast"}})
    response = client.post("/api/cases/case-1/detect", json={})
    assert response.status_code == 202, response.text
    assert "detection (fast)" in response.json()["message"]


def test_allowlist_create_list_and_delete(client: TestClient, database: Database) -> None:
    created = client.post(
        "/api/settings/allowlist",
        json={"kind": "domain", "value": "example.com", "note": "docs"},
    )
    assert created.status_code == 201, created.text
    entry = created.json()
    assert entry["scope"] == "global"
    assert entry["case_id"] is None
    assert entry["kind"] == "domain"
    assert entry["value"] == "example.com"
    assert entry["note"] == "docs"

    # A repeat add is idempotent per (kind, value): the same row comes back.
    again = client.post("/api/settings/allowlist", json={"kind": "domain", "value": "example.com"})
    assert again.status_code == 201, again.text
    assert again.json()["id"] == entry["id"]

    listing = client.get("/api/settings/allowlist").json()
    assert listing["total"] == 1
    assert listing["items"][0]["id"] == entry["id"]

    deleted = client.delete(f"/api/settings/allowlist/{entry['id']}")
    assert deleted.status_code == 200, deleted.text
    assert deleted.json() == {"id": entry["id"], "deleted": True}
    assert client.get("/api/settings/allowlist").json()["items"] == []

    actions = [action for action, _ in _audit_actions(database)]
    assert actions == ["allowlist_changed", "allowlist_changed"]


def test_allowlist_rejects_an_unknown_kind(client: TestClient) -> None:
    response = client.post("/api/settings/allowlist", json={"kind": "nope", "value": "x"})
    assert response.status_code == 422, response.text
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


def test_allowlist_delete_missing_is_404(client: TestClient) -> None:
    response = client.delete("/api/settings/allowlist/999")
    assert response.status_code == 404, response.text
    assert response.json()["error"]["code"] == "NOT_FOUND"
