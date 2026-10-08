"""Mapping-profile API: list, inspect, save, import, delete, preview.

The generic parsers are only usable through a profile, so these endpoints are
how an operator adds a format the build does not know. The shipped profiles are
read-only and a user profile may shadow one by name; these tests pin that a
built-in can be read but never written or deleted, that validation rejects a bad
profile before anything lands on disk, and that a preview renders a sample
without touching the case store.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.ingest.parsers.generic_common import USER_PROFILES_ENV, invalidate_profile_cache

_PROFILE_YAML = (
    "name: custom-one\n"
    "timestamp:\n"
    "  path: ts\n"
    "  format: iso8601\n"
    "timezone: UTC\n"
    "fields:\n"
    "  host: host\n"
    "  src_ip: src\n"
)


@pytest.fixture
def user_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Point the user-profile directory at a scratch dir for one test."""
    directory = tmp_path / "user-profiles"
    monkeypatch.setenv(USER_PROFILES_ENV, str(directory))
    invalidate_profile_cache()
    try:
        yield directory
    finally:
        invalidate_profile_cache()


class TestListAndGet:
    def test_lists_shipped_profiles_as_builtin(self, client: TestClient, user_dir: Path) -> None:
        payload = client.get("/api/profiles").json()
        names = {item["name"] for item in payload["items"]}
        assert {"elastic-ecs", "zeek", "wazuh-alert"} <= names
        assert payload["total"] == len(payload["items"])
        assert all(item["builtin"] for item in payload["items"])

    def test_get_returns_the_yaml_source(self, client: TestClient, user_dir: Path) -> None:
        payload = client.get("/api/profiles/elastic-ecs").json()
        assert payload["builtin"] is True
        assert "name: elastic-ecs" in payload["yaml"]
        assert payload["timestamp"]["path"] == "@timestamp"

    def test_get_unknown_is_404(self, client: TestClient, user_dir: Path) -> None:
        response = client.get("/api/profiles/nope")
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "NOT_FOUND"


class TestWrite:
    def test_put_creates_a_user_profile(self, client: TestClient, user_dir: Path) -> None:
        response = client.put("/api/profiles/custom-one", json={"yaml": _PROFILE_YAML})
        assert response.status_code == 200
        assert response.json()["builtin"] is False
        assert (user_dir / "custom-one.yaml").is_file()

        listing = client.get("/api/profiles").json()["items"]
        created = next(item for item in listing if item["name"] == "custom-one")
        assert created["builtin"] is False

    def test_put_replaces_an_existing_user_profile(
        self, client: TestClient, user_dir: Path
    ) -> None:
        client.put("/api/profiles/custom-one", json={"yaml": _PROFILE_YAML})
        updated = _PROFILE_YAML.replace("host: host", "host: hostname")
        response = client.put("/api/profiles/custom-one", json={"yaml": updated})
        assert response.status_code == 200
        assert response.json()["fields"]["host"] == "hostname"

    def test_put_rejects_a_name_mismatch(self, client: TestClient, user_dir: Path) -> None:
        response = client.put("/api/profiles/other-name", json={"yaml": _PROFILE_YAML})
        assert response.status_code == 422

    def test_put_rejects_an_invalid_profile(self, client: TestClient, user_dir: Path) -> None:
        response = client.put("/api/profiles/custom-one", json={"yaml": "name: x\n"})
        assert response.status_code == 422
        assert not (user_dir / "custom-one.yaml").exists()

    def test_put_rejects_a_builtin_name(self, client: TestClient, user_dir: Path) -> None:
        shadow = _PROFILE_YAML.replace("custom-one", "elastic-ecs")
        response = client.put("/api/profiles/elastic-ecs", json={"yaml": shadow})
        assert response.status_code == 409
        assert response.json()["error"]["code"] == "CONFLICT"

    def test_delete_removes_a_user_profile(self, client: TestClient, user_dir: Path) -> None:
        client.put("/api/profiles/custom-one", json={"yaml": _PROFILE_YAML})
        response = client.delete("/api/profiles/custom-one")
        assert response.status_code == 200
        assert response.json() == {"name": "custom-one", "deleted": True}
        assert client.get("/api/profiles/custom-one").status_code == 404

    def test_delete_rejects_a_builtin(self, client: TestClient, user_dir: Path) -> None:
        assert client.delete("/api/profiles/zeek").status_code == 409

    def test_delete_unknown_is_404(self, client: TestClient, user_dir: Path) -> None:
        assert client.delete("/api/profiles/missing").status_code == 404


class TestImport:
    def test_import_saves_the_uploaded_profile(self, client: TestClient, user_dir: Path) -> None:
        response = client.post(
            "/api/profiles/import",
            files={"file": ("custom-two.yaml", _PROFILE_YAML.encode("utf-8"), "text/yaml")},
        )
        assert response.status_code == 201
        assert response.json()["name"] == "custom-one"
        assert (user_dir / "custom-one.yaml").is_file()

    def test_import_honours_a_name_override(self, client: TestClient, user_dir: Path) -> None:
        renamed = _PROFILE_YAML.replace("custom-one", "custom-three")
        response = client.post(
            "/api/profiles/import",
            files={"file": ("p.yaml", renamed.encode("utf-8"), "text/yaml")},
            data={"name": "custom-three"},
        )
        assert response.status_code == 201
        assert (user_dir / "custom-three.yaml").is_file()


class TestPreview:
    _CSV_SAMPLE = "ts,host,src\n2026-03-01T10:00:00Z,web01,10.0.0.1\n"
    _JSON_SAMPLE = '{"ts":"2026-03-01T10:00:00Z","host":"web01","src":"10.0.0.1"}'

    def test_preview_csv_returns_normalized_rows(self, client: TestClient, user_dir: Path) -> None:
        response = client.post(
            "/api/profiles/preview", json={"sample": self._CSV_SAMPLE, "yaml": _PROFILE_YAML}
        )
        assert response.status_code == 200
        payload = response.json()
        assert payload["log_type"] == "generic_csv"
        assert payload["row_count"] == 1
        assert payload["rows"][0]["host"] == "web01"
        assert payload["rows"][0]["src_ip"] == "10.0.0.1"

    def test_preview_detects_json(self, client: TestClient, user_dir: Path) -> None:
        response = client.post(
            "/api/profiles/preview", json={"sample": self._JSON_SAMPLE, "yaml": _PROFILE_YAML}
        )
        assert response.json()["log_type"] == "generic_json"
        assert response.json()["rows"][0]["host"] == "web01"

    def test_preview_honours_an_explicit_log_type(self, client: TestClient, user_dir: Path) -> None:
        response = client.post(
            "/api/profiles/preview",
            json={
                "sample": self._CSV_SAMPLE,
                "yaml": _PROFILE_YAML,
                "log_type": "generic_csv",
            },
        )
        assert response.status_code == 200

    def test_preview_rejects_an_invalid_profile(self, client: TestClient, user_dir: Path) -> None:
        response = client.post(
            "/api/profiles/preview", json={"sample": self._CSV_SAMPLE, "yaml": "name: x\n"}
        )
        assert response.status_code == 422

    def test_preview_reports_parse_errors(self, client: TestClient, user_dir: Path) -> None:
        profile = _PROFILE_YAML + "  dst_ip: dst\n"
        sample = "ts,host,src,dst\n2026-03-01T10:00:00Z,web01,10.0.0.1\n"
        response = client.post("/api/profiles/preview", json={"sample": sample, "yaml": profile})
        payload = response.json()
        assert payload["error_count"] == 1
        assert payload["errors"][0]["record_ref"] == "line:2"
