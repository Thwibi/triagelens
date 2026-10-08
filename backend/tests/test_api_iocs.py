"""IOC and entity API endpoints (spec 06 "Indicators and entities").

Every test ingests a real NDJSON file through the pipeline so the rows exist as
they would in production, then exercises the HTTP surface on top.
"""

from __future__ import annotations

import io
import json
import time
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.db.connection import Database
from app.main import create_app

JOB_TIMEOUT_SECONDS = 60.0
TERMINAL = {"done", "failed", "cancelled", "needs_input"}


@pytest.fixture
def client(settings: Settings) -> Iterator[TestClient]:
    with TestClient(create_app(settings), base_url="http://127.0.0.1:8787") as test_client:
        yield test_client


def _new_case(client: TestClient) -> str:
    response = client.post("/api/cases", json={"name": "acceptance"})
    assert response.status_code == 201, response.text
    return str(response.json()["id"])


def ioc_ndjson() -> str:
    """Three ECS events carrying tier-1 indicators of every relevant type."""
    records = [
        {
            "@timestamp": "2024-01-01T00:00:00.000Z",
            "ecs": {"version": "8.11.0"},
            "host": {"name": "web-01"},
            "user": {"name": "alice"},
            "source": {"ip": "203.0.113.9", "port": 41111},
            "event": {"category": "network", "action": "connect"},
            "message": "blocked contact to admin@evil.com at "
            "http://evil.com/payload.exe from 203.0.113.9",
        },
        {
            "@timestamp": "2024-01-01T00:00:01.000Z",
            "ecs": {"version": "8.11.0"},
            "host": {"name": "web-02"},
            "destination": {"ip": "203.0.113.10"},
            "message": "downloaded file with sha256 "
            "aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffff0000000011111111 "
            "from evil.com",
        },
        {
            "@timestamp": "2024-01-01T00:00:02.000Z",
            "ecs": {"version": "8.11.0"},
            "host": {"name": "web-01"},
            "source": {"ip": "10.0.0.5"},
            "message": "connect from 10.0.0.5 to 198.51.100.7 via https://scanme.example.com/x",
        },
    ]
    return "".join(json.dumps(record) + "\n" for record in records)


def ingest_iocs(client: TestClient, case_id: str) -> None:
    """Upload the IOC fixture and wait for the parse to land."""
    form = [
        ("files", ("iocs.ndjson", io.BytesIO(ioc_ndjson().encode()), "application/octet-stream"))
    ]
    response = client.post(f"/api/cases/{case_id}/sources", files=form)
    assert response.status_code == 202, response.text
    body: dict[str, Any] = response.json()
    job_id = str(body["jobs"][0]["id"])
    deadline = time.monotonic() + JOB_TIMEOUT_SECONDS
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        poll = client.get(f"/api/jobs/{job_id}")
        assert poll.status_code == 200, poll.text
        last = poll.json()
        if last["status"] in TERMINAL:
            break
        time.sleep(0.05)
    assert last["status"] == "done", f"job ended {last!r}"


@pytest.fixture
def case_id(client: TestClient) -> str:
    """A case with the IOC fixture ingested and the parse finished."""
    case_id = _new_case(client)
    ingest_iocs(client, case_id)
    return case_id


def _iocs(client: TestClient, case_id: str, **params: Any) -> dict[str, Any]:
    response = client.get(f"/api/cases/{case_id}/iocs", params=params)
    assert response.status_code == 200, response.text
    return response.json()


def _ioc_by_type(client: TestClient, case_id: str, ioc_type: str) -> list[dict[str, Any]]:
    payload = _iocs(client, case_id, type=ioc_type, include_private=True, include_allowlisted=True)
    return [item for item in payload["items"] if item["type"] == ioc_type]


class TestListIocs:
    def test_the_fixture_yields_every_expected_type(self, client: TestClient, case_id: str) -> None:
        payload = _iocs(client, case_id, include_private=True, include_allowlisted=True)
        types = {item["type"] for item in payload["items"]}
        assert {"ipv4", "domain", "url", "email", "sha256"} <= types
        envelope_fields = {"items", "total", "limit", "offset"} <= set(payload)
        assert envelope_fields

    def test_items_have_the_spec_detail_fields(self, client: TestClient, case_id: str) -> None:
        item = _iocs(client, case_id)["items"][0]
        for field in (
            "id",
            "case_id",
            "type",
            "value",
            "value_norm",
            "first_seen_ms",
            "last_seen_ms",
            "occurrences",
            "confidence",
            "is_private",
            "is_allowlisted",
            "analyst_state",
            "tags",
        ):
            assert field in item, f"{field} missing from {sorted(item)}"

    def test_private_iocs_are_hidden_by_default(self, client: TestClient, case_id: str) -> None:
        default = _iocs(client, case_id)
        values = {item["value_norm"] for item in default["items"]}
        assert "10.0.0.5" not in values
        with_private = _iocs(client, case_id, include_private=True)
        values = {item["value_norm"] for item in with_private["items"]}
        assert "10.0.0.5" in values

    def test_allowlisted_iocs_are_hidden_by_default(self, client: TestClient, case_id: str) -> None:
        default = {item["value"] for item in _iocs(client, case_id)["items"]}
        assert not any("scanme.example.com" in value for value in default)
        with_allowlisted = {
            item["value"] for item in _iocs(client, case_id, include_allowlisted=True)["items"]
        }
        assert any("scanme.example.com" in value for value in with_allowlisted)

    def test_type_and_min_confidence_filters(self, client: TestClient, case_id: str) -> None:
        assert {item["type"] for item in _ioc_by_type(client, case_id, "domain")} == {"domain"}
        payload = _iocs(client, case_id, min_confidence=80)
        assert all(item["confidence"] >= 80 for item in payload["items"])
        assert payload["items"]

    def test_unknown_type_is_a_validation_error(self, client: TestClient, case_id: str) -> None:
        response = client.get(f"/api/cases/{case_id}/iocs", params={"type": "bogus"})
        assert response.status_code == 422

    def test_q_matches_a_value_substring(self, client: TestClient, case_id: str) -> None:
        payload = _iocs(client, case_id, q="evil.com")
        for item in payload["items"]:
            assert "evil.com" in item["value"] or "evil.com" in item["value_norm"]
        assert payload["items"]

    def test_host_filter_restricts_to_one_host(self, client: TestClient, case_id: str) -> None:
        payload = _iocs(client, case_id, host="web-02")
        assert payload["items"]
        seen_on_web_02 = {
            "203.0.113.10",
            "evil.com",
            "aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffff0000000011111111",
        }
        for item in payload["items"]:
            assert item["value_norm"] in seen_on_web_02

    def test_occurrences_and_value_sorts_are_stable(self, client: TestClient, case_id: str) -> None:
        by_occurrences = _iocs(client, case_id, sort="occurrences", order="desc")["items"]
        counts = [item["occurrences"] for item in by_occurrences]
        assert counts == sorted(counts, reverse=True)
        by_value = _iocs(client, case_id, sort="value", order="asc")["items"]
        values = [item["value_norm"] for item in by_value]
        assert values == sorted(values)


class TestIocDetail:
    def test_get_ioc_returns_an_occurrence_preview(self, client: TestClient, case_id: str) -> None:
        item = _ioc_by_type(client, case_id, "ipv4")[0]
        response = client.get(f"/api/iocs/{item['id']}")
        assert response.status_code == 200, response.text
        detail = response.json()
        assert detail["id"] == item["id"]
        assert detail["type"] == "ipv4"
        preview_fields = {"event_id", "field", "role", "ts_ms", "host"}
        assert preview_fields <= set(detail["occurrences_preview"][0])

    def test_occurrences_are_newest_first(self, client: TestClient, case_id: str) -> None:
        item = _ioc_by_type(client, case_id, "domain")[0]
        body = client.get(f"/api/iocs/{item['id']}/occurrences").json()
        stamps = [row["ts_ms"] for row in body["items"]]
        assert stamps == sorted(stamps, reverse=True)

    def test_unknown_ioc_is_404(self, client: TestClient, case_id: str) -> None:
        response = client.get("/api/iocs/does-not-exist")
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "NOT_FOUND"


class TestPatchIoc:
    def test_setting_an_analyst_verdict_persists(self, client: TestClient, case_id: str) -> None:
        item = _ioc_by_type(client, case_id, "domain")[0]
        response = client.patch(
            f"/api/iocs/{item['id']}",
            json={"analyst_state": "malicious", "tags": ["phishing", "campaign-blue"]},
        )
        assert response.status_code == 200, response.text
        updated = response.json()
        assert updated["analyst_state"] == "malicious"
        assert updated["tags"] == ["phishing", "campaign-blue"]
        again = client.get(f"/api/iocs/{item['id']}").json()
        assert again["analyst_state"] == "malicious"
        assert again["tags"] == ["phishing", "campaign-blue"]

    def test_state_filter_targets_the_updated_ioc(self, client: TestClient, case_id: str) -> None:
        item = _ioc_by_type(client, case_id, "email")[0]
        client.patch(f"/api/iocs/{item['id']}", json={"analyst_state": "suspicious"})
        payload = _iocs(client, case_id, state="suspicious")
        assert any(i["id"] == item["id"] for i in payload["items"])

    def test_allowlist_requires_benign(self, client: TestClient, case_id: str) -> None:
        item = _ioc_by_type(client, case_id, "domain")[0]
        response = client.patch(
            f"/api/iocs/{item['id']}", json={"analyst_state": "malicious", "allowlist": True}
        )
        assert response.status_code == 422

    def test_patching_a_missing_ioc_is_404(self, client: TestClient, case_id: str) -> None:
        response = client.patch("/api/iocs/nope", json={"analyst_state": "benign"})
        assert response.status_code == 404

    def test_benign_with_allowlist_writes_a_case_entry(
        self, client: TestClient, case_id: str, database: Database
    ) -> None:
        item = _ioc_by_type(client, case_id, "domain")[0]
        response = client.patch(
            f"/api/iocs/{item['id']}",
            json={"analyst_state": "benign", "allowlist": True},
        )
        assert response.status_code == 200, response.text
        with database.read_connection() as connection:
            rows = connection.execute(
                "SELECT scope, kind, value FROM allowlist WHERE case_id = ?",
                (case_id,),
            ).fetchall()
        assert ("case", "domain", item["value_norm"]) in {(row[0], row[1], row[2]) for row in rows}


class TestExport:
    def test_csv_has_the_spec_header(self, client: TestClient, case_id: str) -> None:
        response = client.post(f"/api/cases/{case_id}/iocs/export", json={"format": "csv"})
        assert response.status_code == 200, response.text
        disposition = response.headers["content-disposition"]
        assert '.csv"' in disposition
        assert f"iocs-{case_id}" in disposition
        lines = response.text.splitlines()
        assert lines[0].startswith("type,value,confidence,occurrences,first_seen,last_seen")
        assert len(lines) > 1

    def test_txt_defangs_and_lists_one_value_per_line(
        self, client: TestClient, case_id: str
    ) -> None:
        response = client.post(
            f"/api/cases/{case_id}/iocs/export", json={"format": "txt", "defang": True}
        )
        assert response.status_code == 200, response.text
        body = response.text
        assert "hxxp" in body
        lines = body.splitlines()
        assert lines
        assert all(lines)

    def test_txt_excludes_private_by_default(self, client: TestClient, case_id: str) -> None:
        response = client.post(f"/api/cases/{case_id}/iocs/export", json={"format": "txt"})
        assert "10.0.0.5" not in response.text

    def test_stix_is_a_bundle_of_indicators(self, client: TestClient, case_id: str) -> None:
        response = client.post(
            f"/api/cases/{case_id}/iocs/export",
            json={"format": "stix", "filters": {"type": "ipv4"}},
        )
        assert response.status_code == 200, response.text
        bundle = response.json()
        assert bundle["type"] == "bundle"
        assert bundle["spec_version"] == "2.1"
        indicators = [obj for obj in bundle["objects"] if obj["type"] == "indicator"]
        assert indicators
        assert "[ipv4-addr:value = '203.0.113.9']" in {obj["pattern"] for obj in indicators}

    def test_json_is_the_full_record_list(self, client: TestClient, case_id: str) -> None:
        response = client.post(f"/api/cases/{case_id}/iocs/export", json={"format": "json"})
        assert response.status_code == 200, response.text
        items = response.json()
        assert items
        assert {"id", "case_id", "type", "value", "confidence", "occurrences"} <= set(items[0])

    def test_export_by_ids_only_selected_rows(self, client: TestClient, case_id: str) -> None:
        ids = [
            item["id"]
            for item in _ioc_by_type(client, case_id, "ipv4")
            if item["value_norm"].startswith("203.0.113")
        ]
        response = client.post(
            f"/api/cases/{case_id}/iocs/export", json={"format": "txt", "ids": ids}
        )
        assert response.status_code == 200, response.text
        exported = [line for line in response.text.splitlines() if line]
        assert len(exported) == len(ids)
        assert all("203.0.113" in line for line in exported)

    def test_export_unknown_format_is_422(self, client: TestClient, case_id: str) -> None:
        response = client.post(f"/api/cases/{case_id}/iocs/export", json={"format": "xlsx"})
        assert response.status_code == 422

    def test_export_rejects_iocs_from_another_case(self, client: TestClient, case_id: str) -> None:
        other_case = _new_case(client)
        ingest_iocs(client, other_case)
        foreign = _ioc_by_type(client, other_case, "domain")[0]
        response = client.post(
            f"/api/cases/{case_id}/iocs/export",
            json={"format": "txt", "ids": [foreign["id"]]},
        )
        assert response.status_code == 422


class TestEntities:
    def test_hosts_and_users_carry_event_counts(self, client: TestClient, case_id: str) -> None:
        response = client.get(f"/api/cases/{case_id}/entities")
        assert response.status_code == 200, response.text
        entities = response.json()
        hosts = {entity["name"] for entity in entities if entity["kind"] == "host"}
        assert {"web-01", "web-02"} <= hosts
        users = {entity["name"] for entity in entities if entity["kind"] == "user"}
        assert "alice" in users
        web_01 = next(e for e in entities if e["kind"] == "host" and e["name"] == "web-01")
        assert web_01["event_count"] == 2
