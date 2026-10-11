"""Alerts, rules and MITRE API tests (spec 06, spec 09 API tests).

The alerts suite drives a real detection run so the stored alert matches
what the engine produces; the rules suite exercises the catalogue CRUD,
validate/test/export/import paths; the MITRE suite loads a miniature STIX
bundle and queries the matrix, technique detail and navigator layer.
"""

from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

import yaml

from app.db.connection import Database
from app.mitre.loader import load_bundle

_TS = 1_700_000_000_000
_ISO = "2026-01-01T00:00:00.000Z"

_RULE_UUID = "00000000-1111-2222-3333-444444444444"

_RULE_BODY = {
    "title": "SSH Failed Password",
    "id": _RULE_UUID,
    "status": "stable",
    "logsource": {"product": "linux", "service": "sshd"},
    "detection": {
        "selection": {"event_action": ["ssh_failed_password", "ssh_invalid_user"]},
        "condition": "selection",
    },
    "level": "high",
}

_CUSTOM_UUID = "11111111-2222-3333-4444-555555555555"
_ADHOC_UUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
_IMPORTED_UUID = "99999999-8888-7777-6666-555555555555"
_V2_UUID = "12121212-3434-5656-7878-909090909090"


def _seed_case(database: Database) -> None:
    database.writer.execute(
        "INSERT INTO cases (id, name, description, default_timezone, created_at, updated_at) "
        "VALUES ('case-1', 'scene', NULL, 'UTC', ?, ?)",
        (_ISO, _ISO),
    )


def _seed_scene(database: Database) -> None:
    """A case with one Linux auth source and 14 failed-ssh events."""
    _seed_case(database)
    database.writer.execute(
        "INSERT INTO sources (id, case_id, filename, stored_path, size_bytes, sha256, "
        "status, ingested_at) VALUES ('src-1', 'case-1', 'auth.log', '/tmp/auth.log', 0, "
        "'deadbeef', 'done', ?)",
        (_ISO,),
    )
    database.writer.execute(
        "INSERT INTO source_inventory (source_id, log_type, channel, app_name, "
        "ls_category, event_count) VALUES ('src-1', 'linux_auth', '', 'sshd', '', 14)"
    )
    for index in range(14):
        database.writer.execute(
            "INSERT INTO events (case_id, source_id, record_ref, ts_ms, ts_iso, "
            "log_type, ls_category, host, channel, app_name, user_name, message, "
            "raw, event_action, src_ip, fields_json, event_id) "
            "VALUES ('case-1', 'src-1', ?, ?, NULL, 'linux_auth', '', 'web01', '', "
            "'sshd', 'victim', '', '{}', 'ssh_failed_password', ?, '{}', NULL)",
            (str(index), _TS + index * 1000, "198.51.100.77"),
        )


def _insert_rule(
    database: Database,
    *,
    rule_id: str = _RULE_UUID,
    tags: list[str] | None = None,
) -> None:
    document = {key: value for key, value in _RULE_BODY.items() if key != "id"}
    database.writer.execute(
        "INSERT INTO rules (id, title, kind, rule_type, level, status, enabled, yaml, "
        "tags_json, logsource_json, file_path, sha256, compile_error, unroutable, updated_at) "
        "VALUES (?, ?, 'builtin', 'detection', ?, ?, 1, ?, ?, ?, NULL, 'deadbeef', NULL, 0, ?)",
        (
            rule_id,
            _RULE_BODY["title"],
            _RULE_BODY["level"],
            _RULE_BODY["status"],
            yaml.safe_dump(document, sort_keys=False),
            json.dumps(tags or []),
            json.dumps(_RULE_BODY["logsource"]),
            _ISO,
        ),
    )


def _wait_for_terminal(client: Any, job_id: str, *, timeout: float = 10.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        response = client.get(f"/api/jobs/{job_id}")
        assert response.status_code == 200, response.text
        job = response.json()
        if job["status"] not in {"queued", "running"}:
            return job  # type: ignore[no-any-return]
        time.sleep(0.05)
    raise AssertionError(f"job {job_id} did not finish within {timeout}s")


def _detect_once(client: Any, database: Database) -> str:
    """Run a detection pass and return the created alert id."""
    _seed_scene(database)
    _insert_rule(database)
    response = client.post("/api/cases/case-1/detect", json={"profile": "full"})
    assert response.status_code == 202, response.text
    terminal = _wait_for_terminal(client, response.json()["id"])
    assert terminal["status"] == "done", terminal
    row = database.writer.execute("SELECT id FROM alerts WHERE case_id = 'case-1'").fetchone()
    assert row is not None
    return str(row["id"])


def _store_tier1_ips(database: Database) -> None:
    """Store the scene's source IP exactly as the parse worker would (spec 05 §3)."""
    from app.db.repositories.iocs import IocRepository
    from app.ioc import IocType, aggregate, default_allowlist, extract_fields

    rows = database.writer.execute(
        "SELECT id, ts_ms, src_ip FROM events WHERE case_id = 'case-1' ORDER BY id"
    ).fetchall()
    records = [
        (
            int(row["id"]),
            row["ts_ms"],
            extract_fields(
                {"src_ip": str(row["src_ip"])},
                allowlist=default_allowlist(),
                types=frozenset({IocType.IPV4}),
            ),
        )
        for row in rows
    ]
    IocRepository(database.writer).store("case-1", aggregate(records))


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------


def test_alerts_list_detail_patch(client: Any, database: Database) -> None:  # noqa: PLR0915
    """List, detail, evidence, analyst verdict and audit for one alert."""
    alert_id = _detect_once(client, database)

    listing = client.get("/api/cases/case-1/alerts")
    assert listing.status_code == 200, listing.text
    payload = listing.json()
    assert payload["total"] == 1
    item = payload["items"][0]
    assert item["id"] == alert_id
    assert item["case_id"] == "case-1"
    assert item["rule_id"] == _RULE_UUID
    assert item["rule_title"] == "SSH Failed Password"
    assert item["level"] == "high"
    assert item["score"] == 75
    assert item["status"] == "new"
    assert item["host"] == "web01"
    assert item["user_name"] == "victim"
    assert item["match_count"] == 14
    assert item["tactics"] == []
    assert item["techniques"] == []
    assert item["unresolved_tags"] == []

    filtered = client.get("/api/cases/case-1/alerts?level=high&unmapped=true&min_score=70")
    assert filtered.json()["total"] == 1
    filtered = client.get("/api/cases/case-1/alerts?min_score=80")
    assert filtered.json()["total"] == 0
    filtered = client.get("/api/cases/case-1/alerts?status=triaged")
    assert filtered.json()["total"] == 0

    detail = client.get(f"/api/alerts/{alert_id}")
    assert detail.status_code == 200, detail.text
    detail_body = detail.json()
    assert detail_body["score"] == 75
    assert {"label": "base", "delta": 70} in detail_body["score_breakdown"]
    assert any(
        entry["label"].startswith("match_volume") for entry in detail_body["score_breakdown"]
    )
    assert len(detail_body["events"]) == 14
    assert detail_body["iocs"] == []
    assert detail_body["rule"]["id"] == _RULE_UUID
    assert "ssh_failed_password" in detail_body["rule"]["yaml"]

    evidence = client.get(f"/api/alerts/{alert_id}/events")
    assert evidence.status_code == 200, evidence.text
    evidence_body = evidence.json()
    assert evidence_body["total"] == 14
    assert len(evidence_body["items"]) == 14
    assert "raw" not in evidence_body["items"][0]

    verdict = client.patch(
        f"/api/alerts/{alert_id}",
        json={"status": "true_positive", "analyst_notes": "brute force confirmed"},
    )
    assert verdict.status_code == 200, verdict.text
    assert verdict.json()["item"]["status"] == "true_positive"
    assert verdict.json()["item"]["analyst_notes"] == "brute force confirmed"

    detail_after = client.get(f"/api/alerts/{alert_id}").json()
    assert detail_after["status"] == "true_positive"
    assert detail_after["analyst_notes"] == "brute force confirmed"

    bad_verdict = client.patch(f"/api/alerts/{alert_id}", json={"status": "new"})
    assert bad_verdict.status_code == 422

    actions = {
        str(row["action"])
        for row in database.writer.execute(
            "SELECT action FROM audit_log WHERE case_id = 'case-1'"
        ).fetchall()
    }
    assert {"alert_status", "alert_notes"} <= actions


def test_alerts_bulk_update(client: Any, database: Database) -> None:
    """Bulk status update touches every id and audit-logs once."""
    alert_id = _detect_once(client, database)

    response = client.post("/api/alerts/bulk", json={"ids": [alert_id], "status": "triaged"})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["updated"] == 1
    assert body["items"][0]["status"] == "triaged"

    assert client.get(f"/api/alerts/{alert_id}").json()["status"] == "triaged"
    bad = client.post("/api/alerts/bulk", json={"ids": [alert_id], "status": "new"})
    assert bad.status_code == 422
    missing = client.post("/api/alerts/bulk", json={"ids": ["nope"], "status": "triaged"})
    assert missing.status_code == 404

    bad_sort = client.get("/api/cases/case-1/alerts?sort=-score2")
    assert bad_sort.status_code == 422
    bad_level = client.get("/api/cases/case-1/alerts?level=critical2")
    assert bad_level.status_code == 422


def test_alert_links_evidence_iocs(client: Any, database: Database) -> None:
    """A detect run links tier-1 and tier-2 evidence IOCs to the alert (spec 01 §8).

    Scenario A shape: the source IP is linked to the alert with confidence >= 90,
    and the alert detail surfaces the tier-2 command/user-agent extracted from the
    evidence, which is what lights the +5 ``ioc_evidence`` scoring modifier.
    """
    _seed_scene(database)
    _insert_rule(database)
    database.writer.execute(
        "UPDATE events SET process_cmdline = ?, user_agent = ? WHERE id = "
        "(SELECT MIN(id) FROM events WHERE case_id = 'case-1')",
        ("powershell.exe -nop -enc ZQB2AGkAbA==", "sqlmap/1.7"),
    )
    _store_tier1_ips(database)

    response = client.post("/api/cases/case-1/detect", json={"profile": "full"})
    assert response.status_code == 202, response.text
    terminal = _wait_for_terminal(client, response.json()["id"])
    assert terminal["status"] == "done", terminal
    alert_id = str(
        database.writer.execute("SELECT id FROM alerts WHERE case_id = 'case-1'").fetchone()["id"]
    )

    detail = client.get(f"/api/alerts/{alert_id}").json()
    by_value = {item["value"]: item for item in detail["iocs"]}
    assert by_value["198.51.100.77"]["type"] == "ipv4"
    assert by_value["198.51.100.77"]["confidence"] >= 90
    assert by_value["powershell.exe -nop -enc ZQB2AGkAbA=="]["type"] == "command"
    assert by_value["sqlmap/1.7"]["type"] == "user_agent"
    assert len(detail["iocs"]) == 3

    breakdown = {entry["label"]: entry["delta"] for entry in detail["score_breakdown"]}
    assert breakdown.get("ioc_evidence") == 5


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


def test_rules_validate_create_crud(client: Any, database: Database) -> None:
    """Validate, create, read, replace, toggle and delete custom rules."""
    valid = yaml.safe_dump(
        {
            "title": "Custom Brute",
            "id": _CUSTOM_UUID,
            "level": "low",
            "status": "experimental",
            "tags": ["attack.t1110"],
            "logsource": {"product": "linux", "service": "sshd"},
            "detection": {
                "selection": {"event_action": "ssh_failed_password"},
                "condition": "selection",
            },
        },
        sort_keys=False,
    )

    validation = client.post("/api/rules/validate", json={"yaml": valid})
    assert validation.status_code == 200, validation.text
    assert validation.json()["valid"] is True
    assert validation.json()["rules"][0]["id"] == _CUSTOM_UUID

    broken = client.post("/api/rules/validate", json={"yaml": "::: : not a mapping"})
    assert broken.json()["valid"] is False

    created = client.post("/api/rules", json={"yaml": valid})
    assert created.status_code == 200, created.text
    assert created.json()["created"] == 1

    listed = client.get("/api/rules?kind=custom")
    assert listed.status_code == 200, listed.text
    assert listed.json()["total"] == 1
    by_technique = client.get("/api/rules?technique=t1110")
    assert by_technique.json()["total"] == 1

    detail = client.get(f"/api/rules/{_CUSTOM_UUID}")
    assert detail.status_code == 200
    assert "Custom Brute" in detail.json()["yaml"]

    missing = client.get("/api/rules/ghost")
    assert missing.status_code == 404

    _insert_rule(database)
    conflict = client.post("/api/rules", json={"yaml": yaml.safe_dump(_RULE_BODY, sort_keys=False)})
    assert conflict.status_code == 409

    replacement = yaml.safe_dump(
        {
            "title": "Custom Brute V2",
            "id": _CUSTOM_UUID,
            "level": "medium",
            "status": "stable",
            "logsource": {"product": "linux", "service": "sshd"},
            "detection": {
                "selection": {"event_action": "ssh_invalid_user"},
                "condition": "selection",
            },
        },
        sort_keys=False,
    )
    replaced = client.put(f"/api/rules/{_CUSTOM_UUID}", json={"yaml": replacement})
    assert replaced.status_code == 200, replaced.text
    assert replaced.json()["item"]["title"] == "Custom Brute V2"
    assert replaced.json()["item"]["level"] == "medium"

    mismatched = client.put(
        f"/api/rules/{_CUSTOM_UUID}",
        json={
            "yaml": yaml.safe_dump(
                {
                    "title": "Mismatch",
                    "id": _V2_UUID,
                    "level": "low",
                    "status": "experimental",
                    "logsource": {"product": "linux", "service": "sshd"},
                    "detection": {
                        "selection": {"event_action": "ssh_failed_password"},
                        "condition": "selection",
                    },
                },
                sort_keys=False,
            )
        },
    )
    assert mismatched.status_code == 422

    toggled = client.patch(f"/api/rules/{_CUSTOM_UUID}", json={"enabled": False})
    assert toggled.status_code == 200
    assert toggled.json()["item"]["enabled"] is False
    disabled = client.get("/api/rules?enabled=false")
    assert disabled.json()["total"] == 1
    assert client.patch("/api/rules/ghost", json={"enabled": True}).status_code == 404

    protected = client.delete(f"/api/rules/{_RULE_UUID}")
    assert protected.status_code == 409
    deleted = client.delete(f"/api/rules/{_CUSTOM_UUID}")
    assert deleted.status_code == 200
    assert client.get(f"/api/rules/{_CUSTOM_UUID}").status_code == 404


def test_rules_health_export_import(client: Any, database: Database) -> None:
    """Health buckets, zip export and synchronous import."""
    _insert_rule(database)
    health = client.get("/api/rules/health")
    assert health.status_code == 200
    assert health.json()["total"] == 1
    assert health.json()["ok"] == 1

    exported = client.get("/api/rules/export")
    assert exported.status_code == 200
    assert exported.headers["content-type"].startswith("application/zip")
    with zipfile.ZipFile(io.BytesIO(exported.content)) as archive:
        names = archive.namelist()
    assert any(_RULE_UUID in name for name in names)

    payload = yaml.safe_dump(
        {
            "title": "Imported Rule",
            "id": _IMPORTED_UUID,
            "level": "high",
            "status": "test",
            "logsource": {"product": "linux", "service": "sshd"},
            "detection": {
                "selection": {"event_action": "ssh_failed_password"},
                "condition": "selection",
            },
        },
        sort_keys=False,
    ).encode()
    imported = client.post(
        "/api/rules/import",
        files={"files": ("imported_rule.yml", payload, "application/yaml")},
    )
    assert imported.status_code == 200, imported.text
    body = imported.json()
    assert body["imported"] == 1
    assert body["job"]["kind"] == "rules_import"
    assert body["job"]["status"] == "done"
    assert client.get(f"/api/rules/{_IMPORTED_UUID}").status_code == 200

    guard = client.post(
        "/api/rules/import",
        files={"files": ("escape.zip", payload, "application/zip")},
    )
    assert guard.status_code == 422

    # Path traversal is neutralized by writing the basename only.
    traversal = client.post(
        "/api/rules/import",
        files={"files": ("../travelled.yml", payload, "application/yaml")},
    )
    assert traversal.status_code == 200, traversal.text
    assert client.get(f"/api/rules/{_IMPORTED_UUID}").status_code == 200


def test_rules_test_runs_against_case(client: Any, database: Database) -> None:
    """POST /rules/test re-runs the given rule over a case's events."""
    _seed_scene(database)
    document = {
        "title": "Ad-hoc SSH Fail",
        "id": _ADHOC_UUID,
        "level": "high",
        "status": "stable",
        "logsource": {"product": "linux", "service": "sshd"},
        "detection": {
            "selection": {"event_action": ["ssh_failed_password"]},
            "condition": "selection",
        },
    }
    response = client.post(
        "/api/rules/test",
        json={"yaml": yaml.safe_dump(document, sort_keys=False), "case_id": "case-1"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["executed"] is True
    assert body["total_matches"] == 14
    assert len(body["items"]) == 14
    assert "raw" not in body["items"][0]

    no_case = client.post(
        "/api/rules/test",
        json={"yaml": yaml.safe_dump(document, sort_keys=False), "case_id": "unknown"},
    )
    assert no_case.status_code == 200  # engine answers zero matches for an empty case


# ---------------------------------------------------------------------------
# MITRE
# ---------------------------------------------------------------------------


def _mini_bundle(version: str = "2026-10") -> dict[str, Any]:
    return {
        "type": "bundle",
        "id": "bundle--test",
        "x_mitre_version": version,
        "objects": [
            {
                "type": "x-mitre-tactic",
                "id": "tactic--priv-esc",
                "name": "Privilege Escalation",
                "x_mitre_shortname": "privilege-escalation",
                "external_references": [{"source_name": "mitre-attack", "external_id": "TA0004"}],
            },
            {
                "type": "x-mitre-tactic",
                "id": "tactic--execution",
                "name": "Execution",
                "x_mitre_shortname": "execution",
                "external_references": [{"source_name": "mitre-attack", "external_id": "TA0002"}],
            },
            {
                "type": "attack-pattern",
                "id": "pattern--t1000",
                "name": "Technique Foo",
                "description": "A test technique.",
                "x_mitre_is_subtechnique": False,
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "privilege-escalation"}
                ],
                "x_mitre_platforms": ["Linux"],
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1000",
                        "url": "https://attack.mitre.org/techniques/T1000",
                    }
                ],
            },
            {
                "type": "attack-pattern",
                "id": "pattern--t1000-sub",
                "name": "Technique Foo Sub",
                "x_mitre_is_subtechnique": True,
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "privilege-escalation"}
                ],
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1000.001",
                        "url": "https://attack.mitre.org/techniques/T1000/001",
                    }
                ],
            },
            {
                "type": "relationship",
                "relationship_type": "subtechnique-of",
                "source_ref": "pattern--t1000-sub",
                "target_ref": "pattern--t1000",
            },
            {
                "type": "intrusion-set",
                "id": "intrusion-set--g1",
                "name": "Group One",
                "external_references": [{"source_name": "mitre-attack", "external_id": "G0001"}],
            },
        ],
    }


def test_mitre_static_matrix_and_techniques(client: Any, database: Database) -> None:
    """The reference matrix, technique detail and tactic list."""
    load_bundle(database.writer, _mini_bundle())

    matrix = client.get("/api/mitre/matrix")
    assert matrix.status_code == 200, matrix.text
    tactics = {tactic["shortname"]: tactic for tactic in matrix.json()["tactics"]}
    privilege = tactics["privilege-escalation"]
    assert [item["id"] for item in privilege["techniques"]] == ["T1000"]
    assert privilege["techniques"][0]["subtechniques"][0]["id"] == "T1000.001"
    assert matrix.json()["attack_version"] == "2026-10"

    detail = client.get("/api/mitre/techniques/T1000")
    assert detail.status_code == 200, detail.text
    body = detail.json()
    assert body["name"] == "Technique Foo"
    assert body["description"] == "A test technique."
    assert body["platforms"] == ["Linux"]
    assert body["url"] == "https://attack.mitre.org/techniques/T1000"
    assert body["parent_id"] is None
    assert body["tactics"][0]["name"] == "Privilege Escalation"

    sub = client.get("/api/mitre/techniques/T1000.001")
    assert sub.status_code == 200
    assert sub.json()["is_subtechnique"] is True
    assert sub.json()["parent_id"] == "T1000"

    assert client.get("/api/mitre/techniques/T9999").status_code == 404

    tactics_api = client.get("/api/mitre/tactics")
    assert tactics_api.status_code == 200
    names = [tactic["shortname"] for tactic in tactics_api.json()["tactics"]]
    assert names[-1] == "impact"
    assert len(names) == 14


def test_mitre_case_matrix_and_layer(client: Any, database: Database) -> None:
    """Case coverage fold and the navigator layer over stored alerts."""
    load_bundle(database.writer, _mini_bundle())
    _seed_case(database)
    database.writer.execute(
        "INSERT INTO detection_runs (id, case_id, profile, tool_version, ruleset_hash, "
        "attack_version, started_at, finished_at, status) "
        "VALUES ('run-1', 'case-1', 'full', '0.1.0', ?, '2026-10', ?, ?, 'done')",
        ("0" * 64, _ISO, _ISO),
    )
    database.writer.execute(
        "INSERT INTO alerts (id, case_id, run_id, rule_id, rule_title, rule_kind, rule_type, "
        "level, score, status, analyst_notes, tactics_json, techniques_json, "
        "groups_software_json, host, user_name, group_key, first_seen_ms, last_seen_ms, "
        "match_count, false_positives_json, references_json, created_at) "
        "VALUES ('alert-1', 'case-1', 'run-1', 't-rule', 'Foo Hit', 'builtin', 'detection', "
        "'high', 75, 'new', NULL, ?, ?, '[]', 'web01', NULL, 'host|web01', ?, ?, 3, '[]', '[]', ?)",
        (
            json.dumps(["privilege-escalation"]),
            json.dumps([{"id": "T1000", "name": "Technique Foo", "source": "tag"}]),
            _TS,
            _TS + 2000,
            _ISO,
        ),
    )

    matrix = client.get("/api/cases/case-1/mitre")
    assert matrix.status_code == 200, matrix.text
    tactics = {tactic["shortname"]: tactic for tactic in matrix.json()["tactics"]}
    technique = tactics["privilege-escalation"]["techniques"][0]
    assert technique["id"] == "T1000"
    assert technique["alert_count"] == 1
    assert technique["alert_ids"] == ["alert-1"]
    assert technique["max_level"] == "high"

    layer = client.get("/api/cases/case-1/mitre/navigator-layer")
    assert layer.status_code == 200, layer.text
    body = layer.json()
    assert body["name"] == "TriageLens - scene"
    assert body["domain"] == "enterprise-attack"
    assert len(body["techniques"]) == 1
    entry = body["techniques"][0]
    assert entry["techniqueID"] == "T1000"
    assert entry["tactic"] == "privilege-escalation"
    assert entry["score"] == 3

    assert client.get("/api/cases/ghost/mitre/navigator-layer").status_code == 404


def test_mitre_attack_import(client: Any, database: Database) -> None:
    """POST /settings/attack/import replaces the catalogue and audit-logs."""
    bundle = _mini_bundle(version="2026-11")
    response = client.post(
        "/api/settings/attack/import",
        files={"bundle": ("attack.json", json.dumps(bundle).encode(), "application/json")},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["attack_version"] == "2026-11"
    assert body["techniques"] == 2

    assert client.get("/api/mitre/techniques/T1000").json()["name"] == "Technique Foo"
    actions = {
        str(row["action"])
        for row in database.writer.execute("SELECT action FROM audit_log").fetchall()
    }
    assert "attack_imported" in actions

    invalid = client.post(
        "/api/settings/attack/import",
        files={"bundle": ("attack.json", b"not json", "application/json")},
    )
    assert invalid.status_code == 422
