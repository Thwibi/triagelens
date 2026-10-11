"""Detection run API and job runner (spec 06 "Detection", spec 09 API tests).

The runner test drives :class:`DetectRunner` directly so the whole pipeline -
base rules, record_run_alerts, enrichment - runs deterministically in-process.
The API test enqueues through the real job manager and polls the job to
``done``, asserting the run side effects are served by the read endpoints.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any

import yaml

from app.config import Settings
from app.db.connection import Database, atomic
from app.db.repositories.jobs import JobRepository
from app.models.job import JobStatus

BACKEND_ROOT = Path(__file__).resolve().parents[1]

_TS = 1_700_000_000_000
_ISO = "2026-01-01T00:00:00.000Z"

_RULE_BODY = {
    "title": "SSH Failed Password",
    "id": "base-ssh-fail",
    "status": "stable",
    "logsource": {"product": "linux", "service": "sshd"},
    "detection": {
        "selection": {"event_action": ["ssh_failed_password", "ssh_invalid_user"]},
        "condition": "selection",
    },
    "level": "high",
}


def _seed_scene(database: Database) -> None:
    """A case with one Linux auth source, inventory and 14 failed-ssh events."""
    database.writer.execute(
        "INSERT INTO cases (id, name, description, default_timezone, created_at, updated_at) "
        "VALUES ('case-1', 'scene', NULL, 'UTC', ?, ?)",
        (_ISO, _ISO),
    )
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
    with atomic(database.writer):
        for index in range(14):
            database.writer.execute(
                "INSERT INTO events (case_id, source_id, record_ref, ts_ms, ts_iso, "
                "log_type, ls_category, host, channel, app_name, user_name, message, "
                "raw, event_action, src_ip, fields_json, event_id) "
                "VALUES ('case-1', 'src-1', ?, ?, NULL, 'linux_auth', '', 'web01', '', "
                "'sshd', 'victim', '', '{}', 'ssh_failed_password', ?, '{}', NULL)",
                (
                    str(index),
                    _TS + index * 1000,
                    "198.51.100.77",
                ),
            )


def _insert_rule(database: Database) -> None:
    document = {key: value for key, value in _RULE_BODY.items() if key != "id"}
    database.writer.execute(
        "INSERT INTO rules (id, title, kind, rule_type, level, status, enabled, yaml, "
        "tags_json, logsource_json, file_path, sha256, compile_error, unroutable, updated_at) "
        "VALUES (?, ?, 'builtin', 'detection', ?, ?, 1, ?, '[]', ?, NULL, 'deadbeef', NULL, 0, ?)",
        (
            "base-ssh-fail",
            _RULE_BODY["title"],
            _RULE_BODY["level"],
            _RULE_BODY["status"],
            yaml.safe_dump(document, sort_keys=False),
            json.dumps(_RULE_BODY["logsource"]),
            _ISO,
        ),
    )


def _wait_for_terminal(client: Any, job_id: str, *, timeout: float = 10.0) -> dict[str, Any]:
    """Poll the API until the job leaves ``running``/``queued``."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        response = client.get(f"/api/jobs/{job_id}")
        assert response.status_code == 200, response.text
        job = response.json()
        if job["status"] not in {"queued", "running"}:
            return job  # type: ignore[no-any-return]
        time.sleep(0.05)
    raise AssertionError(f"job {job_id} did not finish within {timeout}s")


def test_detect_runner_end_to_end(database: Database, settings: Settings) -> None:
    """A full run: run row ``done``, per-rule rows, one scored, mapped alert."""
    from app.db.repositories.runs import attack_version
    from app.jobs.detect import DetectPayload, DetectRunner
    from app.jobs.progress import ProgressBus
    from app.jobs.writer import DBWriter

    _seed_scene(database)
    _insert_rule(database)
    writer = DBWriter(database)
    try:
        runner = DetectRunner(writer=writer, progress=ProgressBus(), settings=settings)

        async def go() -> None:
            await runner.run(DetectPayload(job_id="job-1", case_id="case-1", profile="full"))

        asyncio.run(go())
    finally:
        writer.stop()

    runs = database.writer.execute(
        "SELECT * FROM detection_runs WHERE case_id = 'case-1' ORDER BY started_at"
    ).fetchall()
    assert len(runs) == 1
    run = runs[0]
    assert run["status"] == "done"
    assert run["profile"] == "full"
    assert len(run["ruleset_hash"]) == 64
    assert run["attack_version"] == attack_version(database.writer)

    rule_runs = database.writer.execute(
        "SELECT * FROM rule_runs WHERE run_id = ?", (run["id"],)
    ).fetchall()
    assert len(rule_runs) == 1
    assert rule_runs[0]["rule_id"] == "base-ssh-fail"
    assert rule_runs[0]["status"] == "ok"
    assert rule_runs[0]["match_count"] == 14

    alerts = database.writer.execute("SELECT * FROM alerts WHERE case_id = 'case-1'").fetchall()
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["rule_id"] == "base-ssh-fail"
    assert alert["match_count"] == 14
    assert alert["score"] == 75  # high base 70 + match_volume_10 5, stable status
    assert alert["host"] == "web01"
    assert json.loads(alert["techniques_json"]) == []
    assert json.loads(alert["tactics_json"]) == []

    evidence = database.writer.execute(
        "SELECT COUNT(*) AS n FROM alert_events WHERE alert_id = ?", (alert["id"],)
    ).fetchone()
    assert evidence["n"] == 14


def test_detect_api_flow(client: Any, database: Database) -> None:
    """POST /detect enqueues; reads of runs and per-rule rows follow."""
    _seed_scene(database)
    _insert_rule(database)

    response = client.post("/api/cases/case-1/detect", json={"profile": "full"})
    assert response.status_code == 202, response.text
    job = response.json()
    assert job["kind"] == "detect"
    assert job["status"] == "queued"

    terminal = _wait_for_terminal(client, job["id"])
    assert terminal["status"] == "done", terminal

    runs = client.get("/api/cases/case-1/detection-runs")
    assert runs.status_code == 200, runs.text
    payload = runs.json()
    assert payload["total"] == 1
    run = payload["items"][0]
    assert run["status"] == "done"
    assert run["profile"] == "full"
    assert run["counts"]["alerts"] == 1
    assert run["counts"]["rules"] == 1

    detail = client.get(f"/api/detection-runs/{run['id']}/rules")
    assert detail.status_code == 200, detail.text
    rows = detail.json()
    assert rows["total"] == 1
    assert rows["items"][0]["rule_id"] == "base-ssh-fail"
    assert rows["items"][0]["status"] == "ok"

    missing = client.get("/api/detection-runs/nope/rules")
    assert missing.status_code == 404
    unknown = client.post("/api/cases/case-1/detect", json={"rule_ids": ["ghost-rule"]})
    assert unknown.status_code == 422
    bad_profile = client.post("/api/cases/case-1/detect", json={"profile": "ultra"})
    assert bad_profile.status_code == 422


def test_detect_cancel_before_start(database: Database, settings: Settings) -> None:
    """A job cancelled before it runs finishes cancelled with no run rows."""
    from app.jobs.detect import DetectPayload, DetectRunner
    from app.jobs.progress import ProgressBus
    from app.jobs.writer import DBWriter
    from app.models.job import JobKind

    _seed_scene(database)
    _insert_rule(database)
    JobRepository(database.writer).create(
        job_id="job-1", kind=JobKind.DETECT, case_id="case-1", message="detection (full)"
    )
    writer = DBWriter(database)
    try:
        runner = DetectRunner(writer=writer, progress=ProgressBus(), settings=settings)
        runner.cancel("job-1")

        async def go() -> None:
            await runner.run(DetectPayload(job_id="job-1", case_id="case-1", profile="full"))

        asyncio.run(go())
    finally:
        writer.stop()

    job = JobRepository(database.writer).get("job-1")
    assert job is not None
    assert job.status is JobStatus.CANCELLED
    rows = database.writer.execute(
        "SELECT COUNT(*) AS n FROM detection_runs WHERE case_id = 'case-1'"
    ).fetchone()
    assert rows["n"] == 0
