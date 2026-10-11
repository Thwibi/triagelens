"""Report generation (spec 06 "Reports", spec 08, spec 09 API tests).

The runner test drives :class:`ReportRunner` directly so the gather/render/write
path runs deterministically in-process; the API test enqueues through the real
job manager and follows the job to ``done``. The security assertions pin the
two rules a report has to keep: log-derived values are HTML-escaped, and the
document makes no external requests.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any

import pytest
import yaml

from app.config import Settings
from app.db.connection import Database, atomic
from app.util.hashing import sha256_bytes

_TS = 1_700_000_000_000
_ISO = "2026-01-01T00:00:00.000Z"
#: A log value that must be escaped everywhere it reaches the HTML.
_HOST = "<script>alert(1)</script>"

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
    """A case with one Linux auth source and three failed-ssh events."""
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
        "ls_category, event_count) VALUES ('src-1', 'linux_auth', '', 'sshd', '', 3)"
    )
    with atomic(database.writer):
        for index in range(3):
            database.writer.execute(
                "INSERT INTO events (case_id, source_id, record_ref, ts_ms, ts_iso, "
                "log_type, ls_category, host, channel, app_name, user_name, message, "
                "raw, event_action, src_ip, fields_json, event_id) "
                "VALUES ('case-1', 'src-1', ?, ?, NULL, 'linux_auth', '', ?, '', "
                "'sshd', 'victim', '', '{}', 'ssh_failed_password', ?, '{}', NULL)",
                (str(index), _TS + index * 1000, _HOST, "198.51.100.77"),
            )


def _insert_rule(database: Database) -> None:
    """A stable builtin rule the detect runner can compile and fire."""
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


def _run_detection(database: Database, settings: Settings) -> None:
    """Run the detect pipeline in-process so the case has one real alert."""
    from app.jobs.detect import DetectPayload, DetectRunner
    from app.jobs.progress import ProgressBus
    from app.jobs.writer import DBWriter

    writer = DBWriter(database)
    try:
        runner = DetectRunner(writer=writer, progress=ProgressBus(), settings=settings)

        async def go() -> None:
            await runner.run(DetectPayload(job_id="detect-1", case_id="case-1", profile="full"))

        asyncio.run(go())
    finally:
        writer.stop()


def _seed_ready(database: Database, settings: Settings) -> None:
    """A case with a detection run and one scored alert."""
    _seed_scene(database)
    _insert_rule(database)
    _run_detection(database, settings)
    count = database.writer.execute(
        "SELECT COUNT(*) AS n FROM alerts WHERE case_id = 'case-1'"
    ).fetchone()
    assert count["n"] == 1


def _wait_for_terminal(client: Any, job_id: str, *, timeout: float = 10.0) -> dict[str, Any]:
    """Poll the API until the job leaves ``queued``/``running``."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        response = client.get(f"/api/jobs/{job_id}")
        assert response.status_code == 200, response.text
        job = response.json()
        if job["status"] not in {"queued", "running"}:
            return job  # type: ignore[no-any-return]
        time.sleep(0.05)
    raise AssertionError(f"job {job_id} did not finish within {timeout}s")


def test_report_runner_writes_escaped_self_contained_html(
    database: Database, settings: Settings
) -> None:
    """The runner records the file, hashes it, audits it, and escapes log data."""
    from app.jobs.progress import ProgressBus
    from app.jobs.report import ReportRunner
    from app.jobs.writer import DBWriter
    from app.reports.options import ReportOptions

    _seed_ready(database, settings)
    writer = DBWriter(database)
    try:
        runner = ReportRunner(writer=writer, progress=ProgressBus(), settings=settings)
        asyncio.run(runner.run("job-1", "case-1", ReportOptions(fmt="html", events_per_alert=3)))
    finally:
        writer.stop()

    rows = database.writer.execute("SELECT * FROM reports WHERE case_id = 'case-1'").fetchall()
    assert len(rows) == 1
    record = rows[0]
    assert record["format"] == "html"
    assert len(record["sha256"]) == 64

    document = Path(record["path"]).read_text(encoding="utf-8")
    assert "scene report" in document
    assert "<script>alert(1)</script>" not in document
    assert "&lt;script&gt;" in document
    assert 'src="http' not in document
    assert 'href="http' not in document
    assert sha256_bytes(document.encode("utf-8")) == record["sha256"]

    actions = [
        row["action"]
        for row in database.writer.execute(
            "SELECT action FROM audit_log WHERE case_id = 'case-1'"
        ).fetchall()
    ]
    assert "report_created" in actions


def test_report_api_flow(client: Any, database: Database, settings: Settings) -> None:
    """POST enqueues; the list and download endpoints serve the JSON report."""
    _seed_ready(database, settings)

    response = client.post("/api/cases/case-1/reports", json={"format": "json"})
    assert response.status_code == 202, response.text
    job = response.json()
    assert job["kind"] == "report"
    assert job["status"] == "queued"
    terminal = _wait_for_terminal(client, job["id"])
    assert terminal["status"] == "done", terminal

    listing = client.get("/api/cases/case-1/reports")
    assert listing.status_code == 200, listing.text
    page = listing.json()
    assert page["total"] == 1
    item = page["items"][0]
    assert item["format"] == "json"
    assert item["options"]["format"] == "json"

    download = client.get(f"/api/reports/{item['id']}/download")
    assert download.status_code == 200, download.text
    assert download.headers["x-sha256"] == item["sha256"]
    body = json.loads(download.content)
    assert body["schema_version"] == "1.0"
    assert body["meta"]["case_id"] == "case-1"
    assert len(body["alerts"]) == 1
    assert body["integrity"]["processed_locally"] is True

    missing = client.get("/api/reports/nope/download")
    assert missing.status_code == 404


def test_report_api_pdf_is_unavailable(client: Any, database: Database) -> None:
    """Without WeasyPrint the PDF format answers 422 PDF_UNAVAILABLE (spec 08 2)."""
    response = client.post("/api/cases/case-1/reports", json={"format": "pdf"})
    assert response.status_code == 422, response.text
    assert response.json()["error"]["code"] == "PDF_UNAVAILABLE"


def test_report_api_validation(client: Any, database: Database, settings: Settings) -> None:
    """Unknown format, unknown status and unknown case are refused."""
    _seed_ready(database, settings)

    bad_format = client.post("/api/cases/case-1/reports", json={"format": "docx"})
    assert bad_format.status_code == 422
    assert bad_format.json()["error"]["code"] == "UNSUPPORTED_FORMAT"

    bad_status = client.post("/api/cases/case-1/reports", json={"include": {"alerts": ["bogus"]}})
    assert bad_status.status_code == 422
    assert bad_status.json()["error"]["code"] == "VALIDATION_ERROR"

    bad_extra = client.post("/api/cases/case-1/reports", json={"nope": True})
    assert bad_extra.status_code == 422

    missing_case = client.post("/api/cases/ghost/reports", json={"format": "json"})
    assert missing_case.status_code == 404


def test_alert_csv_export_guards_formulas(
    client: Any, database: Database, settings: Settings
) -> None:
    """The CSV export carries the total and prefixes formula-leading cells."""
    _seed_ready(database, settings)

    response = client.get("/api/cases/case-1/reports/alerts.csv")
    assert response.status_code == 200, response.text
    assert response.headers["x-total"] == "1"
    lines = response.text.splitlines()
    assert lines[0].startswith("alert_id,level,score,status,rule_id,rule_title")
    assert len(lines) == 2
    assert "base-ssh-fail" in lines[1]


def test_render_alerts_csv_escapes_injection() -> None:
    """A cell starting with a formula character is prefixed with a quote."""
    from app.reports.render import render_alerts_csv

    def page(limit: int, offset: int) -> tuple[list[dict[str, Any]], int]:
        return (
            [
                {
                    "id": "a1",
                    "level": "high",
                    "score": 75,
                    "status": "new",
                    "rule_id": "r1",
                    "rule_title": "=cmd|' /C calc'!A0",
                    "tactics": [{"name": "Execution"}],
                    "techniques": [{"id": "T1059"}],
                    "host": "=1+1",
                    "user_name": "@user",
                    "first_seen": None,
                    "last_seen": None,
                    "match_count": 3,
                    "analyst_notes": "+note",
                }
            ],
            1,
        )

    text, total = render_alerts_csv(page)
    assert total == 1
    assert "'=cmd" in text
    assert "'=1+1" in text
    assert "'@user" in text
    assert "'+note" in text


def test_report_data_is_deterministic(
    monkeypatch: pytest.MonkeyPatch, database: Database, settings: Settings
) -> None:
    """Two gathers of one case differ only in report id and timestamp."""
    from app.reports import gather as gather_module
    from app.reports.gather import gather_report
    from app.reports.options import ReportOptions

    _seed_ready(database, settings)
    monkeypatch.setattr(gather_module, "utc_now_iso", lambda: _ISO)
    options = ReportOptions(fmt="md")
    first = gather_report(database.writer, case_id="case-1", options=options).as_dict()
    second = gather_report(database.writer, case_id="case-1", options=options).as_dict()
    assert first["meta"]["generated_at"] == _ISO
    for document in (first, second):
        assert isinstance(document["meta"], dict)
        document["meta"].pop("report_id")
    assert first == second
