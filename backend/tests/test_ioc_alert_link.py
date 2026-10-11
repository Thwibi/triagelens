"""Alert-scoped IOC extraction and linking (spec 01 section 8, spec 04 section 8)."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from app.config import Settings
from app.db.connection import Database, atomic
from app.db.repositories.alerts import AlertRepository
from app.db.repositories.iocs import IocRepository
from app.detect.ioc_link import link_alert_iocs
from app.detect.scoring import score_alert
from app.ioc import IocType, aggregate, default_allowlist, extract_fields

_TS = 1_700_000_000_000
_ISO = "2026-01-01T00:00:00.000Z"


def _seed_case(database: Database) -> None:
    database.writer.execute(
        "INSERT INTO cases (id, name, description, default_timezone, created_at, updated_at) "
        "VALUES ('case-1', 'scene', NULL, 'UTC', ?, ?)",
        (_ISO, _ISO),
    )
    database.writer.execute(
        "INSERT INTO sources (id, case_id, filename, stored_path, size_bytes, sha256, "
        "status, ingested_at) VALUES ('src-1', 'case-1', 'log', '/tmp/log', 0, "
        "'deadbeef', 'done', ?)",
        (_ISO,),
    )
    database.writer.execute(
        "INSERT INTO detection_runs (id, case_id, profile, tool_version, ruleset_hash, "
        "attack_version, started_at, status) VALUES ('run-1', 'case-1', 'full', '0.0', "
        "?, 'v14.1', ?, 'done')",
        ("a" * 64, _ISO),
    )


def _add_event(database: Database, index: int, **fields: Any) -> int:
    cursor = database.writer.execute(
        "INSERT INTO events (case_id, source_id, record_ref, ts_ms, log_type, src_ip, "
        "process_cmdline, file_path, registry_key, user_agent, raw) VALUES "
        "('case-1', 'src-1', ?, ?, 'linux_syslog', ?, ?, ?, ?, ?, 'raw line')",
        (
            str(index),
            _TS + index,
            fields.get("src_ip"),
            fields.get("process_cmdline"),
            fields.get("file_path"),
            fields.get("registry_key"),
            fields.get("user_agent"),
        ),
    )
    return int(cursor.lastrowid or 0)


def _add_alert(database: Database, event_ids: Iterable[int], *, level: str = "high") -> None:
    ids = list(event_ids)
    database.writer.execute(
        "INSERT INTO alerts (id, case_id, run_id, rule_id, rule_title, rule_kind, "
        "rule_type, level, score, group_key, match_count, created_at) "
        "VALUES ('alert-1', 'case-1', 'run-1', 'rule-1', 'T', 'builtin', 'detection', "
        "?, 50, 'host', ?, ?)",
        (level, len(ids), _ISO),
    )
    database.writer.executemany(
        "INSERT INTO alert_events (alert_id, event_id) VALUES ('alert-1', ?)",
        [(event_id,) for event_id in ids],
    )


def _store_tier1(database: Database, event_ips: Mapping[int, str]) -> None:
    """Simulate the parse worker having stored each evidence event's tier-1 IP."""
    records = [
        (
            event_id,
            None,
            extract_fields(
                {"src_ip": ip},
                allowlist=default_allowlist(),
                types=frozenset({IocType.IPV4}),
            ),
        )
        for event_id, ip in event_ips.items()
    ]
    IocRepository(database.writer).store("case-1", aggregate(records))


def _ioc_values(database: Database, ioc_type: str) -> list[str]:
    rows = database.writer.execute(
        "SELECT value FROM iocs WHERE type = ? ORDER BY value", (ioc_type,)
    ).fetchall()
    return [str(row["value"]) for row in rows]


def _linked_values(database: Database) -> set[str]:
    rows = database.writer.execute(
        "SELECT iocs.value FROM ioc_alerts JOIN iocs ON iocs.id = ioc_alerts.ioc_id"
    ).fetchall()
    return {str(row["value"]) for row in rows}


def test_links_tier1_and_extracts_tier2(database: Database, settings: Settings) -> None:
    _seed_case(database)
    with atomic(database.writer):
        event_id = _add_event(
            database,
            0,
            src_ip="203.0.113.9",
            process_cmdline=r"C:\Users\Public\evil.exe -nop",
            registry_key=r"HKLM\Software\Run\Updater",
            user_agent="sqlmap/1.7",
        )
        _add_alert(database, [event_id])
    _store_tier1(database, {event_id: "203.0.113.9"})

    written = link_alert_iocs(database.writer, case_id="case-1", settings=settings)
    assert written >= 3

    assert _ioc_values(database, "ipv4") == ["203.0.113.9"]
    assert "evil.exe" in _ioc_values(database, "filename")
    assert _ioc_values(database, "command") == [r"C:\Users\Public\evil.exe -nop"]
    assert _ioc_values(database, "user_agent") == ["sqlmap/1.7"]
    assert _ioc_values(database, "registry") == [r"HKLM\Software\Run\Updater"]

    linked = _linked_values(database)
    assert "203.0.113.9" in linked
    assert "evil.exe" in linked
    assert r"C:\Users\Public\evil.exe" in linked


def test_command_only_kept_for_medium_or_higher(database: Database, settings: Settings) -> None:
    _seed_case(database)
    with atomic(database.writer):
        event_id = _add_event(database, 0, process_cmdline=r"C:\temp\a.exe")
        _add_alert(database, [event_id], level="low")

    link_alert_iocs(database.writer, case_id="case-1", settings=settings)

    assert _ioc_values(database, "command") == []
    assert "a.exe" in _ioc_values(database, "filename")


def test_user_agent_kept_when_scanner_or_repeated(database: Database, settings: Settings) -> None:
    _seed_case(database)
    with atomic(database.writer):
        repeated_a = _add_event(database, 0, user_agent="custom-collector/1.0")
        repeated_b = _add_event(database, 1, user_agent="custom-collector/1.0")
        once = _add_event(database, 2, user_agent="Mozilla/5.0 (X11; Linux x86_64)")
        _add_alert(database, [repeated_a, repeated_b, once], level="low")

    link_alert_iocs(database.writer, case_id="case-1", settings=settings)

    values = _ioc_values(database, "user_agent")
    assert values == ["custom-collector/1.0"]


def test_scoring_modifier_fires_after_linking(database: Database, settings: Settings) -> None:
    _seed_case(database)
    with atomic(database.writer):
        event_id = _add_event(database, 0, src_ip="203.0.113.9")
        _add_alert(database, [event_id])
    _store_tier1(database, {event_id: "203.0.113.9"})

    alert = AlertRepository(database.writer).get("alert-1")
    assert alert is not None
    before = score_alert(database.writer, alert, rule_status=None)
    assert "ioc_evidence" not in before.breakdown

    link_alert_iocs(database.writer, case_id="case-1", settings=settings)

    after = score_alert(database.writer, alert, rule_status=None)
    assert after.breakdown["ioc_evidence"] == 5


def test_linking_is_idempotent(database: Database, settings: Settings) -> None:
    _seed_case(database)
    with atomic(database.writer):
        event_id = _add_event(
            database,
            0,
            src_ip="203.0.113.9",
            process_cmdline=r"C:\Users\Public\evil.exe",
            user_agent="sqlmap/1.7",
        )
        _add_alert(database, [event_id])
    _store_tier1(database, {event_id: "203.0.113.9"})

    link_alert_iocs(database.writer, case_id="case-1", settings=settings)
    first_iocs = database.writer.execute("SELECT COUNT(*) AS n FROM iocs").fetchone()["n"]
    first_links = database.writer.execute("SELECT COUNT(*) AS n FROM ioc_alerts").fetchone()["n"]
    first_cmd = database.writer.execute(
        "SELECT occurrences FROM iocs WHERE type = 'command'"
    ).fetchone()["occurrences"]

    link_alert_iocs(database.writer, case_id="case-1", settings=settings)

    assert database.writer.execute("SELECT COUNT(*) AS n FROM iocs").fetchone()["n"] == first_iocs
    assert (
        database.writer.execute("SELECT COUNT(*) AS n FROM ioc_alerts").fetchone()["n"]
        == first_links
    )
    assert (
        database.writer.execute("SELECT occurrences FROM iocs WHERE type = 'command'").fetchone()[
            "occurrences"
        ]
        == first_cmd
    )
