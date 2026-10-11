"""Events API tests (spec 06 "Events").

The suite seeds events directly (rows plus explicit ``events_fts`` rows, the
same split the writer uses) and exercises list/count/detail/facets: keyset
pagination on ``(ts_ms, id)``, the shared filter set, FTS ``q`` errors, case
scoping and the IOC/alert link filters. Sibling alert detail coverage lives in
the alerts suite.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Callable
from typing import Any

import pytest

from app.db.connection import Database
from app.db.repositories.events import EventFilters, EventRepository

_TS = 1_700_000_000_000
_ISO = "2026-01-01T00:00:00.000Z"

_RUN_ID = "run-1"
_ALERT_ID = "alert-0001"
_RULE_ID = "rule-0001"
_IOC_ID = "ioc-0001"


def _seed_case(database: Database, case_id: str = "case-1") -> None:
    database.writer.execute(
        "INSERT INTO cases (id, name, description, default_timezone, created_at, updated_at) "
        "VALUES (?, 'scene', NULL, 'UTC', ?, ?)",
        (case_id, _ISO, _ISO),
    )


def _seed_source(database: Database, case_id: str = "case-1", source_id: str = "src-1") -> None:
    database.writer.execute(
        "INSERT INTO sources (id, case_id, filename, stored_path, size_bytes, sha256, "
        "status, ingested_at) VALUES (?, ?, 'auth.log', '/tmp/auth.log', 0, 'deadbeef', 'done', ?)",
        (source_id, case_id, _ISO),
    )
    database.writer.execute(
        "INSERT INTO source_inventory (source_id, log_type, channel, app_name, "
        "ls_category, event_count) VALUES (?, 'linux_auth', '', 'sshd', '', 0)",
        (source_id,),
    )


def _add_event(
    database: Database,
    *,
    case_id: str = "case-1",
    source_id: str = "src-1",
    index: int,
    ts_ms: int,
    host: str = "web01",
    log_type: str = "linux_auth",
    level: str | None = None,
    event_action: str | None = None,
    message: str = "",
    src_ip: str | None = None,
    user_name: str | None = None,
    channel: str = "",
    ls_category: str = "",
    app_name: str = "sshd",
    event_id: int | None = None,
    fields: dict[str, Any] | None = None,
    process_cmdline: str | None = None,
    raw: str = '{"seed": true}',
) -> int:
    cursor = database.writer.execute(
        "INSERT INTO events (case_id, source_id, record_ref, ts_ms, ts_iso, log_type, "
        "ls_category, host, channel, app_name, event_id, level, event_action, user_name, "
        "src_ip, message, raw, fields_json) "
        "VALUES (?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            case_id,
            source_id,
            str(index),
            ts_ms,
            log_type,
            ls_category,
            host,
            channel,
            app_name,
            event_id,
            level,
            event_action,
            user_name,
            src_ip,
            message,
            raw,
            json.dumps(fields or {}),
        ),
    )
    event_rowid = int(cursor.lastrowid or 0)
    if message or process_cmdline:
        database.writer.execute(
            "INSERT INTO events_fts (rowid, message, process_cmdline, parent_process_cmdline, "
            "url, user_agent, file_path, raw) VALUES (?, ?, ?, '', '', '', '', ?)",
            (event_rowid, message, process_cmdline or "", raw),
        )
    return event_rowid


def _seed_scene(database: Database) -> list[int]:
    """A case with 7 events across hosts/levels; returns their rowids by index."""
    _seed_case(database)
    _seed_source(database)
    ids = []
    for index in range(7):
        message = "failed login victim" if index % 3 == 0 else "normal event"
        ids.append(
            _add_event(
                database,
                index=index,
                ts_ms=_TS + index * 1000,
                host=f"web{index % 2 + 1:02d}",
                level="medium" if index % 2 else "high",
                message=message,
                src_ip="198.51.100.77",
                user_name="victim",
                event_id=4625 if index % 2 else None,
                fields={"foo": index},
            )
        )
    return ids


def _paginate(client: Any, url: str, limit: int) -> list[dict[str, Any]]:
    """Walk one URL with its ``next_cursor`` and return all items."""
    items: list[dict[str, Any]] = []
    cursor: str | None = None
    while True:
        cursor_param = f"&cursor={cursor}" if cursor else ""
        response = client.get(f"{url}?limit={limit}{cursor_param}")
        assert response.status_code == 200, response.text
        payload = response.json()
        items.extend(payload["items"])
        cursor = payload["next_cursor"]
        if cursor is None:
            return items


def _decode_cursor_text(raw: str) -> tuple[int, int]:
    padded = raw + "=" * (-len(raw) % 4)
    ts_s, id_s = base64.urlsafe_b64decode(padded.encode()).decode().split(":", 1)
    return int(ts_s), int(id_s)


# ---------------------------------------------------------------------------
# List, pagination, filters
# ---------------------------------------------------------------------------


def test_events_list_shapes_and_default_order(client: Any, database: Database) -> None:
    _seed_scene(database)
    response = client.get("/api/cases/case-1/events")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["next_cursor"] is None
    assert payload["total"] is None
    assert len(payload["items"]) == 7
    first = payload["items"][0]
    assert first["id"] == 7
    assert first["case_id"] == "case-1"
    assert first["source_id"] == "src-1"
    assert first["host"] == "web01"
    assert first["level"] in {"high", "medium"}
    assert first["fields"] == {"foo": 6}
    assert "raw" not in first
    assert first["message"] == "failed login victim"
    timestamps = [item["ts_ms"] for item in payload["items"]]
    assert timestamps == sorted(timestamps, reverse=True)


def test_events_list_keyset_pagination_no_overlap(client: Any, database: Database) -> None:
    ids = _seed_scene(database)
    items = _paginate(client, "/api/cases/case-1/events", limit=3)
    got = [item["id"] for item in items]
    assert got == sorted(ids, reverse=True)
    assert len(got) == len(set(got)) == 7


def test_events_cursor_is_opaque_keyset_position(client: Any, database: Database) -> None:
    _seed_scene(database)
    first = client.get("/api/cases/case-1/events?limit=3")
    assert first.status_code == 200, first.text
    cursor = first.json()["next_cursor"]
    assert cursor is not None
    ts_ord, event_id = _decode_cursor_text(cursor)
    assert event_id == 5
    assert ts_ord == _TS + 4 * 1000
    next_page = client.get(f"/api/cases/case-1/events?limit=3&cursor={cursor}")
    assert next_page.status_code == 200, next_page.text
    assert [item["id"] for item in next_page.json()["items"]] == [4, 3, 2]


def test_events_list_ascending_sort(client: Any, database: Database) -> None:
    _seed_scene(database)
    response = client.get("/api/cases/case-1/events?sort=ts")
    assert response.status_code == 200, response.text
    timestamps = [item["ts_ms"] for item in response.json()["items"]]
    assert timestamps == sorted(timestamps)


def test_events_list_filters(client: Any, database: Database) -> None:
    _seed_scene(database)
    cases: list[tuple[str, Callable[[Any], bool]]] = [
        ("host=web01", lambda item: bool(item["host"] == "web01")),
        ("level=high", lambda item: bool(item["level"] == "high")),
        ("event_id=4625", lambda item: bool(item["event_id"] == 4625)),
        ("user_name=victim", lambda item: bool(item["user_name"] == "victim")),
        ("src_ip=198.51.100.77", lambda item: bool(item["src_ip"] == "198.51.100.77")),
        ("log_type=linux_auth", lambda item: bool(item["log_type"] == "linux_auth")),
    ]
    for query, predicate in cases:
        response = client.get(f"/api/cases/case-1/events?{query}")
        assert response.status_code == 200, response.text
        items = response.json()["items"]
        assert items, query
        assert all(predicate(item) for item in items), query


def test_events_list_time_range_and_source(client: Any, database: Database) -> None:
    _seed_scene(database)
    response = client.get(f"/api/cases/case-1/events?from_ms={_TS + 2000}&to_ms={_TS + 4000}")
    assert response.status_code == 200, response.text
    assert [item["id"] for item in response.json()["items"]] == [5, 4, 3]
    response = client.get("/api/cases/case-1/events?source_id=src-1")
    assert response.status_code == 200, response.text
    assert len(response.json()["items"]) == 7


def test_events_include_raw_flag(client: Any, database: Database) -> None:
    _seed_scene(database)
    response = client.get("/api/cases/case-1/events?include=raw")
    assert response.status_code == 200, response.text
    item = response.json()["items"][0]
    assert item["raw"] == '{"seed": true}'


def test_events_case_scope_excludes_other_cases(client: Any, database: Database) -> None:
    _seed_scene(database)
    _seed_case(database, case_id="case-2")
    _add_event(database, case_id="case-2", index=0, ts_ms=_TS)
    response = client.get("/api/cases/case-1/events")
    assert response.status_code == 200, response.text
    assert len(response.json()["items"]) == 7
    assert all(item["case_id"] == "case-1" for item in response.json()["items"])


def test_events_count_endpoint(client: Any, database: Database) -> None:
    _seed_scene(database)
    response = client.get("/api/cases/case-1/events/count")
    assert response.status_code == 200, response.text
    assert response.json() == {"count": 7}
    response = client.get("/api/cases/case-1/events/count?host=web01")
    assert response.status_code == 200, response.text
    assert response.json() == {"count": 4}


# ---------------------------------------------------------------------------
# FTS
# ---------------------------------------------------------------------------


def test_events_fts_query(client: Any, database: Database) -> None:
    ids = _seed_scene(database)
    response = client.get("/api/cases/case-1/events", params={"q": '"failed login"'})
    assert response.status_code == 200, response.text
    matched = response.json()["items"]
    assert [item["id"] for item in matched] == [ids[6], ids[3], ids[0]]
    response = client.get("/api/cases/case-1/events/count", params={"q": "victim"})
    assert response.status_code == 200, response.text
    assert response.json() == {"count": 3}


def test_events_fts_invalid_syntax_422(client: Any, database: Database) -> None:
    _seed_scene(database)
    response = client.get("/api/cases/case-1/events?q=NEAR(")
    assert response.status_code == 422, response.text
    body = response.json()["error"]
    assert body["code"] == "VALIDATION_ERROR"
    assert "invalid search query" in body["message"]


# ---------------------------------------------------------------------------
# Facets
# ---------------------------------------------------------------------------


def test_events_facets(client: Any, database: Database) -> None:
    _seed_scene(database)
    response = client.get("/api/cases/case-1/events/facets")
    assert response.status_code == 200, response.text
    facets = response.json()["facets"]
    assert facets["host"][0] == {"value": "web01", "count": 4}
    assert facets["host"][1] == {"value": "web02", "count": 3}
    assert facets["log_type"] == [{"value": "linux_auth", "count": 7}]
    assert {"value": 4625, "count": 3} in facets["event_id"]
    assert facets["user_name"] == [{"value": "victim", "count": 7}]
    assert facets["src_ip"] == [{"value": "198.51.100.77", "count": 7}]


def test_events_facets_respect_filters_and_limit(client: Any, database: Database) -> None:
    _seed_scene(database)
    response = client.get("/api/cases/case-1/events/facets?level=high&limit=5")
    assert response.status_code == 200, response.text
    facets = response.json()["facets"]
    assert sum(item["count"] for item in facets["host"]) == 4
    assert all(item["count"] <= 5 for column in facets.values() for item in column)


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------


def test_events_timeline_auto_and_alert_count(client: Any, database: Database) -> None:
    _seed_links(database)
    response = client.get("/api/cases/case-1/timeline")
    assert response.status_code == 200, response.text
    payload = response.json()
    aligned = (_TS // 60_000) * 60_000
    assert payload["bucket_ms"] == 60_000  # 6 s span -> finest bucket
    assert len(payload["buckets"]) == 1
    bucket = payload["buckets"][0]
    assert bucket["t_ms"] == aligned
    assert bucket["count"] == 7
    assert bucket["by_log_type"] == {"linux_auth": 7}
    assert bucket["alert_count"] == 1  # ids[3] is the only alert-linked event


def test_events_timeline_explicit_bucket_and_hour_split(client: Any, database: Database) -> None:
    _seed_case(database)
    _seed_source(database)
    aligned = (_TS // 60_000) * 60_000
    for index, ts_ms in enumerate((_TS, _TS + 60_000, _TS + 120_000)):
        _add_event(database, index=index, ts_ms=ts_ms, level="high")
    response = client.get("/api/cases/case-1/timeline?bucket=1m")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["bucket_ms"] == 60_000
    assert [b["t_ms"] for b in payload["buckets"]] == [
        aligned,
        aligned + 60_000,
        aligned + 120_000,
    ]
    assert [b["count"] for b in payload["buckets"]] == [1, 1, 1]
    response = client.get("/api/cases/case-1/timeline?bucket=1d")
    assert response.status_code == 200, response.text
    assert response.json()["bucket_ms"] == 86_400_000
    assert response.json()["buckets"][0]["count"] == 3


def test_events_timeline_respects_filters(client: Any, database: Database) -> None:
    _seed_links(database)
    response = client.get("/api/cases/case-1/timeline", params={"q": '"failed login"'})
    assert response.status_code == 200, response.text
    payload = response.json()
    assert len(payload["buckets"]) == 1
    assert payload["buckets"][0]["count"] == 3
    assert payload["buckets"][0]["alert_count"] == 1  # ids[3] is also alert-linked
    response = client.get(f"/api/cases/case-1/timeline?alert_id={_ALERT_ID}")
    assert response.status_code == 200, response.text
    assert response.json()["buckets"][0]["count"] == 1
    response = client.get("/api/cases/case-1/timeline?host=web01")
    assert response.status_code == 200, response.text
    assert response.json()["buckets"][0]["count"] == 4


def test_events_timeline_empty_and_validation(client: Any, database: Database) -> None:
    _seed_case(database)
    response = client.get("/api/cases/case-1/timeline")
    assert response.status_code == 200, response.text
    assert response.json()["bucket_ms"] == 60_000
    assert response.json()["buckets"] == []


def test_events_timeline_bucket_validation(client: Any, database: Database) -> None:
    _seed_scene(database)
    response = client.get("/api/cases/case-1/timeline?bucket=weekly")
    assert response.status_code == 422, response.text
    body = response.json()["error"]
    assert body["code"] == "VALIDATION_ERROR"
    assert "unsupported bucket" in body["message"]
    response = client.get("/api/cases/nope/timeline")
    assert response.status_code == 404, response.text
    assert response.json()["error"]["code"] == "NOT_FOUND"


# ---------------------------------------------------------------------------
# IOC / alert links and detail
# ---------------------------------------------------------------------------


def _seed_links(database: Database) -> list[int]:
    """Two events, one carrying an IOC occurrence and one alert_events link."""
    ids = _seed_scene(database)
    database.writer.execute(
        "INSERT INTO detection_runs (id, case_id, profile, tool_version, ruleset_hash, "
        "attack_version, started_at, status) "
        "VALUES (?, 'case-1', 'full', '1.0', 'deadbeef', '14.1', ?, 'done')",
        (_RUN_ID, _ISO),
    )
    database.writer.execute(
        "INSERT INTO alerts (id, case_id, run_id, rule_id, rule_title, rule_kind, rule_type, "
        "level, score, status, analyst_notes, tactics_json, techniques_json, "
        "groups_software_json, host, user_name, group_key, first_seen_ms, last_seen_ms, "
        "match_count, false_positives_json, references_json, created_at) "
        "VALUES (?, 'case-1', ?, ?, 'SSH Failed Password', 'builtin', 'detection', 'high', "
        "75, 'new', NULL, '[]', '[]', '[]', 'web01', 'victim', 'web01|victim', ?, ?, 1, "
        "'[]', '[]', ?)",
        (_ALERT_ID, _RUN_ID, _RULE_ID, _TS + 2000, _TS + 4000, _ISO),
    )
    database.writer.execute(
        "INSERT INTO alert_events (alert_id, event_id) VALUES (?, ?)",
        (_ALERT_ID, ids[3]),
    )
    database.writer.execute(
        "INSERT INTO iocs (id, case_id, type, value, value_norm, first_seen_ms, last_seen_ms, "
        "occurrences, confidence, is_private, is_allowlisted, analyst_state, tags_json) "
        "VALUES (?, 'case-1', 'ipv4', '198.51.100.77', '198.51.100.77', ?, ?, 1, 80, 0, 0, "
        "'none', '[]')",
        (_IOC_ID, _TS + 2000, _TS + 4000),
    )
    database.writer.execute(
        "INSERT INTO ioc_occurrences (ioc_id, event_id, field, role, decoded_from) "
        "VALUES (?, ?, 'src_ip', 'source', NULL)",
        (_IOC_ID, ids[2]),
    )
    return ids


def test_events_detail_with_alerts_and_iocs(client: Any, database: Database) -> None:
    ids = _seed_links(database)
    response = client.get(f"/api/events/{ids[3]}")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["id"] == ids[3]
    assert payload["raw"] == '{"seed": true}'
    assert payload["fields"] == {"foo": 3}
    assert len(payload["alerts"]) == 1
    alert = payload["alerts"][0]
    assert alert["id"] == _ALERT_ID
    assert alert["rule_title"] == "SSH Failed Password"
    assert alert["level"] == "high"
    assert alert["score"] == 75
    assert alert["status"] == "new"
    response = client.get(f"/api/events/{ids[2]}")
    assert response.status_code == 200, response.text
    assert response.json()["iocs"] == [
        {
            "id": _IOC_ID,
            "type": "ipv4",
            "value": "198.51.100.77",
            "value_norm": "198.51.100.77",
            "confidence": 80,
        }
    ]


def test_events_ioc_and_alert_filters(client: Any, database: Database) -> None:
    ids = _seed_links(database)
    response = client.get(f"/api/cases/case-1/events?ioc_id={_IOC_ID}")
    assert response.status_code == 200, response.text
    assert [item["id"] for item in response.json()["items"]] == [ids[2]]
    response = client.get(f"/api/cases/case-1/events?alert_id={_ALERT_ID}")
    assert response.status_code == 200, response.text
    assert [item["id"] for item in response.json()["items"]] == [ids[3]]
    response = client.get(f"/api/cases/case-1/events/count?ioc_id={_IOC_ID}")
    assert response.status_code == 200, response.text
    assert response.json() == {"count": 1}


# ---------------------------------------------------------------------------
# Validation and error paths
# ---------------------------------------------------------------------------


def test_events_missing_case_404(client: Any, database: Database) -> None:
    response = client.get("/api/cases/nope/events")
    assert response.status_code == 404, response.text
    assert response.json()["error"]["code"] == "NOT_FOUND"


def test_events_detail_missing_404(client: Any, database: Database) -> None:
    response = client.get("/api/events/999999")
    assert response.status_code == 404, response.text
    assert response.json()["error"]["code"] == "NOT_FOUND"


def test_events_validation_errors(client: Any, database: Database) -> None:
    _seed_scene(database)
    base = "/api/cases/case-1/events"
    cases = [
        ("?level=bogus", "unsupported event level"),
        ("?sort=host", "unsupported sort"),
        ("?include=bogus", "unsupported include"),
        ("?cursor=!!!", "invalid event cursor"),
    ]
    for query, message in cases:
        response = client.get(f"{base}{query}")
        assert response.status_code == 422, response.text
        body = response.json()["error"]
        assert body["code"] == "VALIDATION_ERROR", query
        assert message in body["message"], query


# ---------------------------------------------------------------------------
# Repository unit checks
# ---------------------------------------------------------------------------


def test_event_repository_get_and_count_with_fts_error(database: Database) -> None:
    ids = _seed_scene(database)
    with database.read_connection() as connection:
        repo = EventRepository(connection)
        assert repo.get(ids[0]) is not None
        assert repo.get(999_999) is None
        filters = EventFilters(case_id="case-1", q="failed login")
        assert repo.count(filters) == 3
        rows, next_cursor = repo.search(filters, limit=100)
        assert len(rows) == 3
        assert next_cursor is None
        rows, next_cursor = repo.search(EventFilters(case_id="case-1"), limit=2)
        assert len(rows) == 2
        assert next_cursor is not None
        assert next_cursor == (_TS + 5 * 1000, ids[5])
        bad = EventFilters(case_id="case-1", q="NEAR(")
        with pytest.raises(ValueError, match="invalid search query"):
            repo.search(bad)


def test_event_repository_facets_shape(database: Database) -> None:
    _seed_scene(database)
    with database.read_connection() as connection:
        repo = EventRepository(connection)
        facets = repo.facets(EventFilters(case_id="case-1"), limit=20)
        assert set(facets) == {"host", "log_type", "channel", "event_id", "user_name", "src_ip"}
        assert facets["host"][0]["count"] == 4
