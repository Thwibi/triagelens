"""Adversarial SQL-injection sweep (spec 10 section 1, S-04).

Every free-text filter the events API accepts is hit with closing-quote /
``DROP TABLE`` payloads and the response must never be a 500; afterwards the
schema and the event rows must be exactly as before. The rule-field path is
covered separately: a Sigma field name carrying a single quote must compile
into an SQL text where the quote is doubled, so executing the rule cannot
touch anything but ``events`` reads.
"""

from __future__ import annotations

from typing import Any

from app.db.connection import Database
from app.detect.compile import compile_detection
from app.detect.rules import load_rules_from_text

_ISO = "2026-01-01T00:00:00.000Z"

#: The classic breaking quote plus a tautology variant.
_ADVERSARIAL = (
    "'; DROP TABLE events;--",
    "' OR '1'='1",
)

_HOSTILE_FIELD = "a'; DROP TABLE events;--"


def _table_names(database: Database) -> set[str]:
    with database.read_connection() as connection:
        rows = connection.execute(
            "SELECT name FROM sqlite_master WHERE type IN ('table', 'view')"
        ).fetchall()
    return {row["name"] for row in rows}


def _count_events(database: Database) -> int:
    with database.read_connection() as connection:
        return int(connection.execute("SELECT COUNT(*) FROM events").fetchone()[0])


def _seed(database: Database) -> None:
    database.writer.execute(
        "INSERT INTO cases (id, name, description, default_timezone, created_at, updated_at) "
        "VALUES ('case-1', 'scene', NULL, 'UTC', ?, ?)",
        (_ISO, _ISO),
    )
    database.writer.execute(
        "INSERT INTO sources (id, case_id, filename, stored_path, size_bytes, sha256, "
        "status, ingested_at) VALUES ('src-1', 'case-1', 'a.log', '/tmp/a.log', 0, "
        "'deadbeef', 'done', ?)",
        (_ISO,),
    )
    database.writer.execute(
        "INSERT INTO source_inventory (source_id, log_type, channel, app_name, "
        "ls_category, event_count) VALUES ('src-1', 'linux_auth', '', 'sshd', '', 0)"
    )
    database.writer.execute(
        "INSERT INTO events (case_id, source_id, record_ref, ts_ms, ts_iso, log_type, "
        "ls_category, host, channel, app_name, event_id, level, event_action, user_name, "
        "src_ip, message, raw, fields_json) VALUES ('case-1', 'src-1', '1', 1700000000000, "
        "NULL, 'linux_auth', '', 'web01', '', 'sshd', NULL, 'high', NULL, 'root', "
        "'10.0.0.1', 'failed login', '{\"seed\": true}', '{}')"
    )


def _hostile_rule() -> Any:
    body = (
        "title: Inject\n"
        "logsource: { category: webserver }\n"
        "detection:\n"
        "  selection:\n"
        '    "a\'; DROP TABLE events;--": 1\n'
        "  condition: selection\n"
        "level: low\n"
    )
    rules, problems = load_rules_from_text(body)
    assert problems == []
    return rules[0]


class TestEventFilterSweep:
    """Injection payloads through every events filter; nothing may 500."""

    _STRING_PARAMS = (
        "q",
        "host",
        "source_id",
        "log_type",
        "channel",
        "ls_category",
        "user_name",
        "src_ip",
        "dst_ip",
        "ioc_id",
        "alert_id",
        "level",
    )
    _FILTER_ENDPOINTS = (
        "/api/cases/case-1/events",
        "/api/cases/case-1/events/count",
        "/api/cases/case-1/events/facets",
        "/api/cases/case-1/timeline",
    )

    def test_every_filter_param_survives_drop_payloads(
        self, client: Any, database: Database
    ) -> None:
        _seed(database)
        tables_before = _table_names(database)
        count_before = _count_events(database)

        for payload in _ADVERSARIAL:
            for endpoint in self._FILTER_ENDPOINTS:
                for name in self._STRING_PARAMS:
                    response = client.get(endpoint, params={name: payload})
                    assert response.status_code != 500, (
                        f"{endpoint}?{name}={payload!r} -> {response.status_code}"
                    )

        for payload in _ADVERSARIAL:
            assert (
                client.get("/api/cases/case-1/events", params={"sort": payload}).status_code != 500
            )
            assert (
                client.get("/api/cases/case-1/events", params={"cursor": payload}).status_code
                != 500
            )
            assert (
                client.get("/api/cases/case-1/timeline", params={"bucket": payload}).status_code
                != 500
            )
            assert (
                client.get(
                    "/api/cases/case-1/events/export", params={"q": payload, "sort": "-ts"}
                ).status_code
                != 500
            )

        assert _table_names(database) == tables_before
        assert _count_events(database) == count_before

    def test_drop_payload_as_the_host_filter_leaves_the_events_table_alone(
        self, client: Any, database: Database
    ) -> None:
        _seed(database)
        tables_before = _table_names(database)
        for payload in _ADVERSARIAL:
            response = client.get("/api/cases/case-1/events", params={"host": payload, "limit": 5})
            assert response.status_code in (200, 422)
        with database.read_connection() as connection:
            rows = connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'events'"
            ).fetchall()
        assert len(rows) == 1
        assert _table_names(database) == tables_before


class TestRuleFieldNameSweep:
    """A Sigma field name that carries a single quote cannot break the query."""

    def test_the_compiled_sql_doubles_the_quote(self) -> None:
        rule = _hostile_rule()
        compiled = compile_detection(rule.sigma_rule)
        assert compiled is not None
        assert _HOSTILE_FIELD.replace("'", "''") in compiled.sql
        opening = compiled.sql.index('"') + 1
        closing = compiled.sql.index('"', opening)
        key = compiled.sql[opening:closing]
        assert "'" not in key or "''" in key
        assert "out of range" not in compiled.sql.lower()

    def test_executing_the_hostile_rule_leaves_the_schema_intact(self, database: Database) -> None:
        _seed(database)
        rule = _hostile_rule()
        compiled = compile_detection(rule.sigma_rule)
        assert compiled is not None
        route = rule.route
        assert route is not None

        tables_before = _table_names(database)
        count_before = _count_events(database)
        with database.read_connection() as connection:
            sql = (
                f"SELECT id FROM events WHERE case_id = ? AND ({route.sql}) "
                f"AND ({compiled.sql}) ORDER BY ts_ms, id"
            )
            connection.execute(sql, ("case-1",)).fetchall()

        assert _table_names(database) == tables_before
        assert _count_events(database) == count_before

    def test_receiving_a_hostile_field_through_the_import_api_is_harmless(
        self, client: Any, database: Database
    ) -> None:
        _seed(database)
        tables_before = _table_names(database)
        count_before = _count_events(database)
        body = (
            "title: Inject\n"
            "logsource: { category: webserver }\n"
            "detection:\n"
            "  selection:\n"
            '    "a\'; DROP TABLE events;--": 1\n'
            "  condition: selection\n"
            "level: low\n"
        )
        response = client.post(
            "/api/rules/import",
            files={"files": ("hostile.yml", body.encode("utf-8"), "application/yaml")},
        )
        assert response.status_code in (200, 422)
        assert _table_names(database) == tables_before
        assert _count_events(database) == count_before
