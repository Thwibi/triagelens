"""Detection engine execution (spec 04 section 2, spec 09 D-03 to D-06).

Routing (D-03) is exercised against every entry of the shipped
``logsource_map.yaml``: an event pair is derived from each entry's own
statement, so the assertion "selects exactly its events" checks that the
engine routes the entry, that the route rejects a violating event, and that
prune, presence and the match query all run on the derived pair. The time
budget (D-05) and the ReDoS fence (D-06) use patterns calibrated on this
host: ``x+x+x+x+y`` passes the fence and needs milliseconds per value, while
``(a+)+$`` is rejected before any SQL runs.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import pytest
import yaml

from app.db.connection import Database, atomic
from app.detect.engine import EngineResult, execute_rules
from app.detect.routing import Route, Unroutable, build_route, load_logsource_map
from app.models.rule import KIND_CUSTOM, RULE_TYPE_CORRELATION, RuleRecord
from app.models.run import (
    RULE_RUN_ERROR,
    RULE_RUN_OK,
    RULE_RUN_SKIPPED_NO_DATA,
    RULE_RUN_TIMEOUT,
)

BACKEND_ROOT = Path(__file__).resolve().parents[1]
MAP: dict[str, dict[str, str]] = load_logsource_map(BACKEND_ROOT / "rules" / "logsource_map.yaml")

_TS = 1_700_000_000_000
_ISO = "2026-01-01T00:00:00.000Z"
_ROUTE_COLUMN = re.compile(r"(log_type|channel|app_name|ls_category)\b")
_ATOM_IN = re.compile(r"\w+\s+IN\s*\(", re.I)

#: Event column defaults for the fixtures; every test overrides what its rule
#: routes or matches on.
_EVENT_DEFAULTS: dict[str, Any] = {
    "log_type": "linux_auth",
    "app_name": "sshd",
    "channel": None,
    "ls_category": None,
    "host": None,
    "user_name": None,
    "message": "",
    "ts_ms": _TS,
}


def _seed_case(database: Database, case_id: str = "case-1") -> None:
    database.writer.execute(
        "INSERT INTO cases (id, name, description, default_timezone, created_at, updated_at) "
        "VALUES (?, ?, NULL, 'UTC', ?, ?)",
        (case_id, case_id, _ISO, _ISO),
    )


def _seed_source(database: Database, source_id: str = "src-1", case_id: str = "case-1") -> None:
    database.writer.execute(
        "INSERT INTO sources (id, case_id, filename, stored_path, size_bytes, sha256, "
        "status, ingested_at) VALUES (?, ?, ?, ?, 0, 'deadbeef', 'done', ?)",
        (source_id, case_id, f"{source_id}.log", f"/tmp/{source_id}.log", _ISO),
    )


def _insert_inventory(
    database: Database, values: dict[str, str], *, source_id: str = "src-1"
) -> None:
    database.writer.execute(
        "INSERT OR IGNORE INTO source_inventory ("
        "source_id, log_type, channel, app_name, ls_category, event_count"
        ") VALUES (?, ?, ?, ?, ?, 1)",
        (
            source_id,
            values.get("log_type", ""),
            values.get("channel", ""),
            values.get("app_name", ""),
            values.get("ls_category", ""),
        ),
    )


def _insert_events(
    database: Database,
    rows: Sequence[dict[str, Any]],
    *,
    case_id: str = "case-1",
    source_id: str = "src-1",
) -> list[int]:
    ids: list[int] = []
    with atomic(database.writer):
        for offset, row in enumerate(rows):
            values = {**_EVENT_DEFAULTS, **row}
            cursor = database.writer.execute(
                "INSERT INTO events (case_id, source_id, record_ref, ts_ms, ts_iso, "
                "log_type, ls_category, host, channel, app_name, user_name, message, raw) "
                "VALUES (?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, '{}')",
                (
                    case_id,
                    source_id,
                    str(offset),
                    values["ts_ms"],
                    values["log_type"],
                    values["ls_category"],
                    values["host"],
                    values["channel"],
                    values["app_name"],
                    values["user_name"],
                    values["message"],
                ),
            )
            ids.append(int(cursor.lastrowid or 0))
    return ids


def _record(
    *,
    rule_id: str = "rule",
    logsource: dict[str, Any] | None = None,
    detection: dict[str, Any] | None = None,
    yaml_text: str | None = None,
    compile_error: str | None = None,
    unroutable: bool = False,
    rule_type: str = "detection",
) -> RuleRecord:
    source = logsource if logsource is not None else {"product": "linux", "service": "sshd"}
    if yaml_text is None:
        document: dict[str, Any] = {
            "title": f"Rule {rule_id}",
            "logsource": source,
            "detection": detection
            if detection is not None
            else {"selection": {"message": "x"}, "condition": "selection"},
        }
        yaml_text = yaml.safe_dump(document, sort_keys=False)
    return RuleRecord(
        id=rule_id,
        title=f"Rule {rule_id}",
        kind=KIND_CUSTOM,
        rule_type=rule_type,
        level="medium",
        status="stable",
        enabled=True,
        yaml=yaml_text,
        tags=(),
        logsource=source,
        file_path=None,
        sha256="0" * 64,
        compile_error=compile_error,
        unroutable=unroutable,
        updated_at=_ISO,
    )


def _execute(
    database: Database,
    rules: Sequence[RuleRecord],
    *,
    case_id: str = "case-1",
    timeout: float = 30.0,
    is_cancelled: Callable[[], bool] | None = None,
) -> EngineResult:
    with database.read_connection() as connection:
        return execute_rules(
            connection,
            case_id=case_id,
            rules=rules,
            logsource_map=MAP,
            timeout_seconds=timeout,
            is_cancelled=is_cancelled,
        )


def _map_triples(
    table: dict[str, dict[str, str]],
) -> list[tuple[str | None, str | None, str | None]]:
    """One canonical logsource per map entry: every entry reachable exactly once."""
    triples: list[tuple[str | None, str | None, str | None]] = []
    for key in sorted(table["product"]):
        triples.append((key, None, None))
    for key in sorted(table["service"]):
        if "/" in key:
            product, service = key.split("/", 1)
            triples.append((product, service, None))
        else:
            triples.append((None, key, None))
    for key in sorted(table["category"]):
        triples.append((None, None, key))
    return triples


def _route_matches(values: dict[str, str], route_sql: str) -> bool:
    """Evaluate a routing statement against one event's column values."""
    for raw_section in route_sql.split(" AND "):
        section = raw_section.strip()
        if section.startswith("(") and section.endswith(")"):
            section = section[1:-1]
        matched = False
        for raw_atom in re.split(r"\s+OR\s+", section):
            atom = raw_atom.strip()
            column = _ROUTE_COLUMN.match(atom)
            if column is None:  # pragma: no cover - the loader validates atoms
                raise AssertionError(f"unparsed routing atom: {atom!r}")
            value = values.get(column.group(1))
            if value is None:
                continue
            literals = re.findall(r"'([^']*)'", atom)
            if _ATOM_IN.match(atom):
                matched = matched or value in literals
            else:
                matched = matched or (bool(literals) and value == literals[0])
        if not matched:
            return False
    return True


class TestD03Routing:
    def test_every_routing_entry_selects_exactly_its_events(self, database: Database) -> None:
        _seed_case(database)
        _seed_source(database)
        triples = _map_triples(MAP)
        rows: list[dict[str, Any]] = []
        satisfying: list[dict[str, str]] = []
        for index, (product, service, category) in enumerate(triples):
            route = build_route(MAP, product, service, category)
            assert not isinstance(route, Unroutable), f"{(product, service, category)} routes"
            values = _first_literals(route.sql)
            marker = f"match-{index}"
            satisfying.append(values)
            rows.append({**values, "message": marker})
            rows.append(
                {
                    **dict.fromkeys(_ROUTE_COLUMNS, f"__never-{index}__"),
                    "message": marker,
                }
            )
        event_ids = _insert_events(database, rows)

        for index, (product, service, category) in enumerate(triples):
            route = build_route(MAP, product, service, category)
            assert isinstance(route, Route)
            values = satisfying[index]
            violating = {
                **dict.fromkeys(_ROUTE_COLUMNS, f"__never-{index}__"),
                "message": "x",
            }
            assert _route_matches(values, route.sql), f"constructed event misses {route.sql}"
            assert not _route_matches(violating, route.sql), f"violating event matches {route.sql}"
            _insert_inventory(database, values)
            rule = _record(
                rule_id=f"entry-{index}",
                logsource=_logsource(product, service, category),
                detection={"selection": {"message": f"match-{index}"}, "condition": "selection"},
            )
            result = _execute(database, [rule])
            outcome = result.outcomes[0]
            assert outcome.status == RULE_RUN_OK, f"entry {index}: {outcome.error}"
            assert outcome.match_count == 1
            matched = [match.event_id for match in result.executions[0].matches]
            assert matched == [event_ids[2 * index]]

    def test_unknown_logsource_is_unroutable(self, database: Database) -> None:
        _seed_case(database)
        _seed_source(database)
        _insert_inventory(database, {"log_type": "linux_auth", "app_name": "sshd"})
        _insert_events(database, [{"message": "hello"}])
        rule = _record(
            rule_id="unknown",
            logsource={"product": "nonsuch"},
            detection={"selection": {"message": "hello"}, "condition": "selection"},
        )
        result = _execute(database, [rule])
        outcome = result.outcomes[0]
        assert outcome.status == RULE_RUN_ERROR
        assert outcome.error is not None
        assert "unroutable" in outcome.error
        assert "nonsuch" in outcome.error
        assert outcome.match_count == 0


class TestD04Pruning:
    def test_rules_with_no_matching_inventory_are_skipped(self, database: Database) -> None:
        _seed_case(database)
        _seed_source(database)
        _insert_events(database, [{"message": "hello"}])
        rule = _record(detection={"selection": {"message": "hello"}, "condition": "selection"})
        outcome = _execute(database, [rule]).outcomes[0]
        assert outcome.status == RULE_RUN_SKIPPED_NO_DATA
        assert outcome.match_count == 0
        assert outcome.error is None

    def test_inventory_of_another_case_does_not_unskip(self, database: Database) -> None:
        _seed_case(database, "case-1")
        _seed_case(database, "case-2")
        _seed_source(database, "src-1", "case-1")
        _seed_source(database, "src-2", "case-2")
        _insert_inventory(
            database, {"log_type": "linux_auth", "app_name": "sshd"}, source_id="src-2"
        )
        _insert_events(database, [{"message": "hello"}])
        rule = _record(detection={"selection": {"message": "hello"}, "condition": "selection"})
        outcome = _execute(database, [rule], case_id="case-1").outcomes[0]
        assert outcome.status == RULE_RUN_SKIPPED_NO_DATA

    def test_inventory_with_no_events_still_executes(self, database: Database) -> None:
        _seed_case(database)
        _seed_source(database)
        _insert_inventory(database, {"log_type": "linux_auth", "app_name": "sshd"})
        rule = _record(detection={"selection": {"message": "absent"}, "condition": "selection"})
        outcome = _execute(database, [rule]).outcomes[0]
        assert outcome.status == RULE_RUN_OK
        assert outcome.match_count == 0
        assert outcome.error is None


class TestD05Timeout:
    def test_slow_regex_hits_the_budget_and_other_rules_are_unaffected(
        self, database: Database
    ) -> None:
        _seed_case(database)
        _seed_source(database)
        _insert_inventory(database, {"log_type": "linux_auth", "app_name": "sshd"})
        rows: list[dict[str, Any]] = [{"message": "x" * 100} for _ in range(2000)]
        rows.extend({"message": "needle-hit"} for _ in range(5))
        _insert_events(database, rows)

        slow = _record(
            rule_id="slow",
            detection={
                "selection": {"message|re": "x+x+x+x+y"},
                "condition": "selection",
            },
        )
        fast = _record(
            rule_id="fast",
            detection={"selection": {"message": "needle-hit"}, "condition": "selection"},
        )

        started = time.monotonic()
        result = _execute(database, [slow, fast], timeout=1.0)
        elapsed = time.monotonic() - started

        assert result.cancelled is False
        assert [outcome.status for outcome in result.outcomes] == [
            RULE_RUN_TIMEOUT,
            RULE_RUN_OK,
        ]
        slow_out, fast_out = result.outcomes
        assert slow_out.match_count == 0
        assert slow_out.duration_ms >= 1000
        assert slow_out.error is not None
        assert "budget" in slow_out.error
        assert fast_out.match_count == 5
        assert fast_out.error is None
        assert fast_out.duration_ms < 1000
        assert elapsed < 10


class TestD06Redos:
    def test_catastrophic_pattern_is_rejected_before_execution(self, database: Database) -> None:
        _seed_case(database)
        _seed_source(database)
        _insert_inventory(database, {"log_type": "linux_auth", "app_name": "sshd"})
        _insert_events(database, [{"message": "a" * 50 + "!"} for _ in range(10)])

        evil = _record(
            rule_id="evil",
            detection={"selection": {"message|re": "(a+)+$"}, "condition": "selection"},
        )
        companion = _record(
            rule_id="companion",
            detection={"selection": {"message|contains": "a"}, "condition": "selection"},
        )

        started = time.monotonic()
        result = _execute(database, [evil, companion])
        elapsed = time.monotonic() - started

        evil_out, companion_out = result.outcomes
        assert evil_out.status == RULE_RUN_ERROR
        assert evil_out.error is not None
        assert "regexp rejected" in evil_out.error
        assert "'(a+)+$'" in evil_out.error
        assert evil_out.match_count == 0
        assert companion_out.status == RULE_RUN_OK
        assert companion_out.match_count == 10
        assert elapsed < 5


class TestPipelineOutcomes:
    def test_catalogue_compile_error_short_circuits_with_its_reason(
        self, database: Database
    ) -> None:
        rule = _record(
            yaml_text="title: [unclosed",
            compile_error="unsupported modifier: zzz",
        )
        outcome = _execute(database, [rule]).outcomes[0]
        assert outcome.status == RULE_RUN_ERROR
        assert outcome.error == "unsupported modifier: zzz"

    def test_unparseable_yaml_records_a_parse_error(self, database: Database) -> None:
        outcome = _execute(database, [_record(yaml_text="title: [unclosed")]).outcomes[0]
        assert outcome.status == RULE_RUN_ERROR
        assert outcome.error is not None
        assert outcome.error.startswith("cannot parse rule:")

    def test_a_non_mapping_document_records_a_parse_error(self, database: Database) -> None:
        outcome = _execute(database, [_record(yaml_text="- just\n- a list\n")]).outcomes[0]
        assert outcome.status == RULE_RUN_ERROR
        assert outcome.error == "cannot parse rule: rule document is not a mapping"

    def test_field_never_present_is_a_warning_on_a_ok_rule(self, database: Database) -> None:
        _seed_case(database)
        _seed_source(database)
        _insert_inventory(database, {"log_type": "linux_auth", "app_name": "sshd"})
        _insert_events(database, [{"message": "hello"}])
        rule = _record(detection={"selection": {"NonexistentField": "x"}, "condition": "selection"})
        outcome = _execute(database, [rule]).outcomes[0]
        assert outcome.status == RULE_RUN_OK
        assert outcome.match_count == 0
        assert outcome.error == "field_never_present: NonexistentField"

    def test_matches_come_back_in_ts_then_id_order(self, database: Database) -> None:
        _seed_case(database)
        _seed_source(database)
        _insert_inventory(database, {"log_type": "linux_auth", "app_name": "sshd"})
        ids = _insert_events(
            database,
            [
                {"message": "det", "ts_ms": 300},
                {"message": "det", "ts_ms": 100},
                {"message": "det", "ts_ms": 100},
                {"message": "det", "ts_ms": 200},
            ],
        )
        rule = _record(detection={"selection": {"message": "det"}, "condition": "selection"})
        result = _execute(database, [rule])
        matched = [match.event_id for match in result.executions[0].matches]
        assert matched == [ids[1], ids[2], ids[3], ids[0]]

    def test_two_runs_over_the_same_data_agree(self, database: Database) -> None:
        _seed_case(database)
        _seed_source(database)
        _insert_inventory(database, {"log_type": "linux_auth", "app_name": "sshd"})
        _insert_events(
            database,
            [{"message": "det", "ts_ms": _TS + index} for index in range(3)],
        )
        first = _record(
            rule_id="first",
            detection={"selection": {"message": "det"}, "condition": "selection"},
        )
        second = _record(
            rule_id="second",
            detection={"selection": {"message": "det"}, "condition": "selection"},
        )
        run_one = _execute(database, [first, second])
        run_two = _execute(database, [first, second])

        def comparable(result: EngineResult) -> list[tuple[str, str, int, str | None]]:
            return [
                (outcome.rule_id, outcome.status, outcome.match_count, outcome.error)
                for outcome in result.outcomes
            ]

        assert comparable(run_one) == comparable(run_two)
        assert run_one.executions[0].matches == run_two.executions[0].matches
        assert [outcome.rule_id for outcome in run_one.outcomes] == ["first", "second"]

    def test_cancellation_stops_between_rules(self, database: Database) -> None:
        _seed_case(database)
        _seed_source(database)
        _insert_inventory(database, {"log_type": "linux_auth", "app_name": "sshd"})
        _insert_events(database, [{"message": "det"}])
        first = _record(
            rule_id="first", detection={"selection": {"message": "det"}, "condition": "selection"}
        )
        second = _record(
            rule_id="second", detection={"selection": {"message": "det"}, "condition": "selection"}
        )
        polls = {"count": 0}

        def cancel_after_first() -> bool:
            polls["count"] += 1
            return polls["count"] > 1

        result = _execute(database, [first, second], is_cancelled=cancel_after_first)
        assert result.cancelled is True
        assert [execution.outcome.rule_id for execution in result.executions] == ["first"]

    def test_correlation_rules_are_rejected_here(self, database: Database) -> None:
        rule = _record(rule_id="corr", rule_type=RULE_TYPE_CORRELATION)
        with pytest.raises(ValueError, match="correlation"):
            _execute(database, [rule])


def _logsource(product: str | None, service: str | None, category: str | None) -> dict[str, Any]:
    logsource: dict[str, Any] = {}
    if product is not None:
        logsource["product"] = product
    if service is not None:
        logsource["service"] = service
    if category is not None:
        logsource["category"] = category
    return logsource


def _first_literals(route_sql: str) -> dict[str, str]:
    """First literal of the first atom per AND-section: a satisfying assignment."""
    values: dict[str, str] = {}
    for raw_section in route_sql.split(" AND "):
        section = raw_section.strip()
        if section.startswith("(") and section.endswith(")"):
            section = section[1:-1]
        first = re.split(r"\s+OR\s+", section)[0].strip()
        column = _ROUTE_COLUMN.match(first)
        literal = re.search(r"'([^']*)'", first)
        if column is not None and literal is not None:
            values[column.group(1)] = literal.group(1)
    return values


_ROUTE_COLUMNS = ("log_type", "channel", "app_name", "ls_category")
