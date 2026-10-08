"""Correlation stage (spec 04 section 5, spec 09 D-07).

Boundary coverage for every correlation type: the ``event_count`` threshold
(9 vs 10 events) and the closed window edge, ``value_count`` distinctness,
``temporal`` and ``temporal_ordered`` including order violations, nested
chains at the depth limit and beyond, reference cycles, and the
``generate`` flag. Group values ride the base rules' own logsource field
resolution, so a Windows ``IpAddress`` group-by and a Linux ``src_ip``
group-by are both tested end to end.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

import pytest
import yaml

from app.db.connection import Database, atomic
from app.detect.correlation import (
    CorrelationResult,
    bases_suppressed_by_correlations,
    build_firing_drafts,
    execute_correlations,
    record_run_alerts,
    run_drafts,
)
from app.detect.engine import EventMatch, RuleExecution, RuleOutcome
from app.detect.routing import load_logsource_map
from app.detect.rules import load_rules
from app.models.alert import AlertRecord
from app.models.rule import (
    KIND_BUILTIN,
    RULE_TYPE_CORRELATION,
    RULE_TYPE_DETECTION,
    RuleRecord,
)
from app.models.run import (
    RULE_RUN_ERROR,
    RULE_RUN_OK,
    RULE_RUN_SKIPPED_NO_DATA,
)

BACKEND_ROOT = Path(__file__).resolve().parents[1]
MAP: dict[str, dict[str, str]] = load_logsource_map(BACKEND_ROOT / "rules" / "logsource_map.yaml")

_TS = 1_700_000_000_000
_ISO = "2026-01-01T00:00:00.000Z"
_LINUX_SOURCE = {"product": "linux", "service": "sshd"}
_WINDOWS_SOURCE = {"product": "windows", "service": "security"}

_BASE_SSH_FAIL = {
    "title": "SSH Failed Password",
    "id": "base-ssh-fail",
    "status": "stable",
    "logsource": {"product": "linux", "service": "sshd"},
    "detection": {
        "selection": {"event_action": ["ssh_failed_password", "ssh_invalid_user"]},
        "condition": "selection",
    },
    "level": "informational",
}
_BASE_SSH_OK = {
    "title": "SSH Accepted Login",
    "id": "base-ssh-ok",
    "status": "stable",
    "logsource": {"product": "linux", "service": "sshd"},
    "detection": {"selection": {"event_action": "ssh_accepted_login"}, "condition": "selection"},
    "level": "informational",
}
_BASE_WIN_FAIL = {
    "title": "Windows Failed Logon",
    "id": "base-win-fail",
    "status": "stable",
    "logsource": {"product": "windows", "service": "security"},
    "detection": {"selection": {"EventID": 4625}, "condition": "selection"},
    "level": "informational",
}


def _seed(database: Database) -> None:
    database.writer.execute(
        "INSERT INTO cases (id, name, description, default_timezone, created_at, updated_at) "
        "VALUES ('case-1', 'case-1', NULL, 'UTC', ?, ?)",
        (_ISO, _ISO),
    )
    database.writer.executemany(
        "INSERT INTO detection_runs (id, case_id, profile, tool_version, ruleset_hash, "
        "attack_version, started_at, finished_at, status) "
        "VALUES (?, 'case-1', 'standard', '1', ?, '', ?, NULL, 'done')",
        [("run-1", "0" * 64, _ISO), ("run-2", "0" * 64, _ISO)],
    )
    database.writer.execute(
        "INSERT INTO sources (id, case_id, filename, stored_path, size_bytes, sha256, "
        "status, ingested_at) VALUES ('src-1', 'case-1', 'a.log', '/tmp/a.log', 0, "
        "'deadbeef', 'done', ?)",
        (_ISO,),
    )
    database.writer.executemany(
        "INSERT INTO source_inventory (source_id, log_type, channel, app_name, "
        "ls_category, event_count) VALUES ('src-1', ?, ?, ?, '', 1)",
        [
            ("linux_auth", "", "sshd"),
            ("windows_evtx", "Security", ""),
        ],
    )


def _insert_events(
    database: Database,
    rows: list[dict[str, Any]],
) -> list[int]:
    ids: list[int] = []
    with atomic(database.writer):
        for offset, row in enumerate(rows):
            cursor = database.writer.execute(
                "INSERT INTO events (case_id, source_id, record_ref, ts_ms, ts_iso, "
                "log_type, ls_category, host, channel, app_name, user_name, message, "
                "raw, event_action, src_ip, fields_json, event_id) "
                "VALUES ('case-1', 'src-1', ?, ?, NULL, ?, '', ?, ?, ?, ?, '', '{}', "
                "?, ?, ?, ?)",
                (
                    str(offset),
                    row["ts_ms"],
                    row.get("log_type", "linux_auth"),
                    row.get("host"),
                    row.get("channel"),
                    row.get("app_name", "sshd"),
                    row.get("user_name"),
                    row.get("event_action"),
                    row.get("src_ip"),
                    row.get("fields_json", "{}"),
                    row.get("event_id"),
                ),
            )
            ids.append(int(cursor.lastrowid or 0))
    return ids


def _ssh_fail_events(database: Database, count: int, *, src_ip: str = "198.51.100.77") -> list[int]:
    return _insert_events(
        database,
        [
            {
                "ts_ms": _TS + index * 1000,
                "event_action": "ssh_failed_password",
                "src_ip": src_ip,
                "user_name": f"victim{index}",
            }
            for index in range(count)
        ],
    )


def _rule(
    document: dict[str, Any],
    *,
    rule_type: str = RULE_TYPE_DETECTION,
    level: str = "high",
) -> RuleRecord:
    # The catalogue id stays friendly for refs; the YAML drops it because
    # pySigma only accepts UUID identifiers (and Sigma ids are optional).
    body = {key: value for key, value in document.items() if key != "id"}
    return RuleRecord(
        id=str(document["id"]),
        title=str(document["title"]),
        kind=KIND_BUILTIN,
        rule_type=rule_type,
        level=level,
        status=str(document.get("status")) if document.get("status") is not None else None,
        enabled=True,
        yaml=yaml.safe_dump(body, sort_keys=False),
        tags=(),
        logsource=dict(document.get("logsource") or {}),
        file_path=None,
        sha256="deadbeef",
        compile_error=None,
        unroutable=False,
        updated_at=_ISO,
    )


def _corr_rule(
    *,
    rule_id: str,
    title: str,
    corr_type: str,
    refs: list[str],
    group_by: list[str] | None = None,
    timespan: str = "5m",
    condition: dict[str, Any] | None = None,
    generate: bool | None = None,
    level: str = "high",
) -> RuleRecord:
    block: dict[str, Any] = {"type": corr_type, "rules": refs, "timespan": timespan}
    if group_by:
        block["group-by"] = group_by
    if condition is not None:
        block["condition"] = condition
    if generate is not None:
        block["generate"] = generate
    return _rule(
        {"title": title, "id": rule_id, "status": "stable", "correlation": block},
        rule_type=RULE_TYPE_CORRELATION,
        level=level,
    )


def _exec(
    rule_id: str,
    matches: tuple[EventMatch, ...] = (),
    *,
    status: str = RULE_RUN_OK,
    error: str | None = None,
) -> RuleExecution:
    return RuleExecution(RuleOutcome(rule_id, status, len(matches), 1, error), matches)


def _base_records() -> tuple[RuleRecord, RuleRecord, RuleRecord]:
    return (
        _rule(_BASE_SSH_FAIL, level="informational"),
        _rule(_BASE_SSH_OK, level="informational"),
        _rule(_BASE_WIN_FAIL, level="informational"),
    )


def _run(
    database: Database,
    correlations: list[RuleRecord],
    base_executions: dict[str, RuleExecution],
    *,
    catalogue: list[RuleRecord] | None = None,
) -> CorrelationResult:
    all_rules = [*_base_records(), *correlations]
    return execute_correlations(
        database.writer,
        case_id="case-1",
        rules=correlations,
        catalogue=catalogue if catalogue is not None else all_rules,
        base_executions=base_executions,
        logsource_map=MAP,
    )


class TestEventCount:
    def test_nine_events_below_the_threshold_do_not_fire(self, database: Database) -> None:
        _seed(database)
        _ssh_fail_events(database, 9)
        base = _rule(_BASE_SSH_FAIL, level="informational")
        corr = _corr_rule(
            rule_id="c1",
            title="SSH Brute Force",
            corr_type="event_count",
            refs=[base.id],
            group_by=["src_ip"],
            condition={"gte": 10},
        )
        result = _run(database, [corr], {base.id: _exec(base.id)})
        (execution,) = result.executions
        assert execution.outcome.status == RULE_RUN_OK
        assert execution.outcome.match_count == 0
        assert result.firings == ()

    def test_ten_events_in_the_window_fire_once(self, database: Database) -> None:
        _seed(database)
        _ssh_fail_events(database, 10)
        base = _rule(_BASE_SSH_FAIL, level="informational")
        corr = _corr_rule(
            rule_id="c1",
            title="SSH Brute Force",
            corr_type="event_count",
            refs=[base.id],
            group_by=["src_ip"],
            condition={"gte": 10},
        )
        result = _run(database, [corr], {base.id: _exec(base.id)})
        (firing,) = result.firings
        assert firing.rule_id == "c1"
        assert firing.group_key == "198.51.100.77"
        assert len(firing.matches) == 10
        assert firing.matches[0].ts_ms == _TS
        assert firing.matches[-1].ts_ms == _TS + 9000

    def test_the_window_edge_is_inclusive(self, database: Database) -> None:
        _seed(database)
        _insert_events(
            database,
            [
                {
                    "ts_ms": _TS + (300000 if index == 9 else index * 1000),
                    "event_action": "ssh_failed_password",
                    "src_ip": "198.51.100.77",
                    "user_name": f"victim{index}",
                }
                for index in range(10)
            ],
        )
        base = _rule(_BASE_SSH_FAIL, level="informational")
        corr = _corr_rule(
            rule_id="c1",
            title="SSH Brute Force",
            corr_type="event_count",
            refs=[base.id],
            group_by=["src_ip"],
            timespan="5m",
            condition={"gte": 10},
        )
        result = _run(database, [corr], {base.id: _exec(base.id)})
        assert len(result.firings) == 1  # the 10th event sits exactly 5m after the first

    def test_one_millisecond_past_the_edge_falls_out(self, database: Database) -> None:
        _seed(database)
        _insert_events(
            database,
            [
                {
                    "ts_ms": _TS + (300001 if index == 9 else index * 1000),
                    "event_action": "ssh_failed_password",
                    "src_ip": "198.51.100.77",
                    "user_name": f"victim{index}",
                }
                for index in range(10)
            ],
        )
        base = _rule(_BASE_SSH_FAIL, level="informational")
        corr = _corr_rule(
            rule_id="c1",
            title="SSH Brute Force",
            corr_type="event_count",
            refs=[base.id],
            group_by=["src_ip"],
            timespan="5m",
            condition={"gte": 10},
        )
        result = _run(database, [corr], {base.id: _exec(base.id)})
        assert result.firings == ()

    def test_overlapping_firings_coalesce_into_one(self, database: Database) -> None:
        _seed(database)
        _ssh_fail_events(database, 15)
        base = _rule(_BASE_SSH_FAIL, level="informational")
        corr = _corr_rule(
            rule_id="c1",
            title="SSH Brute Force",
            corr_type="event_count",
            refs=[base.id],
            group_by=["src_ip"],
            condition={"gte": 10},
        )
        result = _run(database, [corr], {base.id: _exec(base.id)})
        (firing,) = result.firings
        assert len(firing.matches) == 15
        (execution,) = result.executions
        assert execution.outcome.match_count == 15

    def test_each_group_fires_on_its_own(self, database: Database) -> None:
        _seed(database)
        _ssh_fail_events(database, 10, src_ip="198.51.100.77")
        _ssh_fail_events(database, 10, src_ip="192.0.2.66")
        base = _rule(_BASE_SSH_FAIL, level="informational")
        corr = _corr_rule(
            rule_id="c1",
            title="SSH Brute Force",
            corr_type="event_count",
            refs=[base.id],
            group_by=["src_ip"],
            condition={"gte": 10},
        )
        result = _run(database, [corr], {base.id: _exec(base.id)})
        assert sorted(firing.group_key for firing in result.firings) == [
            "192.0.2.66",
            "198.51.100.77",
        ]


class TestValueCount:
    def _windows_events(self, database: Database, users: list[str]) -> None:
        _insert_events(
            database,
            [
                {
                    "ts_ms": _TS + index * 1000,
                    "log_type": "windows_evtx",
                    "channel": "Security",
                    "app_name": "",
                    "event_id": 4625,
                    "src_ip": "198.51.100.77",
                    "fields_json": json.dumps(
                        {"IpAddress": "198.51.100.77", "TargetUserName": user}
                    ),
                }
                for index, user in enumerate(users)
            ],
        )

    def _spray(self, refs: list[str] | None = None, **kwargs: Any) -> RuleRecord:
        return _corr_rule(
            rule_id="c-spray",
            title="Password Spraying",
            corr_type="value_count",
            refs=refs or ["base-win-fail"],
            group_by=["IpAddress"],
            timespan="10m",
            condition={"gte": 10, "field": "TargetUserName"},
            **kwargs,
        )

    def test_ten_distinct_accounts_spray(self, database: Database) -> None:
        _seed(database)
        self._windows_events(database, [f"user{i}" for i in range(10)])
        base = _rule(_BASE_WIN_FAIL, level="informational")
        result = _run(database, [self._spray()], {base.id: _exec(base.id)})
        (firing,) = result.firings
        assert firing.group_key == "198.51.100.77"
        assert len(firing.matches) == 10

    def test_nine_distinct_accounts_do_not_spray(self, database: Database) -> None:
        _seed(database)
        self._windows_events(database, [f"user{i}" for i in range(9)] + ["user0"])
        base = _rule(_BASE_WIN_FAIL, level="informational")
        result = _run(database, [self._spray()], {base.id: _exec(base.id)})
        assert result.firings == ()


def _login_event(database: Database, ts_ms: int) -> None:
    _insert_events(
        database,
        [{"ts_ms": ts_ms, "event_action": "ssh_accepted_login", "src_ip": "198.51.100.77"}],
    )


class TestTemporal:
    def _rules(self) -> tuple[RuleRecord, RuleRecord]:
        return (
            _rule(_BASE_SSH_FAIL, level="informational"),
            _rule(_BASE_SSH_OK, level="informational"),
        )

    def _executions(self, fail: RuleRecord, ok: RuleRecord) -> dict[str, RuleExecution]:
        return {fail.id: _exec(fail.id), ok.id: _exec(ok.id)}

    def test_both_rules_must_occur_in_the_window(self, database: Database) -> None:
        _seed(database)
        fail, ok = self._rules()
        _ssh_fail_events(database, 1)
        _login_event(database, _TS + 60_000)
        corr = _corr_rule(
            rule_id="c-then",
            title="Success After Failures",
            corr_type="temporal",
            refs=[fail.id, ok.id],
            group_by=["src_ip"],
            timespan="10m",
        )
        result = _run(database, [corr], self._executions(fail, ok))
        (firing,) = result.firings
        assert len(firing.matches) == 2

    def test_a_gap_past_the_window_does_not_fire(self, database: Database) -> None:
        _seed(database)
        fail, ok = self._rules()
        _ssh_fail_events(database, 1)
        _login_event(database, _TS + 600_001)
        corr = _corr_rule(
            rule_id="c-then",
            title="Success After Failures",
            corr_type="temporal",
            refs=[fail.id, ok.id],
            group_by=["src_ip"],
            timespan="10m",
        )
        result = _run(database, [corr], self._executions(fail, ok))
        assert result.firings == ()

    def test_temporal_ignores_order(self, database: Database) -> None:
        _seed(database)
        fail, ok = self._rules()
        _insert_events(
            database,
            [{"ts_ms": _TS, "event_action": "ssh_accepted_login", "src_ip": "198.51.100.77"}],
        )
        _ssh_fail_events(database, 1)
        corr = _corr_rule(
            rule_id="c-then",
            title="Success And Failures",
            corr_type="temporal",
            refs=[fail.id, ok.id],
            group_by=["src_ip"],
            timespan="10m",
        )
        result = _run(database, [corr], self._executions(fail, ok))
        assert len(result.firings) == 1


class TestTemporalOrdered:
    def _rules(self) -> tuple[RuleRecord, RuleRecord]:
        return (
            _rule(_BASE_SSH_FAIL, level="informational"),
            _rule(_BASE_SSH_OK, level="informational"),
        )

    def _corr(self, fail: RuleRecord, ok: RuleRecord) -> RuleRecord:
        return _corr_rule(
            rule_id="c-ordered",
            title="Compromise Pattern",
            corr_type="temporal_ordered",
            refs=[fail.id, ok.id],
            group_by=["src_ip"],
            timespan="10m",
        )

    def _executions(self, fail: RuleRecord, ok: RuleRecord) -> dict[str, RuleExecution]:
        return {fail.id: _exec(fail.id), ok.id: _exec(ok.id)}

    def test_the_listed_order_fires(self, database: Database) -> None:
        _seed(database)
        fail, ok = self._rules()
        _ssh_fail_events(database, 1)
        _login_event(database, _TS + 60_000)
        result = _run(database, [self._corr(fail, ok)], self._executions(fail, ok))
        (firing,) = result.firings
        assert len(firing.matches) == 2

    def test_a_violated_order_does_not_fire(self, database: Database) -> None:
        _seed(database)
        fail, ok = self._rules()
        _insert_events(
            database,
            [{"ts_ms": _TS, "event_action": "ssh_accepted_login", "src_ip": "198.51.100.77"}],
        )
        _ssh_fail_events(database, 1)
        result = _run(database, [self._corr(fail, ok)], self._executions(fail, ok))
        assert result.firings == ()
        (execution,) = result.executions
        assert execution.outcome.status == RULE_RUN_OK
        assert execution.outcome.match_count == 0


class TestNested:
    def _chain(self) -> tuple[list[RuleRecord], dict[str, RuleExecution]]:
        fail = _rule(_BASE_SSH_FAIL, level="informational")
        ok = _rule(_BASE_SSH_OK, level="informational")
        inner = _corr_rule(
            rule_id="c-inner",
            title="Inner Burst",
            corr_type="event_count",
            refs=[fail.id],
            group_by=["src_ip"],
            condition={"gte": 10},
        )
        middle = _corr_rule(
            rule_id="c-middle",
            title="Burst Then Login",
            corr_type="temporal",
            refs=[inner.id, ok.id],
            group_by=["src_ip"],
            timespan="10m",
        )
        outer = _corr_rule(
            rule_id="c-outer",
            title="Outer Wrapper",
            corr_type="event_count",
            refs=[middle.id],
            group_by=["src_ip"],
            condition={"gte": 1},
        )
        return [inner, middle, outer], {fail.id: _exec(fail.id), ok.id: _exec(ok.id)}

    def test_a_depth_three_chain_fires(self, database: Database) -> None:
        _seed(database)
        correlations, executions = self._chain()
        _ssh_fail_events(database, 10)
        _login_event(database, _TS + 30_000)
        result = _run(database, correlations, executions)
        assert [execution.outcome.status for execution in result.executions] == [
            RULE_RUN_OK,
            RULE_RUN_OK,
            RULE_RUN_OK,
        ]
        fired = {firing.rule_id for firing in result.firings}
        assert fired == {"c-inner", "c-middle", "c-outer"}
        outer = next(f for f in result.firings if f.rule_id == "c-outer")
        assert outer.group_key == "198.51.100.77"

    def test_deeper_than_three_levels_errors(self, database: Database) -> None:
        _seed(database)
        correlations, executions = self._chain()
        deepest = _corr_rule(
            rule_id="c-deepest",
            title="Deepest",
            corr_type="event_count",
            refs=["c-outer"],
            group_by=["src_ip"],
            condition={"gte": 1},
        )
        _ssh_fail_events(database, 10)
        _login_event(database, _TS + 30_000)
        result = _run(database, [*correlations, deepest], executions)
        (last,) = [e for e in result.executions if e.outcome.rule_id == "c-deepest"]
        assert last.outcome.status == RULE_RUN_ERROR
        assert "deeper than 3" in (last.outcome.error or "")

    def test_a_reference_cycle_errors(self, database: Database) -> None:
        _seed(database)
        first = _corr_rule(
            rule_id="c-a",
            title="Cycle A",
            corr_type="event_count",
            refs=["c-b"],
            group_by=["src_ip"],
            condition={"gte": 1},
        )
        second = _corr_rule(
            rule_id="c-b",
            title="Cycle B",
            corr_type="event_count",
            refs=["c-a"],
            group_by=["src_ip"],
            condition={"gte": 1},
        )
        result = _run(database, [first, second], {})
        assert all(execution.outcome.status == RULE_RUN_ERROR for execution in result.executions)
        assert "circular" in (result.executions[0].outcome.error or "")


class TestGenerate:
    def _base_and_corr(self, *, generate: bool | None) -> tuple[RuleRecord, RuleRecord]:
        base = _rule(_BASE_SSH_FAIL, level="informational")
        corr = _corr_rule(
            rule_id="c1",
            title="SSH Brute Force",
            corr_type="event_count",
            refs=[base.id],
            group_by=["src_ip"],
            condition={"gte": 10},
            generate=generate,
        )
        return base, corr

    def test_the_referenced_base_is_suppressed_by_default(self) -> None:
        base, corr = self._base_and_corr(generate=None)
        assert bases_suppressed_by_correlations([base, corr]) == {base.id}

    def test_generate_true_releases_the_base(self) -> None:
        base, corr = self._base_and_corr(generate=True)
        assert bases_suppressed_by_correlations([base, corr]) == set()

    def test_one_generate_true_is_enough(self) -> None:
        base, quiet = self._base_and_corr(generate=None)
        loud = _corr_rule(
            rule_id="c2",
            title="Also Brute Force",
            corr_type="event_count",
            refs=[base.id],
            group_by=["src_ip"],
            condition={"gte": 5},
            generate=True,
        )
        assert bases_suppressed_by_correlations([base, quiet, loud]) == set()

    def test_a_suppressed_base_yields_only_the_correlation_alert(self, database: Database) -> None:
        _seed(database)
        _ssh_fail_events(database, 10)
        base, corr = self._base_and_corr(generate=None)
        rules = {record.id: record for record in [base, corr]}
        base_matches = tuple(
            EventMatch(index, _TS + index * 1000, None, None) for index in range(10)
        )
        result = _run(database, [corr], {base.id: _exec(base.id, base_matches)})
        drafts = run_drafts(
            case_id="case-1",
            run_id="run-1",
            rules=rules,
            base_executions=[_exec(base.id, base_matches)],
            correlation_result=result,
            window_minutes=60,
            max_sample_events=50,
        )
        assert [draft.rule_id for draft in drafts] == [corr.id]

    def test_generate_true_keeps_the_base_alert(self, database: Database) -> None:
        _seed(database)
        _ssh_fail_events(database, 10)
        base, corr = self._base_and_corr(generate=True)
        rules = {record.id: record for record in [base, corr]}
        base_matches = tuple(
            EventMatch(index, _TS + index * 1000, None, None) for index in range(10)
        )
        result = _run(database, [corr], {base.id: _exec(base.id, base_matches)})
        drafts = run_drafts(
            case_id="case-1",
            run_id="run-1",
            rules=rules,
            base_executions=[_exec(base.id, base_matches)],
            correlation_result=result,
            window_minutes=60,
            max_sample_events=50,
        )
        assert sorted({draft.rule_id for draft in drafts}) == sorted({base.id, corr.id})


class TestErrorOutcomes:
    def test_an_unknown_reference_errors(self, database: Database) -> None:
        _seed(database)
        corr = _corr_rule(
            rule_id="c1",
            title="Broken",
            corr_type="event_count",
            refs=["nope"],
            group_by=["src_ip"],
            condition={"gte": 1},
        )
        result = _run(database, [corr], {})
        (execution,) = result.executions
        assert execution.outcome.status == RULE_RUN_ERROR
        assert "unknown rule reference" in (execution.outcome.error or "")

    def test_a_base_outside_the_run_errors(self, database: Database) -> None:
        _seed(database)
        base = _rule(_BASE_SSH_FAIL, level="informational")
        corr = _corr_rule(
            rule_id="c1",
            title="Orphaned",
            corr_type="event_count",
            refs=[base.id],
            group_by=["src_ip"],
            condition={"gte": 1},
        )
        result = _run(database, [corr], {})
        (execution,) = result.executions
        assert execution.outcome.status == RULE_RUN_ERROR
        assert "not part of this run" in (execution.outcome.error or "")

    def test_a_failed_base_errors_the_correlation(self, database: Database) -> None:
        _seed(database)
        base = _rule(_BASE_SSH_FAIL, level="informational")
        corr = _corr_rule(
            rule_id="c1",
            title="Downstream",
            corr_type="event_count",
            refs=[base.id],
            group_by=["src_ip"],
            condition={"gte": 1},
        )
        result = _run(
            database,
            [corr],
            {base.id: _exec(base.id, status=RULE_RUN_ERROR, error="boom")},
        )
        (execution,) = result.executions
        assert execution.outcome.status == RULE_RUN_ERROR
        assert "did not run" in (execution.outcome.error or "")

    def test_skipped_no_data_bubbles_up(self, database: Database) -> None:
        _seed(database)
        base = _rule(_BASE_SSH_FAIL, level="informational")
        corr = _corr_rule(
            rule_id="c1",
            title="No Data Downstream",
            corr_type="event_count",
            refs=[base.id],
            group_by=["src_ip"],
            condition={"gte": 1},
        )
        result = _run(database, [corr], {base.id: _exec(base.id, status=RULE_RUN_SKIPPED_NO_DATA)})
        (execution,) = result.executions
        assert execution.outcome.status == RULE_RUN_SKIPPED_NO_DATA
        assert result.firings == ()

    @pytest.mark.parametrize(
        ("kwargs", "message"),
        [
            ({"timespan": "soon"}, "cannot parse timespan"),
            ({"corr_type": "conspiracy"}, "unknown correlation type"),
            ({}, "condition"),
        ],
    )
    def test_malformed_documents_error(
        self, database: Database, kwargs: dict[str, Any], message: str | None
    ) -> None:
        _seed(database)
        base = _rule(_BASE_SSH_FAIL, level="informational")
        params: dict[str, Any] = {
            "rule_id": "c1",
            "title": "Malformed",
            "corr_type": "event_count",
            "refs": [base.id],
            "group_by": ["src_ip"],
        }
        params.update(kwargs)
        corr = _corr_rule(**params)
        result = _run(database, [corr], {base.id: _exec(base.id)})
        (execution,) = result.executions
        assert execution.outcome.status == RULE_RUN_ERROR
        if message is not None:
            assert message in (execution.outcome.error or "")

    def test_value_count_needs_a_condition_field(self, database: Database) -> None:
        _seed(database)
        base = _rule(_BASE_SSH_FAIL, level="informational")
        corr = _rule(
            {
                "title": "No Field",
                "id": "c1",
                "correlation": {
                    "type": "value_count",
                    "rules": [base.id],
                    "group-by": ["src_ip"],
                    "timespan": "5m",
                    "condition": {"gte": 10},
                },
            },
            rule_type=RULE_TYPE_CORRELATION,
        )
        result = _run(database, [corr], {base.id: _exec(base.id)})
        (execution,) = result.executions
        assert execution.outcome.status == RULE_RUN_ERROR
        assert "condition.field" in (execution.outcome.error or "")

    def test_a_detection_rule_cannot_run_here(self, database: Database) -> None:
        _seed(database)
        base = _rule(_BASE_SSH_FAIL, level="informational")
        with pytest.raises(ValueError, match="correlation stage"):
            execute_correlations(
                database.writer,
                case_id="case-1",
                rules=[base],
                catalogue=[base],
                base_executions={},
                logsource_map=MAP,
            )


class TestFiringAlerts:
    def _firing_run(self, database: Database) -> tuple[RuleRecord, RuleRecord, CorrelationResult]:
        _seed(database)
        _ssh_fail_events(database, 12)
        base = _rule(_BASE_SSH_FAIL, level="high")
        corr = _corr_rule(
            rule_id="c1",
            title="SSH Brute Force",
            corr_type="event_count",
            refs=[base.id],
            group_by=["src_ip"],
            condition={"gte": 10},
            level="high",
        )
        result = _run(database, [corr], {base.id: _exec(base.id)})
        return base, corr, result

    def test_firings_become_deterministic_drafts(self, database: Database) -> None:
        base, corr, result = self._firing_run(database)
        rules = {record.id: record for record in [base, corr]}
        drafts = build_firing_drafts(
            case_id="case-1",
            run_id="run-1",
            rules=rules,
            firings=result.firings,
            max_sample_events=3,
        )
        (draft,) = drafts
        assert draft.rule_id == corr.id
        assert draft.group_key == "198.51.100.77"
        assert draft.match_count == 12
        assert draft.event_ids == tuple(range(1, 4))
        assert draft.first_seen_ms == _TS
        assert draft.last_seen_ms == _TS + 11000

    def test_record_run_alerts_persists_scores_and_reruns_stably(self, database: Database) -> None:
        base, corr, result = self._firing_run(database)
        rules = {record.id: record for record in [base, corr]}
        base_exec = _exec(base.id, tuple(EventMatch(i, _TS, None, None) for i in range(12)))
        first = record_run_alerts(
            database.writer,
            case_id="case-1",
            run_id="run-1",
            rules=rules,
            base_executions=[base_exec],
            correlation_result=result,
            window_minutes=60,
            max_sample_events=500,
        )
        second = record_run_alerts(
            database.writer,
            case_id="case-1",
            run_id="run-2",
            rules=rules,
            base_executions=[base_exec],
            correlation_result=result,
            window_minutes=60,
            max_sample_events=500,
        )
        assert len(first) == 1
        assert isinstance(first[0], AlertRecord)
        assert first[0].score >= 70
        assert [record.id for record in first] == [record.id for record in second]
        assert second[0].run_id == "run-2"


class TestLoaderKeepsGenerateHealthy:
    def test_a_generate_rule_loads_without_a_compile_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            rules_dir = Path(directory)
            (rules_dir / "gen.yml").write_text(
                yaml.safe_dump(
                    {
                        "title": "Generates",
                        "correlation": {
                            "type": "event_count",
                            "rules": ["base-ssh-fail"],
                            "group-by": ["src_ip"],
                            "timespan": "5m",
                            "condition": {"gte": 10},
                            "generate": True,
                        },
                        "level": "high",
                    }
                ),
                encoding="utf-8",
            )
            loaded, problems = load_rules(builtin_dir=rules_dir)
        assert problems == []
        (record,) = loaded
        assert record.compile_error is None
        assert record.rule_type == RULE_TYPE_CORRELATION


class TestTitleReference:
    def test_refs_resolve_by_title(self, database: Database) -> None:
        _seed(database)
        _ssh_fail_events(database, 10)
        base = _rule(_BASE_SSH_FAIL, level="informational")
        corr = _corr_rule(
            rule_id="c1",
            title="SSH Brute Force",
            corr_type="event_count",
            refs=["SSH Failed Password"],
            group_by=["src_ip"],
            condition={"gte": 10},
        )
        result = _run(database, [corr], {base.id: _exec(base.id)})
        assert len(result.firings) == 1


class TestGroupByWithoutFields:
    def test_no_group_by_makes_one_global_group(self, database: Database) -> None:
        _seed(database)
        _ssh_fail_events(database, 10, src_ip="198.51.100.77")
        _ssh_fail_events(database, 10, src_ip="192.0.2.66")
        base = _rule(_BASE_SSH_FAIL, level="informational")
        corr = _corr_rule(
            rule_id="c1",
            title="Global Burst",
            corr_type="event_count",
            refs=[base.id],
            timespan="5m",
            condition={"gte": 20},
        )
        result = _run(database, [corr], {base.id: _exec(base.id)})
        (firing,) = result.firings
        assert firing.group_key == ""
        assert len(firing.matches) == 20
