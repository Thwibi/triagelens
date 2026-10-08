"""Alert construction and re-run recording (spec 04 section 6, spec 09 D-08).

D-08 covers the grouping contract: a gap larger than the window splits
alerts, ids are deterministic across two runs, and an analyst's status and
notes survive the next run. The replacement rule is pinned down too -
previous ``new`` alerts are replaced, analyst-touched ones stay behind with
their old ``run_id``, which is what makes them read as stale.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

import yaml

from app.db.connection import Database, atomic
from app.db.repositories.alerts import AlertRepository
from app.db.repositories.runs import DetectionRunRepository
from app.detect.alerts import build_alerts, record_alerts
from app.detect.engine import EventMatch, RuleExecution, RuleOutcome
from app.models.alert import (
    ALERT_STATUS_FALSE_POSITIVE,
    ALERT_STATUS_TRIAGED,
    AlertDraft,
)
from app.models.rule import KIND_CUSTOM, RULE_TYPE_CORRELATION, RuleRecord
from app.models.run import RULE_RUN_ERROR, RULE_RUN_OK, RULE_RUN_TIMEOUT
from app.util.hashing import content_id

_TS = 1_700_000_000_000
_ISO = "2026-01-01T00:00:00.000Z"
_WINDOW_MINUTES = 60
_WINDOW_MS = _WINDOW_MINUTES * 60 * 1000


def _seed_case(database: Database, case_id: str = "case-1") -> None:
    database.writer.execute(
        "INSERT OR IGNORE INTO cases ("
        "id, name, description, default_timezone, created_at, updated_at"
        ") VALUES (?, ?, NULL, 'UTC', ?, ?)",
        (case_id, case_id, _ISO, _ISO),
    )


def _seed_source(database: Database, source_id: str = "src-1", case_id: str = "case-1") -> None:
    database.writer.execute(
        "INSERT OR IGNORE INTO sources (id, case_id, filename, stored_path, size_bytes, "
        "sha256, status, ingested_at) VALUES (?, ?, ?, ?, 0, 'deadbeef', 'done', ?)",
        (source_id, case_id, f"{source_id}.log", f"/tmp/{source_id}.log", _ISO),
    )


def _insert_events(database: Database, rows: Sequence[dict[str, Any]]) -> list[int]:
    _seed_case(database)
    _seed_source(database)
    ids: list[int] = []
    with atomic(database.writer):
        for offset, row in enumerate(rows):
            cursor = database.writer.execute(
                "INSERT INTO events (case_id, source_id, record_ref, ts_ms, ts_iso, "
                "log_type, host, user_name, message, raw) "
                "VALUES ('case-1', 'src-1', ?, ?, NULL, 'linux_auth', ?, ?, ?, '{}')",
                (
                    str(offset),
                    row["ts_ms"],
                    row.get("host", "web01"),
                    row.get("user_name", "alice"),
                    row.get("message", "hit"),
                ),
            )
            ids.append(int(cursor.lastrowid or 0))
    return ids


def _rule(
    rule_id: str = "rule-1",
    *,
    level: str = "medium",
    status: str | None = "stable",
    rule_type: str = "detection",
    false_positives: list[str] | None = None,
    references: list[str] | None = None,
) -> RuleRecord:
    document: dict[str, Any] = {
        "title": f"Rule {rule_id}",
        "logsource": {"product": "linux", "service": "sshd"},
        "detection": {"selection": {"message": "hit"}, "condition": "selection"},
    }
    if false_positives is not None:
        document["falsepositives"] = false_positives
    if references is not None:
        document["references"] = references
    return RuleRecord(
        id=rule_id,
        title=f"Rule {rule_id}",
        kind=KIND_CUSTOM,
        rule_type=rule_type,
        level=level,
        status=status,
        enabled=True,
        yaml=yaml.safe_dump(document, sort_keys=False),
        tags=(),
        logsource={"product": "linux", "service": "sshd"},
        file_path=None,
        sha256="0" * 64,
        compile_error=None,
        unroutable=False,
        updated_at=_ISO,
    )


def _match(
    event_id: int,
    ts_ms: int | None,
    *,
    host: str | None = "web01",
    user_name: str | None = "alice",
) -> EventMatch:
    return EventMatch(event_id=event_id, ts_ms=ts_ms, host=host, user_name=user_name)


def _execution(
    rule_id: str, matches: Sequence[EventMatch], *, status: str = RULE_RUN_OK
) -> RuleExecution:
    return RuleExecution(
        outcome=RuleOutcome(rule_id, status, len(matches), 1, None),
        matches=tuple(matches),
    )


def _start_run(database: Database, case_id: str = "case-1") -> str:
    _seed_case(database, case_id)
    run = DetectionRunRepository(database.writer).start(
        case_id=case_id,
        profile="standard",
        tool_version="1",
        ruleset_hash="0" * 64,
        attack_version="",
    )
    return run.id


def _build(
    rule: RuleRecord, matches: Sequence[EventMatch], *, max_sample_events: int = 500
) -> list[AlertDraft]:
    return build_alerts(
        case_id="case-1",
        run_id="run-1",
        rules={rule.id: rule},
        executions=[_execution(rule.id, matches)],
        window_minutes=_WINDOW_MINUTES,
        max_sample_events=max_sample_events,
    )


class TestD08Grouping:
    def test_a_gap_of_exactly_the_window_stays_one_alert(self) -> None:
        drafts = _build(_rule(), [_match(1, _TS), _match(2, _TS + _WINDOW_MS)])
        assert len(drafts) == 1
        assert drafts[0].match_count == 2
        assert drafts[0].first_seen_ms == _TS
        assert drafts[0].last_seen_ms == _TS + _WINDOW_MS

    def test_a_gap_beyond_the_window_splits_alerts(self) -> None:
        drafts = _build(_rule(), [_match(1, _TS), _match(2, _TS + _WINDOW_MS + 1)])
        assert len(drafts) == 2
        first, second = drafts
        assert (first.match_count, second.match_count) == (1, 1)
        assert first.id != second.id
        assert first.first_seen_ms == _TS
        assert second.first_seen_ms == _TS + _WINDOW_MS + 1

    def test_group_key_separates_every_host_and_user_pair(self) -> None:
        drafts = _build(
            _rule(),
            [
                _match(1, _TS),
                _match(2, _TS, user_name="bob"),
                _match(3, _TS, host="web02"),
                _match(4, _TS + 1),
            ],
        )
        assert sorted(draft.group_key for draft in drafts) == [
            "web01|alice",
            "web01|bob",
            "web02|alice",
        ]
        merged = next(draft for draft in drafts if draft.group_key == "web01|alice")
        assert merged.match_count == 2  # both web01/alice matches cluster together

    def test_alert_id_follows_the_spec_formula(self) -> None:
        drafts = _build(_rule(), [_match(7, _TS + 5)])
        assert drafts[0].id == content_id("case-1", "rule-1", "web01|alice", str(_TS + 5))
        assert len(drafts[0].id) == 16

    def test_falsepositives_and_references_come_from_the_rule_yaml(self) -> None:
        rule = _rule(
            false_positives=["Administrator resetting passwords", "monitoring probe"],
            references=["https://example.org/runbook"],
        )
        drafts = _build(rule, [_match(1, _TS)])
        assert drafts[0].false_positives == (
            "Administrator resetting passwords",
            "monitoring probe",
        )
        assert drafts[0].references == ("https://example.org/runbook",)

    def test_correlation_rules_are_left_to_the_correlation_stage(self) -> None:
        rule = _rule(rule_type=RULE_TYPE_CORRELATION)
        drafts = _build(rule, [_match(1, _TS)])
        assert drafts == []

    def test_non_ok_outcomes_produce_no_alerts(self) -> None:
        rule = _rule()
        for status in (RULE_RUN_ERROR, RULE_RUN_TIMEOUT):
            drafts = build_alerts(
                case_id="case-1",
                run_id="run-1",
                rules={rule.id: rule},
                executions=[_execution(rule.id, [_match(1, _TS)], status=status)],
                window_minutes=_WINDOW_MINUTES,
                max_sample_events=500,
            )
            assert drafts == []

    def test_a_sample_is_capped_but_match_count_is_the_real_total(self) -> None:
        matches = [_match(index, _TS + index) for index in range(5)]
        drafts = _build(_rule(), matches, max_sample_events=2)
        assert drafts[0].match_count == 5
        assert drafts[0].event_ids == (0, 1)


class TestD08Recording:
    def test_alert_ids_are_deterministic_across_two_runs(self, database: Database) -> None:
        event_ids = _insert_events(
            database,
            [{"ts_ms": _TS + index} for index in range(3)],
        )
        rule = _rule()
        matches = [_match(event_id, _TS + index) for index, event_id in enumerate(event_ids)]

        first_run = _start_run(database)
        first = record_alerts(
            database.writer,
            case_id="case-1",
            run_id=first_run,
            rules={rule.id: rule},
            executions=[_execution(rule.id, matches)],
            window_minutes=_WINDOW_MINUTES,
            max_sample_events=500,
        )
        second_run = _start_run(database)
        second = record_alerts(
            database.writer,
            case_id="case-1",
            run_id=second_run,
            rules={rule.id: rule},
            executions=[_execution(rule.id, matches)],
            window_minutes=_WINDOW_MINUTES,
            max_sample_events=500,
        )

        assert len(first) == 1
        assert len(second) == 1
        assert first[0].id == second[0].id
        assert first[0].run_id != second[0].run_id
        assert second[0].run_id == second_run
        assert second[0].match_count == 3
        # Same id, same row: the re-run replaced, not duplicated.
        assert len(AlertRepository(database.writer).list_for_case("case-1")) == 1

    def test_analyst_status_and_notes_survive_a_rerun(self, database: Database) -> None:
        event_ids = _insert_events(database, [{"ts_ms": _TS}])
        rule = _rule()
        matches = [_match(event_ids[0], _TS)]

        first_run = _start_run(database)
        record_alerts(
            database.writer,
            case_id="case-1",
            run_id=first_run,
            rules={rule.id: rule},
            executions=[_execution(rule.id, matches)],
            window_minutes=_WINDOW_MINUTES,
            max_sample_events=500,
        )
        repository = AlertRepository(database.writer)
        [alert] = repository.list_for_case("case-1")
        database.writer.execute(
            "UPDATE alerts SET status = ?, analyst_notes = ? WHERE id = ?",
            (ALERT_STATUS_TRIAGED, "looks real", alert.id),
        )

        second_run = _start_run(database)
        record_alerts(
            database.writer,
            case_id="case-1",
            run_id=second_run,
            rules={rule.id: rule},
            executions=[_execution(rule.id, matches)],
            window_minutes=_WINDOW_MINUTES,
            max_sample_events=500,
        )
        updated = repository.get(alert.id)
        assert updated is not None
        assert updated.status == ALERT_STATUS_TRIAGED
        assert updated.analyst_notes == "looks real"
        assert updated.run_id == second_run

    def test_new_alerts_are_replaced_and_analyst_touched_ones_go_stale(
        self, database: Database
    ) -> None:
        first_ids = _insert_events(database, [{"ts_ms": _TS}, {"ts_ms": _TS + 1}])
        rule_a, rule_b = _rule("rule-a"), _rule("rule-b")
        first_matches = [_match(event_id, _TS + index) for index, event_id in enumerate(first_ids)]
        first_run = _start_run(database)
        record_alerts(
            database.writer,
            case_id="case-1",
            run_id=first_run,
            rules={rule_a.id: rule_a, rule_b.id: rule_b},
            executions=[
                _execution(rule_a.id, first_matches),
                _execution(rule_b.id, first_matches),
            ],
            window_minutes=_WINDOW_MINUTES,
            max_sample_events=500,
        )
        repository = AlertRepository(database.writer)
        by_rule = {record.rule_id: record for record in repository.list_for_case("case-1")}
        touched = by_rule["rule-b"]
        database.writer.execute(
            "UPDATE alerts SET status = ?, analyst_notes = ? WHERE id = ?",
            (ALERT_STATUS_FALSE_POSITIVE, "known scanner", touched.id),
        )

        second_ids = _insert_events(database, [{"ts_ms": _TS + 2 * _WINDOW_MS}])
        second_run = _start_run(database)
        records = record_alerts(
            database.writer,
            case_id="case-1",
            run_id=second_run,
            rules={rule_a.id: rule_a},
            executions=[_execution(rule_a.id, [_match(second_ids[0], _TS + 2 * _WINDOW_MS)])],
            window_minutes=_WINDOW_MINUTES,
            max_sample_events=500,
        )

        # Untouched alert of the old run is gone entirely...
        assert repository.get(by_rule["rule-a"].id) is None
        # ...while the analyst-touched one keeps status, notes and old run.
        stale = repository.get(touched.id)
        assert stale is not None
        assert stale.status == ALERT_STATUS_FALSE_POSITIVE
        assert stale.analyst_notes == "known scanner"
        assert stale.run_id == first_run
        # The new run's alert replaces rule-a under a fresh, deterministic id.
        assert [record.run_id for record in records] == [second_run]
        assert len(repository.list_for_case("case-1")) == 2

    def test_a_run_that_matches_nothing_clears_previous_new_alerts(
        self, database: Database
    ) -> None:
        event_ids = _insert_events(database, [{"ts_ms": _TS}])
        rule = _rule()
        first_run = _start_run(database)
        record_alerts(
            database.writer,
            case_id="case-1",
            run_id=first_run,
            rules={rule.id: rule},
            executions=[_execution(rule.id, [_match(event_ids[0], _TS)])],
            window_minutes=_WINDOW_MINUTES,
            max_sample_events=500,
        )
        assert len(AlertRepository(database.writer).list_for_case("case-1")) == 1

        second_run = _start_run(database)
        records = record_alerts(
            database.writer,
            case_id="case-1",
            run_id=second_run,
            rules={rule.id: rule},
            executions=[],
            window_minutes=_WINDOW_MINUTES,
            max_sample_events=500,
        )
        assert records == []
        assert AlertRepository(database.writer).list_for_case("case-1") == []

    def test_stored_evidence_follows_the_capped_sample(self, database: Database) -> None:
        event_ids = _insert_events(database, [{"ts_ms": _TS + index} for index in range(5)])
        rule = _rule()
        matches = [_match(event_id, _TS + index) for index, event_id in enumerate(event_ids)]
        run_id = _start_run(database)
        [record] = record_alerts(
            database.writer,
            case_id="case-1",
            run_id=run_id,
            rules={rule.id: rule},
            executions=[_execution(rule.id, matches)],
            window_minutes=_WINDOW_MINUTES,
            max_sample_events=2,
        )
        repository = AlertRepository(database.writer)
        assert record.match_count == 5
        assert repository.event_ids(record.id) == event_ids[:2]

    def test_falsepositives_round_trip_as_stored_json(self, database: Database) -> None:
        event_ids = _insert_events(database, [{"ts_ms": _TS}])
        rule = _rule(false_positives=["misconfigured sensor"], references=["https://x.test"])
        run_id = _start_run(database)
        [record] = record_alerts(
            database.writer,
            case_id="case-1",
            run_id=run_id,
            rules={rule.id: rule},
            executions=[_execution(rule.id, [_match(event_ids[0], _TS)])],
            window_minutes=_WINDOW_MINUTES,
            max_sample_events=500,
        )
        stored = AlertRepository(database.writer).get(record.id)
        assert stored is not None
        assert json.loads(stored.false_positives_json) == ["misconfigured sensor"]
        assert json.loads(stored.references_json) == ["https://x.test"]
