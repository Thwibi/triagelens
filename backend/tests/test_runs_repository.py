"""Detection run recording (spec 04 section 2, spec 01 section 9)."""

from __future__ import annotations

import sqlite3

import pytest

from app.db.connection import Database
from app.db.repositories.runs import DetectionRunRepository, attack_version
from app.detect.engine import RuleOutcome
from app.models.run import RULE_RUN_ERROR, RULE_RUN_OK, RUN_STATUS_DONE
from app.util.ids import is_id

_ISO = "2026-01-01T00:00:00.000Z"


@pytest.fixture
def repo(database: Database) -> DetectionRunRepository:
    return DetectionRunRepository(database.writer)


def _seed_case(repo: DetectionRunRepository, case_id: str = "case-1") -> None:
    repo.connection.execute(
        "INSERT OR IGNORE INTO cases ("
        "id, name, description, default_timezone, created_at, updated_at"
        ") VALUES (?, ?, NULL, 'UTC', ?, ?)",
        (case_id, case_id, _ISO, _ISO),
    )


def _started(repo: DetectionRunRepository, *, case_id: str = "case-1") -> str:
    """Seed ``case_id`` (idempotent) and open a run on it; returns the run id."""
    _seed_case(repo, case_id)
    run = repo.start(
        case_id=case_id,
        profile="standard",
        tool_version="9.9.9",
        ruleset_hash="aa" * 32,
        attack_version="v15",
    )
    return run.id


def _outcome(
    rule_id: str = "r-1",
    *,
    status: str = RULE_RUN_OK,
    match_count: int = 3,
    duration_ms: int = 12,
    error: str | None = None,
) -> RuleOutcome:
    return RuleOutcome(rule_id, status, match_count, duration_ms, error)


class TestStart:
    def test_start_opens_a_running_run_with_versions(self, repo: DetectionRunRepository) -> None:
        run = repo.get(_started(repo))
        assert run is not None
        assert run.status == "running"
        assert run.finished_at is None
        assert run.profile == "standard"
        assert run.tool_version == "9.9.9"
        assert run.ruleset_hash == "aa" * 32
        assert run.attack_version == "v15"
        assert is_id(run.id)

    def test_start_requires_an_existing_case(self, repo: DetectionRunRepository) -> None:
        with pytest.raises(sqlite3.IntegrityError):
            repo.start(
                case_id="ghost",
                profile="standard",
                tool_version="1",
                ruleset_hash="0" * 64,
                attack_version="",
            )

    def test_get_unknown_run_returns_none(self, repo: DetectionRunRepository) -> None:
        assert repo.get("nope") is None


class TestFinish:
    def test_finish_closes_the_run_exactly_once(self, repo: DetectionRunRepository) -> None:
        run_id = _started(repo)
        assert repo.finish(run_id, status=RUN_STATUS_DONE) is True
        run = repo.get(run_id)
        assert run is not None
        assert run.status == RUN_STATUS_DONE
        assert run.finished_at is not None
        assert repo.finish(run_id, status="failed") is False
        again = repo.get(run_id)
        assert again is not None
        assert again.status == RUN_STATUS_DONE

    def test_finish_rejects_a_non_terminal_status(self, repo: DetectionRunRepository) -> None:
        run_id = _started(repo)
        with pytest.raises(ValueError, match="invalid terminal run status"):
            repo.finish(run_id, status="running")

    def test_finishing_an_unknown_run_is_false(self, repo: DetectionRunRepository) -> None:
        assert repo.finish("nope", status=RUN_STATUS_DONE) is False


class TestRecordRules:
    def test_one_row_lands_per_outcome(self, repo: DetectionRunRepository) -> None:
        run_id = _started(repo)
        count = repo.record_rules(
            run_id,
            [
                _outcome("r-b", match_count=5, duration_ms=40),
                _outcome("r-a", status=RULE_RUN_ERROR, match_count=0, error="boom"),
            ],
        )
        assert count == 2
        rows = repo.rule_runs(run_id)
        assert [(row.rule_id, row.status) for row in rows] == [
            ("r-a", RULE_RUN_ERROR),
            ("r-b", RULE_RUN_OK),
        ]
        assert rows[0].error == "boom"
        assert rows[1].match_count == 5
        assert rows[1].duration_ms == 40

    def test_recording_upserts_an_existing_row(self, repo: DetectionRunRepository) -> None:
        run_id = _started(repo)
        assert repo.record_rules(run_id, [_outcome("r-1", match_count=1)]) == 1
        assert repo.record_rules(run_id, [_outcome("r-1", match_count=9)]) == 1
        rows = repo.rule_runs(run_id)
        assert len(rows) == 1
        assert rows[0].match_count == 9

    def test_an_invalid_status_is_rejected(self, repo: DetectionRunRepository) -> None:
        run_id = _started(repo)
        with pytest.raises(ValueError, match="invalid rule run status"):
            repo.record_rules(run_id, [_outcome("r-1", status="skipped")])

    def test_no_outcomes_records_nothing(self, repo: DetectionRunRepository) -> None:
        run_id = _started(repo)
        assert repo.record_rules(run_id, []) == 0
        assert repo.rule_runs(run_id) == []


class TestListing:
    def test_list_for_case_is_newest_first_and_case_scoped(
        self, repo: DetectionRunRepository
    ) -> None:
        first_id = _started(repo)
        second_id = _started(repo)
        other_id = _started(repo, case_id="case-2")
        repo.connection.execute(
            "UPDATE detection_runs SET started_at = ? WHERE id = ?",
            ("2026-01-01T00:00:00.000Z", first_id),
        )
        repo.connection.execute(
            "UPDATE detection_runs SET started_at = ? WHERE id = ?",
            ("2026-01-02T00:00:00.000Z", second_id),
        )
        assert [run.id for run in repo.list_for_case("case-1")] == [second_id, first_id]
        assert [run.id for run in repo.list_for_case("case-1", limit=1)] == [second_id]
        assert [run.id for run in repo.list_for_case("case-2")] == [other_id]

    def test_rule_runs_are_sorted_by_rule_id(self, repo: DetectionRunRepository) -> None:
        run_id = _started(repo)
        repo.record_rules(run_id, [_outcome("zeta"), _outcome("alpha"), _outcome("mid")])
        assert [row.rule_id for row in repo.rule_runs(run_id)] == ["alpha", "mid", "zeta"]


class TestAttackVersion:
    def test_no_bundle_reports_an_empty_version(self, repo: DetectionRunRepository) -> None:
        assert attack_version(repo.connection) == ""

    def test_the_stored_bundle_version_round_trips(self, repo: DetectionRunRepository) -> None:
        repo.connection.execute(
            "INSERT INTO mitre_meta (key, value) VALUES ('attack_version', 'v15')"
        )
        assert attack_version(repo.connection) == "v15"
