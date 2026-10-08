"""Severity scoring (spec 04 section 8, spec 09 D-09).

Every modifier gets its own case, clamping is exercised in both directions,
and every assertion goes through ``_check`` so ``sum(breakdown) == score``
holds for every result the module can produce - including clamped ones,
where the difference lands under the ``clamp`` key.
"""

from __future__ import annotations

import pytest

from app.db.connection import Database, atomic
from app.db.repositories.alerts import AlertRepository
from app.detect.scoring import ScoreResult, score_alert
from app.models.alert import AlertRecord

_TS = 1_700_000_000_000
_ISO = "2026-01-01T00:00:00.000Z"
_QUARTER_HOUR_MS = 15 * 60 * 1000


def _seed(database: Database, *, case_id: str = "case-1", run_id: str = "run-1") -> None:
    with atomic(database.writer):
        database.writer.execute(
            "INSERT OR IGNORE INTO cases ("
            "id, name, description, default_timezone, created_at, updated_at"
            ") VALUES (?, ?, NULL, 'UTC', ?, ?)",
            (case_id, case_id, _ISO, _ISO),
        )
        database.writer.execute(
            "INSERT OR IGNORE INTO detection_runs ("
            "id, case_id, profile, tool_version, ruleset_hash, attack_version, "
            "started_at, finished_at, status"
            ") VALUES (?, ?, 'standard', '1', ?, '', ?, NULL, 'done')",
            (run_id, case_id, "0" * 64, _ISO),
        )


def _insert_alert(
    database: Database,
    alert_id: str,
    *,
    case_id: str = "case-1",
    run_id: str = "run-1",
    rule_id: str = "rule-1",
    host: str | None = "web01",
    user_name: str | None = "alice",
    level: str = "medium",
    status: str = "new",
    first_ms: int = _TS,
    last_ms: int = _TS + 1000,
    match_count: int = 3,
) -> AlertRecord:
    _seed(database, case_id=case_id, run_id=run_id)
    database.writer.execute(
        "INSERT INTO alerts ("
        "id, case_id, run_id, rule_id, rule_title, rule_kind, rule_type, "
        "level, score, status, host, user_name, group_key, "
        "first_seen_ms, last_seen_ms, match_count, created_at"
        ") VALUES (?, ?, ?, ?, ?, 'custom', 'detection', ?, 0, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            alert_id,
            case_id,
            run_id,
            rule_id,
            f"Rule {rule_id}",
            level,
            status,
            host,
            user_name,
            f"{host or ''}|{user_name or ''}",
            first_ms,
            last_ms,
            match_count,
            _ISO,
        ),
    )
    record = AlertRepository(database.writer).get(alert_id)
    assert record is not None
    return record


def _insert_ioc_link(
    database: Database,
    ioc_id: str,
    alert_id: str,
    *,
    ioc_type: str = "ipv4",
    confidence: int = 90,
    is_private: int = 0,
    is_allowlisted: int = 0,
) -> None:
    database.writer.execute(
        "INSERT INTO iocs ("
        "id, case_id, type, value, value_norm, confidence, is_private, is_allowlisted"
        ") VALUES (?, 'case-1', ?, ?, ?, ?, ?, ?)",
        (
            ioc_id,
            ioc_type,
            "185.220.101.45",
            "185.220.101.45",
            confidence,
            is_private,
            is_allowlisted,
        ),
    )
    database.writer.execute(
        "INSERT INTO ioc_alerts (ioc_id, alert_id) VALUES (?, ?)", (ioc_id, alert_id)
    )


def _score(
    database: Database, alert: AlertRecord, *, rule_status: str | None = "stable"
) -> ScoreResult:
    return score_alert(database.writer, alert, rule_status=rule_status)


def _check(result: ScoreResult) -> int:
    """Assert the breakdown invariant and return the score (D-09)."""
    assert sum(result.breakdown.values()) == result.score
    return result.score


class TestBaseScore:
    @pytest.mark.parametrize(
        ("level", "expected"),
        [
            ("critical", 90),
            ("high", 70),
            ("medium", 50),
            ("low", 30),
            ("informational", 10),
        ],
    )
    def test_each_level_starts_from_its_base(
        self, database: Database, level: str, expected: int
    ) -> None:
        alert = _insert_alert(database, "only", level=level)
        result = _score(database, alert)
        assert result.breakdown == {"base": expected}
        assert _check(result) == expected

    def test_an_unknown_level_falls_back_to_informational(self, database: Database) -> None:
        alert = _insert_alert(database, "only", level="bogus")
        assert _check(_score(database, alert)) == 10


class TestHostOverlapModifier:
    def test_overlapping_alert_on_the_same_host_adds_ten(self, database: Database) -> None:
        alert = _insert_alert(database, "self-1")
        _insert_alert(database, "other-1", first_ms=_TS - 5000, last_ms=_TS - 4000)
        result = _score(database, alert)
        assert result.breakdown["host_overlap"] == 10
        assert _check(result) == 60

    def test_exactly_fifteen_minutes_away_still_counts(self, database: Database) -> None:
        alert = _insert_alert(database, "self-1")
        _insert_alert(
            database,
            "other-1",
            first_ms=_TS - _QUARTER_HOUR_MS - 1000,
            last_ms=_TS - _QUARTER_HOUR_MS,
        )
        assert _check(_score(database, alert)) == 60

    def test_more_than_fifteen_minutes_away_does_not_count(self, database: Database) -> None:
        alert = _insert_alert(database, "self-1")
        _insert_alert(
            database,
            "other-1",
            first_ms=_TS - _QUARTER_HOUR_MS - 2000,
            last_ms=_TS - _QUARTER_HOUR_MS - 1,
        )
        assert "host_overlap" not in _score(database, alert).breakdown
        assert _check(_score(database, alert)) == 50

    def test_a_different_host_never_overlaps(self, database: Database) -> None:
        alert = _insert_alert(database, "self-1")
        _insert_alert(database, "other-1", host="db01", first_ms=_TS - 1, last_ms=_TS + 1)
        assert _check(_score(database, alert)) == 50

    def test_alerts_without_a_host_never_match_each_other(self, database: Database) -> None:
        alert = _insert_alert(database, "self-1", host=None, user_name=None)
        _insert_alert(database, "other-1", host=None, user_name=None, first_ms=_TS, last_ms=_TS + 1)
        assert _check(_score(database, alert)) == 50


class TestIocEvidenceModifier:
    def test_a_confident_non_private_ip_adds_five(self, database: Database) -> None:
        alert = _insert_alert(database, "self-1")
        _insert_ioc_link(database, "ioc-1", "self-1")
        result = _score(database, alert)
        assert result.breakdown["ioc_evidence"] == 5
        assert _check(result) == 55

    def test_a_confident_domain_also_counts(self, database: Database) -> None:
        alert = _insert_alert(database, "self-1")
        _insert_ioc_link(database, "ioc-1", "self-1", ioc_type="domain")
        assert _check(_score(database, alert)) == 55

    @pytest.mark.parametrize(
        ("confidence", "is_private", "is_allowlisted"),
        [(69, 0, 0), (90, 1, 0), (90, 0, 1)],
    )
    def test_weak_private_or_allowlisted_iocs_do_not_count(
        self, database: Database, confidence: int, is_private: int, is_allowlisted: int
    ) -> None:
        alert = _insert_alert(database, "self-1")
        _insert_ioc_link(
            database,
            "ioc-1",
            "self-1",
            confidence=confidence,
            is_private=is_private,
            is_allowlisted=is_allowlisted,
        )
        assert "ioc_evidence" not in _score(database, alert).breakdown
        assert _check(_score(database, alert)) == 50

    @pytest.mark.parametrize("ioc_type", ["url", "md5", "email"])
    def test_non_ip_domain_ioc_types_do_not_count(self, database: Database, ioc_type: str) -> None:
        alert = _insert_alert(database, "self-1")
        _insert_ioc_link(database, "ioc-1", "self-1", ioc_type=ioc_type, confidence=95)
        assert _check(_score(database, alert)) == 50


class TestMatchVolumeModifier:
    @pytest.mark.parametrize(
        ("match_count", "expected"),
        [(9, 50), (10, 55), (99, 55), (100, 60), (1000, 60)],
    )
    def test_volume_thresholds_add_five_each(
        self, database: Database, match_count: int, expected: int
    ) -> None:
        alert = _insert_alert(database, "only", match_count=match_count)
        result = _score(database, alert)
        if match_count >= 100:
            assert result.breakdown["match_volume_10"] == 5
            assert result.breakdown["match_volume_100"] == 5
        elif match_count >= 10:
            assert result.breakdown["match_volume_10"] == 5
            assert "match_volume_100" not in result.breakdown
        else:
            assert "match_volume_10" not in result.breakdown
        assert _check(result) == expected


class TestRuleStatusModifier:
    @pytest.mark.parametrize("status", ["experimental", "unsupported"])
    def test_degraded_rule_statuses_subtract_ten(self, database: Database, status: str) -> None:
        alert = _insert_alert(database, "only")
        result = _score(database, alert, rule_status=status)
        assert result.breakdown["rule_status"] == -10
        assert _check(result) == 40

    @pytest.mark.parametrize("status", ["stable", "test", "deprecated", None])
    def test_other_rule_statuses_do_not_count(self, database: Database, status: str | None) -> None:
        alert = _insert_alert(database, "only")
        result = _score(database, alert, rule_status=status)
        assert "rule_status" not in result.breakdown
        assert _check(result) == 50


class TestSiblingFalsePositiveModifier:
    def test_a_dismissed_sibling_subtracts_ten(self, database: Database) -> None:
        alert = _insert_alert(database, "self-1")
        _insert_alert(
            database,
            "sibling",
            status="false_positive",
            first_ms=_TS - 60 * 60 * 1000,
            last_ms=_TS - 60 * 60 * 1000 + 1000,
        )
        result = _score(database, alert)
        assert result.breakdown["sibling_false_positive"] == -10
        assert _check(result) == 40

    def test_a_dismissed_alert_of_another_rule_never_counts(self, database: Database) -> None:
        alert = _insert_alert(database, "self-1")
        _insert_alert(
            database,
            "sibling",
            rule_id="rule-2",
            status="false_positive",
            first_ms=_TS - 60 * 60 * 1000,
            last_ms=_TS - 60 * 60 * 1000 + 1000,
        )
        assert "sibling_false_positive" not in _score(database, alert).breakdown
        assert _check(_score(database, alert)) == 50

    def test_a_dismissed_alert_on_another_host_never_counts(self, database: Database) -> None:
        alert = _insert_alert(database, "self-1")
        _insert_alert(database, "sibling", host="db01", status="false_positive")
        assert _check(_score(database, alert)) == 50


class TestClamping:
    def test_the_score_clamps_at_one_hundred(self, database: Database) -> None:
        alert = _insert_alert(database, "hot", level="critical", match_count=100)
        _insert_alert(database, "near", first_ms=_TS - 5000, last_ms=_TS - 4000)
        _insert_ioc_link(database, "ioc-1", "hot")
        result = _score(database, alert)
        assert result.score == 100
        assert result.breakdown["clamp"] == -15  # 115 raw -> 100
        assert _check(result) == 100

    def test_the_score_clamps_at_zero(self, database: Database) -> None:
        alert = _insert_alert(database, "cold", level="informational")
        _insert_alert(
            database,
            "dismissed",
            status="false_positive",
            first_ms=_TS - _QUARTER_HOUR_MS - 2000,
            last_ms=_TS - _QUARTER_HOUR_MS - 1000,
        )
        result = _score(database, alert, rule_status="experimental")
        assert result.score == 0
        assert result.breakdown["clamp"] == 10  # -10 raw -> 0
        assert _check(result) == 0
