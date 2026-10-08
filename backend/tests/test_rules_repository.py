"""Rule catalogue repository: upserts, filters, health (spec 04 sections 1, 9)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from app.db.connection import Database
from app.db.repositories.rules import RuleRepository
from app.detect.rules import LoadedRule, load_rules
from app.models.rule import KIND_CUSTOM, RULE_TYPE_DETECTION
from app.util.hashing import hash_mapping

BACKEND_ROOT = Path(__file__).resolve().parents[1]
BUILTIN_DIR = BACKEND_ROOT / "rules" / "builtin"
MAP = BACKEND_ROOT / "rules" / "logsource_map.yaml"


@pytest.fixture
def builtin() -> list[LoadedRule]:
    rules, problems = load_rules(builtin_dir=BUILTIN_DIR, logsource_map=MAP)
    assert problems == []
    return rules


@pytest.fixture
def repo(database: Database) -> RuleRepository:
    return RuleRepository(database.writer)


def _loaded(rule_id: str = "custom-1", **overrides: Any) -> LoadedRule:
    values: dict[str, Any] = {
        "id": rule_id,
        "title": "Custom Rule",
        "kind": KIND_CUSTOM,
        "rule_type": RULE_TYPE_DETECTION,
        "level": "high",
        "status": "stable",
        "yaml": "title: Custom Rule\n",
        "tags": ("attack.t1059",),
        "logsource": {"category": "webserver"},
        "file_path": None,
        "sha256": "a" * 64,
        "compile_error": None,
        "unroutable": False,
        "route": None,
        "sigma_rule": None,
    }
    values.update(overrides)
    return LoadedRule(**values)


class TestUpsert:
    def test_every_loaded_rule_lands_with_its_health(
        self, repo: RuleRepository, builtin: list[LoadedRule]
    ) -> None:
        assert repo.upsert_many(builtin) == 16
        assert repo.count() == 16
        assert repo.health_counts() == {"ok": 16, "compile_error": 0, "unroutable": 0}

    def test_a_stored_rule_round_trips_its_metadata(
        self, repo: RuleRepository, builtin: list[LoadedRule]
    ) -> None:
        repo.upsert_many(builtin)
        record = repo.get("7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e01")
        assert record is not None
        assert record.title == "SSH Failed Password (base)"
        assert record.kind == "builtin"
        assert record.rule_type == "detection"
        assert record.level == "informational"
        assert record.status == "stable"
        assert record.enabled is True
        assert record.tags == ("attack.credential-access", "attack.t1110.001")
        assert record.logsource == {"product": "linux", "service": "sshd"}
        assert "SSH Failed Password" in record.yaml
        assert record.compile_error is None
        assert record.unroutable is False
        assert record.healthy is True

    def test_reload_never_re_enables_a_disabled_rule(
        self, repo: RuleRepository, builtin: list[LoadedRule]
    ) -> None:
        repo.upsert_many(builtin)
        assert repo.set_enabled("7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e01", enabled=False)
        repo.upsert_many(builtin)
        record = repo.get("7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e01")
        assert record is not None
        assert record.enabled is False

    def test_reload_refreshes_stale_health(
        self, repo: RuleRepository, builtin: list[LoadedRule]
    ) -> None:
        repo.upsert_many(builtin)
        repo.upsert_many([_loaded(compile_error="unsupported modifier: x")])
        assert repo.health_counts()["compile_error"] == 1
        repo.upsert_many([_loaded(compile_error=None)])
        assert repo.health_counts() == {
            "ok": len(builtin) + 1,
            "compile_error": 0,
            "unroutable": 0,
        }

    def test_upserting_nothing_is_a_noop(self, repo: RuleRepository) -> None:
        assert repo.upsert_many([]) == 0
        assert repo.count() == 0


class TestRead:
    def test_get_missing_is_none_and_delete_reports_absence(self, repo: RuleRepository) -> None:
        assert repo.get("nothing") is None
        assert repo.delete("nothing") is False
        assert repo.set_enabled("nothing", enabled=False) is False

    def test_delete_removes_a_custom_rule(
        self, repo: RuleRepository, builtin: list[LoadedRule]
    ) -> None:
        repo.upsert_many([*builtin, _loaded()])
        assert repo.count() == 17
        assert repo.delete("custom-1") is True
        assert repo.get("custom-1") is None
        assert repo.count() == 16

    def test_paging_is_stable(self, repo: RuleRepository, builtin: list[LoadedRule]) -> None:
        repo.upsert_many(builtin)
        first = [rule.id for rule in repo.list(limit=5, offset=0)]
        second = [rule.id for rule in repo.list(limit=5, offset=5)]
        assert len(first) == len(second) == 5
        assert set(first).isdisjoint(second)

    def test_count_matches_the_full_list(
        self, repo: RuleRepository, builtin: list[LoadedRule]
    ) -> None:
        repo.upsert_many(builtin)
        assert repo.count(q="SSH") == len(repo.list(q="SSH", limit=100)) > 0

    def test_enabled_rules_exclude_disabled_and_order_bases_first(
        self, repo: RuleRepository, builtin: list[LoadedRule]
    ) -> None:
        repo.upsert_many(builtin)
        repo.set_enabled("7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e02", enabled=False)  # a correlation
        rules = repo.enabled_rules()
        assert len(rules) == 15
        assert all(
            rule.rule_type != "correlation" or rule.id != ("7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e02")
            for rule in rules
        )
        types = [rule.rule_type for rule in rules]
        assert types == sorted(types, key=lambda value: value == "correlation")
        assert rules == repo.enabled_rules()  # deterministic across calls


class TestFilters:
    @pytest.fixture
    def stocked(self, repo: RuleRepository, builtin: list[LoadedRule]) -> RuleRepository:
        repo.upsert_many([*builtin, _loaded()])
        return repo

    def test_kind(self, stocked: RuleRepository) -> None:
        assert stocked.count(kind="builtin") == 16
        assert [rule.id for rule in stocked.list(kind="custom")] == ["custom-1"]

    def test_level_and_status(self, stocked: RuleRepository) -> None:
        informational = {rule.id for rule in stocked.list(level="informational")}
        assert "7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e01" in informational
        assert len(informational) == 4
        test_status = {rule.id for rule in stocked.list(status="test")}
        assert test_status == {
            "7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e23",
            "7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e41",
        }

    def test_enabled(self, stocked: RuleRepository) -> None:
        stocked.set_enabled("custom-1", enabled=False)
        assert stocked.count(enabled=False) == 1
        assert stocked.count(enabled=True) == 16

    def test_tag_matches_any_listed_tag(self, stocked: RuleRepository) -> None:
        hits = {rule.id for rule in stocked.list(tag="attack.t1110.001")}
        assert hits == {
            "7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e01",
            "7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e02",
            "7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e12",
        }

    def test_title_search_is_literal_about_wildcards(self, stocked: RuleRepository) -> None:
        assert [rule.id for rule in stocked.list(q="Port Scan")] == [
            "7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e31"
        ]
        assert stocked.count(q="%") == 0  # a bare wildcard matches no title
        assert stocked.count(q="_") == 0

    def test_health_buckets(self, stocked: RuleRepository) -> None:
        assert stocked.count(health="ok") == 17
        assert stocked.count(health="compile_error") == 0
        assert stocked.count(health="unroutable") == 0

    def test_an_unknown_health_filter_is_rejected(self, stocked: RuleRepository) -> None:
        with pytest.raises(ValueError, match="unknown rule health filter"):
            stocked.list(health="fine")

    def test_filters_combine(self, stocked: RuleRepository) -> None:
        assert stocked.count(kind="builtin", level="informational", health="ok") == 4


class TestHealthCounts:
    def test_buckets_sum_to_the_catalogue(self, repo: RuleRepository) -> None:
        repo.upsert_many(
            [
                _loaded(rule_id="good"),
                _loaded(rule_id="bad-compile", compile_error="unsupported modifier: x"),
                _loaded(rule_id="bad-route", unroutable=True),
                _loaded(rule_id="bad-both", compile_error="nope", unroutable=True),
            ]
        )
        counts = repo.health_counts()
        assert counts == {"ok": 1, "compile_error": 2, "unroutable": 1}
        assert sum(counts.values()) == 4  # precedence: compile errors win

    def test_an_empty_catalogue_reports_zeroes(self, repo: RuleRepository) -> None:
        assert repo.health_counts() == {"ok": 0, "compile_error": 0, "unroutable": 0}


class TestRulesetHash:
    def test_an_empty_catalogue_hashes_the_empty_set(self, repo: RuleRepository) -> None:
        assert repo.ruleset_hash() == hash_mapping({})

    def test_hash_covers_only_enabled_rules(
        self, repo: RuleRepository, builtin: list[LoadedRule]
    ) -> None:
        repo.upsert_many(builtin)
        assert repo.ruleset_hash() == hash_mapping({rule.id: rule.sha256 for rule in builtin})
        disabled = builtin[0].id
        assert repo.set_enabled(disabled, enabled=False)
        assert repo.ruleset_hash() == hash_mapping(
            {rule.id: rule.sha256 for rule in builtin if rule.id != disabled}
        )
