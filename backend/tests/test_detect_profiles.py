"""Detection profile selection (spec 04 section 2)."""

from __future__ import annotations

import pytest

from app.detect.profiles import level_at_least, select_for_profile
from app.models.rule import KIND_BUILTIN, KIND_CUSTOM, KIND_SIGMA, RuleRecord


def _record(
    *,
    rule_id: str = "rule",
    kind: str = KIND_SIGMA,
    level: str = "medium",
    status: str | None = "stable",
    enabled: bool = True,
    rule_type: str = "detection",
) -> RuleRecord:
    return RuleRecord(
        id=rule_id,
        title="Example",
        kind=kind,
        rule_type=rule_type,
        level=level,
        status=status,
        enabled=enabled,
        yaml="title: Example\n",
        tags=(),
        logsource={},
        file_path=None,
        sha256="0" * 64,
        compile_error=None,
        unroutable=False,
        updated_at="2026-01-01T00:00:00+00:00",
    )


def _selected(rules: list[RuleRecord], profile: str) -> set[str]:
    return {rule.id for rule in select_for_profile(rules, profile)}


class TestFast:
    def test_builtins_always_run_even_when_informational(self) -> None:
        rule = _record(rule_id="base", kind=KIND_BUILTIN, level="informational")
        assert _selected([rule], "fast") == {"base"}

    def test_high_and_stable_sigma_rules_run(self) -> None:
        assert _selected([_record(rule_id="h", level="high")], "fast") == {"h"}
        assert _selected([_record(rule_id="c", level="critical", status="test")], "fast") == {"c"}

    def test_experimental_and_unstatused_high_rules_do_not_run(self) -> None:
        assert (
            _selected([_record(rule_id="e", level="high", status="experimental")], "fast") == set()
        )
        assert _selected([_record(rule_id="n", level="high", status=None)], "fast") == set()

    def test_medium_sigma_rules_do_not_run(self) -> None:
        assert _selected([_record(rule_id="m", level="medium")], "fast") == set()


class TestStandard:
    def test_medium_and_above_sigma_rules_run(self) -> None:
        assert _selected([_record(rule_id="m", level="medium")], "standard") == {"m"}
        assert _selected([_record(rule_id="l", level="low")], "standard") == set()

    def test_status_does_not_matter_at_standard(self) -> None:
        rule = _record(rule_id="x", level="high", status="experimental")
        assert _selected([rule], "standard") == {"x"}

    def test_every_custom_rule_runs_regardless_of_level(self) -> None:
        rule = _record(rule_id="k", kind=KIND_CUSTOM, level="informational")
        assert _selected([rule], "standard") == {"k"}

    def test_builtins_run(self) -> None:
        rule = _record(rule_id="b", kind=KIND_BUILTIN, level="low")
        assert _selected([rule], "standard") == {"b"}


class TestFullAndDisabled:
    def test_full_runs_everything_enabled(self) -> None:
        rules = [
            _record(rule_id="i", level="informational", status="experimental"),
            _record(rule_id="l", level="low"),
        ]
        assert _selected(rules, "full") == {"i", "l"}

    @pytest.mark.parametrize("profile", ["fast", "standard", "full"])
    def test_disabled_rules_never_run(self, profile: str) -> None:
        rules = [
            _record(rule_id="on", kind=KIND_BUILTIN, enabled=True),
            _record(rule_id="off", kind=KIND_BUILTIN, enabled=False),
        ]
        assert _selected(rules, profile) == {"on"}


class TestValidation:
    def test_an_unknown_profile_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="unknown detection profile"):
            select_for_profile([_record()], "turbo")

    def test_input_order_is_preserved(self) -> None:
        rules = [
            _record(rule_id="zeta", level="high"),
            _record(rule_id="alpha", level="high"),
            _record(rule_id="skip", level="low"),
        ]
        chosen = select_for_profile(rules, "standard")
        assert [rule.id for rule in chosen] == ["zeta", "alpha"]


class TestLevelAtLeast:
    @pytest.mark.parametrize(
        ("level", "minimum", "expected"),
        [
            ("medium", "medium", True),
            ("high", "medium", True),
            ("critical", "medium", True),
            ("low", "medium", False),
            ("informational", "medium", False),
            ("HIGH", "medium", True),  # case-insensitive
            ("bogus", "medium", False),  # unknown level never matches
            ("high", "bogus", False),  # unknown floor never matches
        ],
    )
    def test_ranking(self, level: str, minimum: str, expected: bool) -> None:
        assert level_at_least(level, minimum) is expected
