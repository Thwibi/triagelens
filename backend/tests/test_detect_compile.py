"""Sigma rule -> SQL compilation (spec 04 section 2)."""

from __future__ import annotations

import pytest
from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule

from app.detect.backend import TriageBackend
from app.detect.compile import CompileError, compile_detection, referenced_fields
from app.detect.ext import install_sigma_extensions


def _rule(body: dict[str, object], **extra: object) -> SigmaRule:
    rule = {
        "title": "t",
        "status": "stable",
        "id": "00000000-0000-0000-0000-000000000001",
        **extra,
        **body,
    }
    return SigmaRule.from_dict(rule)


class TestTemplates:
    def test_an_equality_on_a_numeric_field(self) -> None:
        rule = _rule(
            {
                "logsource": {"product": "windows", "service": "security"},
                "detection": {"sel": {"EventID": 4625}, "condition": "sel"},
            }
        )
        compiled = compile_detection(rule)
        assert compiled is not None
        assert compiled.sql == "(event_id=4625)"
        assert compiled.fields == ("event_id",)

    def test_a_string_equality_is_case_insensitive(self) -> None:
        rule = _rule(
            {
                "logsource": {"product": "windows", "service": "security"},
                "detection": {"sel": {"user_name": "ADMIN"}, "condition": "sel"},
            }
        )
        compiled = compile_detection(rule)
        assert compiled is not None
        assert "COLLATE NOCASE" in compiled.sql

    def test_a_keyword_search_covers_the_keyword_columns(self) -> None:
        rule = _rule(
            {
                "logsource": {"product": "linux"},
                "detection": {"sel": "mimikatz", "condition": "sel"},
            }
        )
        compiled = compile_detection(rule)
        assert compiled is not None
        for column in ("message", "process_cmdline", "url", "raw"):
            assert f"{column} LIKE '%mimikatz%'" in compiled.sql
        assert compiled.fields == ()

    def test_contains_on_a_string_field(self) -> None:
        rule = _rule(
            {
                "logsource": {"category": "webserver"},
                "detection": {"sel": {"cs-uri-query|contains": "union select"}, "condition": "sel"},
            }
        )
        compiled = compile_detection(rule)
        assert compiled is not None
        assert compiled.sql == "(url_query LIKE '%union select%' ESCAPE '\\')"
        assert compiled.fields == ("url_query",)

    def test_cidr_compiles_to_the_single_udf_call(self) -> None:
        rule = _rule(
            {
                "logsource": {"product": "linux"},
                "detection": {"sel": {"src_ip|cidr": "10.0.0.0/8"}, "condition": "sel"},
            }
        )
        compiled = compile_detection(rule)
        assert compiled is not None
        assert compiled.sql == "(cidr_match(src_ip, '10.0.0.0/8'))"

    def test_re_compiles_to_the_regexp_operator(self) -> None:
        rule = _rule(
            {
                "logsource": {"product": "linux"},
                "detection": {"sel": {"process_cmdline|re": r"bash.+/sh"}, "condition": "sel"},
            }
        )
        compiled = compile_detection(rule)
        assert compiled is not None
        assert compiled.sql == "(process_cmdline REGEXP 'bash.+/sh')"

    def test_an_absent_field_is_a_nulls_test(self) -> None:
        rule = _rule(
            {
                "logsource": {"product": "linux"},
                "detection": {"sel": {"target_user_name": None}, "condition": "sel"},
            }
        )
        compiled = compile_detection(rule)
        assert compiled is not None
        assert compiled.sql == "(target_user_name IS NULL)"

    def test_a_field_reference_compares_two_columns(self) -> None:
        rule = _rule(
            {
                "logsource": {"product": "linux"},
                "detection": {"sel": {"user_name|fieldref": "src_ip"}, "condition": "sel"},
            }
        )
        compiled = compile_detection(rule)
        assert compiled is not None
        assert compiled.sql == "(user_name=src_ip COLLATE NOCASE)"
        assert set(compiled.fields) == {"user_name", "src_ip"}

    def test_and_not_combines_two_selections(self) -> None:
        rule = _rule(
            {
                "logsource": {"product": "linux", "service": "sshd"},
                "detection": {
                    "sel": {"event_action": "ssh_failed_password"},
                    "filter": {"user_name": "root"},
                    "condition": "sel and not filter",
                },
            }
        )
        compiled = compile_detection(rule)
        assert compiled is not None
        assert "event_action" in compiled.sql
        assert "NOT COALESCE" in compiled.sql
        assert "user_name='root'" in compiled.sql

    def test_one_of_a_named_selection_is_an_or(self) -> None:
        rule = _rule(
            {
                "logsource": {"product": "windows", "service": "security"},
                "detection": {
                    "s1": {"EventID": 4648},
                    "s2": {"EventID": 4672},
                    "condition": "1 of s*",
                },
            }
        )
        compiled = compile_detection(rule)
        assert compiled is not None
        assert compiled.sql == "(event_id=4648 OR event_id=4672)"

    def test_contains_on_a_numeric_column_casts_to_text(self) -> None:
        rule = _rule(
            {
                "logsource": {"category": "webserver"},
                "detection": {"sel": {"sc-status|contains": "50"}, "condition": "sel"},
            }
        )
        compiled = compile_detection(rule)
        assert compiled is not None
        assert compiled.sql == "(CAST(http_status AS TEXT) LIKE '%50%' ESCAPE '\\')"

    def test_firewall_deny_maps_to_the_derived_value(self) -> None:
        rule = _rule(
            {
                "logsource": {"category": "firewall"},
                "detection": {"sel": {"action": "deny"}, "condition": "sel"},
            }
        )
        compiled = compile_detection(rule)
        assert compiled is not None
        assert "firewall" in compiled.sql

    def test_an_unknown_field_resolves_through_fields_json(self) -> None:
        rule = _rule(
            {
                "logsource": {"product": "windows", "service": "security"},
                "detection": {"sel": {"TargetUserName": "svc_bot"}, "condition": "sel"},
            }
        )
        compiled = compile_detection(rule)
        assert compiled is not None
        assert "json_extract(fields_json, '$.\"TargetUserName\"')" in compiled.sql

    def test_multi_byte_fieldless_keyword(self) -> None:
        rule = _rule(
            {
                "logsource": {"product": "linux"},
                "detection": {"sel": "Камбер", "condition": "sel"},
            }
        )
        compiled = compile_detection(rule)
        assert compiled is not None
        assert compiled.sql.count("Камбер") == 4  # verbatim in all four keyword columns
        assert "LIKE '%Камбер%'" in compiled.sql


class TestExt:
    def test_the_utf16le_alias_is_installed_and_compiles(self) -> None:
        install_sigma_extensions()
        rule = _rule(
            {
                "logsource": {"product": "windows", "service": "sysmon"},
                "detection": {
                    "sel": {"CommandLine|utf16le|contains": "powershell"},
                    "condition": "sel",
                },
            }
        )
        compiled = compile_detection(rule)
        assert compiled is not None
        assert "LIKE" in compiled.sql

    def test_installing_extensions_twice_is_safe(self) -> None:
        install_sigma_extensions()
        install_sigma_extensions()


class TestRejects:
    def test_a_conversion_with_no_output_is_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        rule = _rule(
            {
                "logsource": {"product": "windows", "service": "security"},
                "detection": {"sel": {"EventID": 4624}, "condition": "sel"},
            }
        )
        monkeypatch.setattr(TriageBackend, "convert_rule", lambda self, rule, *a, **k: [])
        with pytest.raises(CompileError, match="no matching condition"):
            compile_detection(rule)

    def test_a_backend_failure_is_wrapped_as_a_compile_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        rule = _rule(
            {
                "logsource": {"product": "linux"},
                "detection": {"sel": "x", "condition": "sel"},
            }
        )

        def boom(self: TriageBackend, rule: SigmaRule, *args: object, **kwargs: object) -> None:
            raise RuntimeError("backend exploded")

        monkeypatch.setattr(TriageBackend, "convert_rule", boom)
        with pytest.raises(CompileError, match="backend exploded"):
            compile_detection(rule)

    def test_a_shape_error_is_reported(self, monkeypatch: pytest.MonkeyPatch) -> None:
        rule = _rule(
            {
                "logsource": {"product": "linux"},
                "detection": {"sel": "x", "condition": "sel"},
            }
        )
        monkeypatch.setattr(
            TriageBackend, "convert_rule", lambda self, rule, *a, **k: ["not a query"]
        )
        with pytest.raises(CompileError, match="unexpected shape"):
            compile_detection(rule)

    def test_a_correlation_rule_compiles_to_nothing(self) -> None:
        correlation = __import__("sigma.correlations", fromlist=["SigmaCorrelationRule"])
        rule = correlation.SigmaCorrelationRule.from_dict(
            {
                "title": "corr",
                "id": "00000000-0000-0000-0000-000000000002",
                "logsource": {"product": "windows", "service": "security"},
                "correlation": {
                    "type": "event_count",
                    "rules": ["00000000-0000-0000-0000-000000000001"],
                    "group-by": ["user_name"],
                    "timespan": "5m",
                    "condition": {"gte": 10},
                },
            }
        )
        assert isinstance(rule, SigmaCorrelationRule)
        assert compile_detection(rule) is None


class TestReferencedFields:
    def test_plain_fields_are_collected(self) -> None:
        rule = _rule(
            {
                "logsource": {"product": "linux"},
                "detection": {
                    "sel": {"user_name": "bob", "event_action": "play"},
                    "condition": "sel",
                },
            }
        )
        assert referenced_fields(rule) == {"user_name", "event_action"}

    def test_field_references_are_collected(self) -> None:
        rule = _rule(
            {
                "logsource": {"product": "linux"},
                "detection": {"sel": {"user_name|fieldref": "src_ip"}, "condition": "sel"},
            }
        )
        assert referenced_fields(rule) == {"user_name", "src_ip"}

    def test_keyword_only_rules_reference_nothing(self) -> None:
        rule = _rule(
            {
                "logsource": {"product": "linux"},
                "detection": {"sel": "tokens", "condition": "sel"},
            }
        )
        assert referenced_fields(rule) == set()
