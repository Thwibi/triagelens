"""Field resolution: logsource maps, normalized columns and json fallback."""

from __future__ import annotations

import pytest

from app.detect.fields import (
    FIREWALL_FIELD_MAP,
    NORMALIZED_COLUMNS,
    FieldContext,
    FieldResolver,
)


def _windows() -> FieldResolver:
    return FieldResolver(FieldContext(product="windows", category="process_creation"))


def _web() -> FieldResolver:
    return FieldResolver(FieldContext(category="webserver"))


def _firewall() -> FieldResolver:
    return FieldResolver(FieldContext(category="firewall"))


def _generic() -> FieldResolver:
    return FieldResolver(FieldContext())


class TestLogsourceMaps:
    def test_windows_fields_resolve_to_columns(self) -> None:
        resolver = _windows()
        assert resolver.resolve("CommandLine") == "process_cmdline"
        assert resolver.resolve("Image") == "process_path"
        assert resolver.resolve("User") == "user_name"

    def test_the_windows_map_is_case_insensitive(self) -> None:
        assert _windows().resolve("commandline") == "process_cmdline"

    def test_web_fields_resolve_to_columns(self) -> None:
        resolver = _web()
        assert resolver.resolve("cs-uri-query") == "url_query"
        assert resolver.resolve("sc-status") == "http_status"
        assert resolver.resolve("c-ip") == "src_ip"

    def test_firewall_action_resolves_to_the_derived_column(self) -> None:
        resolver = _firewall()
        assert resolver.resolve("action") == "event_action"
        assert resolver.uses_firewall_action is True

    def test_firewall_only_claims_its_own_map(self) -> None:
        assert _firewall()._field_map is FIREWALL_FIELD_MAP
        assert _windows().uses_firewall_action is False


class TestNormalizedColumns:
    @pytest.mark.parametrize(
        "field",
        [
            "src_ip",
            "dst_port",
            "user_name",
            "channel",
            "http_status",
            "raw",
            "fields_json",
        ],
    )
    def test_a_direct_column_is_kept_verbatim(self, field: str) -> None:
        assert _generic().resolve(field) == field

    def test_a_column_lookup_is_case_insensitive(self) -> None:
        assert _generic().resolve("SRC_IP") == "src_ip"
        assert _generic().resolve("Event_Id") == "event_id"

    def test_every_event_column_resolves_to_itself_through_the_map_windows(
        self,
    ) -> None:
        resolver = _windows()
        for column in NORMALIZED_COLUMNS:
            assert resolver.resolve(column) == column


class TestJsonFallback:
    def test_an_unknown_field_becomes_a_json_extract(self) -> None:
        resolved = _generic().resolve("TargetUserName")
        assert resolved == "json_extract(fields_json, '$.\"TargetUserName\"')"

    def test_the_json_key_keeps_the_rules_own_casing(self) -> None:
        """Parser writes original EventData keys; json_extract is case-sensitive."""
        assert _generic().resolve("TargetUserName") == (
            "json_extract(fields_json, '$.\"TargetUserName\"')"
        )
        assert _generic().resolve("targetusername") != _generic().resolve("TargetUserName")

    def test_a_quote_inside_a_field_name_is_escaped(self) -> None:
        resolved = _generic().resolve('He"llo')
        assert 'He\\"llo' in resolved

    def test_a_single_quote_in_a_field_name_cannot_break_the_sql_literal(self) -> None:
        resolved = _generic().resolve("a'; DROP TABLE events;--")
        assert resolved == "json_extract(fields_json, '$.\"a''; DROP TABLE events;--\"')"


class TestNumericAndPresence:
    def test_numeric_columns_are_flagged(self) -> None:
        assert _web().is_numeric_field("sc-status") is True
        assert _web().is_numeric_field("c-ip") is False

    def test_a_json_fallback_is_not_numeric(self) -> None:
        assert _generic().is_numeric_field("HttpStatusCode") is False

    def test_presence_expression_is_an_is_not_null_on_the_resolved_column(self) -> None:
        assert _windows().presence_expression("process_cmdline") == ("process_cmdline IS NOT NULL")
