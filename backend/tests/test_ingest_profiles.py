"""Mapping profile loading and resolution (spec 03 section 6)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from app.ingest.profiles import (
    ProfileError,
    flatten,
    load_profile,
    load_profiles,
    resolve,
    validate_path,
)

ECS_RECORD: dict[str, Any] = {
    "@timestamp": "2026-03-01T10:00:00Z",
    "host": {"name": "web01"},
    "source": {"ip": "192.168.1.5", "port": 44322},
    "event": {"category": ["process"], "outcome": "success"},
    "extra": {"nested": {"deep": "value"}},
}


class TestFlatten:
    """Nested dicts collapse to dot notation; arrays stay whole."""

    def test_nested_dicts_are_dotted(self) -> None:
        assert flatten(ECS_RECORD)["host.name"] == "web01"
        assert flatten(ECS_RECORD)["extra.nested.deep"] == "value"

    def test_arrays_are_not_indexed(self) -> None:
        # Arrays are addressed with [*] by path, so no event.category.0 keys.
        assert "event.category.0" not in flatten(ECS_RECORD)
        assert flatten(ECS_RECORD)["event.category"] == ["process"]

    def test_non_dict_returns_empty(self) -> None:
        assert flatten(["a"]) == {}
        assert flatten("text") == {}

    def test_nested_dict_leaves_are_dotted_not_duplicated(self) -> None:
        # Leaves only: the intermediate dict is reachable through its dotted
        # path, so a second entry for it would be redundant.
        assert "host" not in flatten(ECS_RECORD)
        assert flatten(ECS_RECORD)["host.name"] == "web01"


class TestResolve:
    """Dot paths, [*] for arrays, and a missing key is not an error."""

    def test_simple_path(self) -> None:
        assert resolve(ECS_RECORD, "host.name") == "web01"

    def test_ecs_at_prefixed_key(self) -> None:
        assert resolve(ECS_RECORD, "@timestamp") == "2026-03-01T10:00:00Z"

    def test_star_takes_first_array_element(self) -> None:
        assert resolve(ECS_RECORD, "event.category[*]") == "process"

    def test_missing_key_returns_none(self) -> None:
        assert resolve(ECS_RECORD, "host.missing") is None
        assert resolve(ECS_RECORD, "absent") is None

    def test_walking_into_a_scalar_returns_none(self) -> None:
        assert resolve(ECS_RECORD, "host.name.deeper") is None

    def test_empty_path_returns_none(self) -> None:
        assert resolve(ECS_RECORD, "") is None

    def test_star_on_a_missing_list_returns_none(self) -> None:
        assert resolve(ECS_RECORD, "absent[*]") is None


class TestValidatePath:
    """Rejected paths become ProfileError, not a silent NULL column."""

    @pytest.mark.parametrize("path", ["host.name", "@timestamp", "a.b.c", "x[*]", "user-name"])
    def test_accepts_ordinary_paths(self, path: str) -> None:
        assert validate_path(path) == path

    @pytest.mark.parametrize("path", ["", ".a", "a.", "a..b", "a b", "a/*", "a[]", "a.b$c"])
    def test_rejects_malformed_paths(self, path: str) -> None:
        with pytest.raises(ProfileError):
            validate_path(path)


class TestLoadProfile:
    """A broken profile must be refused loudly rather than half-applied."""

    def write(self, tmp_path: Path, body: str) -> Path:
        path = tmp_path / "p.yaml"
        path.write_text(body, encoding="utf-8")
        return path

    def test_loads_the_shipped_ecs_profile(self) -> None:
        shipped = Path(__file__).resolve().parents[1] / "data" / "profiles" / "elastic-ecs.yaml"
        profile = load_profile(shipped)
        assert profile.name == "elastic-ecs"
        assert profile.timestamp_path == "@timestamp"
        assert profile.fields["host"] == "host.name"
        assert profile.applies_to(ECS_RECORD) is True

    def test_shipped_profile_maps_every_documented_column(self) -> None:
        shipped = Path(__file__).resolve().parents[1] / "data" / "profiles" / "elastic-ecs.yaml"
        fields = load_profile(shipped).fields
        for column in (
            "host",
            "user_name",
            "src_ip",
            "src_port",
            "dst_ip",
            "dst_port",
            "process_path",
            "process_cmdline",
            "parent_process_path",
            "file_path",
            "url",
            "http_method",
            "http_status",
            "user_agent",
            "message",
            "event_id",
            "event_action",
            "event_outcome",
        ):
            assert column in fields, f"{column} is not mapped"

    def test_valid_minimal_profile(self, tmp_path: Path) -> None:
        path = self.write(tmp_path, "name: minimal\ntimestamp: {path: ts}\n")
        assert load_profile(path).timestamp_format == "iso8601"

    def test_missing_name_is_rejected(self, tmp_path: Path) -> None:
        path = self.write(tmp_path, "timestamp: {path: ts}\n")
        with pytest.raises(ProfileError, match="non-empty name"):
            load_profile(path)

    def test_missing_timestamp_is_rejected(self, tmp_path: Path) -> None:
        path = self.write(tmp_path, "name: x\n")
        with pytest.raises(ProfileError, match="timestamp mapping"):
            load_profile(path)

    def test_bad_timestamp_format_is_rejected(self, tmp_path: Path) -> None:
        path = self.write(tmp_path, "name: x\ntimestamp: {path: ts, format: banana}\n")
        with pytest.raises(ProfileError, match="unsupported timestamp format"):
            load_profile(path)

    def test_strptime_format_is_accepted(self, tmp_path: Path) -> None:
        path = self.write(tmp_path, "name: x\ntimestamp: {path: ts, format: 'strptime:%d/%b/%Y'}\n")
        assert load_profile(path).timestamp_format == "strptime:%d/%b/%Y"

    def test_bad_field_path_is_rejected(self, tmp_path: Path) -> None:
        path = self.write(tmp_path, "name: x\ntimestamp: {path: ts}\nfields: {host: 'a b'}\n")
        with pytest.raises(ProfileError):
            load_profile(path)

    def test_category_rule_needs_both_halves(self, tmp_path: Path) -> None:
        path = self.write(
            tmp_path, "name: x\ntimestamp: {path: ts}\ncategory_rules: [{when: {a: b}}]\n"
        )
        with pytest.raises(ProfileError, match="ls_category"):
            load_profile(path)

    def test_non_mapping_document_is_rejected(self, tmp_path: Path) -> None:
        path = self.write(tmp_path, "- just\n- a\n- list\n")
        with pytest.raises(ProfileError, match="YAML mapping"):
            load_profile(path)

    def test_malformed_yaml_is_rejected(self, tmp_path: Path) -> None:
        path = self.write(tmp_path, "name: [unclosed\n")
        with pytest.raises(ProfileError, match="not valid YAML"):
            load_profile(path)


class TestCategoryRules:
    """First match wins, and array-valued fields match element-wise."""

    def test_matching_rule_wins(self, tmp_path: Path) -> None:
        path = tmp_path / "p.yaml"
        path.write_text(
            "name: x\n"
            "timestamp: {path: ts}\n"
            "category_rules:\n"
            "  - {when: {event.category: process}, ls_category: process_creation}\n"
            "  - {when: {event.category: network}, ls_category: network_connection}\n",
            encoding="utf-8",
        )
        profile = load_profile(path)
        assert profile.category_for(ECS_RECORD) == "process_creation"

    def test_array_valued_category_matches(self, tmp_path: Path) -> None:
        path = tmp_path / "p.yaml"
        path.write_text(
            "name: x\n"
            "timestamp: {path: ts}\n"
            "category_rules:\n"
            "  - {when: {event.category: network}, ls_category: network_connection}\n",
            encoding="utf-8",
        )
        profile = load_profile(path)
        assert profile.category_for({"event": {"category": ["network"]}}) == "network_connection"

    def test_no_match_returns_none(self, tmp_path: Path) -> None:
        path = tmp_path / "p.yaml"
        path.write_text(
            "name: x\n"
            "timestamp: {path: ts}\n"
            "category_rules:\n"
            "  - {when: {event.category: network}, ls_category: network_connection}\n",
            encoding="utf-8",
        )
        assert load_profile(path).category_for({"event": {"category": ["process"]}}) is None

    def test_unconditional_profile_applies_to_anything(self, tmp_path: Path) -> None:
        path = tmp_path / "p.yaml"
        path.write_text("name: x\ntimestamp: {path: ts}\n", encoding="utf-8")
        profile = load_profile(path)
        assert profile.applies_to({"anything": 1}) is True
        assert profile.applies_to({}) is True


class TestApplyWhen:
    """applies_when is how one JSON file can hold several record shapes."""

    def test_any_key_match_claims_the_record(self, tmp_path: Path) -> None:
        path = tmp_path / "p.yaml"
        path.write_text(
            "name: x\ntimestamp: {path: '@timestamp'}\napplies_when: {any_key: ['@timestamp']}\n",
            encoding="utf-8",
        )
        profile = load_profile(path)
        assert profile.applies_to(ECS_RECORD) is True
        assert profile.applies_to({"other": 1}) is False

    def test_any_key_must_be_a_list(self, tmp_path: Path) -> None:
        path = tmp_path / "p.yaml"
        path.write_text(
            "name: x\ntimestamp: {path: ts}\napplies_when: {any_key: nope}\n", encoding="utf-8"
        )
        with pytest.raises(ProfileError, match="must be a list"):
            load_profile(path)


class TestLoadProfiles:
    """Directory loading fails on a bad file instead of skipping it."""

    def test_loads_shipped_profiles(self) -> None:
        shipped = Path(__file__).resolve().parents[1] / "data" / "profiles"
        assert "elastic-ecs" in load_profiles(shipped)

    def test_missing_directory_is_empty(self, tmp_path: Path) -> None:
        assert load_profiles(tmp_path / "absent") == {}

    def test_one_bad_profile_raises(self, tmp_path: Path) -> None:
        (tmp_path / "good.yaml").write_text("name: good\ntimestamp: {path: ts}\n", encoding="utf-8")
        (tmp_path / "bad.yaml").write_text("name: bad\n", encoding="utf-8")
        with pytest.raises(ProfileError):
            load_profiles(tmp_path)
