"""Generic JSON and CSV parsers plus the mapping-profile engine (spec 03 6).

The two readers turn a file into records differently - JSON walks objects, CSV
walks header-labelled rows - but both hand a dict to the same profile engine, so
one set of tests covers the mapping once and the readers separately. Detection is
held to routing every fixture to a confident log type (spec 09 P-11), and the
goldens pin the ECS, Wazuh, CloudTrail, Zeek, Splunk and Defender mappings.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.ingest.detect import detect
from app.ingest.events import EVENT_COLUMNS, NormalizedEvent
from app.ingest.parsers.base import ParseContext, ParseFailure
from app.ingest.parsers.generic_csv import GenericCsvParser
from app.ingest.parsers.generic_json import GenericJsonParser
from app.ingest.profiles import (
    CategoryRule,
    Profile,
    ProfileError,
    flatten,
    load_profile,
    resolve,
    validate_path,
)
from app.ingest.text import read_head

GENERIC_DIR = Path(__file__).resolve().parent / "fixtures" / "generic"

#: Every fixture with the parser that reads it and the type detection promises.
_FIXTURES = [
    ("elastic_ecs.ndjson", GenericJsonParser(), "generic_json", 0.9),
    ("wazuh_alerts.json", GenericJsonParser(), "generic_json", 0.9),
    ("cloudtrail.json", GenericJsonParser(), "generic_json", 0.9),
    ("zeek_conn.json", GenericJsonParser(), "generic_json", 0.9),
    ("zeek_conn.log", GenericCsvParser(), "generic_csv", 0.9),
    ("splunk_export.csv", GenericCsvParser(), "generic_csv", 0.85),
    ("defender_events.csv", GenericCsvParser(), "generic_csv", 0.85),
]

_DETECTION = [(name, log_type, confidence) for name, _p, log_type, confidence in _FIXTURES]


def _context(path: Path, timezone: str | None = "UTC") -> ParseContext:
    return ParseContext(
        case_id="fixture",
        source_id="fixture",
        filename=path.name,
        path=path,
        max_line_bytes=1 << 20,
        timezone=timezone,
    )


def _run(parser: object, path: Path) -> tuple[list[NormalizedEvent], list[ParseFailure]]:
    events: list[NormalizedEvent] = []
    failures: list[ParseFailure] = []
    for item in parser.parse(_context(path)):  # type: ignore[attr-defined]
        if isinstance(item, ParseFailure):
            failures.append(item)
        else:
            events.append(item)
    return events, failures


def _write(tmp_path: Path, name: str, body: str) -> Path:
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return path


def _golden(event: NormalizedEvent) -> dict:
    """The stable projection of an event stored in a golden."""
    return {
        name: getattr(event, name) for name in EVENT_COLUMNS if name not in ("source_id", "case_id")
    }


def _profile(**overrides: object) -> Profile:
    """A minimal usable profile, overridden per test.

    Tests build profiles directly rather than leaning on the shipped files, so a
    change to ``data/profiles`` cannot silently change what a unit test proves.
    """
    base: dict[str, object] = {
        "name": "test",
        "timestamp_path": "ts",
        "timestamp_format": "iso8601",
        "timezone": "UTC",
        "fields": {"host": "host", "src_ip": "src"},
    }
    base.update(overrides)
    return Profile(**base)  # type: ignore[arg-type]


class TestDetection:
    """Each fixture is claimed by the promised log type, confidently."""

    @pytest.mark.parametrize(("name", "log_type", "confidence"), _DETECTION)
    def test_detect(self, name: str, log_type: str, confidence: float) -> None:
        result = detect(GENERIC_DIR / name)
        assert result.log_type == log_type
        assert result.confidence == pytest.approx(confidence)
        assert result.needs_input is False

    def test_unknown_csv_is_not_confident(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "mystery.csv", "a,b,c\n1,2,3\n")
        assert GenericCsvParser().sniff(read_head(path)) == 0.5

    def test_zeek_tsv_is_most_confident(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "conn.log", "#separator \\x09\n#fields\ta\tb\nx\ty\n")
        assert GenericCsvParser().sniff(read_head(path)) == 0.9


class TestProfileEngine:
    """Loading, validating and applying a mapping profile."""

    def test_flatten_nests_with_dots(self) -> None:
        assert flatten({"a": {"b": 1}, "c": [1, 2]}) == {"a.b": 1, "c": [1, 2]}

    def test_resolve_walks_and_stops_at_non_object(self) -> None:
        record = {"a": {"b": {"c": 1}}, "s": "text"}
        assert resolve(record, "a.b.c") == 1
        assert resolve(record, "a.b.deeper") is None
        assert resolve(record, "missing") is None

    def test_resolve_takes_first_array_element(self) -> None:
        assert resolve({"a": [{"b": 7}]}, "a[*].b") == 7
        assert resolve({"a": []}, "a[*].b") is None

    def test_resolve_matches_a_dotted_flat_column(self) -> None:
        # A CSV column literally named ``id.orig_h`` must win over dot-walking.
        assert resolve({"id.orig_h": "10.0.0.1"}, "id.orig_h") == "10.0.0.1"

    def test_validate_path_accepts_nesting_and_array(self) -> None:
        assert validate_path("a.b[*]") == "a.b[*]"

    def test_validate_path_rejects_bad_segments(self) -> None:
        with pytest.raises(ProfileError):
            validate_path("a..b")
        with pytest.raises(ProfileError):
            validate_path("a.b!")

    def test_applies_when_narrows_claim(self) -> None:
        profile = _profile(applies_when_keys=frozenset({"id.orig_h"}))
        assert profile.applies_to({"id.orig_h": "x"}) is True
        assert profile.applies_to({"other": "x"}) is False

    def test_unconditional_profile_claims_everything(self) -> None:
        assert _profile().applies_to({"anything": 1}) is True

    def test_category_rule_beats_default(self) -> None:
        profile = _profile(
            default_category="network_connection",
            category_rules=[CategoryRule({"event.action": "start"}, "process_creation")],
        )
        assert profile.category_for({"event": {"action": "start"}}) == "process_creation"
        assert profile.category_for({"event": {"action": "stop"}}) == "network_connection"

    def test_category_rule_matches_inside_a_list(self) -> None:
        rule = CategoryRule({"event.category": "network"}, "network_connection")
        assert rule.matches({"event": {"category": ["network", "connection"]}}) is True

    def test_no_rule_and_no_default_is_none(self) -> None:
        assert _profile().category_for({}) is None

    def test_validate_path_rejects_empty(self) -> None:
        with pytest.raises(ProfileError):
            validate_path("")

    def test_load_profile_reads_default_category(self, tmp_path: Path) -> None:
        path = _write(
            tmp_path,
            "p.yaml",
            "name: z\n"
            "timestamp:\n  path: ts\n"
            "default_category: network_connection\n"
            "fields:\n  host: host\n",
        )
        assert load_profile(path).default_category == "network_connection"

    def test_load_profile_rejects_bad_default_category(self, tmp_path: Path) -> None:
        path = _write(
            tmp_path,
            "p.yaml",
            "name: z\ntimestamp:\n  path: ts\ndefault_category: [1]\n",
        )
        with pytest.raises(ProfileError, match="default_category"):
            load_profile(path)

    def test_load_profile_rejects_unknown_format(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "p.yaml", "name: z\ntimestamp:\n  path: ts\n  format: lunar\n")
        with pytest.raises(ProfileError, match="unsupported timestamp format"):
            load_profile(path)

    def test_load_profile_needs_a_name(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "p.yaml", "timestamp:\n  path: ts\n")
        with pytest.raises(ProfileError, match="name"):
            load_profile(path)


class TestCsvReader:
    """Delimiter sniffing, header handling and per-row failures."""

    def test_comma_table_parses(self, tmp_path: Path) -> None:
        body = "ts,host,src\n2026-03-01T10:00:00Z,web01,10.0.0.1\n"
        path = _write(tmp_path, "t.csv", body)
        events, failures = _run(GenericCsvParser({"test": _profile()}), path)
        assert failures == []
        assert len(events) == 1
        assert events[0].host == "web01"
        assert events[0].src_ip == "10.0.0.1"

    def test_semicolon_delimiter_is_sniffed(self, tmp_path: Path) -> None:
        body = "ts;host;src\n2026-03-01T10:00:00Z;web01;10.0.0.1\n"
        path = _write(tmp_path, "t.csv", body)
        events, failures = _run(GenericCsvParser({"test": _profile()}), path)
        assert failures == []
        assert events[0].host == "web01"

    def test_pipe_delimiter_is_sniffed(self, tmp_path: Path) -> None:
        body = "ts|host|src\n2026-03-01T10:00:00Z|web01|10.0.0.1\n"
        path = _write(tmp_path, "t.csv", body)
        events, _failures = _run(GenericCsvParser({"test": _profile()}), path)
        assert events[0].host == "web01"

    def test_quoted_field_keeps_its_comma(self, tmp_path: Path) -> None:
        profile = _profile(fields={"message": "msg", "host": "host"})
        body = 'ts,host,msg\n2026-03-01T10:00:00Z,web01,"a, b, c"\n'
        path = _write(tmp_path, "t.csv", body)
        events, failures = _run(GenericCsvParser({"test": profile}), path)
        assert failures == []
        assert events[0].message == "a, b, c"

    def test_short_row_is_a_failure(self, tmp_path: Path) -> None:
        profile = _profile(fields={"host": "host", "src_ip": "src", "dst_ip": "dst"})
        body = "ts,host,src,dst\n2026-03-01T10:00:00Z,web01,10.0.0.1\n"
        path = _write(tmp_path, "t.csv", body)
        events, failures = _run(GenericCsvParser({"test": profile}), path)
        assert events == []
        assert len(failures) == 1
        assert "expected 4 columns, found 3" in failures[0].reason

    def test_row_with_no_matching_profile_is_a_failure(self, tmp_path: Path) -> None:
        profile = _profile(applies_when_keys=frozenset({"wanted"}))
        body = "ts,host,src\n2026-03-01T10:00:00Z,web01,10.0.0.1\n"
        path = _write(tmp_path, "t.csv", body)
        events, failures = _run(GenericCsvParser({"test": profile}), path)
        assert events == []
        assert failures[0].reason == "no mapping profile matches this record"

    def test_single_column_header_is_a_failure(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "t.csv", "host\nweb01\n")
        events, failures = _run(GenericCsvParser({"test": _profile()}), path)
        assert events == []
        assert "fewer than two columns" in failures[0].reason

    def test_zeek_directives_name_columns_and_separator(self, tmp_path: Path) -> None:
        profile = _profile(fields={"host": "host", "src_ip": "src"})
        body = (
            "#separator \\x09\n"
            "#fields\tts\thost\tsrc\n"
            "2026-03-01T10:00:00Z\tweb01\t10.0.0.1\n"
            "#close\n"
        )
        path = _write(tmp_path, "conn.log", body)
        events, failures = _run(GenericCsvParser({"test": profile}), path)
        assert failures == []
        assert len(events) == 1
        assert events[0].src_ip == "10.0.0.1"

    def test_comment_only_file_yields_nothing(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "t.csv", "# just a comment\n")
        events, failures = _run(GenericCsvParser({"test": _profile()}), path)
        assert events == []
        assert failures == []


class TestJsonReader:
    """Single-document shapes and failure handling."""

    def test_ndjson_line(self, tmp_path: Path) -> None:
        body = '{"ts":"2026-03-01T10:00:00Z","host":"h","src":"10.0.0.1"}\n'
        path = _write(tmp_path, "t.ndjson", body)
        events, failures = _run(GenericJsonParser({"test": _profile()}), path)
        assert failures == []
        assert events[0].host == "h"

    def test_wrapper_document_expands_its_list(self, tmp_path: Path) -> None:
        body = (
            '{"Records": ['
            '{"ts":"2026-03-01T10:00:00Z","host":"web01"},'
            '{"ts":"2026-03-01T10:00:01Z","host":"web02"}]}\n'
        )
        path = _write(tmp_path, "t.json", body)
        events, failures = _run(GenericJsonParser({"test": _profile()}), path)
        assert failures == []
        assert [event.host for event in events] == ["web01", "web02"]

    def test_invalid_json_line_is_a_failure(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "t.ndjson", "not json\n")
        events, failures = _run(GenericJsonParser({"test": _profile()}), path)
        assert events == []
        assert "invalid JSON" in failures[0].reason

    def test_no_profiles_yields_a_file_failure(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "t.ndjson", '{"a": 1}\n')
        events, failures = _run(GenericJsonParser({}), path)
        assert events == []
        assert failures[0].reason == "no mapping profiles are installed"


class TestGoldens:
    """Every committed generic fixture parses to its recorded golden."""

    @pytest.mark.parametrize(("name", "parser"), [(n, p) for n, p, _t, _c in _FIXTURES])
    def test_golden(self, name: str, parser: object) -> None:
        expected = json.loads((GENERIC_DIR / f"{name}.expected.json").read_text(encoding="utf-8"))
        events, failures = _run(parser, GENERIC_DIR / name)
        assert {"event_count": len(events), "events": [_golden(e) for e in events]} == {
            "event_count": expected["event_count"],
            "events": expected["events"],
        }
        assert [{"record_ref": f.record_ref, "reason": f.reason} for f in failures] == expected[
            "failures"
        ]
