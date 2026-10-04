"""Parser framework and the generic JSON/NDJSON parser (spec 03 sections 1, 6, 7)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from app.ingest.events import NormalizedEvent
from app.ingest.parsers.base import (
    Candidate,
    ParseContext,
    ParseCounters,
    ParseFailure,
    ParserRegistry,
    load_builtin_parsers,
)
from app.ingest.parsers.generic_json import GenericJsonParser
from app.ingest.profiles import load_profiles
from app.ingest.text import read_head

PROFILES_DIR = Path(__file__).resolve().parents[1] / "data" / "profiles"


def ecs_record(**overrides: Any) -> dict[str, Any]:
    """A representative Elastic Common Schema event."""
    record: dict[str, Any] = {
        "@timestamp": "2026-03-01T10:00:00Z",
        "host": {"name": "web01"},
        "source": {"ip": "192.168.1.5", "port": 44322},
        "destination": {"ip": "10.0.0.9", "port": 443},
        "user": {"name": "alice"},
        "event": {"code": "4624", "category": ["process"], "outcome": "success", "action": "logon"},
        "process": {
            "executable": "C:\\Windows\\System32\\cmd.exe",
            "command_line": "cmd.exe /c whoami",
            "parent": {"executable": "C:\\Windows\\explorer.exe"},
        },
        "file": {"path": "C:\\Users\\alice\\notes.txt"},
        "url": {"original": "https://example.test/a"},
        "http": {"request": {"method": "POST"}, "response": {"status_code": 200}},
        "user_agent": {"original": "curl/8.0"},
        "message": "accepted",
    }
    record.update(overrides)
    return record


@pytest.fixture
def parser() -> GenericJsonParser:
    """A parser using the shipped profiles."""
    return GenericJsonParser(load_profiles(PROFILES_DIR))


@pytest.fixture
def context(tmp_path: Path) -> Any:
    """A factory for parse contexts over paths the test writes to."""

    def build(path: Path, **overrides: Any) -> ParseContext:
        kwargs: dict[str, Any] = {
            "case_id": "case-1",
            "source_id": "source-1",
            "filename": path.name,
            "path": path,
            "max_line_bytes": 4096,
        }
        kwargs.update(overrides)
        return ParseContext(**kwargs)

    return build


def write_ndjson(path: Path, records: list[Any], **kwargs: Any) -> Path:
    """One JSON value per line."""
    lines = [json.dumps(record) for record in records]
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8", **kwargs)
    return path


def run(parser: GenericJsonParser, ctx: ParseContext) -> list[NormalizedEvent | ParseFailure]:
    """Drain a parse, keeping events and failures apart."""
    return list(parser.parse(ctx))


def events_of(results: list[NormalizedEvent | ParseFailure]) -> list[NormalizedEvent]:
    """Just the events."""
    return [item for item in results if isinstance(item, NormalizedEvent)]


def failures_of(results: list[NormalizedEvent | ParseFailure]) -> list[ParseFailure]:
    """Just the failures."""
    return [item for item in results if isinstance(item, ParseFailure)]


class TestParserRegistry:
    """Registration is explicit and a duplicate log_type is a bug."""

    def test_builtin_parsers_are_registered(self) -> None:
        assert "generic_json" in load_builtin_parsers()

    def test_register_and_get(self) -> None:
        registry = ParserRegistry()
        parser = GenericJsonParser({})
        registry.register(parser)
        assert registry.get("generic_json") is parser
        assert "generic_json" in registry
        assert len(registry) == 1

    def test_unknown_log_type_is_none(self) -> None:
        assert ParserRegistry().get("nope") is None

    def test_duplicate_log_type_is_rejected(self) -> None:
        registry = ParserRegistry()
        registry.register(GenericJsonParser({}))

        class Other(GenericJsonParser):
            pass

        with pytest.raises(ValueError, match="already registered"):
            registry.register(Other({}))

    def test_all_is_stable_and_sorted(self) -> None:
        registry = ParserRegistry()
        registry.register(GenericJsonParser({}))
        assert [item.log_type for item in registry.all()] == ["generic_json"]

    def test_reloading_builtins_is_idempotent(self) -> None:
        first = len(load_builtin_parsers())
        assert len(load_builtin_parsers()) == first


class TestSniff:
    """Detection needs a cheap, bounded opinion."""

    def test_ndjson_scores_high(self, parser: GenericJsonParser, tmp_path: Path) -> None:
        path = write_ndjson(tmp_path / "a.ndjson", [ecs_record(), ecs_record()])
        assert parser.sniff(read_head(path)) >= 0.6

    def test_single_object_scores_low_but_nonzero(
        self, parser: GenericJsonParser, tmp_path: Path
    ) -> None:
        path = tmp_path / "one.json"
        path.write_text(json.dumps(ecs_record(), indent=2), encoding="utf-8")
        score = parser.sniff(read_head(path))
        assert 0.0 < score < 0.6

    def test_plain_text_scores_zero(self, parser: GenericJsonParser, tmp_path: Path) -> None:
        path = tmp_path / "plain.log"
        path.write_text("nothing to see\njust words\n", encoding="utf-8")
        assert parser.sniff(read_head(path)) == 0.0

    def test_empty_file_scores_zero(self, parser: GenericJsonParser, tmp_path: Path) -> None:
        path = tmp_path / "empty.log"
        path.write_bytes(b"")
        assert parser.sniff(read_head(path)) == 0.0


class TestNdjsonParsing:
    """One record in, one event or one failure out (spec 03 section 7)."""

    def test_ecs_record_maps_every_column(
        self, parser: GenericJsonParser, context: Any, tmp_path: Path
    ) -> None:
        path = write_ndjson(tmp_path / "ecs.ndjson", [ecs_record()])
        events = events_of(run(parser, context(path)))
        assert len(events) == 1
        event = events[0]
        assert event.host == "web01"
        assert event.src_ip == "192.168.1.5"
        assert event.src_port == 44322
        assert event.dst_ip == "10.0.0.9"
        assert event.dst_port == 443
        assert event.user_name == "alice"
        assert event.process_path == "C:\\Windows\\System32\\cmd.exe"
        assert event.process_cmdline == "cmd.exe /c whoami"
        assert event.parent_process_path == "C:\\Windows\\explorer.exe"
        assert event.file_path == "C:\\Users\\alice\\notes.txt"
        assert event.url == "https://example.test/a"
        assert event.http_method == "POST"
        assert event.http_status == 200
        assert event.user_agent == "curl/8.0"
        assert event.message == "accepted"
        assert event.event_id == 4624
        assert event.event_action == "logon"
        assert event.event_outcome == "success"

    def test_case_and_source_are_carried_from_the_context(
        self, parser: GenericJsonParser, context: Any, tmp_path: Path
    ) -> None:
        path = write_ndjson(tmp_path / "ecs.ndjson", [ecs_record()])
        event = events_of(run(parser, context(path)))[0]
        assert (event.case_id, event.source_id) == ("case-1", "source-1")
        assert event.log_type == "generic_json"

    def test_timestamp_is_parsed_to_epoch_ms(
        self, parser: GenericJsonParser, context: Any, tmp_path: Path
    ) -> None:
        path = write_ndjson(tmp_path / "t.ndjson", [ecs_record()])
        event = events_of(run(parser, context(path)))[0]
        assert event.ts_ms == 1772359200000

    def test_category_rule_is_applied(
        self, parser: GenericJsonParser, context: Any, tmp_path: Path
    ) -> None:
        path = write_ndjson(tmp_path / "c.ndjson", [ecs_record()])
        assert events_of(run(parser, context(path)))[0].ls_category == "process_creation"

    def test_raw_is_kept_for_evidence(
        self, parser: GenericJsonParser, context: Any, tmp_path: Path
    ) -> None:
        path = write_ndjson(tmp_path / "r.ndjson", [ecs_record()])
        assert json.loads(events_of(run(parser, context(path)))[0].raw)["host"]["name"] == "web01"

    def test_record_ref_is_the_line_number(
        self, parser: GenericJsonParser, context: Any, tmp_path: Path
    ) -> None:
        path = write_ndjson(tmp_path / "n.ndjson", [ecs_record(), ecs_record()])
        assert [event.record_ref for event in events_of(run(parser, context(path)))] == [
            "line:1",
            "line:2",
        ]

    def test_blank_lines_are_skipped(
        self, parser: GenericJsonParser, context: Any, tmp_path: Path
    ) -> None:
        path = tmp_path / "gaps.ndjson"
        body = json.dumps(ecs_record())
        path.write_text(f"\n{body}\n\n{body}\n", encoding="utf-8")
        assert len(events_of(run(parser, context(path)))) == 2

    def test_invalid_json_is_a_failure_not_a_crash(
        self, parser: GenericJsonParser, context: Any, tmp_path: Path
    ) -> None:
        # A valid first line proves this is NDJSON, so the broken second line is
        # a per-line failure rather than a whole-document one.
        path = tmp_path / "bad.ndjson"
        path.write_text(
            json.dumps(ecs_record()) + '\n{"@timestamp": "2026-03-01T10:00:00Z"\n', encoding="utf-8"
        )
        results = run(parser, context(path))
        assert len(events_of(results)) == 1
        assert "invalid JSON" in failures_of(results)[0].reason

    def test_unterminated_single_object_is_a_document_failure(
        self, parser: GenericJsonParser, context: Any, tmp_path: Path
    ) -> None:
        path = tmp_path / "truncated.json"
        path.write_text('{"@timestamp": "2026-03-01T10:00:00Z"\n', encoding="utf-8")
        failures = failures_of(run(parser, context(path)))
        assert len(failures) == 1
        assert "could not read JSON document" in failures[0].reason

    def test_non_object_line_is_a_failure(
        self, parser: GenericJsonParser, context: Any, tmp_path: Path
    ) -> None:
        path = tmp_path / "scalar.ndjson"
        path.write_text('"just a string"\n', encoding="utf-8")
        assert "expected a JSON object" in failures_of(run(parser, context(path)))[0].reason

    def test_unmatched_record_is_a_failure(
        self, parser: GenericJsonParser, context: Any, tmp_path: Path
    ) -> None:
        path = write_ndjson(tmp_path / "x.ndjson", [{"totally": "unrelated"}])
        assert "no mapping profile" in failures_of(run(parser, context(path)))[0].reason

    def test_good_and_bad_records_mix_without_losing_either(
        self, parser: GenericJsonParser, context: Any, tmp_path: Path
    ) -> None:
        path = tmp_path / "mix.ndjson"
        body = json.dumps(ecs_record())
        path.write_text(f"{body}\nnot json\n{body}\n", encoding="utf-8")
        results = run(parser, context(path))
        assert len(events_of(results)) == 2
        assert len(failures_of(results)) == 1

    def test_truncated_line_is_reported_not_parsed(
        self, parser: GenericJsonParser, context: Any, tmp_path: Path
    ) -> None:
        path = tmp_path / "long.ndjson"
        path.write_text(json.dumps(ecs_record(message="x" * 5000)) + "\n", encoding="utf-8")
        ctx = context(path, max_line_bytes=200)
        failures = failures_of(run(parser, ctx))
        assert len(failures) == 1
        assert "max_line_bytes" in failures[0].reason

    def test_no_profiles_is_reported_clearly(self, context: Any, tmp_path: Path) -> None:
        parser = GenericJsonParser({})
        path = write_ndjson(tmp_path / "p.ndjson", [ecs_record()])
        failures = failures_of(run(parser, context(path)))
        assert "no mapping profiles" in failures[0].reason


class TestSingleDocumentParsing:
    """Whole-document arrays, which spec 03 section 7 item 1 permits."""

    @pytest.mark.parametrize("key", ["events", "records", "Records"])
    def test_record_array_under_known_keys(
        self, parser: GenericJsonParser, context: Any, tmp_path: Path, key: str
    ) -> None:
        path = tmp_path / "doc.json"
        path.write_text(json.dumps({key: [ecs_record(), ecs_record()]}), encoding="utf-8")
        results = run(parser, context(path))
        assert len(events_of(results)) == 2
        assert [event.record_ref for event in events_of(results)] == ["row:1", "row:2"]

    def test_bare_top_level_array(
        self, parser: GenericJsonParser, context: Any, tmp_path: Path
    ) -> None:
        path = tmp_path / "array.json"
        path.write_text(json.dumps([ecs_record()]), encoding="utf-8")
        assert len(events_of(run(parser, context(path)))) == 1

    def test_elastic_hits_wrapper_is_unwrapped(
        self, parser: GenericJsonParser, context: Any, tmp_path: Path
    ) -> None:
        path = tmp_path / "hits.json"
        path.write_text(
            json.dumps({"hits": {"hits": [{"_source": ecs_record()}]}}), encoding="utf-8"
        )
        events = events_of(run(parser, context(path)))
        assert len(events) == 1
        assert events[0].host == "web01"

    def test_document_without_a_record_list_is_reported(
        self, parser: GenericJsonParser, context: Any, tmp_path: Path
    ) -> None:
        # Pretty-printed, so it is read as one document rather than one record.
        path = tmp_path / "other.json"
        path.write_text(json.dumps({"unrelated": [1, 2]}, indent=2), encoding="utf-8")
        assert "no events, records" in failures_of(run(parser, context(path)))[0].reason

    def test_compact_object_without_a_record_list_is_read_as_one_record(
        self, parser: GenericJsonParser, context: Any, tmp_path: Path
    ) -> None:
        # One line, no wrapper key: indistinguishable from NDJSON, so it is
        # treated as a record and reported for having no matching profile.
        path = tmp_path / "compact.json"
        path.write_text(json.dumps({"unrelated": [1, 2]}), encoding="utf-8")
        failures = failures_of(run(parser, context(path)))
        assert failures[0].record_ref == "line:1"
        assert "no mapping profile" in failures[0].reason

    def test_malformed_document_is_reported(
        self, parser: GenericJsonParser, context: Any, tmp_path: Path
    ) -> None:
        path = tmp_path / "broken.json"
        path.write_text("[{unclosed", encoding="utf-8")
        assert "could not read JSON document" in failures_of(run(parser, context(path)))[0].reason

    def test_non_object_inside_array_is_reported(
        self, parser: GenericJsonParser, context: Any, tmp_path: Path
    ) -> None:
        path = tmp_path / "mixed.json"
        path.write_text(json.dumps([ecs_record(), "scalar"]), encoding="utf-8")
        results = run(parser, context(path))
        assert len(events_of(results)) == 1
        assert len(failures_of(results)) == 1


class TestNormalizingWhileMapping:
    """Values are normalized on the way into columns, not afterwards."""

    def test_ipv6_is_canonicalized(
        self, parser: GenericJsonParser, context: Any, tmp_path: Path
    ) -> None:
        record = ecs_record()
        record["source"] = {"ip": "2001:0db8:0000:0000:0000:0000:0000:0001", "port": 1}
        path = write_ndjson(tmp_path / "v6.ndjson", [record])
        assert events_of(run(parser, context(path)))[0].src_ip == "2001:db8::1"

    def test_invalid_ip_does_not_reach_the_column_but_is_kept(
        self, parser: GenericJsonParser, context: Any, tmp_path: Path
    ) -> None:
        record = ecs_record()
        record["source"] = {"ip": "999.1.1.1", "port": 1}
        path = write_ndjson(tmp_path / "badip.ndjson", [record])
        event = events_of(run(parser, context(path)))[0]
        assert event.src_ip is None
        assert event.fields_json["src_ip_raw"] == "999.1.1.1"

    def test_string_port_is_coerced(
        self, parser: GenericJsonParser, context: Any, tmp_path: Path
    ) -> None:
        record = ecs_record()
        record["source"] = {"ip": "10.0.0.1", "port": "44322"}
        path = write_ndjson(tmp_path / "sp.ndjson", [record])
        assert events_of(run(parser, context(path)))[0].src_port == 44322

    def test_out_of_range_port_is_dropped(
        self, parser: GenericJsonParser, context: Any, tmp_path: Path
    ) -> None:
        record = ecs_record()
        record["source"] = {"ip": "10.0.0.1", "port": 99999}
        path = write_ndjson(tmp_path / "bp.ndjson", [record])
        assert events_of(run(parser, context(path)))[0].src_port is None

    def test_non_numeric_event_id_becomes_null(
        self, parser: GenericJsonParser, context: Any, tmp_path: Path
    ) -> None:
        record = ecs_record()
        record["event"] = {"id": "not-a-number", "category": ["process"]}
        path = write_ndjson(tmp_path / "nid.ndjson", [record])
        assert events_of(run(parser, context(path)))[0].event_id is None

    def test_all_original_fields_survive_in_fields_json(
        self, parser: GenericJsonParser, context: Any, tmp_path: Path
    ) -> None:
        path = write_ndjson(tmp_path / "f.ndjson", [ecs_record()])
        fields = events_of(run(parser, context(path)))[0].fields_json
        assert fields["host.name"] == "web01"
        assert fields["source.ip"] == "192.168.1.5"

    def test_control_characters_are_stripped(
        self, parser: GenericJsonParser, context: Any, tmp_path: Path
    ) -> None:
        record = ecs_record()
        record["host"] = {"name": "web\x0001"}
        path = write_ndjson(tmp_path / "ctl.ndjson", [record])
        assert events_of(run(parser, context(path)))[0].host == "web01"


class TestDocumentShapeDetection:
    """One document or many is a content question, not a first-character one."""

    def test_leading_blank_lines_do_not_confuse_the_shape(
        self, parser: GenericJsonParser, context: Any, tmp_path: Path
    ) -> None:
        path = tmp_path / "padded.json"
        path.write_text("\n\n  " + json.dumps([ecs_record()]), encoding="utf-8")
        assert len(events_of(run(parser, context(path)))) == 1

    def test_pretty_printed_wrapper_is_read_as_a_document(
        self, parser: GenericJsonParser, context: Any, tmp_path: Path
    ) -> None:
        path = tmp_path / "pretty.json"
        path.write_text(json.dumps({"events": [ecs_record()]}, indent=2), encoding="utf-8")
        assert len(events_of(run(parser, context(path)))) == 1

    def test_compact_wrapper_on_one_line_is_read_as_a_document(
        self, parser: GenericJsonParser, context: Any, tmp_path: Path
    ) -> None:
        path = tmp_path / "oneline.json"
        path.write_text(json.dumps({"events": [ecs_record()]}), encoding="utf-8")
        events = events_of(run(parser, context(path)))
        assert len(events) == 1
        assert events[0].record_ref == "row:1"

    def test_single_record_file_yields_one_event_either_way(
        self, parser: GenericJsonParser, context: Any, tmp_path: Path
    ) -> None:
        path = tmp_path / "single.ndjson"
        path.write_text(json.dumps(ecs_record()) + "\n", encoding="utf-8")
        assert len(events_of(run(parser, context(path)))) == 1

    def test_pretty_printed_single_record_is_parsed_as_one_record(
        self, parser: GenericJsonParser, context: Any, tmp_path: Path
    ) -> None:
        path = tmp_path / "pretty-record.json"
        path.write_text(json.dumps(ecs_record(), indent=2), encoding="utf-8")
        events = events_of(run(parser, context(path)))
        assert len(events) == 1
        assert events[0].host == "web01"
        assert events[0].record_ref == "row:1"


class TestCounters:
    """The ingest stage needs totals without re-reading the file."""

    def test_events_errors_and_inventory(
        self, parser: GenericJsonParser, context: Any, tmp_path: Path
    ) -> None:
        path = tmp_path / "c.ndjson"
        body = json.dumps(ecs_record())
        path.write_text(f"{body}\nbroken\n{body}\n", encoding="utf-8")
        ctx = context(path)
        run(parser, ctx)
        assert ctx.counters.events == 2
        assert ctx.counters.errors == 1
        assert ctx.counters.inventory[("generic_json", "", "", "process_creation")] == 2

    def test_time_bounds_track_the_events(
        self, parser: GenericJsonParser, context: Any, tmp_path: Path
    ) -> None:
        first = ecs_record(**{"@timestamp": "2026-03-01T10:00:00Z"})
        second = ecs_record(**{"@timestamp": "2026-03-01T12:00:00Z"})
        path = write_ndjson(tmp_path / "b.ndjson", [second, first])
        ctx = context(path)
        run(parser, ctx)
        assert ctx.counters.first_ts_ms == 1772359200000
        assert ctx.counters.last_ts_ms == 1772366400000

    def test_inventory_rows_are_sorted_and_shaped_for_the_repository(
        self, parser: GenericJsonParser, context: Any, tmp_path: Path
    ) -> None:
        path = write_ndjson(tmp_path / "i.ndjson", [ecs_record()])
        ctx = context(path)
        run(parser, ctx)
        rows = ctx.counters.inventory_rows()
        assert rows == [("generic_json", "", "", "process_creation", 1)]

    def test_counters_start_empty(self) -> None:
        counters = ParseCounters()
        assert (counters.events, counters.errors) == (0, 0)


class TestParseFailure:
    """Failures carry enough to find and explain the record."""

    def test_row_shape_matches_parse_errors_table(self) -> None:
        assert ParseFailure("line:7", "boom", "raw").as_row() == ("line:7", "boom", "raw")

    def test_excerpt_is_optional(self) -> None:
        assert ParseFailure("file:1", "boom").as_row() == ("file:1", "boom", None)


class TestCandidate:
    """Detection results are surfaced to the UI as JSON."""

    def test_as_dict_rounds_and_omits_empty_reason(self) -> None:
        assert Candidate("generic_json", 0.9).as_dict() == {
            "log_type": "generic_json",
            "confidence": 0.9,
        }

    def test_reason_is_included_when_present(self) -> None:
        assert Candidate("generic_json", 1.0, "magic").as_dict()["reason"] == "magic"
