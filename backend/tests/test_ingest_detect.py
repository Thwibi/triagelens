"""Format detection (spec 03 section 1, spec 09 P-05)."""

from __future__ import annotations

import gzip
import json
from pathlib import Path
from typing import Any

import pytest

from app.ingest.detect import (
    ACCEPT_THRESHOLD,
    DECISION_MARGIN,
    DetectionResult,
    detect,
    detect_suffix,
    is_binary,
    match_signature,
    vote,
)
from app.ingest.parsers.base import Candidate, ParserRegistry, load_builtin_parsers
from app.ingest.parsers.generic_json import GenericJsonParser, load_profiles_cached
from app.ingest.text import TextHead, read_head

PROFILES_DIR = Path(__file__).resolve().parents[1] / "data" / "profiles"

ECS_RECORD: dict[str, Any] = {
    "@timestamp": "2026-03-01T10:00:00Z",
    "host": {"name": "web01"},
    "event": {"code": "1", "category": ["process"]},
    "message": "hello",
}


def write_ndjson(path: Path, count: int = 20) -> Path:
    """A file that content detection should confidently call JSON."""
    body = "\n".join(json.dumps(ECS_RECORD) for _ in range(count))
    path.write_text(body + "\n", encoding="utf-8")
    return path


def write_plain(path: Path, count: int = 20) -> Path:
    """A file no parser claims."""
    path.write_text(
        "\n".join(f"plain line {n} of prose" for n in range(count)) + "\n", encoding="utf-8"
    )
    return path


def signature_of(head: bytes) -> str | None:
    """The log type of the first signature in ``head``, if any."""
    signature = match_signature(head)
    return signature.log_type if signature else None


class StubParser:
    """A parser with a fixed score, for exercising the decision rules."""

    __slots__ = ("log_type", "score")

    def __init__(self, log_type: str, score: float) -> None:
        self.log_type = log_type
        self.score = score

    def sniff(self, head: TextHead) -> float:
        """Always the same score."""
        return self.score

    def parse(self, context: Any) -> Any:
        """Not used by detection."""
        raise NotImplementedError


class TestSuffixMap:
    """The filename is a hint the operator typed."""

    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            ("a.evtx", "windows_evtx"),
            ("a.xml", "windows_event_xml"),
            ("a.json", "generic_json"),
            ("a.ndjson", "generic_json"),
            ("a.jsonl", "generic_json"),
            ("a.csv", "generic_csv"),
            ("A.EVTX", "windows_evtx"),
        ],
    )
    def test_known_suffixes(self, name: str, expected: str) -> None:
        assert detect_suffix(name) == expected

    @pytest.mark.parametrize("name", ["a.log", "a.txt", "a", "a.tar.gz", "system"])
    def test_unknown_suffixes(self, name: str) -> None:
        assert detect_suffix(name) is None


class TestSignatures:
    """Magic bytes are certain, so they are checked before anything votes."""

    def test_evtx_magic(self) -> None:
        assert match_signature(b"ElfFile\x00\x01\x02") is not None

    def test_xml_declaration(self) -> None:
        assert signature_of(b'<?xml version="1.0"?><Events/>') == "windows_event_xml"

    def test_xml_declaration_after_a_utf8_bom(self) -> None:
        assert signature_of(b"\xef\xbb\xbf<Events><Event/></Events>") == "windows_event_xml"

    def test_events_root(self) -> None:
        assert signature_of(b"<Events><Event/></Events>") == "windows_event_xml"

    def test_case_is_folded_for_text_signatures(self) -> None:
        assert signature_of(b"<EVENTS>") == "windows_event_xml"

    def test_no_signature(self) -> None:
        assert match_signature(b'{"a": 1}') is None

    def test_a_later_mention_does_not_count(self) -> None:
        # Only a prefix match counts, so prose about XML is not XML.
        head = b"x" * 400 + b'<?xml version="1.0"?>'
        assert match_signature(head) is None

    def test_plain_text_is_not_xml(self) -> None:
        assert match_signature(b"<not really xml") is None


class TestVote:
    """Every parser scores the same bounded prefix."""

    def test_scores_are_sorted_and_filtered(self) -> None:
        registry = ParserRegistry()
        registry.register(StubParser("low", 0.2))
        registry.register(StubParser("high", 0.9))
        registry.register(StubParser("zero", 0.0))
        scored = vote(TextHead(head=b"x"), registry)
        assert [item.log_type for item in scored] == ["high", "low"]

    def test_ties_break_deterministically(self) -> None:
        registry = ParserRegistry()
        registry.register(StubParser("beta", 0.7))
        registry.register(StubParser("alpha", 0.7))
        assert vote(TextHead(head=b"x"), registry)[0].log_type == "alpha"

    def test_out_of_range_scores_are_clamped(self) -> None:
        registry = ParserRegistry()
        registry.register(StubParser("over", 4.0))
        registry.register(StubParser("under", -3.0))
        scored = vote(TextHead(head=b"x"), registry)
        assert [item.log_type for item in scored] == ["over"]

    def test_real_json_parser_scores_the_real_format(self, tmp_path: Path) -> None:
        parser = GenericJsonParser(load_profiles_cached())
        registry = ParserRegistry()
        registry.register(parser)
        head = read_head(write_ndjson(tmp_path / "real.ndjson"))
        assert vote(head, registry)[0].log_type == "generic_json"


class TestDetectionDecisions:
    """The four steps, and what happens when they disagree."""

    def test_override_wins_over_everything(self, tmp_path: Path) -> None:
        path = write_ndjson(tmp_path / "a.ndjson")
        result = detect(path, override="generic_json")
        assert result.log_type == "generic_json"
        assert result.source == "override"
        assert result.needs_input is False

    def test_override_for_an_unbuilt_parser_is_flagged(self, tmp_path: Path) -> None:
        path = write_plain(tmp_path / "a.log")
        result = detect(path, override="linux_iptables")
        assert result.log_type == "linux_iptables"
        assert result.parser_available is False
        assert "no parser" in result.reason
        # A choice this build cannot honour is not a decision: queueing a parse
        # job for it would only fail later.
        assert result.needs_input is True

    def test_magic_beats_content(self, tmp_path: Path) -> None:
        path = tmp_path / "weird.ndjson"
        path.write_bytes(b"ElfFile\x00" + json.dumps(ECS_RECORD).encode())
        result = detect(path)
        assert result.log_type == "windows_evtx"
        assert result.source == "magic"

    def test_recognized_format_without_a_parser_is_flagged_not_guessed(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "a.evtx"
        path.write_bytes(b"ElfFile\x00" + b"\x00" * 32)
        # A registry without the EVTX parser: the magic is still recognized, but
        # this build cannot parse it, so it must not be guessed at.
        registry = ParserRegistry()
        registry.register(StubParser("generic_json", 0.0))
        result = detect(path, registry=registry)
        assert result.log_type == "windows_evtx"
        assert result.parser_available is False
        assert "no parser" in result.reason
        assert result.needs_input is True

    def test_clear_json_content_is_accepted(self, tmp_path: Path) -> None:
        path = write_ndjson(tmp_path / "a.ndjson")
        result = detect(path)
        assert result.log_type == "generic_json"
        assert result.source == "content"
        assert result.confidence >= ACCEPT_THRESHOLD

    def test_unrecognized_text_needs_input(self, tmp_path: Path) -> None:
        path = write_plain(tmp_path / "prose.log")
        result = detect(path)
        assert result.log_type is None
        assert result.needs_input is True
        assert result.source == "none"

    def test_needs_input_explains_itself(self, tmp_path: Path) -> None:
        result = detect(write_plain(tmp_path / "prose.log"))
        assert "choose a format" in result.reason

    def test_a_tie_is_not_a_decision(self, tmp_path: Path) -> None:
        registry = ParserRegistry()
        registry.register(StubParser("a", 0.9))
        registry.register(StubParser("b", 0.9))
        result = detect(write_plain(tmp_path / "tie.log"), registry=registry)
        assert result.needs_input is True

    def test_a_narrow_lead_is_not_a_decision(self, tmp_path: Path) -> None:
        registry = ParserRegistry()
        registry.register(StubParser("a", 0.9))
        registry.register(StubParser("b", 0.9 - DECISION_MARGIN / 2))
        result = detect(write_plain(tmp_path / "x.log"), registry=registry)
        assert result.log_type is None

    def test_a_clear_winner_over_many_parsers_is_accepted(self, tmp_path: Path) -> None:
        registry = ParserRegistry()
        registry.register(StubParser("winner", 0.95))
        for index in range(5):
            registry.register(StubParser(f"other{index}", 0.1))
        result = detect(write_plain(tmp_path / "x.log"), registry=registry)
        assert result.log_type == "winner"

    def test_a_single_decisive_parser_needs_no_margin(self, tmp_path: Path) -> None:
        registry = ParserRegistry()
        registry.register(StubParser("only", 0.95))
        assert detect(write_plain(tmp_path / "x.log"), registry=registry).log_type == "only"


class TestFilenameFallback:
    """When content is undecided, a deliberate filename is still useful."""

    def test_suffix_resolves_undecided_content(self, tmp_path: Path) -> None:
        registry = ParserRegistry()
        registry.register(StubParser("a", 0.9))
        registry.register(StubParser("b", 0.9))
        registry.register(StubParser("windows_evtx", 0.0))
        result = detect(write_plain(tmp_path / "export.evtx"), registry=registry)
        assert result.log_type == "windows_evtx"
        assert result.source == "filename"

    def test_suffix_does_not_override_a_clear_content_verdict(self, tmp_path: Path) -> None:
        # Content says JSON confidently; a misleading .csv name must not win.
        path = tmp_path / "mislabelled.csv"
        write_ndjson(path)
        assert detect(path).log_type == "generic_json"

    def test_suffix_suggestion_is_listed_when_undecided(self, tmp_path: Path) -> None:
        path = tmp_path / "mystery.json"
        write_plain(path)
        result = detect(path)
        assert "generic_json" in [item.log_type for item in result.candidates]

    def test_uploaded_name_is_used_over_the_stored_one(self, tmp_path: Path) -> None:
        path = write_plain(tmp_path / "stored.bin")
        registry = ParserRegistry()
        registry.register(StubParser("generic_json", 0.5))
        result = detect(path, filename="original.json", registry=registry)
        assert result.log_type == "generic_json"
        assert result.source == "filename"


class TestDetectionResultShape:
    """The result is serialized for the API and the needs_input prompt."""

    def test_needs_input_when_no_type(self) -> None:
        assert DetectionResult(log_type=None, source="none").needs_input is True

    def test_not_needs_input_when_accepted(self) -> None:
        assert DetectionResult(log_type="generic_json", source="content").needs_input is False

    def test_needs_input_when_the_parser_is_missing(self) -> None:
        result = DetectionResult(log_type="windows_evtx", source="magic", parser_available=False)
        assert result.needs_input is True

    def test_an_override_for_a_missing_parser_needs_input(self) -> None:
        result = DetectionResult(log_type="windows_evtx", source="override", parser_available=False)
        assert result.needs_input is True

    def test_confidence_is_zero_without_candidates(self) -> None:
        assert DetectionResult(log_type=None, source="none").confidence == 0.0

    def test_as_dict_is_json_ready(self, tmp_path: Path) -> None:
        payload = detect(write_ndjson(tmp_path / "a.ndjson")).as_dict()
        assert payload["log_type"] == "generic_json"
        assert payload["needs_input"] is False
        assert isinstance(payload["candidates"], list)
        json.dumps(payload)

    def test_needs_input_payload_carries_candidates(self, tmp_path: Path) -> None:
        payload = detect(write_plain(tmp_path / "a.log")).as_dict()
        assert payload["needs_input"] is True
        assert payload["reason"]

    def test_candidate_dict_is_json_ready(self) -> None:
        json.dumps(Candidate("generic_json", 0.9, "content signature").as_dict())


class TestBinaryHeuristic:
    """Binary files get told they are binary, not offered text formats."""

    def test_evtx_head_is_binary(self) -> None:
        assert is_binary(TextHead(head=b"ElfFile\x00" + b"\x01\x02\x03")) is True

    def test_gzip_head_is_binary(self) -> None:
        assert is_binary(TextHead(head=gzip.compress(b"x" * 100)[:512])) is True

    def test_text_head_is_not_binary(self) -> None:
        assert is_binary(TextHead(head=b"2026-03-01 host web01 accepted\n" * 10)) is False

    def test_empty_head_is_not_binary(self) -> None:
        assert is_binary(TextHead(head=b"")) is False


class TestBuiltinRegistryIsUsable:
    """Detection works against the real registry, not only stubs."""

    def test_builtins_are_discoverable(self) -> None:
        assert "generic_json" in load_builtin_parsers()

    def test_real_detection_on_a_real_file(self, tmp_path: Path) -> None:
        result = detect(write_ndjson(tmp_path / "real.ndjson"))
        assert result.log_type == "generic_json"
        assert result.parser_available is True
