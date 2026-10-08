"""Generic JSON parser driven by a mapping profile (spec 03 section 6).

Handles both shapes the spec calls for: newline-delimited JSON, and a single
document holding a list under ``events``, ``records``, ``Records`` or
``hits.hits[*]._source``. Only the second is read whole, which spec 03 section 7
item 1 explicitly permits.

This parser exists in Phase 1 so the pipeline is exercised end to end with
something real. It is not a placeholder: the ECS profile in ``data/profiles``
maps genuine Elastic records, and the Windows, Linux, web and firewall parsers
in later phases narrow their handling from here.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from app.ingest.events import NormalizedEvent
from app.ingest.parsers.base import (
    ParseContext,
    ParseFailure,
    _register,
)
from app.ingest.parsers.generic_common import (
    load_profiles_cached,
    map_record,
    pick_profile,
)
from app.ingest.profiles import Profile, ProfileError
from app.ingest.text import TextHead

#: Keys under which a JSON array of records may hide (spec 03 section 6).
_ARRAY_KEYS: tuple[str, ...] = ("events", "records", "Records")

#: Elastic wraps its records one level deeper.
_HITS_PATH = ("hits", "hits")

#: Matches a JSON object at the start of a line, cheaply. Used only for sniffing.
_OBJECT_LINE = re.compile(r"^\s*\{")

#: Share of sampled lines that must be JSON objects to call a file NDJSON.
_JSON_LINE_SHARE = 0.8

#: Keys that mark a JSON object as a ``journalctl -o json`` record. The generic
#: JSON parser defers to ``linux_journald`` when it sees them, because the same
#: bytes would otherwise be claimed here and lose the journal-specific mapping.
_JOURNALD_MARKERS = ("__REALTIME_TIMESTAMP", "SYSLOG_IDENTIFIER")

#: Bytes read to decide whether a file is one document or many.
_DOCUMENT_HEAD_BYTES = 64 * 1024

#: Largest file read whole as one JSON document. Above this the file is streamed
#: as NDJSON instead, so a huge pretty-printed export cannot exhaust memory.
_MAX_DOCUMENT_BYTES = 1 << 30


def _looks_like_journal(line: str) -> bool:
    """True when a JSON line carries a ``journalctl -o json`` marker key."""
    try:
        record = json.loads(line)
    except (ValueError, TypeError):
        return False
    if not isinstance(record, dict):
        return False
    return any(marker in record for marker in _JOURNALD_MARKERS)


class GenericJsonParser:
    """NDJSON and JSON documents, mapped through a profile."""

    __slots__ = ("_profiles",)

    log_type = "generic_json"

    def __init__(self, profiles: dict[str, Profile] | None = None) -> None:
        # None means "load the shipped profiles lazily". An empty dict is a
        # deliberate choice to parse with no profiles at all, which is how a
        # broken profile directory surfaces instead of half-working.
        self._profiles = profiles

    def sniff(self, head: TextHead) -> float:
        """0.9 for JSON lines, 0.85 for a document that starts with an object."""
        lines = [line for line in head.lines if line.strip()]
        if not lines:
            return 0.0
        if _looks_like_journal(lines[0]):
            return 0.0
        json_lines = sum(1 for line in lines if _OBJECT_LINE.match(line))
        fraction = json_lines / len(lines)
        if fraction >= _JSON_LINE_SHARE:
            return 0.9
        # A pretty-printed document is one object spanning many lines; only the
        # first line is informative, so this stays deliberately low.
        return 0.5 if _OBJECT_LINE.match(lines[0]) else 0.0

    def parse(self, context: ParseContext) -> Iterator[NormalizedEvent | ParseFailure]:
        """Stream the file into events and failures.

        Totals accumulate into ``context.counters`` as records are yielded, so
        the ingest stage gets counts without this generator having to return them.
        """
        for item in self._records(context):
            if isinstance(item, ParseFailure):
                context.counters.record_failure()
            else:
                context.counters.record_event(item)
            yield item

    def _records(self, context: ParseContext) -> Iterator[NormalizedEvent | ParseFailure]:
        """Records in the file's own shape: NDJSON or a single document."""
        profiles = self._profiles if self._profiles is not None else load_profiles_cached()
        if not profiles:
            yield ParseFailure(
                record_ref="file:1",
                reason="no mapping profiles are installed",
                raw_excerpt=None,
            )
            return
        if _is_single_document(context.path):
            yield from self._parse_single_document(context, profiles)
        else:
            yield from self._parse_ndjson(context, profiles)

    def _parse_ndjson(
        self,
        context: ParseContext,
        profiles: dict[str, Profile],
    ) -> Iterator[NormalizedEvent | ParseFailure]:
        """One JSON value per line."""
        from app.ingest.text import iter_text_lines

        for number, line, truncated in iter_text_lines(
            context.path, max_line_bytes=context.max_line_bytes
        ):
            if truncated:
                # A clipped line cannot be valid JSON; report it rather than
                # inventing a reason deeper in the parser.
                yield ParseFailure(
                    record_ref=f"line:{number}",
                    reason="line exceeded max_line_bytes and cannot be parsed",
                    raw_excerpt=line,
                )
                continue
            if not line.strip():
                continue
            record_ref = f"line:{number}"
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                yield ParseFailure(record_ref, f"invalid JSON: {error.msg}", line)
                continue
            if not isinstance(record, dict):
                yield ParseFailure(record_ref, "expected a JSON object", line)
                continue
            profile = pick_profile(record, profiles)
            if profile is None:
                yield ParseFailure(record_ref, "no mapping profile matches this record", line)
                continue
            yield self._to_event(context, profile, record, record_ref, line)

    def _parse_single_document(
        self,
        context: ParseContext,
        profiles: dict[str, Profile],
    ) -> Iterator[NormalizedEvent | ParseFailure]:
        """A whole-document array, which spec 03 section 7 allows us to hold."""
        try:
            document = json.loads(context.path.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, OSError) as error:
            yield ParseFailure("file:1", f"could not read JSON document: {error}", None)
            return
        records = _records_from_document(document)
        if records is None:
            # A pretty-printed file holding one record has no list, but it is
            # still a perfectly good record, so try it as one before giving up.
            if isinstance(document, dict) and pick_profile(document, profiles) is not None:
                records = [document]
            else:
                yield ParseFailure(
                    "file:1",
                    "JSON document has no events, records, Records or hits.hits[*]._source list",
                    None,
                )
                return
        for index, record in enumerate(records, start=1):
            record_ref = f"row:{index}"
            if not isinstance(record, dict):
                yield ParseFailure(record_ref, "expected a JSON object", None)
                continue
            profile = pick_profile(record, profiles)
            if profile is None:
                yield ParseFailure(record_ref, "no mapping profile matches this record", None)
                continue
            raw = json.dumps(record, ensure_ascii=False)
            yield self._to_event(context, profile, record, record_ref, raw)

    def _to_event(
        self,
        context: ParseContext,
        profile: Profile,
        record: dict[str, Any],
        record_ref: str,
        raw: str,
    ) -> NormalizedEvent:
        """Map one record through a profile into an event."""
        return map_record(
            context=context,
            profile=profile,
            record=record,
            record_ref=record_ref,
            raw=raw,
            log_type=self.log_type,
        )


def _records_from_document(document: Any) -> list[Any] | None:
    """Find the record list inside a JSON document."""
    if isinstance(document, list):
        return document
    if not isinstance(document, dict):
        return None
    for key in _ARRAY_KEYS:
        value = document.get(key)
        if isinstance(value, list):
            return value
    hits = document.get(_HITS_PATH[0])
    if isinstance(hits, dict):
        inner = hits.get(_HITS_PATH[1])
        if isinstance(inner, list):
            return [item.get("_source", item) if isinstance(item, dict) else item for item in inner]
    return None


def _is_single_document(path: Path) -> bool:
    """True when the file holds one JSON document rather than newline-delimited ones.

    Deciding on the first character alone is not enough. ``[`` is unambiguous, but
    a wrapper object and a single NDJSON record both start with ``{``, and
    ``{"events": [...]}`` parsed as NDJSON becomes one unmatchable record rather
    than the rows it holds. So an object is resolved by looking for a record list
    inside it:

    - the first line parses and carries a wrapper key -> single document
    - the first line parses and carries none -> NDJSON, which yields the same
      single event either way
    - the first line does not parse -> the document is pretty-printed, so it is
      read whole. That is bounded by :data:`_MAX_DOCUMENT_BYTES`, because spec 03
      section 7 permits holding a JSON array in memory but not a 50 GB file.
    """
    try:
        size = path.stat().st_size
    except OSError:
        return False
    with path.open("rb") as handle:
        head = handle.read(_DOCUMENT_HEAD_BYTES).lstrip()
    if head[:1] == b"[":
        return True
    if head[:1] != b"{":
        return False
    first_line = head.split(b"\n", 1)[0]
    try:
        candidate = json.loads(first_line.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return size <= _MAX_DOCUMENT_BYTES
    if not isinstance(candidate, dict):
        return False
    return _records_from_document(candidate) is not None


def build() -> GenericJsonParser:
    """Construct the parser for the registry."""
    try:
        return GenericJsonParser(load_profiles_cached())
    except ProfileError:
        # A broken profile is reported by the profile loader and by detection;
        # the parser still registers so needs_input can explain the situation
        # rather than the log type simply vanishing from the format list.
        return GenericJsonParser({})


_register(build())


__all__ = ["GenericJsonParser", "build", "load_profiles_cached"]
