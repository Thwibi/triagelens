"""``linux_journald`` (spec 03 section 3.2).

Reads the newline-delimited JSON that ``journalctl -o json`` writes. Every key in
a record is kept verbatim in ``fields_json``; the columns the spec names are
lifted out of it:

===============  =====================
Journal key      Column
===============  =====================
``__REALTIME_TIMESTAMP``  ``ts_ms`` (microseconds)
``_HOSTNAME``    ``host``
``SYSLOG_IDENTIFIER``  ``app_name`` / ``provider``
``_PID``         ``process_pid``
``MESSAGE``      ``message`` (a byte array is decoded)
``PRIORITY``     ``level``
``_EXE``         ``process_path``
``_CMDLINE``     ``process_cmdline``
===============  =====================

Daemon messages are then run through the same table as syslog, keyed by
``SYSLOG_IDENTIFIER`` (spec 03 section 3.2).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

from app.ingest.events import NormalizedEvent
from app.ingest.normalize import (
    canonical_ip,
    clean_text,
    normalize_outcome,
    parse_timestamp,
    to_int,
    to_port,
    truncate,
)
from app.ingest.parsers.base import (
    ParseContext,
    ParseFailure,
    _register,
)
from app.ingest.parsers.linux_common import level_from_pri, match_message
from app.ingest.text import TextHead, iter_text_lines

#: Share of sampled lines that must be journal records to claim the file.
_JOURNAL_SHARE = 0.8

#: Realtime markers in preference order: the record's own time, then the source's.
_REALTIME_KEYS = ("__REALTIME_TIMESTAMP", "_SOURCE_REALTIME_TIMESTAMP")

#: Microseconds in a millisecond, for the epoch conversion the schema stores.
_MICROS_PER_MS = 1000


def _record_marks_journal(record: Any) -> bool:
    """True when a parsed JSON value carries a journal-only key."""
    return isinstance(record, dict) and any(key in record for key in _REALTIME_KEYS)


def _decode_message(value: Any) -> str | None:
    """A journal ``MESSAGE`` as text: bytes-as-array decodes, a string is itself."""
    if isinstance(value, list):
        try:
            return bytes(int(item) for item in value).decode("utf-8", errors="replace")
        except (TypeError, ValueError):
            return None
    return clean_text(value)


def _realtime_ms(record: dict[str, Any]) -> int | None:
    """The record time as UTC epoch milliseconds, or ``None``."""
    for key in _REALTIME_KEYS:
        micros = to_int(record.get(key))
        if micros is None:
            continue
        parsed = parse_timestamp(micros // _MICROS_PER_MS, fmt="epoch_ms")
        if parsed is not None:
            return parsed[0]
    return None


class LinuxJournaldParser:
    """Newline-delimited ``journalctl -o json`` output."""

    log_type = "linux_journald"

    def sniff(self, head: TextHead) -> float:
        lines = [line for line in head.lines if line.strip()]
        if not lines:
            return 0.0
        matched = sum(1 for line in lines if _looks_like_journal(line))
        if matched / len(lines) < _JOURNAL_SHARE:
            return 0.0
        return 0.9

    def parse(self, context: ParseContext) -> Iterator[NormalizedEvent | ParseFailure]:
        """Stream the file, counting each record as events and failures."""
        for item in self._records(context):
            if isinstance(item, ParseFailure):
                context.counters.record_failure()
            else:
                context.counters.record_event(item)
            yield item

    def _records(self, context: ParseContext) -> Iterator[NormalizedEvent | ParseFailure]:
        for number, line, truncated in iter_text_lines(
            context.path, max_line_bytes=context.max_line_bytes
        ):
            if truncated:
                yield ParseFailure(
                    f"line:{number}",
                    "line exceeded max_line_bytes and cannot be parsed",
                    line,
                )
                continue
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                yield ParseFailure(f"line:{number}", f"invalid JSON: {error.msg}", line)
                continue
            if not isinstance(record, dict):
                yield ParseFailure(f"line:{number}", "expected a JSON object", line)
                continue
            yield self._event(context, record, number, line)

    def _event(
        self,
        context: ParseContext,
        record: dict[str, Any],
        number: int,
        line: str,
    ) -> NormalizedEvent:
        """Map one journal record into an event."""
        app = clean_text(record.get("SYSLOG_IDENTIFIER"))
        message = _decode_message(record.get("MESSAGE"))
        matched = match_message(message, app) if message else None
        columns = dict(matched.columns) if matched is not None else {}
        fields: dict[str, Any] = dict(record)
        if matched is not None:
            fields.update(matched.fields)
        fields.setdefault("_journal", "linux_journald")
        raw = truncate(line, context.max_line_bytes)[0]
        return NormalizedEvent(
            case_id=context.case_id,
            source_id=context.source_id,
            record_ref=f"line:{number}",
            log_type=self.log_type,
            raw=raw,
            ts_ms=_realtime_ms(record),
            ls_category=matched.category if matched is not None else None,
            host=clean_text(record.get("_HOSTNAME")),
            provider=app,
            app_name=app,
            level=level_from_pri(to_int(record.get("PRIORITY"))),
            event_action=matched.action if matched is not None else None,
            event_outcome=normalize_outcome(matched.outcome) if matched is not None else None,
            user_name=columns.get("user_name"),
            target_user_name=columns.get("target_user_name"),
            src_ip=canonical_ip(columns.get("src_ip")) if columns.get("src_ip") else None,
            src_port=to_port(columns.get("src_port")),
            process_pid=to_int(record.get("_PID")),
            process_path=clean_text(record.get("_EXE")),
            process_cmdline=clean_text(record.get("_CMDLINE")),
            file_path=columns.get("file_path"),
            message=columns.get("message", message),
            fields_json=fields,
        )


def _looks_like_journal(line: str) -> bool:
    """True when a raw line parses to a journal-marked JSON object."""
    try:
        record = json.loads(line)
    except json.JSONDecodeError:
        return False
    return _record_marks_journal(record)


_register(LinuxJournaldParser())


__all__ = ["LinuxJournaldParser"]
