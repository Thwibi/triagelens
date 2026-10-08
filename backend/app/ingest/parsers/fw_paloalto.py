"""``fw_paloalto``: PAN-OS firewall CSV logs (spec 03 section 5.4).

PAN-OS writes each log as a positional CSV row whose column meanings are fixed by
index; the column that names the log type (``TRAFFIC``, ``THREAT``, ...) is the
one reliable anchor. The ordered names live in
``data/profiles/paloalto_fields.yaml`` so the mapping is version-driven and
auditable rather than a wall of magic numbers in code.

Only traffic and threat rows are mapped onto the five-tuple and the firewall
category; any other recognized type is stored whole, because the other layouts
are not shipped yet and guessing their columns would invent evidence.
"""

from __future__ import annotations

from collections.abc import Iterator
from functools import lru_cache
from pathlib import Path
from typing import cast

import yaml

from app.ingest.events import NormalizedEvent
from app.ingest.normalize import canonical_ip, parse_timestamp, to_port, truncate
from app.ingest.parsers.base import (
    ParseContext,
    ParseFailure,
    _register,
)
from app.ingest.parsers.fw_common import (
    normalize_action,
    payload_and_framed,
    proto_name,
    split_csv,
)
from app.ingest.parsers.linux_common import Framed, SyslogClock
from app.ingest.text import TextHead, iter_text_lines

#: Share of non-empty sampled lines that must look like PAN-OS records.
_SHARE = 0.8

#: How confident a recognized PAN-OS file is.
_CONFIDENCE = 0.9

#: Fewest columns a row needs before its type column can be trusted (spec 5.4).
_MIN_COLUMNS = 30

#: The log types the type column may carry (spec 03 section 5.4).
_TYPES = frozenset({"TRAFFIC", "THREAT", "SYSTEM", "CONFIG", "URL", "GLOBALPROTECT"})

#: The two layouts this build maps positionally.
_MAPPED = frozenset({"traffic", "threat"})

#: The positional layout file, relative to the backend package root.
_LAYOUT_PATH = Path(__file__).resolve().parents[3] / "data" / "profiles" / "paloalto_fields.yaml"

#: The PAN-OS generated-time layout, e.g. ``2026/03/01 12:00:00``.
_TIME_FORMAT = "strptime:%Y/%m/%d %H:%M:%S"

#: Threat severity to normalized level (spec 03 section 5.4).
_SEVERITY_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "info",
    "informational": "info",
}


@lru_cache(maxsize=1)
def _layout_document() -> dict[str, object]:
    """The parsed layout file, loaded once."""
    return cast(dict[str, object], yaml.safe_load(_LAYOUT_PATH.read_text(encoding="utf-8")))


def _type_index() -> int:
    """The column that carries the log type."""
    value = _layout_document()["type_index"]
    if isinstance(value, (str, int)):
        return int(value)
    raise ValueError(f"layout type_index must be an integer, got {value!r}")


def _layout(name: str) -> tuple[str, ...]:
    """The ordered column names for one layout."""
    layouts = _layout_document()["layouts"]
    return tuple(str(field) for field in layouts[name])  # type: ignore[index]


def _field(fields: list[str], layout: tuple[str, ...], name: str) -> str | None:
    """The value of a named column, or ``None`` when absent or ``-``."""
    try:
        index = layout.index(name)
    except ValueError:
        return None
    if index >= len(fields):
        return None
    value = fields[index].strip()
    return value if value not in ("", "-") else None


def _looks_like_paloalto(payload: str) -> bool:
    """A row is PAN-OS-shaped when the type column is known and it is wide enough."""
    fields = split_csv(payload)
    type_index = _type_index()
    return (
        len(fields) >= _MIN_COLUMNS
        and type_index < len(fields)
        and fields[type_index].strip().upper() in _TYPES
    )


def _share(head: TextHead) -> float:
    """Fraction of non-empty sampled lines that are PAN-OS records."""
    lines = [line for line in head.lines if line.strip()]
    if not lines:
        return 0.0
    matched = sum(1 for line in lines if _looks_like_paloalto(payload_and_framed(line)[0]))
    return matched / len(lines)


class FwPaloaltoParser:
    """PAN-OS firewall CSV logs."""

    log_type = "fw_paloalto"

    def sniff(self, head: TextHead) -> float:
        return _CONFIDENCE if _share(head) >= _SHARE else 0.0

    def parse(self, context: ParseContext) -> Iterator[NormalizedEvent | ParseFailure]:
        """Stream the file, counting each record as events and failures."""
        for item in self._records(context):
            if isinstance(item, ParseFailure):
                context.counters.record_failure()
            else:
                context.counters.record_event(item)
            yield item

    def _records(self, context: ParseContext) -> Iterator[NormalizedEvent | ParseFailure]:
        clock = SyslogClock(context)
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
            payload, framed = payload_and_framed(line)
            if not _looks_like_paloalto(payload):
                yield ParseFailure(f"line:{number}", "line is not a PAN-OS CSV record", line)
                continue
            yield self._event(
                context, line=line, payload=payload, framed=framed, clock=clock, number=number
            )

    def _event(
        self,
        context: ParseContext,
        *,
        line: str,
        payload: str,
        framed: Framed | None,
        clock: SyslogClock,
        number: int,
    ) -> NormalizedEvent:
        """Map one PAN-OS record into an event."""
        fields = split_csv(payload)
        type_value = fields[_type_index()].strip()
        key = type_value.lower()
        if key in _MAPPED:
            return self._mapped_event(context, line, fields, key, number)
        return NormalizedEvent(
            case_id=context.case_id,
            source_id=context.source_id,
            record_ref=f"line:{number}",
            log_type=self.log_type,
            raw=truncate(line, context.max_line_bytes)[0],
            ts_ms=clock.epoch_ms(framed) if framed is not None else None,
            app_name=type_value,
            message=type_value,
            fields_json={"type": type_value},
        )

    def _mapped_event(
        self,
        context: ParseContext,
        line: str,
        fields: list[str],
        key: str,
        number: int,
    ) -> NormalizedEvent:
        """Map a traffic or threat row onto the normalized columns."""
        layout = _layout(key)
        action = normalize_action(_field(fields, layout, "action"))
        severity = _field(fields, layout, "severity")
        moment = parse_timestamp(
            _field(fields, layout, "time_generated"), fmt=_TIME_FORMAT, assume_tz=context.timezone
        )
        fields_json: dict[str, object] = {}
        for name in (
            "type",
            "subtype",
            "serial_number",
            "rule",
            "srcuser",
            "dstuser",
            "app",
            "vsys",
            "from",
            "to",
            "inbound_if",
            "outbound_if",
            "sessionid",
            "repeatcnt",
            "log_action",
            "flags",
            "action",
        ):
            value = _field(fields, layout, name)
            if value is not None:
                fields_json[name] = value
        for name in ("threat_id", "category", "severity"):
            value = _field(fields, layout, name)
            if value is not None:
                fields_json[name] = value
        event = NormalizedEvent(
            case_id=context.case_id,
            source_id=context.source_id,
            record_ref=f"line:{number}",
            log_type=self.log_type,
            raw=truncate(line, context.max_line_bytes)[0],
            ts_ms=moment[0] if moment is not None else None,
            app_name=_field(fields, layout, "app"),
            level=_SEVERITY_LEVEL.get(severity.lower()) if severity is not None else None,
            ls_category="firewall",
            event_action=_action_name(action.action),
            event_outcome=action.outcome,
            user_name=_field(fields, layout, "srcuser"),
            src_ip=canonical_ip(_field(fields, layout, "src")),
            src_port=to_port(_field(fields, layout, "sport")),
            dst_ip=canonical_ip(_field(fields, layout, "dst")),
            dst_port=to_port(_field(fields, layout, "dport")),
            protocol=proto_name(_field(fields, layout, "proto")),
            url=_field(fields, layout, "url_filename"),
            fields_json=fields_json,
        )
        event.split_url()
        return event


def _action_name(action: str | None) -> str:
    """The event action for a firewall verdict."""
    if action == "deny":
        return "firewall_deny"
    if action == "allow":
        return "firewall_allow"
    return "firewall_event"


_register(FwPaloaltoParser())


__all__ = ["FwPaloaltoParser"]
