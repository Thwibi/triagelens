"""``fw_fortinet``: FortiGate ``key=value`` log lines (spec 03 section 5.3).

FortiGate writes one line of ``key=value`` tokens, with double quotes around any
value that contains spaces. A line is a FortiGate record when it carries ``type=``
and either ``srcip=`` or ``dstip=``. The five-tuple comes from the ip/port keys,
the verdict from ``action=``; every token is kept in ``fields_json``.

The timestamp is ``eventtime`` (nanoseconds since the epoch) when present, else
``date`` + ``time`` (+ ``tz``). FortiGate's own ``proto`` is a number (``6``).
"""

from __future__ import annotations

from collections.abc import Iterator

from app.ingest.events import NormalizedEvent
from app.ingest.normalize import (
    canonical_ip,
    normalize_level,
    parse_timestamp,
    to_port,
    truncate,
)
from app.ingest.parsers.base import (
    ParseContext,
    ParseFailure,
    _register,
)
from app.ingest.parsers.fw_common import (
    normalize_action,
    parse_kv,
    payload_and_framed,
    proto_name,
)
from app.ingest.parsers.linux_common import Framed, SyslogClock
from app.ingest.text import TextHead, iter_text_lines

#: Share of non-empty sampled lines that must look like FortiGate records.
_SHARE = 0.8

#: How confident a recognized FortiGate file is.
_CONFIDENCE = 0.9

#: FortiGate's date and time keys.
_DATE = "date"
_TIME = "time"

#: Nanoseconds in a millisecond, for ``eventtime``.
_NS_PER_MS = 1_000_000

#: Width of a ``+HHMM`` / ``-HHMM`` timezone token.
_TZ_WIDTH = 5


def _looks_like_fortinet(payload: str) -> bool:
    """A FortiGate record names its type and at least one IP."""
    tokens = parse_kv(payload)
    return "type" in tokens and ("srcip" in tokens or "dstip" in tokens)


def _share(head: TextHead) -> float:
    """Fraction of non-empty sampled lines that are FortiGate records."""
    lines = [line for line in head.lines if line.strip()]
    if not lines:
        return 0.0
    matched = sum(1 for line in lines if _looks_like_fortinet(payload_and_framed(line)[0]))
    return matched / len(lines)


def _moment(tokens: dict[str, str], assume_tz: str | None):
    """Epoch milliseconds from ``eventtime`` or ``date``+``time``(+``tz``)."""
    eventtime = tokens.get("eventtime")
    if eventtime is not None and eventtime.strip().isdigit():
        return int(eventtime) // _NS_PER_MS
    date = tokens.get(_DATE)
    time = tokens.get(_TIME)
    if date is None or time is None:
        return None
    stamp = f"{date} {time}"
    zone = tokens.get("tz")
    if zone is not None and (zone.startswith(("+", "-")) and len(zone) == _TZ_WIDTH):
        layout = "%Y-%m-%d %H:%M:%S %z"
        stamp = f"{stamp} {zone}"
    else:
        layout = "%Y-%m-%d %H:%M:%S"
    parsed = parse_timestamp(stamp, fmt=f"strptime:{layout}", assume_tz=assume_tz)
    return parsed[0] if parsed is not None else None


class FwFortinetParser:
    """FortiGate key=value firewall logs."""

    log_type = "fw_fortinet"

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
            if not _looks_like_fortinet(payload):
                yield ParseFailure(
                    f"line:{number}", "line is not a FortiGate key=value record", line
                )
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
        """Map one FortiGate record into an event."""
        tokens = parse_kv(payload)
        action = normalize_action(tokens.get("action"))
        moment = _moment(tokens, context.timezone)
        if moment is None and framed is not None:
            moment = clock.epoch_ms(framed)
        user = tokens.get("user") or tokens.get("srcuser")
        event = NormalizedEvent(
            case_id=context.case_id,
            source_id=context.source_id,
            record_ref=f"line:{number}",
            log_type=self.log_type,
            raw=truncate(line, context.max_line_bytes)[0],
            ts_ms=moment,
            host=tokens.get("devname"),
            app_name=tokens.get("subtype"),
            level=normalize_level(tokens.get("level")),
            ls_category="firewall",
            event_action=_action_name(action.action),
            event_outcome=action.outcome,
            user_name=user,
            src_ip=canonical_ip(tokens.get("srcip")),
            src_port=to_port(tokens.get("srcport")),
            dst_ip=canonical_ip(tokens.get("dstip")),
            dst_port=to_port(tokens.get("dstport")),
            protocol=proto_name(tokens.get("proto")),
            url=tokens.get("url"),
            fields_json=dict(tokens),
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


_register(FwFortinetParser())


__all__ = ["FwFortinetParser"]
