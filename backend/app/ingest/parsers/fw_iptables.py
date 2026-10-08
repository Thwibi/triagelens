"""``fw_iptables``: iptables and UFW kernel denial/allow lines (spec 03 5.1).

The line is a syslog-framed ``kernel:`` message (UFW writes ``/var/log/ufw.log``
this way) or a bare kernel line. Either way the payload is a run of ``KEY=VALUE``
tokens after one or two bracket markers, the second of which names the verdict
(``[UFW BLOCK]``). The verdict is read from the bracket text, the five-tuple from
``SRC``/``DST``/``SPT``/``DPT``/``PROTO``, and every token is kept in
``fields_json`` so nothing the kernel logged is lost.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from app.ingest.events import NormalizedEvent
from app.ingest.normalize import canonical_ip, to_port, truncate
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
    syslog_moment,
)
from app.ingest.parsers.linux_common import Framed, SyslogClock
from app.ingest.text import TextHead, iter_text_lines

#: Share of non-empty sampled lines that must look like an iptables record.
_SHARE = 0.8

#: How confident a recognized iptables file is.
_CONFIDENCE = 0.9

#: The bracket prefix: UFW emits ``[ 1234.567] [UFW BLOCK]`` before the tokens.
_PREFIX = re.compile(r"^(?P<prefix>(?:\[[^\]]*\]\s*)+)")

#: The verdict is whichever of these words the brackets carry.
_VERDICT = re.compile(r"\b(BLOCK|DROP|REJECT|DENY|ALLOW|ACCEPT)\b", re.IGNORECASE)

#: TCP flag words that iptables logs bare (``... FLAGS SYN``).
_FLAGS = re.compile(r"\b(SYN|ACK|FIN|RST|PSH|URG|DF|ECE|CWR|NS)\b", re.IGNORECASE)


def _looks_like_iptables(payload: str) -> bool:
    """A record has the three tokens that make an iptables line legible."""
    return "IN=" in payload and "SRC=" in payload and "DST=" in payload


def _share(head: TextHead) -> float:
    """Fraction of non-empty sampled lines that are iptables records."""
    lines = [line for line in head.lines if line.strip()]
    if not lines:
        return 0.0
    matched = sum(1 for line in lines if _looks_like_iptables(payload_and_framed(line)[0]))
    return matched / len(lines)


def _verdict(text: str) -> str | None:
    """The first verdict keyword in ``text``, lowercased, or ``None``."""
    matched = _VERDICT.search(text)
    return matched.group(1).lower() if matched is not None else None


def _flags(payload: str) -> list[str]:
    """TCP flag words the kernel logged as bare tokens, in first-seen order."""
    seen: dict[str, None] = {}
    for flag in _FLAGS.findall(payload):
        seen.setdefault(flag.upper(), None)
    return list(seen)


def _action_name(action: str | None) -> str:
    """The event action for a firewall verdict."""
    if action == "deny":
        return "firewall_deny"
    if action == "allow":
        return "firewall_allow"
    return "firewall_event"


class FwIptablesParser:
    """iptables/UFW kernel firewall lines."""

    log_type = "fw_iptables"

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
            if not _looks_like_iptables(payload):
                yield ParseFailure(f"line:{number}", "line is not an iptables/UFW record", line)
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
        """Map one iptables/UFW record into an event."""
        prefix_match = _PREFIX.match(payload)
        prefix = prefix_match.group("prefix").strip() if prefix_match is not None else ""
        rest = payload[prefix_match.end() :] if prefix_match is not None else payload
        tokens = parse_kv(rest)
        action = normalize_action(_verdict(prefix) or _verdict(payload))
        fields: dict[str, object] = {**tokens}
        if prefix:
            fields["prefix"] = prefix
        flags = _flags(payload)
        if flags:
            fields["flags"] = flags
        return NormalizedEvent(
            case_id=context.case_id,
            source_id=context.source_id,
            record_ref=f"line:{number}",
            log_type=self.log_type,
            raw=truncate(line, context.max_line_bytes)[0],
            ts_ms=syslog_moment(framed, clock),
            host=framed.host if framed is not None else None,
            app_name=framed.app if framed is not None else None,
            ls_category="firewall",
            event_action=_action_name(action.action),
            event_outcome=action.outcome,
            src_ip=canonical_ip(tokens.get("SRC")),
            src_port=to_port(tokens.get("SPT")),
            dst_ip=canonical_ip(tokens.get("DST")),
            dst_port=to_port(tokens.get("DPT")),
            protocol=proto_name(tokens.get("PROTO")),
            fields_json=fields,
        )


_register(FwIptablesParser())


__all__ = ["FwIptablesParser"]
