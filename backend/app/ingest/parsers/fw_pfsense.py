"""``fw_pfsense``: pfSense ``filterlog`` CSV (spec 03 section 5.2).

pfSense writes a syslog line whose tag is ``filterlog`` and whose message is a
positional CSV record. The first nine columns are common; the rest depend on the
IP version, so the field indices are read from a small table keyed on
``ip_version`` (4 or 6). The verdict is the ``action`` column.
"""

from __future__ import annotations

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
    payload_and_framed,
    proto_name,
    split_csv,
    syslog_moment,
)
from app.ingest.parsers.linux_common import Framed, SyslogClock
from app.ingest.text import TextHead, iter_text_lines

#: Share of non-empty sampled lines that must look like filterlog records.
_SHARE = 0.8

#: How confident a recognized pfSense file is.
_CONFIDENCE = 0.9

#: Column indices shared by both IP versions.
_ACTION = 6
_INTERFACE = 4
_DIRECTION = 7
_RULE = 0
_TRACKER = 3
_REASON = 5
_IP_VERSION = 8

#: Fewest columns that can carry the common prefix of a filterlog record.
_MIN_COMMON_FIELDS = 9

#: The two IP-version column values, as ints.
_IPV4 = 4
_IPV6 = 6

#: Per-version indices: version -> (src, dst, sport, dport, protocol_id, protocol_name).
_V4 = (18, 19, 20, 21, 15, 16)
_V6 = (15, 16, 17, 18, 13, 12)

#: Minimum columns needed to read the addresses for each version.
_MIN_FIELDS = {_IPV4: 20, _IPV6: 17}

#: An IP version column value we can place.
_VERSIONS = frozenset({"4", "6"})


def _payload_is_filterlog(payload: str, framed: Framed | None) -> bool:
    """True when the framing or the CSV shape says this is a filterlog record."""
    if framed is not None and (framed.app or "").lower() == "filterlog":
        return True
    fields = split_csv(payload)
    return (
        len(fields) >= _MIN_COMMON_FIELDS
        and fields[_IP_VERSION].strip() in _VERSIONS
        and fields[_RULE].strip().isdigit()
        and fields[_TRACKER].strip().isdigit()
    )


def _share(head: TextHead) -> float:
    """Fraction of non-empty sampled lines that are filterlog records."""
    lines = [line for line in head.lines if line.strip()]
    if not lines:
        return 0.0
    matched = sum(1 for line in lines if _payload_is_filterlog(*payload_and_framed(line)))
    return matched / len(lines)


def _version(fields: list[str]) -> int | None:
    """The IP version, or ``None`` when the column is not 4 or 6."""
    value = fields[_IP_VERSION].strip()
    if value in _VERSIONS:
        return int(value)
    return None


class FwPfsenseParser:
    """pfSense ``filterlog`` records."""

    log_type = "fw_pfsense"

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
            fields = split_csv(payload)
            version = _version(fields) if len(fields) > _IP_VERSION else None
            if version is None or len(fields) < _MIN_FIELDS[version]:
                yield ParseFailure(f"line:{number}", "line is not a pfSense filterlog record", line)
                continue
            yield self._event(
                context,
                line=line,
                fields=fields,
                version=version,
                framed=framed,
                clock=clock,
                number=number,
            )

    def _event(
        self,
        context: ParseContext,
        *,
        line: str,
        fields: list[str],
        version: int,
        framed: Framed | None,
        clock: SyslogClock,
        number: int,
    ) -> NormalizedEvent:
        """Map one filterlog record into an event."""
        src, dst, sport, dport, proto_id, proto_field = _V4 if version == _IPV4 else _V6
        action = normalize_action(fields[_ACTION])
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
            src_ip=canonical_ip(fields[src]),
            dst_ip=canonical_ip(fields[dst]),
            src_port=to_port(fields[sport]),
            dst_port=to_port(fields[dport]),
            protocol=proto_name(fields[proto_field]) or proto_name(fields[proto_id]),
            fields_json={
                "interface": fields[_INTERFACE],
                "direction": fields[_DIRECTION],
                "rule": fields[_RULE],
                "tracker": fields[_TRACKER],
                "reason": fields[_REASON],
                "ip_version": version,
                "action": fields[_ACTION],
            },
        )


def _action_name(action: str | None) -> str:
    """The event action for a firewall verdict."""
    if action == "deny":
        return "firewall_deny"
    if action == "allow":
        return "firewall_allow"
    return "firewall_event"


_register(FwPfsenseParser())


__all__ = ["FwPfsenseParser"]
