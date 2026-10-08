"""``fw_cisco_asa``: Cisco ASA ``%ASA-<sev>-<id>:`` messages (spec 03 5.5).

An ASA line is framed as ``%ASA-<severity>-<message-id>: <text>``, optionally
behind an RFC 3164 prefix. The severity and message id are mapped on their own,
so an unknown message id still produces an event with its id, level and text;
a handful of message ids are then parsed into columns. The set implemented here
is exactly the one spec 09 P-10 lists:

* ``106023``/``106100`` access-list denials and permits,
* ``302013``/``302015`` connection builds and ``302014``/``302016`` teardowns,
* ``113005``/``113015`` AAA authentication failures,
* ``605005``/``611101`` login/VPN successes.
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
    payload_and_framed,
    syslog_moment,
)
from app.ingest.parsers.linux_common import Framed, SyslogClock
from app.ingest.text import TextHead, iter_text_lines

#: Share of non-empty sampled lines that must look like ASA messages.
_SHARE = 0.8

#: How confident a recognized ASA file is.
_CONFIDENCE = 0.9

#: ``%ASA-<severity>-<id>:`` anywhere in the line. Located with ``search`` rather
#: than ``match`` because a syslog prefix (``Mon d HH:MM:SS host ``) precedes it,
#: and because syslog framing can mistake ``%ASA-6-302013`` for a tag.
_FRAME = re.compile(r"%ASA-(?P<sev>\d)-(?P<msgid>\d+):\s?(?P<text>.*)$")

#: The message ids this phase maps.
_DENY = 106023
_ACCESS_LIST = 106100
_BUILT = frozenset({302013, 302015})
_TEARDOWN = frozenset({302014, 302016})
_AAA_FAILURE = frozenset({113005, 113015})
_LOGIN = frozenset({605005, 611101})

#: The two message-id families that are always a firewall event (spec 03 5.5).
_ACCESS_LIST_RANGE = (106000, 107000)
_CONNECTION_RANGE = (302000, 303000)

#: ASA severity to normalized level (spec 03 5.5): 0-2 critical, 3 error,
#: 4 warning, 5-6 info, 7 debug.
_SEVERITY_LEVEL: dict[int, str] = {
    0: "critical",
    1: "critical",
    2: "critical",
    3: "error",
    4: "warning",
    5: "info",
    6: "info",
    7: "debug",
}

#: Per-message-id column patterns (spec 03 5.5).
_PATTERNS: dict[int, re.Pattern[str]] = {
    _DENY: re.compile(
        r"Deny (?P<proto>\w+) src (?P<sif>\S+):(?P<sip>[\d.]+)/(?P<sport>\d+) "
        r"dst (?P<dif>\S+):(?P<dip>[\d.]+)/(?P<dport>\d+) by access-group \"(?P<acl>[^\"]+)\""
    ),
    _ACCESS_LIST: re.compile(
        r"access-list (?P<acl>\S+) (?P<act>permitted|denied) (?P<proto>\w+) "
        r"(?P<sif>\S+)/(?P<sip>[\d.]+)\((?P<sport>\d+)\) -> "
        r"(?P<dif>\S+)/(?P<dip>[\d.]+)\((?P<dport>\d+)\)"
    ),
}
_BUILT_RE = re.compile(
    r"Built (?P<dir>inbound|outbound) (?P<proto>TCP|UDP) connection (?P<cid>\d+) for "
    r"(?P<sif>\S+):(?P<sip>[\d.]+)/(?P<sport>\d+) \([^)]*\) to "
    r"(?P<dif>\S+):(?P<dip>[\d.]+)/(?P<dport>\d+)"
)
_TEARDOWN_RE = re.compile(
    r"Teardown (?P<proto>TCP|UDP) connection (?P<cid>\d+) for "
    r"(?P<sif>\S+):(?P<sip>[\d.]+)/(?P<sport>\d+) \([^)]*\) to "
    r"(?P<dif>\S+):(?P<dip>[\d.]+)/(?P<dport>\d+)"
)
_AAA_RE = re.compile(r"AAA user authentication Rejected .*?user = (?P<user>\S+)")
_LOGIN_RE = re.compile(r"user = (?P<user>\S+)")


def _match_asa(line: str) -> re.Match[str] | None:
    """Locate the ``%ASA-`` frame anywhere in a line."""
    return _FRAME.search(line)


def _share(head: TextHead) -> float:
    """Fraction of non-empty sampled lines that are ASA records."""
    lines = [line for line in head.lines if line.strip()]
    if not lines:
        return 0.0
    matched = sum(1 for line in lines if _match_asa(line) is not None)
    return matched / len(lines)


def _category_for(msgid: int) -> str | None:
    """The normalized category a message id belongs to.

    Spec 03 5.5 makes every ``106xxx``/``302xxx`` message a firewall event, not
    only the ids this phase parses into columns, so an unrecognized variant is
    still filed correctly.
    """
    if _ACCESS_LIST_RANGE[0] <= msgid < _ACCESS_LIST_RANGE[1] or (
        _CONNECTION_RANGE[0] <= msgid < _CONNECTION_RANGE[1]
    ):
        return "firewall"
    if msgid in _AAA_FAILURE or msgid in _LOGIN:
        return "logon"
    return None


def _tuple_columns(match: re.Match[str]) -> tuple[dict[str, object], dict[str, object]]:
    """The shared src/dst columns and fields a five-tuple match contributes."""
    columns: dict[str, object] = {
        "src_ip": canonical_ip(match.group("sip")),
        "src_port": to_port(match.group("sport")),
        "dst_ip": canonical_ip(match.group("dip")),
        "dst_port": to_port(match.group("dport")),
        "protocol": _match_proto(match),
    }
    fields: dict[str, object] = {}
    if "sif" in match.re.groupindex:
        fields["ingress"] = match.group("sif")
        fields["egress"] = match.group("dif")
    if "acl" in match.re.groupindex:
        fields["acl"] = match.group("acl")
    return columns, fields


def _match_proto(match: re.Match[str]) -> str | None:
    """The protocol from a match, if the pattern captured one."""
    if "proto" not in match.re.groupindex:
        return None
    value = match.group("proto").lower()
    return "tcp" if value == "tcp" else ("udp" if value == "udp" else value)


class FwCiscoAsaParser:
    """Cisco ASA ``%ASA-`` messages."""

    log_type = "fw_cisco_asa"

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
            _payload, framed = payload_and_framed(line)
            matched = _match_asa(line)
            if matched is None:
                yield ParseFailure(f"line:{number}", "line is not a Cisco ASA record", line)
                continue
            yield self._event(
                context, line=line, matched=matched, framed=framed, clock=clock, number=number
            )

    def _event(
        self,
        context: ParseContext,
        *,
        line: str,
        matched: re.Match[str],
        framed: Framed | None,
        clock: SyslogClock,
        number: int,
    ) -> NormalizedEvent:
        """Map one ASA record into an event, enriching known message ids."""
        severity = int(matched.group("sev"))
        msgid = int(matched.group("msgid"))
        text = matched.group("text")
        columns, fields, action, outcome = self._detail(msgid, text)
        return NormalizedEvent(
            case_id=context.case_id,
            source_id=context.source_id,
            record_ref=f"line:{number}",
            log_type=self.log_type,
            raw=truncate(line, context.max_line_bytes)[0],
            ts_ms=syslog_moment(framed, clock),
            host=framed.host if framed is not None else None,
            level=_SEVERITY_LEVEL.get(severity),
            ls_category=_category_for(msgid),
            event_id=msgid,
            event_action=action,
            event_outcome=outcome,
            message=text,
            fields_json=fields,
            **columns,  # type: ignore[arg-type]
        )

    def _detail(  # noqa: PLR0911 - one return per message-id family, by design
        self, msgid: int, text: str
    ) -> tuple[dict[str, object], dict[str, object], str | None, str | None]:
        """Columns, fields, action and outcome for a known message id."""
        if msgid in _PATTERNS:
            detail = _PATTERNS[msgid].search(text)
            if detail is None:
                return {}, {}, None, None
            columns, fields = _tuple_columns(detail)
            if msgid == _DENY:
                return columns, fields, "firewall_deny", "failure"
            permitted = detail.group("act") == "permitted"
            action = "firewall_allow" if permitted else "firewall_deny"
            return columns, fields, action, "success" if permitted else "failure"
        if msgid in _BUILT or msgid in _TEARDOWN:
            detail = (_BUILT_RE if msgid in _BUILT else _TEARDOWN_RE).search(text)
            if detail is None:
                return {}, {}, None, None
            columns, fields = _tuple_columns(detail)
            if "dir" in detail.re.groupindex:
                fields["direction"] = detail.group("dir")
            fields["connection_id"] = detail.group("cid")
            verb = "built" if msgid in _BUILT else "teardown"
            return columns, fields, f"firewall_connection_{verb}", None
        if msgid in _AAA_FAILURE:
            detail = _AAA_RE.search(text)
            if detail is not None:
                return (
                    {"user_name": detail.group("user")},
                    {},
                    "aaa_authentication_failed",
                    "failure",
                )
        elif msgid in _LOGIN:
            detail = _LOGIN_RE.search(text)
            if detail is not None:
                return {"user_name": detail.group("user")}, {}, "vpn_login", "success"
        return {}, {}, None, None


_register(FwCiscoAsaParser())


__all__ = ["FwCiscoAsaParser"]
