"""Shared helpers for the firewall parsers (spec 03 section 5).

Every firewall format in this phase is one of two shapes:

* a **syslog-framed** line, where the vendor payload sits after the RFC 3164
  prefix (UFW's ``kernel:`` line, pfSense's ``filterlog[pid]:`` CSV), or
* a **self-describing** line, where the payload is the whole line and carries its
  own timestamp (FortiGate ``key=value``, PAN-OS CSV, Cisco ASA ``%ASA-``).

The framing is therefore handled once, here: :func:`payload_and_framed` peels an
RFC 3164 prefix when one is present and hands back the payload plus the
:class:`Framed` (so a parser can ask :class:`SyslogClock` for the timestamp).
The rest of the module is the small vocabulary the vendors share: key=value
parsing, quoted-CSV splitting, and the action/protocol normalizers.
"""

from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass

from app.ingest.normalize import clean_text
from app.ingest.parsers.linux_common import Framed, SyslogClock, match_framing

#: An RFC 3164 prefix: optional ``<PRI>``, ``Mon dd HH:MM:SS``, host, ``tag[pid]:``.
#: Only used as a fallback when :func:`match_framing` declines the line, so a
#: vendor payload that merely looks syslog-ish is not decapitated by accident.
SYSLOG_PREFIX = re.compile(
    r"^(?:<\d{1,3}>)?[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}\s"
    r"\S+\s+[^\s:\[]+(?:\[\d+\])?:\s?"
)

#: One ``KEY=VALUE`` token, where the value may be a double-quoted string.
_KV = re.compile(r'(?P<key>[A-Za-z0-9_.-]+)=(?P<value>"[^"]*"|\S+)')

#: Shortest string that can be a quoted value: the two quote marks themselves.
_MIN_QUOTED_LEN = 2

#: Actions that mean the traffic was refused, and that it was permitted.
_DENY_ACTIONS = frozenset(
    {
        "deny",
        "denied",
        "block",
        "blocked",
        "drop",
        "dropped",
        "reject",
        "rejected",
        "reset-client",
        "reset-server",
        "reset-both",
        "block-url",
        "ip-conn",
    }
)
_ALLOW_ACTIONS = frozenset(
    {"allow", "allowed", "accept", "accepted", "pass", "passed", "permit", "permitted"}
)

#: Numeric IP-protocol to name, plus the names themselves passed through.
_PROTOCOLS: dict[str, str] = {
    "1": "icmp",
    "6": "tcp",
    "17": "udp",
    "58": "ipv6-icmp",
    "tcp": "tcp",
    "udp": "udp",
    "icmp": "icmp",
}


@dataclass(slots=True)
class FirewallAction:
    """A normalized verdict: ``allow``/``deny`` and the matching outcome."""

    action: str | None
    outcome: str | None


def strip_syslog(line: str) -> str:
    """Remove a leading RFC 3164 prefix, when one is present."""
    return SYSLOG_PREFIX.sub("", line, count=1)


def payload_and_framed(line: str) -> tuple[str, Framed | None]:
    """Split a line into the vendor payload and its syslog framing, if any.

    Returns ``(payload, framed)``: the payload is the text a vendor parser reads,
    and ``framed`` is ``None`` for a self-describing line.
    """
    framed = match_framing(line)
    if framed is not None:
        return framed.message, framed
    return strip_syslog(line), None


def syslog_moment(framed: Framed | None, clock: SyslogClock) -> int | None:
    """Epoch milliseconds for a framed line's timestamp, or ``None``."""
    if framed is None:
        return None
    return clock.epoch_ms(framed)


def parse_kv(text: str) -> dict[str, str]:
    """Every ``key=value`` token in ``text``, quotes stripped from the value."""
    tokens: dict[str, str] = {}
    for matched in _KV.finditer(text):
        value = matched.group("value")
        if value.startswith('"') and value.endswith('"') and len(value) >= _MIN_QUOTED_LEN:
            value = value[1:-1]
        tokens[matched.group("key")] = value
    return tokens


def split_csv(line: str) -> list[str]:
    """Split one CSV record, honouring double-quoted fields with commas inside."""
    try:
        return next(csv.reader(io.StringIO(line)))
    except (csv.Error, StopIteration):
        return line.split(",")


def normalize_action(value: object) -> FirewallAction:
    """Map a vendor verdict onto ``allow``/``deny`` and an outcome.

    An unrecognized value yields ``(None, None)`` rather than a guess; the caller
    keeps the raw text in ``fields_json.action`` regardless.
    """
    text = clean_text(value)
    if text is None:
        return FirewallAction(None, None)
    lowered = text.lower()
    if lowered in _DENY_ACTIONS:
        return FirewallAction("deny", "failure")
    if lowered in _ALLOW_ACTIONS:
        return FirewallAction("allow", "success")
    return FirewallAction(None, None)


def proto_name(value: object) -> str | None:
    """A protocol name from a numeric id (``6``) or a name (``TCP``)."""
    text = clean_text(value)
    if text is None:
        return None
    return _PROTOCOLS.get(text.lower(), text.lower())


__all__ = [
    "SYSLOG_PREFIX",
    "FirewallAction",
    "normalize_action",
    "parse_kv",
    "payload_and_framed",
    "proto_name",
    "split_csv",
    "strip_syslog",
    "syslog_moment",
]
