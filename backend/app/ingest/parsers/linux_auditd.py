"""``linux_auditd`` (spec 03 section 3.3).

The Linux audit daemon writes one logical event as several lines sharing a
``msg=audit(<epoch>.<ms>:<serial>)`` id, each with its own ``type=``: a
``SYSCALL`` line, an ``EXECVE`` line holding the argv, ``PATH`` lines, a
``SOCKADDR`` line for a connect, and so on. The parser groups consecutive lines
by serial (flushing on a serial change or at end of file) and emits exactly one
``NormalizedEvent`` per group.

Two encodings need care because getting them wrong loses evidence:

- Arguments and ``proctitle`` may be hex-encoded when they contain characters
  the kernel cannot print. They are decoded only when the value really is hex and
  the result is text (spec 03 section 3.3).
- ``saddr`` is a packed ``sockaddr`` in hex; the port and address are pulled out
  by family (AF_INET / AF_INET6).
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

from app.ingest.events import NormalizedEvent
from app.ingest.normalize import (
    canonical_ip,
    clean_text,
    normalize_outcome,
    parse_timestamp,
    to_int,
    truncate,
)
from app.ingest.parsers.base import (
    ParseContext,
    ParseFailure,
    _register,
)
from app.ingest.text import TextHead, iter_text_lines

#: ``type=`` at the head of every audit line.
_TYPE = re.compile(r"\btype=(?P<type>[A-Z_0-9]+)")

#: The audit id shared by every line of one logical event.
_AUDIT_ID = re.compile(r"msg=audit\((?P<epoch>\d+(?:\.\d+)?):(?P<serial>\d+)\)")

#: ``key=value`` pairs. A value is a quoted string or a run of non-space bytes.
_FIELD = re.compile(r"(?P<key>[A-Za-z_][A-Za-z0-9_]*)=(?P<value>\"[^\"]*\"|'[^']*'|\S*)")

#: An unset audit user id, which must not become a stored user name.
_UNSET_AUID = "4294967295"

#: Hex only, the shape auditd uses for an encoded argument.
_HEX_ONLY = re.compile(r"\A[0-9A-Fa-f]+\Z")

#: ``a0``, ``a1`` ... argument keys.
_ARGV_KEY = re.compile(r"\Aa(?P<index>\d+)\Z")

#: Record types that mean an account was created or changed.
_ACCOUNT_TYPES = frozenset(
    {
        "ADD_USER",
        "DEL_USER",
        "ADD_GROUP",
        "DEL_GROUP",
        "USER_MGMT",
        "GRP_MGMT",
        "ROLE_ASSIGN",
        "USER_CHAUTHTOK",
    }
)

#: sockaddr sa_family values the parser understands.
_AF_INET = 2
_AF_INET6 = 10

#: Shortest bytes needed for an IPv4 ``sockaddr`` and for an IPv6 one.
_SOCKADDR_MIN_BYTES = 8
_SOCKADDR_INET6_BYTES = 24

#: Where the 16-byte IPv6 address begins inside a packed ``sockaddr_in6``.
_IPV6_ADDRESS_OFFSET = 8

#: A quoted value needs at least one character between its two quotes.
_MIN_QUOTED = 2

#: The highest code point treated as a control character.
_PRINTABLE_FLOOR = 0x20

#: Share of sampled lines that must be audit records, and the score when they are.
_SNIFF_SHARE = 0.8
_SNIFF_SCORE = 0.9


def _unquote(value: str | None) -> str | None:
    """Drop one matching pair of surrounding quotes, if present."""
    if value is None:
        return None
    if len(value) >= _MIN_QUOTED and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def _parse_values(line: str) -> dict[str, str]:
    """``key=value`` pairs, including the pairs nested in a quoted ``msg=``.

    An audit login line carries its useful fields inside ``msg='...'``; a plain
    scanning pass would stop at the surrounding quotes. The nested pairs are
    merged in without letting them overwrite the outer ones, since the outer
    ``pid``/``type``/``msg`` describe the record itself.
    """
    outer: dict[str, str] = {
        matched.group("key") or "": _unquote(matched.group("value")) or ""
        for matched in _FIELD.finditer(line)
    }
    inner: dict[str, str] = {}
    for value in outer.values():
        if value and "=" in value:
            for matched in _FIELD.finditer(value):
                inner.setdefault(matched.group("key") or "", _unquote(matched.group("value")) or "")
    if not inner:
        return outer
    return {**inner, **outer}


def _decode_hex(text: str) -> str:
    """Decode a hex-encoded audit value, or return it unchanged.

    A value is decoded only when it is even-length hex and yields printable text;
    anything else is returned exactly as it was, so a plain string that happens to
    look like hex is never mangled. The check on control characters is what keeps
    a word like ``deadbeef`` from being decoded into binary noise.
    """
    if not text or len(text) % 2 or _HEX_ONLY.match(text) is None:
        return text
    try:
        decoded = bytes.fromhex(text).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return text
    if any(ord(char) < _PRINTABLE_FLOOR and char not in "\t\n" for char in decoded):
        return text
    return decoded


def _looks_like_audit(line: str) -> bool:
    return _TYPE.search(line) is not None


def _decode_argv(fields: dict[str, str]) -> list[str]:
    """Ordered ``a0..aN`` values, hex-decoded where encoded."""
    indexed: list[tuple[int, str]] = []
    for key, value in fields.items():
        match = _ARGV_KEY.match(key)
        if match is not None:
            indexed.append((int(match.group("index")), value))
    indexed.sort()
    return [_decode_hex(value) for _, value in indexed]


def _decode_proctitle(value: str) -> str | None:
    """Hex ``proctitle`` with NUL separators turned into spaces."""
    if not value or len(value) % 2 or not _HEX_ONLY.match(value):
        return clean_text(value)
    try:
        data = bytes.fromhex(value)
    except ValueError:
        return None
    return data.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip() or None


def _decode_sockaddr(value: str) -> tuple[str | None, int | None]:
    """``(address, port)`` from a packed hex ``sockaddr``."""
    text = value.strip("\"'")
    if not text or len(text) % 2 or not _HEX_ONLY.match(text):
        return None, None
    try:
        data = bytes.fromhex(text)
    except ValueError:
        return None, None
    if len(data) < _SOCKADDR_MIN_BYTES:
        return None, None
    # ``sockaddr`` stores the family in host byte order and everything after it
    # in network byte order; getting the family wrong makes every connect look
    # like a family we cannot decode.
    family = int.from_bytes(data[0:2], "little")
    port = int.from_bytes(data[2:4], "big")
    if family == _AF_INET:
        address = ".".join(str(octet) for octet in data[4:8])
        return canonical_ip(address), port
    if family == _AF_INET6 and len(data) >= _SOCKADDR_INET6_BYTES:
        parts = [
            data[index : index + 2].hex()
            for index in range(_IPV6_ADDRESS_OFFSET, _SOCKADDR_INET6_BYTES, 2)
        ]
        address = ":".join(parts)
        return canonical_ip(address), port
    return None, None


class LinuxAuditdParser:
    """Audit daemon logs, one event per serial."""

    log_type = "linux_auditd"

    def sniff(self, head: TextHead) -> float:
        lines = [line for line in head.lines if line.strip()]
        if not lines:
            return 0.0
        matched = sum(1 for line in lines if _looks_like_audit(line))
        if matched / len(lines) < _SNIFF_SHARE:
            return 0.0
        return _SNIFF_SCORE

    def parse(self, context: ParseContext) -> Iterator[NormalizedEvent | ParseFailure]:
        """Stream the file, counting each group as an event."""
        for item in self._records(context):
            if isinstance(item, ParseFailure):
                context.counters.record_failure()
            else:
                context.counters.record_event(item)
            yield item

    def _records(self, context: ParseContext) -> Iterator[NormalizedEvent | ParseFailure]:
        group: list[str] = []
        serial: str | None = None
        for number, line, truncated in iter_text_lines(
            context.path, max_line_bytes=context.max_line_bytes
        ):
            if truncated:
                if group:
                    yield self._event(context, group, serial)
                    group = []
                yield ParseFailure(
                    f"line:{number}",
                    "line exceeded max_line_bytes and cannot be parsed",
                    line,
                )
                continue
            if not line.strip():
                continue
            match = _AUDIT_ID.search(line)
            line_serial = match.group("serial") if match is not None else None
            if group and line_serial is not None and line_serial != serial:
                yield self._event(context, group, serial)
                group = []
            if not group and not _looks_like_audit(line):
                yield ParseFailure(f"line:{number}", "line is not an audit record", line)
                continue
            group.append(line)
            if line_serial is not None:
                serial = line_serial
        if group:
            yield self._event(context, group, serial)

    def _event(
        self,
        context: ParseContext,
        group: list[str],
        serial: str | None,
    ) -> NormalizedEvent:
        """Merge one grouped logical event into a single event."""
        types: list[str] = []
        flat: dict[str, str] = {}
        by_type: dict[str, dict[str, str]] = {}
        path_names: list[str] = []
        for line in group:
            match = _TYPE.search(line)
            name = match.group("type") if match is not None else None
            if name is not None:
                types.append(name)
            fields = _parse_values(line)
            if name is not None:
                by_type.setdefault(name, {}).update(fields)
            if name == "PATH" and fields.get("name"):
                path_names.append(fields["name"])
            flat.update(fields)

        execve = by_type.get("EXECVE", {})
        argv = _decode_argv(execve)
        proctitle = _decode_proctitle(by_type.get("PROCTITLE", {}).get("proctitle", ""))
        sockaddr = by_type.get("SOCKADDR", {}).get("saddr")
        dst_ip, dst_port = _decode_sockaddr(sockaddr) if sockaddr else (None, None)

        primary = _primary_type(types)
        category, action = _classify(
            primary, has_execve=bool(execve), has_sockaddr=sockaddr is not None
        )

        auid = flat.get("AUID") or flat.get("auid")
        if auid == _UNSET_AUID:
            auid = None
        user_name = flat.get("acct") or auid
        host = flat.get("hostname")
        if host in {"?", "(none)"}:
            host = None
        process_cmdline = " ".join(argv) if argv else proctitle
        file_path = path_names[0] if path_names else None
        address = flat.get("addr")
        if address in {"?", "(none)"}:
            address = None

        event_fields: dict[str, Any] = dict(flat)
        event_fields["types"] = types
        if argv:
            event_fields["argv"] = argv
        if proctitle:
            event_fields["proctitle"] = proctitle
        raw = truncate("\n".join(group), context.max_line_bytes)[0]
        return NormalizedEvent(
            case_id=context.case_id,
            source_id=context.source_id,
            record_ref=f"audit:{serial if serial is not None else 'unknown'}",
            log_type=self.log_type,
            raw=raw,
            ts_ms=_event_time(group),
            ls_category=category,
            host=clean_text(host),
            level="info",
            event_action=action,
            event_outcome=normalize_outcome(flat.get("res")),
            user_name=clean_text(user_name),
            src_ip=canonical_ip(address) if address else None,
            dst_ip=dst_ip,
            dst_port=dst_port,
            process_pid=to_int(flat.get("pid")),
            process_path=clean_text(flat.get("exe")),
            process_cmdline=clean_text(process_cmdline),
            file_path=clean_text(file_path),
            message=clean_text(process_cmdline or file_path or primary),
            fields_json=event_fields,
        )


def _primary_type(types: list[str]) -> str | None:
    """The most meaningful type in a group, for the action and message."""
    for preferred in ("SYSCALL", "EXECVE", "SOCKADDR"):
        if preferred in types:
            return preferred
    for name in types:
        if name not in {"EOE", "CWD", "PATH", "PROCTITLE"}:
            return name
    return types[0] if types else None


def _classify(
    primary: str | None, *, has_execve: bool, has_sockaddr: bool
) -> tuple[str | None, str | None]:
    """``(ls_category, event_action)`` for a logical event."""
    if has_execve:
        return "process_creation", "process_created"
    if has_sockaddr:
        return None, "socket_connect"
    if primary in _ACCOUNT_TYPES:
        return "account_management", primary.lower()
    if primary is not None and primary.startswith(("USER", "CRED")):
        return "logon", primary.lower()
    return None, primary.lower() if primary is not None else None


def _event_time(group: list[str]) -> int | None:
    """Timestamp from the group's audit id, in UTC epoch milliseconds."""
    for line in group:
        match = _AUDIT_ID.search(line)
        if match is None:
            continue
        parsed = parse_timestamp(float(match.group("epoch")), fmt="epoch_s")
        if parsed is not None:
            return parsed[0]
    return None


_register(LinuxAuditdParser())


__all__ = ["LinuxAuditdParser"]
