"""``linux_syslog`` and ``linux_auth`` (spec 03 section 3.1).

The two log types differ only in what they are called. Both frame a file with
the shared machinery in :mod:`app.ingest.parsers.linux_common`, and detection
decides between them: a file whose name or contents say "authentication" is
``linux_auth``, everything else is ``linux_syslog``.

A line that matches no framing and does not begin with whitespace is one
malformed record and yields a :class:`ParseFailure`. A line that does begin with
whitespace is a continuation of the record before it, appended to that record's
message and raw text (spec 03 section 3.1).
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from app.ingest.events import NormalizedEvent
from app.ingest.normalize import canonical_ip, normalize_outcome, to_port, truncate
from app.ingest.parsers.base import (
    ParseContext,
    ParseFailure,
    _register,
)
from app.ingest.parsers.linux_common import (
    Framed,
    SyslogClock,
    is_auth_app,
    level_from_pri_or_info,
    match_framing,
    match_message,
)
from app.ingest.text import TextHead, iter_text_lines, sniff_name

#: Share of sampled lines that must parse as a framing to call the file syslog.
_FRAMING_SHARE = 0.8

#: Share of authentication daemon tags that makes a file an authentication log.
_AUTH_SHARE = 0.6

#: Daemons whose syslog lines belong to a firewall parser, not to ``linux_syslog``.
_FIREWALL_APPS = frozenset({"filterlog"})

#: A tag that is really a Cisco ASA ``%ASA-`` frame, not a daemon name.
_FIREWALL_APP_PREFIX = "%asa-"

#: The UFW verdict marker that rides inside a ``kernel:`` message.
_FIREWALL_MARKER = re.compile(r"\[UFW (?:BLOCK|ALLOW|AUDIT|LIMIT)\]")

#: Share of firewall-shaped lines above which this file is left to a firewall parser.
_FIREWALL_SHARE = 0.6


def _defers_to_firewall(head: TextHead) -> bool:
    """True when the file is mostly firewall lines that a Phase 4 parser owns.

    ``kernel:`` UFW lines, pfSense ``filterlog`` lines and Cisco ASA lines all
    frame exactly like syslog, so without this deferral both this parser and the
    firewall parser would claim them and the vote would be a tie. Handing them
    over cleanly keeps detection decisive (spec 03 section 3.1 delegates UFW
    kernel lines to 5.1).
    """
    lines = [line for line in head.lines if line.strip()]
    if not lines:
        return False
    firewall = 0
    for line in lines:
        framed = match_framing(line)
        message = framed.message if framed is not None else line
        app = (framed.app or "").lower() if framed is not None else ""
        if (
            app in _FIREWALL_APPS
            or app.startswith(_FIREWALL_APP_PREFIX)
            or "%ASA-" in message.upper()
            or _FIREWALL_MARKER.search(message)
            or ("IN=" in message and "SRC=" in message and "DST=" in message)
        ):
            firewall += 1
    return firewall / len(lines) >= _FIREWALL_SHARE


def _is_auth_file(head: TextHead) -> bool:
    """True when the filename or the daemon tags say this is an auth log."""
    name = sniff_name(head.name or "")
    if name.startswith(("auth.log", "secure")):
        return True
    apps = [
        framed.app
        for line in head.lines
        if line.strip() and (framed := match_framing(line)) is not None and framed.app
    ]
    if not apps:
        return False
    auth = sum(1 for app in apps if is_auth_app(app))
    return auth / len(apps) >= _AUTH_SHARE


def _sniff(head: TextHead, *, want_auth: bool) -> float:
    """Score a head for one of the two log types.

    The two are mutually exclusive: whichever the filename and tags select scores
    high and the other scores zero, so detection is decisive rather than a tie.
    """
    lines = [line for line in head.lines if line.strip()]
    if not lines:
        return 0.0
    # A continuation line (leading whitespace) belongs to the framed record
    # before it, so it counts as explained by the framing too.
    framed = sum(1 for line in lines if match_framing(line) is not None or line[:1].isspace())
    if framed / len(lines) < _FRAMING_SHARE:
        return 0.0
    if _defers_to_firewall(head):
        return 0.0
    if want_auth:
        return 0.95 if _is_auth_file(head) else 0.0
    return 0.0 if _is_auth_file(head) else 0.9


class LinuxSyslogParser:
    """RFC 3164 / RFC 3339 / RFC 5424 syslog and the daemons that write it."""

    log_type = "linux_syslog"

    def sniff(self, head: TextHead) -> float:
        return _sniff(head, want_auth=False)

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
        raw_lines: list[str] = []
        framed: Framed | None = None
        line_no = 0
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
            current = match_framing(line)
            if current is not None:
                if framed is not None:
                    yield self._event(context, framed, raw_lines, line_no, clock)
                framed, raw_lines, line_no = current, [line], number
                continue
            if line[:1].isspace() and framed is not None:
                raw_lines.append(line)
                continue
            if framed is not None:
                yield self._event(context, framed, raw_lines, line_no, clock)
                framed, raw_lines = None, []
            yield ParseFailure(f"line:{number}", "line does not match any syslog framing", line)
        if framed is not None:
            yield self._event(context, framed, raw_lines, line_no, clock)

    def _event(
        self,
        context: ParseContext,
        framed: Framed,
        raw_lines: list[str],
        line_no: int,
        clock: SyslogClock,
    ) -> NormalizedEvent:
        """Turn one framed record and its continuation lines into an event."""
        message = framed.message
        if len(raw_lines) > 1:
            continuation = "\n".join(part.strip() for part in raw_lines[1:] if part.strip())
            if continuation:
                message = f"{message}\n{continuation}"
        matched = match_message(message, framed.app)
        columns = dict(matched.columns) if matched is not None else {}
        fields = dict(matched.fields) if matched is not None else {}
        fields.setdefault("framing", framed.framing)
        if framed.pid is not None:
            fields.setdefault("pid", framed.pid)
        raw = truncate("\n".join(raw_lines), context.max_line_bytes)[0]
        return NormalizedEvent(
            case_id=context.case_id,
            source_id=context.source_id,
            record_ref=f"line:{line_no}",
            log_type=self.log_type,
            raw=raw,
            ts_ms=clock.epoch_ms(framed),
            ls_category=matched.category if matched is not None else None,
            host=framed.host,
            provider=framed.app,
            app_name=framed.app,
            level=level_from_pri_or_info(framed.pri),
            event_action=matched.action if matched is not None else None,
            event_outcome=normalize_outcome(matched.outcome) if matched is not None else None,
            user_name=columns.get("user_name"),
            target_user_name=columns.get("target_user_name"),
            src_ip=canonical_ip(columns.get("src_ip")) if columns.get("src_ip") else None,
            src_port=to_port(columns.get("src_port")),
            process_pid=framed.pid,
            process_cmdline=columns.get("process_cmdline"),
            file_path=columns.get("file_path"),
            message=columns.get("message", message),
            fields_json=fields,
        )


class LinuxAuthParser(LinuxSyslogParser):
    """The same reader, labelled ``linux_auth`` for authentication logs."""

    log_type = "linux_auth"

    def sniff(self, head: TextHead) -> float:
        return _sniff(head, want_auth=True)


_register(LinuxSyslogParser())
_register(LinuxAuthParser())


__all__ = ["LinuxAuthParser", "LinuxSyslogParser"]
