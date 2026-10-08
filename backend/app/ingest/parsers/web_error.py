"""``nginx_error`` and ``apache_error`` (spec 03 section 4.2).

The two error logs share almost nothing on the wire — nginx leads with a
slash-separated local clock and a ``pid#tid:`` tag, Apache with a bracketed
ctime and ``[module:level]`` — so each has its own pattern. What they do share is
the shape of the event: a severity, a process id, the offending client when the
line names one, and the free-text message kept whole.

An error line's timestamp carries no offset on either server, so it is read in
the case timezone and left unset when the case has none, rather than assuming
UTC and moving evidence across a day boundary.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from app.ingest.events import NormalizedEvent
from app.ingest.normalize import (
    canonical_ip,
    normalize_level,
    parse_timestamp,
    to_int,
    to_port,
    truncate,
)
from app.ingest.parsers.base import ParseContext, ParseFailure, _register
from app.ingest.parsers.web_common import (
    APACHE_ERROR,
    APACHE_ERROR_TIMESTAMP_FORMATS,
    NGINX_ERROR,
    NGINX_ERROR_TIMESTAMP_FORMAT,
    dash_to_none,
)
from app.ingest.text import TextHead, iter_text_lines

#: Share of sampled lines that must match before the format is claimed.
_ERROR_SHARE = 0.8

#: Confidence of a decisive error-log vote.
_ERROR_MATCH = 0.9

#: ``client: <ip>[:port]`` inside a nginx message.
_NGINX_CLIENT = re.compile(r"client: (?P<ip>[0-9A-Fa-f:.]+)(?::(?P<port>\d+))?")

#: ``request: "<method> <uri> ..."`` inside a nginx message.
_NGINX_REQUEST = re.compile(r'request: "(?P<request>[^"]*)"')

#: An Apache ``AH``-prefixed error id, kept in ``fields_json``.
_APACHE_CODE = re.compile(r"\b(?P<code>AH\d{5})\b")

#: A tidy request inside a quoted field.
_HTTP_METHOD = re.compile(r"^(?P<method>[A-Z]+) (?P<uri>\S+)(?: (?P<proto>HTTP/[\d.]+))?$")


def _share(lines: list[str], pattern: re.Pattern[str]) -> float:
    """Fraction of non-empty sampled lines matching ``pattern``."""
    usable = [line for line in lines if line.strip()]
    if not usable:
        return 0.0
    matched = sum(1 for line in usable if pattern.match(line) is not None)
    return matched / len(usable)


class _ErrorParser:
    """Shared parse loop for the two error formats."""

    log_type = ""
    _pattern: re.Pattern[str]

    def sniff(self, head: TextHead) -> float:
        return _ERROR_MATCH if _share(head.lines, self._pattern) >= _ERROR_SHARE else 0.0

    def parse(self, context: ParseContext) -> Iterator[NormalizedEvent | ParseFailure]:
        for number, line, truncated in iter_text_lines(
            context.path, max_line_bytes=context.max_line_bytes
        ):
            if truncated:
                context.counters.record_failure()
                yield ParseFailure(
                    f"line:{number}",
                    "line exceeded max_line_bytes and cannot be parsed",
                    line,
                )
                continue
            if not line.strip():
                continue
            matched = self._pattern.match(line)
            if matched is None:
                context.counters.record_failure()
                yield ParseFailure(
                    f"line:{number}", "line does not match an error log format", line
                )
                continue
            event = self._event(context, matched, number, line)
            context.counters.record_event(event)
            yield event

    def _event(
        self, context: ParseContext, matched: re.Match[str], number: int, line: str
    ) -> NormalizedEvent:
        raise NotImplementedError


class NginxErrorParser(_ErrorParser):
    """nginx ``error.log``."""

    log_type = "nginx_error"
    _pattern = NGINX_ERROR

    def _event(
        self, context: ParseContext, matched: re.Match[str], number: int, line: str
    ) -> NormalizedEvent:
        groups = matched.groupdict()
        message = groups["msg"]
        moment = parse_timestamp(
            groups["ts"],
            fmt=f"strptime:{NGINX_ERROR_TIMESTAMP_FORMAT}",
            assume_tz=context.timezone,
        )
        fields: dict[str, object] = {}
        if groups["tid"] is not None:
            fields["thread_id"] = groups["tid"]
        if groups["cid"] is not None:
            fields["connection"] = groups["cid"]
        method, url = _request_parts(_NGINX_REQUEST, message)
        client = _NGINX_CLIENT.search(message)
        event = NormalizedEvent(
            case_id=context.case_id,
            source_id=context.source_id,
            record_ref=f"line:{number}",
            log_type=self.log_type,
            raw=truncate(line, context.max_line_bytes)[0],
            ts_ms=moment[0] if moment is not None else None,
            ls_category="webserver_error",
            level=normalize_level(groups["level"]),
            process_pid=to_int(groups["pid"]),
            src_ip=canonical_ip(client.group("ip")) if client is not None else None,
            src_port=to_port(client.group("port")) if client is not None else None,
            http_method=method,
            url=url,
            message=message,
            fields_json=fields,
        )
        event.split_url()
        return event


class ApacheErrorParser(_ErrorParser):
    """Apache 2.4 ``error.log``."""

    log_type = "apache_error"
    _pattern = APACHE_ERROR

    def _event(
        self, context: ParseContext, matched: re.Match[str], number: int, line: str
    ) -> NormalizedEvent:
        groups = matched.groupdict()
        message = groups["msg"]
        moment = None
        for layout in APACHE_ERROR_TIMESTAMP_FORMATS:
            moment = parse_timestamp(
                groups["ts"], fmt=f"strptime:{layout}", assume_tz=context.timezone
            )
            if moment is not None:
                break
        fields: dict[str, object] = {}
        if groups["module"] is not None:
            fields["module"] = groups["module"]
        code = _APACHE_CODE.search(message)
        if code is not None:
            fields["error_code"] = code.group("code")
        return NormalizedEvent(
            case_id=context.case_id,
            source_id=context.source_id,
            record_ref=f"line:{number}",
            log_type=self.log_type,
            raw=truncate(line, context.max_line_bytes)[0],
            ts_ms=moment[0] if moment is not None else None,
            ls_category="webserver_error",
            level=normalize_level(groups["level"]),
            process_pid=to_int(groups["pid"]),
            src_ip=canonical_ip(groups["ip"]),
            src_port=to_port(groups["port"]),
            message=message,
            fields_json=fields,
        )


def _request_parts(pattern: re.Pattern[str], message: str) -> tuple[str | None, str | None]:
    """``(method, url)`` from a quoted request inside a message, if present."""
    matched = pattern.search(message)
    if matched is None:
        return None, None
    request = matched.group("request")
    parsed = _HTTP_METHOD.match(request)
    if parsed is None:
        return None, dash_to_none(request)
    return parsed.group("method"), dash_to_none(parsed.group("uri"))


_register(NginxErrorParser())
_register(ApacheErrorParser())


__all__ = ["ApacheErrorParser", "NginxErrorParser"]
