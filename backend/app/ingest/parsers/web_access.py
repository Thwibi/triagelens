"""``apache_access`` and ``nginx_access`` (spec 03 section 4.1).

The combined-log line is the same on both servers, so one reader serves both; the
two differ only in the ``log_type`` they record and in the filename that selects
between them. They are deliberately mutually exclusive during detection: a name
mentioning ``nginx`` scores the nginx reader and zeroes the Apache one, and any
other name does the reverse, so a vote is decisive rather than an alphabetical
tie.

A line that is not a combined record is retried as the malformed fallback, which
keeps a scanner's binary junk or a bare ``"-"`` request as an event with the
request stored verbatim and no method (spec 09 P-09). Only a line that is neither
becomes a parse error.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from app.ingest.events import NormalizedEvent
from app.ingest.normalize import canonical_ip, parse_timestamp, to_int, truncate
from app.ingest.parsers.base import (
    ParseContext,
    ParseFailure,
    _register,
)
from app.ingest.parsers.web_common import (
    ACCESS_TIMESTAMP_FORMAT,
    dash_to_none,
    decode_url,
    match_access,
    split_request,
)
from app.ingest.text import TextHead, iter_text_lines, sniff_name

#: Share of sampled lines that must look like an access record to claim the file.
_ACCESS_SHARE = 0.8

#: Confidence of a decisive access vote.
_ACCESS_MATCH = 0.9

#: HTTP statuses at or above this are treated as failures.
_CLIENT_ERROR = 400

#: Unix epoch seconds for ``1970``-based time math is not needed; the timestamp
#: helper handles the zone carried by the Apache ``%z`` field.
_TS_FORMAT = f"strptime:{ACCESS_TIMESTAMP_FORMAT}"


def _access_share(head: TextHead) -> float:
    """Fraction of non-empty sampled lines that match an access framing."""
    lines = [line for line in head.lines if line.strip()]
    if not lines:
        return 0.0
    matched = sum(1 for line in lines if match_access(line) is not None)
    return matched / len(lines)


def _sniff(head: TextHead, *, nginx: bool) -> float:
    """Score a head for Apache or nginx access, exclusive of the other."""
    if _access_share(head) < _ACCESS_SHARE:
        return 0.0
    named_nginx = "nginx" in sniff_name(head.name or "").lower()
    return _ACCESS_MATCH if nginx == named_nginx else 0.0


class _AccessParser:
    """The combined access-log reader, shared by Apache and nginx."""

    log_type = ""
    _is_nginx = False

    def sniff(self, head: TextHead) -> float:
        return _sniff(head, nginx=self._is_nginx)

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
            matched = match_access(line)
            if matched is None:
                yield ParseFailure(
                    f"line:{number}", "line does not match an access log format", line
                )
                continue
            yield self._event(context, matched, number, line)

    def _event(
        self,
        context: ParseContext,
        matched: re.Match[str],
        number: int,
        line: str,
    ) -> NormalizedEvent:
        """Map one access record into an event."""
        groups = matched.groupdict()
        if "method" in matched.re.groupindex:
            method = groups["method"]
            url = dash_to_none(groups["uri"])
            protocol = groups["proto"]
        else:
            method, url, protocol = split_request(groups["request"])
        status = to_int(groups["status"])
        result = "success" if status is not None and status < _CLIENT_ERROR else "failure"
        fields: dict[str, object] = {
            "referer": dash_to_none(groups["referer"]),
            "protocol": protocol,
        }
        decoded = decode_url(url)
        if decoded is not None:
            fields["url_decoded"] = decoded
        moment = parse_timestamp(groups["ts"], fmt=_TS_FORMAT)
        event = NormalizedEvent(
            case_id=context.case_id,
            source_id=context.source_id,
            record_ref=f"line:{number}",
            log_type=self.log_type,
            raw=truncate(line, context.max_line_bytes)[0],
            ts_ms=moment[0] if moment is not None else None,
            ls_category="webserver",
            event_action="http_request",
            event_outcome=result,
            user_name=dash_to_none(groups["user"]),
            src_ip=canonical_ip(groups["ip"]),
            http_method=method,
            url=url,
            http_status=status,
            bytes_out=to_int(groups["bytes"]),
            user_agent=dash_to_none(groups["ua"]),
            fields_json=dict(fields),
        )
        event.split_url()
        return event


class ApacheAccessParser(_AccessParser):
    """Apache ``access.log`` in combined format."""

    log_type = "apache_access"
    _is_nginx = False


class NginxAccessParser(_AccessParser):
    """nginx ``access.log`` in combined format."""

    log_type = "nginx_access"
    _is_nginx = True


_register(ApacheAccessParser())
_register(NginxAccessParser())


__all__ = ["ApacheAccessParser", "NginxAccessParser"]
