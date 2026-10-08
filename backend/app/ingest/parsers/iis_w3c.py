"""``iis_w3c`` — IIS W3C extended logs (spec 03 section 4.3).

The file is self-describing: ``#Fields:`` names the columns and every row after
it is positional whitespace-separated data. That header is also the only safe
way to read the file, so a fragment with no header scores zero rather than
guessing column meanings from position.

W3C encodes a space as ``+`` and escapes the rest, so every token is
percent-decoded on the way in (:func:`urllib.parse.unquote_plus`) and the
original spellings are kept in ``fields_json``.
"""

from __future__ import annotations

from collections.abc import Iterator
from urllib.parse import unquote_plus

from app.ingest.events import NormalizedEvent
from app.ingest.normalize import (
    canonical_ip,
    parse_timestamp,
    to_int,
    to_port,
    truncate,
)
from app.ingest.parsers.base import ParseContext, ParseFailure, _register
from app.ingest.parsers.web_common import IIS_FIELDS, IIS_SOFTWARE, dash_to_none
from app.ingest.text import TextHead, iter_text_lines

#: Confidence of a header-bearing IIS file.
_IIS_MATCH = 0.95

#: Apache-style ctime is not IIS's; IIS carries ``date`` and ``time`` columns.
_IIS_TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"

#: IIS defaults to UTC when no zone is configured.
_IIS_TIMEZONE = "UTC"

#: Columns promoted onto the event, all other columns stay in ``fields_json``.
_DIRECT = {
    "c-ip": "src_ip",
    "s-ip": "dst_ip",
    "s-port": "dst_port",
    "cs-method": "http_method",
    "cs-username": "user_name",
    "cs(user-agent)": "user_agent",
    "sc-status": "http_status",
    "sc-bytes": "bytes_out",
}

#: HTTP statuses at or above this are treated as failures.
_CLIENT_ERROR = 400


def _fields_map(head: TextHead) -> list[str] | None:
    """The lowercased column names declared by a ``#Fields:`` header."""
    for line in head.lines:
        matched = IIS_FIELDS.match(line)
        if matched is not None:
            return matched.group("fields").split()
    return None


class IisW3cParser:
    """IIS ``*.log`` in W3C extended format."""

    log_type = "iis_w3c"

    def sniff(self, head: TextHead) -> float:
        """Claim the file only when it declares its columns."""
        for line in head.lines:
            if IIS_FIELDS.match(line) is not None or IIS_SOFTWARE.match(line) is not None:
                return _IIS_MATCH
        return 0.0

    def parse(self, context: ParseContext) -> Iterator[NormalizedEvent | ParseFailure]:
        columns: list[str] | None = None
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
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("#"):
                matched = IIS_FIELDS.match(stripped)
                if matched is not None:
                    columns = [name.lower() for name in matched.group("fields").split()]
                continue
            if columns is None:
                context.counters.record_failure()
                yield ParseFailure(
                    f"line:{number}", "data line appeared before a #Fields header", line
                )
                continue
            values = [unquote_plus(token) for token in stripped.split()]
            if len(values) != len(columns):
                context.counters.record_failure()
                yield ParseFailure(
                    f"line:{number}",
                    f"expected {len(columns)} fields, found {len(values)}",
                    line,
                )
                continue
            event = self._event(context, number, line, columns, values)
            context.counters.record_event(event)
            yield event

    def _event(
        self,
        context: ParseContext,
        number: int,
        line: str,
        columns: list[str],
        values: list[str],
    ) -> NormalizedEvent:
        row = dict(zip(columns, values, strict=True))
        fields: dict[str, object] = dict(row)
        ts_ms = _timestamp(row)
        url_path = dash_to_none(row.get("cs-uri-stem"))
        url_query = dash_to_none(row.get("cs-uri-query"))
        url = url_path
        if url is not None and url_query is not None:
            url = f"{url_path}?{url_query}"
        status = to_int(row.get("sc-status"))
        result = "success" if status is not None and status < _CLIENT_ERROR else "failure"
        return NormalizedEvent(
            case_id=context.case_id,
            source_id=context.source_id,
            record_ref=f"line:{number}",
            log_type=self.log_type,
            raw=truncate(line, context.max_line_bytes)[0],
            ts_ms=ts_ms,
            ls_category="webserver",
            event_action="http_request",
            event_outcome=result,
            src_ip=canonical_ip(row.get("c-ip")),
            dst_ip=canonical_ip(row.get("s-ip")),
            dst_port=to_port(row.get("s-port")),
            http_method=dash_to_none(row.get("cs-method")),
            url=url,
            url_path=url_path,
            url_query=url_query,
            http_status=status,
            bytes_out=to_int(row.get("sc-bytes")),
            user_name=dash_to_none(row.get("cs-username")),
            user_agent=dash_to_none(row.get("cs(user-agent)")),
            fields_json=fields,
        )


def _timestamp(row: dict[str, str]) -> int | None:
    """``date`` + ``time`` in UTC, or ``None`` when either is absent."""
    date = dash_to_none(row.get("date"))
    time = dash_to_none(row.get("time"))
    if date is None or time is None:
        return None
    moment = parse_timestamp(
        f"{date} {time}", fmt=f"strptime:{_IIS_TIMESTAMP_FORMAT}", assume_tz=_IIS_TIMEZONE
    )
    return moment[0] if moment is not None else None


_register(IisW3cParser())


__all__ = ["IisW3cParser"]
