"""Shared web-log framing and mapping (spec 03 sections 4 and 6).

Four log types share three wire shapes:

- Apache and nginx **access** logs: the combined line, plus a fallback shape for
  a request field that is not a tidy ``METHOD uri`` pair (``"-"``, binary junk).
  The two servers are cosmetically different, so one parser reads both and only
  the ``log_type`` label and the filename hint tell them apart.
- nginx and Apache **error** logs: two distinct bracket layouts.
- IIS **W3C** logs: a header that names the columns, then whitespace-separated
  rows.

Keeping the regular expressions and the small mapping helpers here means the
parsers themselves are about turning a match into an event, not about the wire
formats, which keeps them readable and the formats greppable in one place.
"""

from __future__ import annotations

import re
from urllib.parse import unquote

from app.ingest.normalize import clean_text

#: Combined access line: ``ip ident user [time] "method uri proto" status bytes
#: "referer" "ua"``. ``ident`` and the trailing quotes are optional in the wild.
ACCESS_COMBINED = re.compile(
    r"^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "
    r'"(?P<method>[A-Z]+) (?P<uri>\S+)(?: (?P<proto>HTTP/[\d.]+))?" '
    r"(?P<status>\d{3}) (?P<bytes>\d+|-)"
    r'(?: "(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?\s*$'
)

#: Fallback: the request field is anything (``"-"``, binary junk), so it is kept
#: whole and the method is left unknown rather than guessed.
ACCESS_FALLBACK = re.compile(
    r"^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "
    r'"(?P<request>[^"]*)" '
    r"(?P<status>\d{3}) (?P<bytes>\d+|-)"
    r'(?: "(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?\s*$'
)

#: ``%d/%b/%Y:%H:%M:%S %z`` — Apache/nginx combined log time, always offset.
ACCESS_TIMESTAMP_FORMAT = "%d/%b/%Y:%H:%M:%S %z"

#: nginx error line: ``2026/03/01 12:00:00 [error] 1234#0: *1 message``.
NGINX_ERROR = re.compile(
    r"^(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) "
    r"\[(?P<level>\w+)\] (?P<pid>\d+)#(?P<tid>\d+): "
    r"(?:\*(?P<cid>\d+) )?(?P<msg>.*)$"
)

#: Apache 2.4 error line: ``[Wed Oct 01 ...] [module:level] [pid N:tid M] [client
#: ip:port] message``. The module, thread and client parts are optional.
APACHE_ERROR = re.compile(
    r"^\[(?P<ts>[^\]]+)\] "
    r"\[(?:(?P<module>[^:\]]+):)?(?P<level>\w+)\] "
    r"\[pid (?P<pid>\d+)(?::tid \d+)?\]"
    r"(?: \[client (?P<ip>[^\]:]+)(?::(?P<port>\d+))?\])? (?P<msg>.*)$"
)

#: nginx error wall-clock time; no zone, so the case timezone applies.
NGINX_ERROR_TIMESTAMP_FORMAT = "%Y/%m/%d %H:%M:%S"

#: Apache error time, with and without microseconds (both are in common use).
APACHE_ERROR_TIMESTAMP_FORMATS = ("%a %b %d %H:%M:%S.%f %Y", "%a %b %d %H:%M:%S %Y")

#: IIS W3C: the header declares the column order for the rows that follow.
IIS_FIELDS = re.compile(r"^#Fields:\s*(?P<fields>.+)$")
IIS_SOFTWARE = re.compile(r"^#Software:\s*Microsoft Internet Information Services", re.IGNORECASE)
IIS_TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"

#: IIS writes a space as ``+`` and encodes the rest; :func:`unquote_plus` undoes
#: both, which is exactly W3C log-file semantics.
_HTTP_METHOD = re.compile(r"^(?P<method>[A-Z]+) (?P<uri>\S+)(?: (?P<proto>HTTP/[\d.]+))?$")


def dash_to_none(value: str | None) -> str | None:
    """Clean a field, turning the ``-`` placeholder into ``None``."""
    text = clean_text(value)
    if text is None or text == "-":
        return None
    return text


def match_access(line: str) -> re.Match[str] | None:
    """Match an access line as combined, or as the malformed fallback."""
    matched = ACCESS_COMBINED.match(line)
    if matched is not None:
        return matched
    return ACCESS_FALLBACK.match(line)


def split_request(request: str | None) -> tuple[str | None, str | None, str | None]:
    """``(method, url, protocol)`` from a request field.

    A field that is not a tidy ``METHOD uri`` pair (a bare ``"-"``, a scanner's
    binary junk) yields a ``None`` method and the whole text as the URL, so the
    evidence is still recorded.
    """
    text = clean_text(request)
    if text is None:
        return None, None, None
    matched = _HTTP_METHOD.match(text)
    if matched is None:
        return None, dash_to_none(text), None
    return matched.group("method"), dash_to_none(matched.group("uri")), matched.group("proto")


def decode_url(url: str | None) -> str | None:
    """The percent-decoded form of ``url``, for the IOC and detection stages.

    The stored ``url`` column keeps the raw bytes exactly as the server logged
    them (spec 09 P-09); this decoded copy is only ever a ``fields_json`` value.
    """
    if url is None:
        return None
    decoded = unquote(url)
    return decoded if decoded != url else None


__all__ = [
    "ACCESS_COMBINED",
    "ACCESS_FALLBACK",
    "ACCESS_TIMESTAMP_FORMAT",
    "APACHE_ERROR",
    "APACHE_ERROR_TIMESTAMP_FORMATS",
    "IIS_FIELDS",
    "IIS_SOFTWARE",
    "IIS_TIMESTAMP_FORMAT",
    "NGINX_ERROR",
    "NGINX_ERROR_TIMESTAMP_FORMAT",
    "dash_to_none",
    "decode_url",
    "match_access",
    "split_request",
]
