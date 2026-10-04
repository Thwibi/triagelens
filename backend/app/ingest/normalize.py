"""Text, address and timestamp normalization (spec 02 section 2).

Every parser funnels its extracted values through these helpers so that the
same input always produces the same stored value, no matter which parser saw it.
The rules are not cosmetic:

- Control characters are stripped because they break log viewers, CSV export and
  the FTS index, and because an attacker can hide text inside them.
- Invalid addresses never reach a column. They survive only in ``fields_json``,
  which is kept verbatim as evidence.
- Timestamps are always converted to UTC. A naive local time is never guessed:
  it raises, because guessing an offset silently shifts evidence.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import UTC, date, datetime
from typing import Any

from app.util.time import iso_utc, to_utc_ms

#: Control characters removed from every extracted string. Tab, newline and
#: carriage return survive: they are legitimate inside a multi-line record.
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

#: Marker appended to a line that hit ``limits.max_line_bytes`` (spec 03 section 1).
TRUNCATION_MARKER = "…[truncated]"

#: Highest valid TCP/UDP port.
MAX_PORT = 65535

#: Above this magnitude a numeric timestamp is milliseconds, not seconds: epoch
#: milliseconds reach 10^11 in 1973 and epoch seconds do not until the year 5138,
#: so no realistic timestamp sits near the boundary.
EPOCH_MS_THRESHOLD = 100_000_000_000

#: Syslog severities, mapped onto the five normalized levels (spec 02 section 1).
_SYSLOG_LEVELS: dict[str, str] = {
    "emerg": "critical",
    "alert": "critical",
    "crit": "critical",
    "critical": "critical",
    "err": "error",
    "error": "error",
    "warning": "warning",
    "warn": "warning",
    "notice": "info",
    "info": "info",
    "informational": "info",
    "debug": "debug",
    "trace": "debug",
}

#: Windows numeric severities, ``EventID``-adjacent level fields.
_NUMERIC_LEVELS: dict[int, str] = {
    0: "info",
    1: "critical",
    2: "critical",
    3: "error",
    4: "warning",
    5: "info",
}

#: Every severity word, syslog and Windows alike. The two vocabularies agree
#: wherever they overlap, so one table is enough and avoids two lookups on the
#: hot path.
_LEVELS: dict[str, str] = {
    **_SYSLOG_LEVELS,
    "fatal": "critical",
    "crit": "critical",
    "information": "info",
    "informational": "info",
    "verbose": "debug",
}

#: Outcome words across EVTX, Wazuh and firewall formats.
_OUTCOMES: dict[str, str] = {
    "success": "success",
    "succeeded": "success",
    "ok": "success",
    "true": "success",
    "allow": "success",
    "allowed": "success",
    "accept": "success",
    "accepted": "success",
    "failure": "failure",
    "failed": "failure",
    "fail": "failure",
    "false": "failure",
    "deny": "failure",
    "denied": "failure",
    "block": "failure",
    "blocked": "failure",
    "error": "failure",
    "unknown": "unknown",
}


def clean_text(value: Any) -> str | None:
    """Strip NUL and C0 control characters; empty becomes ``None``.

    Non-strings are rendered with :func:`str` so a number or bool arriving from a
    JSON record is not silently dropped.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    text = value if isinstance(value, str) else str(value)
    cleaned = _CONTROL_CHARS.sub("", text)
    cleaned = cleaned.strip()
    return cleaned or None


def truncate(text: str, max_bytes: int) -> tuple[str, bool]:
    """Clip ``text`` to ``max_bytes`` UTF-8 bytes.

    Returns the text and whether it was clipped. Clipping happens on a character
    boundary so the result is always valid UTF-8, which byte slicing would not
    guarantee.
    """
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return text, False
    budget = max(max_bytes - len(TRUNCATION_MARKER.encode("utf-8")), 0)
    clipped = encoded[:budget].decode("utf-8", errors="ignore")
    return f"{clipped}{TRUNCATION_MARKER}", True


def canonical_ip(value: Any) -> str | None:
    """Validate and canonicalize an address, or ``None`` when it is not one.

    Canonical means the compressed lowercase form that :mod:`ipaddress` produces,
    so ``2001:0DB8::1``, ``2001:db8:0:0:0:0:0:1`` and ``::ffff:10.0.0.1`` each
    compare equal to the form stored. A value that does not parse returns
    ``None``; the caller keeps the original text in ``fields_json``.
    """
    if value is None:
        return None
    text = clean_text(value)
    if text is None:
        return None
    # Some sources carry a port suffix or a scope id; neither belongs in the
    # stored address, but a bare address must survive untouched.
    candidate = text
    if candidate.startswith("[") and "]" in candidate:
        candidate = candidate[1 : candidate.index("]")]
    elif candidate.count(":") == 1 and "." in candidate:
        # host:port, which only IPv4 records produce.
        candidate = candidate.rsplit(":", 1)[0]
    if "%" in candidate:
        candidate = candidate.split("%", 1)[0]
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def to_port(value: Any) -> int | None:
    """Coerce a port to an int in 0-65535, or ``None`` when it is not one."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        number = value
    elif isinstance(value, str):
        # Fields such as ``source.port`` arrive as "443" but also as "443/tcp".
        text = value.strip().split("/", 1)[0]
        if not text.isdigit():
            return None
        number = int(text)
    else:
        return None
    return number if 0 <= number <= MAX_PORT else None


def to_int(value: Any) -> int | None:
    """Coerce a whole-number field, or ``None`` when it is not one.

    A CSV export writes every column as text, so ``"443"``, ``"443.0"`` and
    ``443`` all have to arrive as the same integer.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    number = _to_number(value)
    if number is None or not number.is_integer():
        return None
    return int(number)


def normalize_level(value: Any) -> str | None:
    """Map a severity onto ``critical, error, warning, info, debug``.

    Handles the syslog words, the Windows text names and the Windows numeric
    severities. Anything unrecognised becomes ``None`` rather than a guess.
    """
    if isinstance(value, int) and not isinstance(value, bool):
        return _NUMERIC_LEVELS.get(value)
    text = clean_text(value)
    if text is None:
        return None
    key = text.lower()
    if key.isdigit():
        # A bare number in a text field is still a Windows severity.
        return _NUMERIC_LEVELS.get(int(key))
    return _LEVELS.get(key)


def normalize_outcome(value: Any) -> str | None:
    """Map an outcome onto ``success``, ``failure`` or ``unknown``."""
    if isinstance(value, bool):
        return "success" if value else "failure"
    text = clean_text(value)
    if text is None:
        return None
    return _OUTCOMES.get(text.lower())


def _parse_by_format(value: Any, fmt: str | None) -> datetime | None:
    """Dispatch to the parser named by ``fmt``, or ``None`` when it fails."""
    if fmt is None or fmt == "iso8601":
        parsed = _parse_iso8601(value)
        if parsed is None and fmt is None:
            # Some feeds put a bare epoch in a field named *timestamp*.
            return _parse_epoch(value)
        return parsed
    if fmt in {"epoch_s", "epoch_ms"}:
        return _parse_epoch(value, milliseconds=fmt == "epoch_ms")
    if fmt.startswith("strptime:"):
        return _parse_strptime(value, fmt.removeprefix("strptime:"))
    raise ValueError(f"unsupported timestamp format {fmt!r}")


def parse_timestamp(
    value: Any,
    *,
    fmt: str | None = None,
    assume_tz: str | None = None,
) -> tuple[int, str] | None:
    """Convert a timestamp to ``(epoch_ms, iso)`` in UTC, or ``None``.

    ``fmt`` is one of:

    - ``None`` or ``"iso8601"``: ISO-8601, with or without a ``Z``.
    - ``"epoch_s"`` or ``"epoch_ms"``: a numeric epoch.
    - ``"strptime:<layout>"``: a :func:`time.strptime` layout.

    A timestamp with no offset is interpreted in ``assume_tz`` when one is given;
    without that it is rejected. Silently assuming UTC would move evidence across
    a day boundary for anyone west of Greenwich, and guessing a local offset is
    exactly the kind of assumption this project refuses to make. The record is
    still stored, with ``ts_ms`` NULL and counted in ``error_count``.
    """
    if value is None or isinstance(value, bool):
        return None
    moment = _parse_by_format(value, fmt)
    if moment is None:
        return None
    if moment.tzinfo is None:
        if assume_tz is None:
            return None
        from app.util.time import localize

        try:
            moment = localize(moment, assume_tz)
        except ValueError:
            return None
    epoch_ms = to_utc_ms(moment)
    return epoch_ms, iso_utc(moment)


def _parse_iso8601(value: Any) -> datetime | None:
    """Parse an ISO-8601 timestamp, tolerating a trailing ``Z`` and no offset."""
    if isinstance(value, datetime):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return _parse_epoch(value)
    text = clean_text(value)
    if text is None:
        return None
    candidate = text.replace("Z", "+00:00") if text.endswith("Z") else text
    try:
        return datetime.fromisoformat(candidate)
    except ValueError:
        pass
    # A space-separated timestamp with no offset is common in exports.
    for layout in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(text, layout)
        except ValueError:
            continue
    return None


def _to_number(value: Any) -> float | None:
    """Best-effort numeric value of a scalar, or ``None``."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = clean_text(value)
    if text is None:
        return None
    try:
        return float(text)
    except ValueError:
        return None


def _parse_epoch(value: Any, *, milliseconds: bool = False) -> datetime | None:
    """Parse a numeric epoch, inferring seconds versus milliseconds by magnitude.

    The threshold is 10^11: epoch milliseconds reach that in 1973 and epoch
    seconds do not until the year 5138, so no realistic timestamp is ambiguous.
    """
    if isinstance(value, datetime):
        return value
    number = _to_number(value)
    if number is None:
        return None
    if not milliseconds and abs(number) >= EPOCH_MS_THRESHOLD:
        milliseconds = True
    seconds = number / 1000 if milliseconds else number
    try:
        return datetime.fromtimestamp(seconds, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None


def _parse_strptime(value: Any, layout: str) -> datetime | None:
    """Parse with an explicit :func:`time.strptime` layout."""
    if isinstance(value, datetime):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return _parse_epoch(value)
    text = clean_text(value)
    if text is None:
        return None
    try:
        return datetime.strptime(text, layout)
    except ValueError:
        return None


def year_from(value: Any) -> int | None:
    """Four-digit year from a filename or timestamp, for syslog year inference."""
    if isinstance(value, date):
        return value.year
    text = clean_text(value)
    if text is None:
        return None
    match = re.search(r"(?<!\d)(19|20)\d{2}(?!\d)", text)
    return int(match.group(0)) if match else None


__all__ = [
    "TRUNCATION_MARKER",
    "canonical_ip",
    "clean_text",
    "normalize_level",
    "normalize_outcome",
    "parse_timestamp",
    "to_int",
    "to_port",
    "truncate",
    "year_from",
]
