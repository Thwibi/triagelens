"""UTC time helpers.

Spec 00 section 8 rule 6: every timestamp is stored as UTC epoch milliseconds
plus an ISO-8601 string. Spec 02 section 5 fixes the string format as UTC with a
``Z`` suffix. Everything here returns timezone-aware UTC datetimes so a naive
value can never reach the database.
"""

from __future__ import annotations

from datetime import UTC, datetime

#: ISO-8601 in the database and on the wire: UTC, milliseconds, ``Z`` suffix.
ISO_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


def utc_now() -> datetime:
    """Current time as an aware UTC datetime."""
    return datetime.now(UTC)


def utc_now_ms() -> int:
    """Current time as UTC epoch milliseconds."""
    return to_utc_ms(utc_now())


def to_utc(value: datetime) -> datetime:
    """Convert an aware datetime to UTC.

    Raises:
        ValueError: if ``value`` is naive. Interpret ambiguous local times with
            :func:`localize` first, which applies the case timezone and fold
            rules (spec 09 P-05).
    """
    if value.tzinfo is None:
        raise ValueError("naive datetime; localize it with an explicit timezone first")
    return value.astimezone(UTC)


def to_utc_ms(value: datetime) -> int:
    """UTC epoch milliseconds for an aware datetime."""
    return int(to_utc(value).timestamp() * 1000)


def from_utc_ms(value: int) -> datetime:
    """Aware UTC datetime for UTC epoch milliseconds."""
    return datetime.fromtimestamp(value / 1000, tz=UTC)


def iso_utc(value: datetime) -> str:
    """Render an aware datetime as ``YYYY-MM-DDTHH:MM:SS.sssZ``."""
    return to_utc(value).strftime(ISO_FORMAT)


def iso_from_ms(value: int | None) -> str | None:
    """Render epoch milliseconds as an ISO-8601 string, ``None`` passthrough."""
    if value is None:
        return None
    return iso_utc(from_utc_ms(value))


def utc_now_iso() -> str:
    """Current time as an ISO-8601 UTC string."""
    return iso_utc(utc_now())


def localize(
    naive: datetime,
    tz: str,
    *,
    ambiguous: str = "raise",
) -> datetime:
    """Attach ``tz`` to a naive datetime and convert to UTC.

    ``ambiguous`` is ``raise`` (the default, so a DST fold is never resolved
    silently), ``earlier`` or ``later`` for the two readings of a repeated hour.
    """
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

    try:
        zone = ZoneInfo(tz)
    except ZoneInfoNotFoundError as exc:
        raise ValueError(f"unknown timezone {tz!r}") from exc
    if ambiguous not in {"raise", "earlier", "later"}:
        raise ValueError("ambiguous must be 'raise', 'earlier' or 'later'")
    earlier = naive.replace(tzinfo=zone, fold=0)
    later = naive.replace(tzinfo=zone, fold=1)
    # A local time is ambiguous (repeated hour) or imaginary (spring-forward
    # gap) exactly when the two folds disagree about the UTC offset.
    is_ambiguous = earlier.utcoffset() != later.utcoffset()
    if ambiguous == "raise" and is_ambiguous:
        raise ValueError(
            f"{naive.isoformat()} is ambiguous or nonexistent in {tz}; "
            "pass ambiguous='earlier' or 'later'"
        )
    return (earlier if ambiguous == "earlier" else later).astimezone(UTC)


__all__ = [
    "ISO_FORMAT",
    "from_utc_ms",
    "iso_from_ms",
    "iso_utc",
    "localize",
    "to_utc",
    "to_utc_ms",
    "utc_now",
    "utc_now_iso",
    "utc_now_ms",
]
