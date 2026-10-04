"""Normalization helpers (spec 02 section 2, spec 09 P-12).

These decide what a stored value actually is, so they are tested at their edges:
control characters, IPv6 forms, numeric-looking strings and naive timestamps are
where a normalization bug becomes wrong evidence rather than a visible crash.
"""

from __future__ import annotations

from datetime import UTC, date, datetime

import pytest

from app.ingest.normalize import (
    EPOCH_MS_THRESHOLD,
    MAX_PORT,
    TRUNCATION_MARKER,
    canonical_ip,
    clean_text,
    normalize_level,
    normalize_outcome,
    parse_timestamp,
    to_int,
    to_port,
    truncate,
    year_from,
)

#: 2026-03-01T10:00:00Z, the instant every epoch assertion below refers to.
MOMENT_MS = 1772359200000
MOMENT_ISO = "2026-03-01T10:00:00.000000Z"


class TestCleanText:
    """Control characters go; tab, newline and carriage return stay."""

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("plain", "plain"),
            ("  padded  ", "padded"),
            ("with\x00nul", "withnul"),
            ("bell\x07here", "bellhere"),
            ("escape\x1b[31m", "escape[31m"),
            ("del\x7f", "del"),
        ],
    )
    def test_control_characters_are_removed(self, raw: str, expected: str) -> None:
        assert clean_text(raw) == expected

    @pytest.mark.parametrize("raw", ["tab\there", "line\nbreak", "cr\rreturn"])
    def test_structural_whitespace_survives(self, raw: str) -> None:
        assert clean_text(raw) == raw

    @pytest.mark.parametrize("raw", ["", "   ", "\x00", None])
    def test_empty_becomes_none(self, raw: str | None) -> None:
        assert clean_text(raw) is None

    @pytest.mark.parametrize(("raw", "expected"), [(42, "42"), (1.5, "1.5")])
    def test_non_strings_are_rendered(self, raw: object, expected: str) -> None:
        assert clean_text(raw) == expected

    @pytest.mark.parametrize(("raw", "expected"), [(True, "true"), (False, "false")])
    def test_booleans_are_lowercased_words(self, raw: bool, expected: str) -> None:
        # str(True) is "True", which no log format uses.
        assert clean_text(raw) == expected


class TestTruncate:
    """Clipping must never produce invalid UTF-8."""

    def test_short_text_is_untouched(self) -> None:
        assert truncate("hello", 100) == ("hello", False)

    def test_exactly_at_the_limit_is_untouched(self) -> None:
        assert truncate("hello", 5) == ("hello", False)

    def test_long_text_is_clipped_and_flagged(self) -> None:
        text, clipped = truncate("x" * 500, 100)
        assert clipped is True
        assert text.endswith(TRUNCATION_MARKER)
        assert len(text.encode("utf-8")) <= 100

    def test_clipping_lands_on_a_character_boundary(self) -> None:
        text, clipped = truncate("\U0001f600" * 100, 50)
        assert clipped is True
        assert text.endswith(TRUNCATION_MARKER)
        assert "\ufffd" not in text

    def test_a_budget_smaller_than_the_marker_still_returns_the_marker(self) -> None:
        text, clipped = truncate("abcdefghij", 4)
        assert clipped is True
        assert text == TRUNCATION_MARKER


class TestCanonicalIp:
    """One stored form per address, or nothing at all."""

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("192.168.1.5", "192.168.1.5"),
            ("10.0.0.1", "10.0.0.1"),
            ("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
            ("2001:DB8::1", "2001:db8::1"),
            ("::ffff:10.0.0.1", "::ffff:10.0.0.1"),
            ("::1", "::1"),
        ],
    )
    def test_forms_are_canonicalized(self, raw: str, expected: str) -> None:
        assert canonical_ip(raw) == expected

    @pytest.mark.parametrize(
        "raw",
        [
            "999.1.1.1",
            "not-an-ip",
            "192.168.1",
            "",
            "   ",
            None,
            "1.2.3.4.5",
        ],
    )
    def test_invalid_addresses_are_dropped(self, raw: str | None) -> None:
        assert canonical_ip(raw) is None

    def test_host_port_form_is_accepted(self) -> None:
        # Some firewall logs record "10.0.0.1:44322" in one field.
        assert canonical_ip("10.0.0.1:44322") == "10.0.0.1"

    def test_bracketed_ipv6_with_port_is_accepted(self) -> None:
        assert canonical_ip("[2001:db8::1]:443") == "2001:db8::1"

    def test_scope_id_is_dropped(self) -> None:
        assert canonical_ip("fe80::1%eth0") == "fe80::1"

    def test_plain_ipv6_is_not_mistaken_for_host_port(self) -> None:
        # More than one colon, so this is an address and not "host:port".
        assert canonical_ip("2001:db8::1") == "2001:db8::1"

    def test_control_characters_are_removed_first(self) -> None:
        assert canonical_ip("10.0.0.1\x00") == "10.0.0.1"


class TestToPort:
    """Ports arrive as ints, as strings and as "443/tcp"."""

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [(443, 443), ("443", 443), ("443/tcp", 443), (" 80 ", 80), (0, 0), (MAX_PORT, MAX_PORT)],
    )
    def test_valid_ports(self, raw: object, expected: int) -> None:
        assert to_port(raw) == expected

    @pytest.mark.parametrize(
        "raw", [-1, MAX_PORT + 1, "99999", "abc", "", None, True, False, 443.0, [443]]
    )
    def test_invalid_ports_are_dropped(self, raw: object) -> None:
        assert to_port(raw) is None


class TestToInt:
    """A CSV export turns every column into text, so numbers arrive as strings."""

    @pytest.mark.parametrize(
        ("raw", "expected"), [(4624, 4624), ("4624", 4624), ("443.0", 443), (1.0, 1)]
    )
    def test_valid_integers(self, raw: object, expected: int) -> None:
        assert to_int(raw) == expected

    @pytest.mark.parametrize("raw", [None, True, False, "abc", "1.5", "", [], 3.7])
    def test_invalid_integers_are_dropped(self, raw: object) -> None:
        assert to_int(raw) is None


class TestNormalizeLevel:
    """Syslog words, Windows names and Windows numeric severities."""

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("emerg", "critical"),
            ("alert", "critical"),
            ("crit", "critical"),
            ("critical", "critical"),
            ("err", "error"),
            ("error", "error"),
            ("warning", "warning"),
            ("warn", "warning"),
            ("notice", "info"),
            ("info", "info"),
            ("debug", "debug"),
            ("trace", "debug"),
            ("fatal", "critical"),
            ("information", "info"),
            ("verbose", "debug"),
        ],
    )
    def test_words(self, raw: str, expected: str) -> None:
        assert normalize_level(raw) == expected

    @pytest.mark.parametrize("raw", ["INFO", "Warning", "ERROR", "  Debug  "])
    def test_case_and_padding_are_ignored(self, raw: str) -> None:
        assert normalize_level(raw) is not None

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [(0, "info"), (1, "critical"), (2, "critical"), (3, "error"), (4, "warning"), (5, "info")],
    )
    def test_windows_numeric_severities(self, raw: int, expected: str) -> None:
        assert normalize_level(raw) == expected

    @pytest.mark.parametrize(
        ("raw", "expected"), [("2", "critical"), ("4", "warning"), ("0", "info")]
    )
    def test_numeric_severity_in_a_text_field(self, raw: str, expected: str) -> None:
        assert normalize_level(raw) == expected

    @pytest.mark.parametrize("raw", [None, "", "   ", "banana", 99, True])
    def test_unknown_levels_are_dropped(self, raw: object) -> None:
        assert normalize_level(raw) is None


class TestNormalizeOutcome:
    """Outcome words across EVTX, Wazuh and firewall vocabularies."""

    @pytest.mark.parametrize(
        "raw",
        ["success", "succeeded", "ok", "true", "allow", "allowed", "accept", "accepted"],
    )
    def test_success_words(self, raw: str) -> None:
        assert normalize_outcome(raw) == "success"

    @pytest.mark.parametrize(
        "raw",
        ["failure", "failed", "fail", "false", "deny", "denied", "block", "blocked", "error"],
    )
    def test_failure_words(self, raw: str) -> None:
        assert normalize_outcome(raw) == "failure"

    def test_unknown_is_kept_as_unknown(self) -> None:
        assert normalize_outcome("unknown") == "unknown"

    @pytest.mark.parametrize(("raw", "expected"), [(True, "success"), (False, "failure")])
    def test_booleans(self, raw: bool, expected: str) -> None:
        assert normalize_outcome(raw) == expected

    @pytest.mark.parametrize("raw", [None, "", "banana", 5])
    def test_unrecognized_outcomes_are_dropped(self, raw: object) -> None:
        assert normalize_outcome(raw) is None


class TestParseTimestamp:
    """Everything becomes UTC epoch milliseconds, or nothing at all."""

    def test_iso_with_zulu(self) -> None:
        result = parse_timestamp("2026-03-01T10:00:00Z")
        assert result == (MOMENT_MS, MOMENT_ISO)

    def test_iso_with_explicit_offset_is_converted(self) -> None:
        assert parse_timestamp("2026-03-01T12:00:00+02:00") == (MOMENT_MS, MOMENT_ISO)

    def test_naive_without_assumed_timezone_is_refused(self) -> None:
        # Guessing an offset silently shifts evidence across a day boundary.
        assert parse_timestamp("2026-03-01T10:00:00") is None

    def test_naive_with_assumed_timezone_is_localized(self) -> None:
        assert parse_timestamp("2026-03-01T10:00:00", assume_tz="UTC") == (MOMENT_MS, MOMENT_ISO)

    def test_assumed_timezone_shifts_the_instant(self) -> None:
        # 10:00 in Amsterdam is 09:00 UTC, so the stored instant moves.
        result = parse_timestamp("2026-03-01T10:00:00", assume_tz="Europe/Amsterdam")
        assert result is not None
        assert result[1] == "2026-03-01T09:00:00.000000Z"

    def test_utc_is_resolved_without_a_timezone_database(self) -> None:
        # UTC is a constant offset, not a zone: it must not depend on tzdata.
        assert parse_timestamp("2026-03-01T10:00:00", assume_tz="UTC") is not None

    def test_an_invalid_assumed_timezone_is_refused(self) -> None:
        assert parse_timestamp("2026-03-01T10:00:00", assume_tz="Not/AZone") is None

    def test_epoch_seconds(self) -> None:
        assert parse_timestamp(1772359200, fmt="epoch_s") == (MOMENT_MS, MOMENT_ISO)

    def test_epoch_milliseconds(self) -> None:
        assert parse_timestamp(1772359200000, fmt="epoch_ms") == (MOMENT_MS, MOMENT_ISO)

    def test_epoch_seconds_are_inferred_by_magnitude(self) -> None:
        # No format given: a value past the threshold is milliseconds.
        assert parse_timestamp(1772359200000) == (MOMENT_MS, MOMENT_ISO)

    def test_strptime_layout(self) -> None:
        result = parse_timestamp(
            "01/Mar/2026:10:00:00", fmt="strptime:%d/%b/%Y:%H:%M:%S", assume_tz="UTC"
        )
        assert result == (MOMENT_MS, MOMENT_ISO)

    def test_strptime_needs_a_timezone_for_naive_input(self) -> None:
        assert parse_timestamp("01/Mar/2026:10:00:00", fmt="strptime:%d/%b/%Y:%H:%M:%S") is None

    def test_datetime_passes_through(self) -> None:
        moment = datetime(2026, 3, 1, 10, 0, tzinfo=UTC)
        result = parse_timestamp(moment)
        assert result is not None
        assert result[0] == 1772359200000

    def test_naive_datetime_needs_a_timezone(self) -> None:
        # Naive on purpose: this is the input the refusal exists for.
        assert parse_timestamp(datetime(2026, 3, 1, 10, 0)) is None  # noqa: DTZ001

    def test_space_separated_without_offset(self) -> None:
        result = parse_timestamp("2026-03-01 10:00:00", assume_tz="UTC")
        assert result is not None
        assert result[0] == 1772359200000

    def test_space_separated_with_fraction(self) -> None:
        result = parse_timestamp("2026-03-01 10:00:00.500", assume_tz="UTC")
        assert result is not None
        assert result[0] == 1772359200500

    @pytest.mark.parametrize(
        "raw", [None, "", "not a date", True, False, [], "2026-13-45T99:99:99Z"]
    )
    def test_unparseable_values_return_none(self, raw: object) -> None:
        assert parse_timestamp(raw) is None

    def test_an_out_of_range_epoch_returns_none(self) -> None:
        assert parse_timestamp(10**30) is None

    def test_an_unsupported_format_is_a_programming_error(self) -> None:
        with pytest.raises(ValueError, match="unsupported timestamp format"):
            parse_timestamp("2026-03-01T10:00:00Z", fmt="banana")

    def test_numeric_string_epoch_is_accepted(self) -> None:
        result = parse_timestamp("1772359200", fmt="epoch_s")
        assert result is not None
        assert result[0] == 1772359200000

    def test_threshold_is_far_from_any_real_timestamp(self) -> None:
        # Documented invariant: 10^11 is seconds only in the year 5138.
        assert EPOCH_MS_THRESHOLD == 100_000_000_000


class TestYearFrom:
    """A four-digit year, for syslog records that omit one."""

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("syslog-2026.log", 2026),
            ("2026-03-01", 2026),
            ("Mar  1 2026", 2026),
            ("1999", 1999),
        ],
    )
    def test_year_is_extracted(self, raw: str, expected: int) -> None:
        assert year_from(raw) == expected

    @pytest.mark.parametrize(
        "raw", ["Mar  1", "no digits", "", None, "3000", "12345", "1899", "2199"]
    )
    def test_absent_or_implausible_year_returns_none(self, raw: str | None) -> None:
        assert year_from(raw) is None

    def test_date_objects(self) -> None:
        assert year_from(date(2026, 3, 1)) == 2026

    def test_datetime_objects(self) -> None:
        assert year_from(datetime(2019, 1, 1, tzinfo=UTC)) == 2019

    def test_a_year_embedded_in_longer_digits_is_ignored(self) -> None:
        assert year_from("id-12026-thing") is None
