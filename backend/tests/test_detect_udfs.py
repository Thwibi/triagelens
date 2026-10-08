"""REGEXP and cidr_match user functions (spec 04 section 2)."""

from __future__ import annotations

import sqlite3

import pytest

from app.detect.udfs import cidr_match, regexp, register_udfs

_GOOD_CELLAR = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"


def _connection() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:")
    register_udfs(connection)
    return connection


class TestRegexp:
    def test_a_full_match_is_true(self) -> None:
        assert regexp(r"bash.+/sh", "bash -c /bin/sh") is True

    def test_a_partial_match_is_false(self) -> None:
        # Sigma's |re modifier matches the whole value (spec 04), unlike search().
        assert regexp(r"mimikatz", "x mimikatz y") is False

    def test_no_match_is_false(self) -> None:
        assert regexp(r"bash.+/sh", "zsh -c /bin/sh") is False

    def test_an_invalid_pattern_is_false(self) -> None:
        assert regexp("[", "anything") is False

    def test_a_none_value_is_false(self) -> None:
        assert regexp(".*", None) is False

    def test_a_nested_quantifier_pattern_is_rejected(self) -> None:
        """Catastrophic backtracking stays a compile-time no, not a stall."""
        assert regexp(r"(a+)+$", _GOOD_CELLAR) is False

    def test_a_quantified_backreference_is_rejected(self) -> None:
        assert regexp(r"(\w+)\1+", "xxxx") is False

    def test_a_huge_value_is_false(self) -> None:
        assert regexp("x", "x" * 300_000) is False

    def test_an_empty_pattern_is_false(self) -> None:
        assert regexp("", "anything") is False

    def test_unicode_patterns_work(self) -> None:
        assert regexp("Камбер", "Камбер") is True
        assert regexp("Камбер", "какая-то другая строка") is False


class TestCidr:
    @pytest.mark.parametrize(
        ("value", "network", "expected"),
        [
            ("10.1.2.3", "10.0.0.0/8", True),
            ("192.168.1.1", "10.0.0.0/8", False),
            ("10.0.0.0", "10.0.0.0/8", True),  # strict=False host bits allowed
            ("2001:db8::1", "2001:db8::/32", True),
            ("fe80::1%eth0", "fe80::/64", True),  # zone ids are link scope
            ("not-an-ip", "10.0.0.0/8", False),
            ("1.2.3.4", "not-a-network", False),
            (None, "10.0.0.0/8", False),
            ("  10.1.2.3 ", "10.0.0.0/8", True),
        ],
    )
    def test_membership(self, value: object, network: str, expected: bool) -> None:
        assert cidr_match(value, network) is expected


class TestRegisteredFunctions:
    def test_regexp_works_through_the_sql_operator(self) -> None:
        connection = _connection()
        try:
            row = connection.execute("SELECT 'foo bar' REGEXP 'f.+r'").fetchone()
            assert row[0] == 1
            row = connection.execute("SELECT 'foo bar' REGEXP 'zzz'").fetchone()
            assert row[0] == 0
        finally:
            connection.close()

    def test_cidr_match_works_from_sql(self) -> None:
        connection = _connection()
        try:
            row = connection.execute(
                "SELECT cidr_match('10.2.3.4', '10.0.0.0/8'), cidr_match('8.8.8.8', '10.0.0.0/8')"
            ).fetchone()
            assert row[0] == 1
            assert row[1] == 0
        finally:
            connection.close()

    def test_a_garbage_regexp_from_sql_is_false_not_an_error(self) -> None:
        connection = _connection()
        try:
            row = connection.execute("SELECT 'x' REGEXP '['").fetchone()
            assert row[0] == 0
        finally:
            connection.close()
