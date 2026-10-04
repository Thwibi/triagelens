"""The normalized event shape and its insert payload (spec 02 section 1).

The invariant worth protecting is that a parser cannot bypass normalization:
``__post_init__`` cleans text, coerces integers, lowercases the protocol and
rebuilds ``ts_iso`` from ``ts_ms`` rather than trusting whatever arrived.
"""

from __future__ import annotations

import json
import re
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from app.ingest.events import EVENT_COLUMNS, NormalizedEvent
from app.ingest.normalize import TRUNCATION_MARKER


def make_event(**overrides: object) -> NormalizedEvent:
    """A minimal valid event, with overrides applied."""
    base: dict[str, object] = {
        "case_id": "case-1",
        "source_id": "src-1",
        "record_ref": "line-7",
        "log_type": "syslog",
        "raw": "Mar  1 10:00:00 host sshd[1]: accepted",
    }
    base.update(overrides)
    return NormalizedEvent(**base)  # type: ignore[arg-type]


class TestSchema:
    """The dataclass and the table must not drift apart."""

    def test_columns_match_the_events_table(self) -> None:
        migration = Path(__file__).resolve().parents[1] / "migrations" / "0001_init.sql"
        sql = migration.read_text(encoding="utf-8")
        table = sql.split("CREATE TABLE events", 1)[1].split(");", 1)[0]
        # Columns are packed several per line, so match on the declared type
        # rather than one column per line. The trailing id is the database's.
        declared = re.findall(r"([a-z_][a-z0-9_]*)\s+(?:TEXT|INTEGER|REAL)\b", table)
        assert declared == ["id", *EVENT_COLUMNS, "fields_json", "raw"]

    def test_values_are_in_column_order(self) -> None:
        event = make_event(host="ws-01", level="info")
        row = event.row()
        assert len(row) == len(EVENT_COLUMNS)
        assert row[EVENT_COLUMNS.index("host")] == "ws-01"
        assert row[EVENT_COLUMNS.index("level")] == "info"

    def test_fields_json_and_raw_follow_the_columns(self) -> None:
        event = make_event(fields_json={"b": 2, "a": 1}, raw="the record")
        values = event.values()
        assert len(values) == len(EVENT_COLUMNS) + 2
        assert values[-2] == '{"a": 1, "b": 2}'
        assert values[-1] == "the record"

    def test_insert_sql_binds_one_placeholder_per_column(self) -> None:
        event = make_event()
        sql = event.insert_sql()
        assert sql.count("?") == len(event.values())
        # No value is ever interpolated into the statement text.
        assert "case-1" not in sql

    def test_insert_sql_names_every_column(self) -> None:
        sql = make_event().insert_sql()
        for column in (*EVENT_COLUMNS, "fields_json", "raw"):
            assert column in sql

    def test_raw_is_bound_because_the_table_requires_it(self) -> None:
        # events.raw is NOT NULL, so leaving it out breaks every insert.
        assert re.search(r"\braw\b", make_event().insert_sql())


class TestPostInitNormalization:
    """A parser cannot smuggle an unclean value into a column."""

    def test_text_fields_are_cleaned(self) -> None:
        event = make_event(host="  ws\x00-01  ", user_name="root\x07")
        assert event.host == "ws-01"
        assert event.user_name == "root"

    def test_blank_text_becomes_null(self) -> None:
        assert make_event(host="   ").host is None

    def test_integer_fields_are_coerced(self) -> None:
        event = make_event(event_id="4624", src_port="443", http_status="200")
        assert event.event_id == 4624
        assert event.src_port == 443
        assert event.http_status == 200

    def test_unparsable_integers_raise_rather_than_storing_a_wrong_number(self) -> None:
        with pytest.raises((TypeError, ValueError)):
            make_event(event_id="banana")

    def test_none_integer_fields_stay_none(self) -> None:
        event = make_event()
        assert event.event_id is None
        assert event.src_port is None

    def test_protocol_is_lowercased(self) -> None:
        assert make_event(protocol="TCP").protocol == "tcp"

    def test_protocol_of_none_stays_none(self) -> None:
        assert make_event().protocol is None

    def test_ts_iso_is_rebuilt_from_ts_ms(self) -> None:
        # A parser-supplied ts_iso is ignored: two representations of one
        # instant must never disagree.
        event = make_event(ts_ms=1772359200000, ts_iso="1999-01-01T00:00:00Z")
        assert event.ts_iso == "2026-03-01T10:00:00.000000Z"

    def test_ts_iso_is_none_without_a_timestamp(self) -> None:
        event = make_event(ts_ms=None, ts_iso="2026-03-01T10:00:00Z")
        assert event.ts_iso is None


class TestHasTimestamp:
    """A record without a usable time is stored and reported, never dropped."""

    def test_true_with_a_timestamp(self) -> None:
        assert make_event(ts_ms=1772359200000).has_timestamp is True

    def test_false_without_a_timestamp(self) -> None:
        assert make_event().has_timestamp is False


class TestSplitUrl:
    """Path and query are split once, on the first question mark."""

    def test_query_is_split_off(self) -> None:
        event = make_event(url="https://evil.test/a/b?x=1&y=2")
        event.split_url()
        assert event.url_path == "https://evil.test/a/b"
        assert event.url_query == "x=1&y=2"

    def test_url_without_a_query(self) -> None:
        event = make_event(url="https://evil.test/a/b")
        event.split_url()
        assert event.url_path == "https://evil.test/a/b"
        assert event.url_query is None

    def test_empty_query_marker(self) -> None:
        event = make_event(url="https://evil.test/a?")
        event.split_url()
        assert event.url_path == "https://evil.test/a"
        assert event.url_query is None

    def test_existing_path_is_not_overwritten(self) -> None:
        event = make_event(url="https://a.test/x?y=1", url_path="/already")
        event.split_url()
        assert event.url_path == "/already"

    def test_no_url_is_a_no_op(self) -> None:
        event = make_event()
        event.split_url()
        assert event.url_path is None


class TestClipRaw:
    """One enormous line must not blow up storage."""

    def test_short_raw_is_untouched(self) -> None:
        event = make_event(raw="short")
        assert event.clip_raw(1000) is False
        assert event.raw == "short"

    def test_long_raw_is_clipped(self) -> None:
        event = make_event(raw="x" * 5000)
        assert event.clip_raw(1000) is True
        assert event.raw.endswith(TRUNCATION_MARKER)
        assert len(event.raw.encode("utf-8")) <= 1000

    def test_clipping_is_idempotent_in_length(self) -> None:
        event = make_event(raw="x" * 5000)
        event.clip_raw(1000)
        first = len(event.raw)
        event.clip_raw(1000)
        assert len(event.raw) == first


class TestSerialization:
    """Everything stored or exported goes through one of these."""

    def test_as_json_is_deterministic_and_sorted(self) -> None:
        event = make_event(fields_json={"z": 1, "a": {"n": 2}, "m": [1, 2]})
        assert event.as_json() == '{"a": {"n": 2}, "m": [1, 2], "z": 1}'

    def test_as_json_renders_odd_values(self) -> None:
        # A parser may hand over a type JSON cannot encode; it must not explode.
        assert json.loads(make_event(fields_json={"when": object()}).as_json()) is not None

    def test_as_json_keeps_unicode_readable(self) -> None:
        assert "\\u" not in make_event(fields_json={"host": "café"}).as_json()

    def test_to_dict_carries_every_field(self) -> None:
        payload = make_event(host="ws-01", ts_ms=1772359200000).to_dict()
        for column in EVENT_COLUMNS:
            assert column in payload
        assert payload["host"] == "ws-01"

    def test_to_dict_copies_fields_json(self) -> None:
        event = make_event(fields_json={"a": 1})
        payload = event.to_dict()
        payload["fields_json"]["a"] = 2
        assert event.fields_json == {"a": 1}

    def test_to_dict_reports_truncation(self) -> None:
        event = make_event(raw=f"x{TRUNCATION_MARKER}")
        assert event.to_dict()["raw_truncated"] is True

    def test_to_dict_reports_an_intact_raw(self) -> None:
        assert make_event(raw="plain").to_dict()["raw_truncated"] is False

    def test_fields_json_defaults_to_empty_not_shared(self) -> None:
        first = make_event()
        second = make_event()
        first.fields_json["x"] = 1
        assert second.fields_json == {}

    @pytest.mark.parametrize("column", EVENT_COLUMNS)
    def test_every_column_is_a_real_attribute(self, column: str) -> None:
        # Guards against a column added to the tuple but not the dataclass.
        assert hasattr(make_event(), column)

    def test_record_ref_is_required(self) -> None:
        with pytest.raises(TypeError):
            NormalizedEvent(  # type: ignore[call-arg]
                case_id="c", source_id="s", log_type="syslog", raw="x"
            )

    def test_event_id_and_status_stay_integers(self) -> None:
        event = make_event(event_id=4624, http_status=200, bytes_out=1024)
        assert (event.event_id, event.http_status, event.bytes_out) == (4624, 200, 1024)

    def test_insert_sql_is_a_single_statement(self) -> None:
        sql = make_event().insert_sql()
        assert sql.startswith("INSERT INTO events (")
        assert re.fullmatch(r"INSERT INTO events \([^)]+\) VALUES \((?:\?, )*\?\)", sql)


class TestAgainstRealSchema:
    """Run the insert against the migration, not against a mock.

    The unit tests above can all pass while the statement is unusable: a column
    the dataclass forgot, or a NOT NULL column it never binds, only shows up when
    the real table rejects it.
    """

    @staticmethod
    def _connection() -> sqlite3.Connection:
        sql = (Path(__file__).resolve().parents[1] / "migrations" / "0001_init.sql").read_text(
            encoding="utf-8"
        )
        connection = sqlite3.connect(":memory:")
        connection.row_factory = sqlite3.Row
        # The FTS5 virtual table is irrelevant here and is not always compiled in.
        connection.executescript(sql.split("CREATE VIRTUAL TABLE events_fts")[0])
        connection.execute(
            "INSERT INTO cases (id, name, created_at, updated_at) VALUES (?, ?, ?, ?)",
            ("case-1", "Case", "2026-03-01T00:00:00Z", "2026-03-01T00:00:00Z"),
        )
        connection.execute(
            "INSERT INTO sources (id, case_id, filename, stored_path, size_bytes, sha256,"
            " status, ingested_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("src-1", "case-1", "a.log", "/tmp/a.log", 5, "0" * 64, "done", "2026-03-01T00:00:00Z"),
        )
        return connection

    def test_an_event_round_trips_into_the_real_table(self) -> None:
        event = make_event(
            ts_ms=1772359200000,
            host="ws-01",
            src_ip="10.0.0.1",
            fields_json={"extra": 1},
        )
        with closing(self._connection()) as connection:
            connection.execute(event.insert_sql(), event.values())
            row = connection.execute(
                "SELECT * FROM events WHERE case_id = ?", ("case-1",)
            ).fetchone()
        assert row["raw"] == event.raw
        assert row["ts_iso"] == "2026-03-01T10:00:00.000000Z"
        assert row["ts_ms"] == 1772359200000
        assert row["src_ip"] == "10.0.0.1"
        assert json.loads(row["fields_json"]) == {"extra": 1}

    def test_raw_is_stored_untruncated_when_it_fits(self) -> None:
        with closing(self._connection()) as connection:
            connection.execute(
                make_event(raw="x" * 10_000).insert_sql(), make_event(raw="x" * 10_000).values()
            )
            stored = connection.execute("SELECT length(raw) AS n FROM events").fetchone()["n"]
        assert stored == 10_000

    def test_a_null_optional_column_round_trips_as_null(self) -> None:
        with closing(self._connection()) as connection:
            connection.execute(make_event().insert_sql(), make_event().values())
            row = connection.execute("SELECT host, event_id, url FROM events").fetchone()
        assert row["host"] is None
        assert row["event_id"] is None
        assert row["url"] is None

    def test_two_events_from_one_source_both_land(self) -> None:
        with closing(self._connection()) as connection:
            for index in range(2):
                event = make_event(record_ref=f"line-{index}", raw=f"record {index}")
                connection.execute(event.insert_sql(), event.values())
            count = connection.execute("SELECT count(*) AS n FROM events").fetchone()["n"]
        assert count == 2
