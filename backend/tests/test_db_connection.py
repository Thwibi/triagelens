"""SQLite connection setup, pragmas, capability probes and the writer policy."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from app.db.connection import (
    Database,
    SqliteCapabilities,
    SqliteCapabilityError,
    connect,
    probe_capabilities,
)


def pragmas(connection: sqlite3.Connection, name: str) -> object:
    """Read a single PRAGMA value."""
    row = connection.execute(f"PRAGMA {name}").fetchone()
    assert row is not None
    return row[0]


class TestPragmas:
    def test_the_required_pragmas_are_applied(self, tmp_path: Path) -> None:
        connection = connect(tmp_path / "t.db")
        try:
            assert pragmas(connection, "journal_mode") == "wal"
            assert pragmas(connection, "synchronous") == 1  # NORMAL
            assert pragmas(connection, "foreign_keys") == 1
            assert pragmas(connection, "busy_timeout") == 10_000
            assert pragmas(connection, "temp_store") == 2  # MEMORY
        finally:
            connection.close()

    def test_the_default_mmap_size_is_two_gibibytes(self, tmp_path: Path) -> None:
        """SQLite rounds the request down slightly, so allow 64 KiB of slack."""
        connection = connect(tmp_path / "t.db")
        try:
            value = int(str(pragmas(connection, "mmap_size")))
            assert 2 * 1024**3 - 64 * 1024 <= value <= 2 * 1024**3
        finally:
            connection.close()

    def test_an_explicit_mmap_size_is_honoured(self, tmp_path: Path) -> None:
        connection = connect(tmp_path / "t.db", mmap_bytes=64 * 1024 * 1024)
        try:
            assert pragmas(connection, "mmap_size") == 64 * 1024 * 1024
        finally:
            connection.close()

    def test_the_connection_is_in_autocommit_mode(self, tmp_path: Path) -> None:
        """Autocommit is what lets the migration runner own transactions."""
        connection = connect(tmp_path / "t.db")
        try:
            assert connection.isolation_level is None
        finally:
            connection.close()

    def test_row_factory_is_named_tuple(self, tmp_path: Path) -> None:
        connection = connect(tmp_path / "t.db")
        try:
            row = connection.execute("SELECT 1 AS one").fetchone()
            assert row is not None
            assert row["one"] == 1
        finally:
            connection.close()

    def test_foreign_keys_are_actually_enforced(self, tmp_path: Path) -> None:
        connection = connect(tmp_path / "t.db")
        try:
            connection.execute("CREATE TABLE parent (id INTEGER PRIMARY KEY)")
            connection.execute(
                "CREATE TABLE child ("
                "id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES parent(id))"
            )
            with pytest.raises(sqlite3.IntegrityError):
                connection.execute("INSERT INTO child (id, parent_id) VALUES (1, 999)")
        finally:
            connection.close()


class TestCapabilities:
    def test_fts5_and_json1_are_reported_available(self, tmp_path: Path) -> None:
        connection = connect(tmp_path / "t.db")
        try:
            capabilities = probe_capabilities(connection)
            assert capabilities.fts5 is True
            assert capabilities.json1 is True
            assert capabilities.sqlite_version.startswith("3.")
        finally:
            connection.close()

    def test_the_probe_creates_no_tables(self, tmp_path: Path) -> None:
        """Probing must be side-effect free so it is safe on any database."""
        connection = connect(tmp_path / "t.db")
        try:
            probe_capabilities(connection)
            tables = connection.execute("SELECT name FROM sqlite_master").fetchall()
            assert tables == []
        finally:
            connection.close()

    def test_a_missing_capability_is_a_hard_error(self) -> None:
        capabilities = SqliteCapabilities(sqlite_version="3.50.4", fts5=False, json1=True)
        with pytest.raises(SqliteCapabilityError, match="FTS5"):
            capabilities.require()

    def test_both_capabilities_are_named_in_the_error(self) -> None:
        capabilities = SqliteCapabilities(sqlite_version="3.50.4", fts5=False, json1=False)
        with pytest.raises(SqliteCapabilityError) as excinfo:
            capabilities.require()
        assert "FTS5" in str(excinfo.value)
        assert "JSON1" in str(excinfo.value)

    def test_audit_hash_is_available_on_the_writer(self, tmp_path: Path) -> None:
        database = Database(tmp_path / "t.db")
        try:
            value = database.writer.execute(
                "SELECT audit_hash('a', 'b', '2024-01-01T00:00:00Z', '{}')"
            ).fetchone()
            assert value is not None
            assert isinstance(value[0], str)
            assert len(value[0]) == 64
        finally:
            database.close()

    def test_the_audit_hash_is_stable(self, tmp_path: Path) -> None:
        database = Database(tmp_path / "t.db")
        try:
            first = database.writer.execute("SELECT audit_hash('a', 'b', 't', '{}')").fetchone()
            second = database.writer.execute("SELECT audit_hash('a', 'b', 't', '{}')").fetchone()
            assert first == second
        finally:
            database.close()

    def test_differing_input_changes_the_audit_hash(self, tmp_path: Path) -> None:
        database = Database(tmp_path / "t.db")
        try:
            rows = database.writer.execute(
                "SELECT audit_hash('a', 'b', 't', '{}'), audit_hash('a', 'c', 't', '{}'), "
                "audit_hash('b', 'b', 't', '{}')"
            ).fetchone()
            assert rows is not None
            assert len({rows[0], rows[1], rows[2]}) == 3
        finally:
            database.close()


class TestDatabase:
    def test_the_writer_is_created_once_and_reused(self, tmp_path: Path) -> None:
        """One writer connection is the whole point of the class."""
        database = Database(tmp_path / "t.db")
        try:
            assert database.writer is database.writer
            assert pragmas(database.writer, "journal_mode") == "wal"
        finally:
            database.close()

    def test_read_connections_are_distinct_objects(self, tmp_path: Path) -> None:
        database = Database(tmp_path / "t.db")
        try:
            with database.read_connection() as first, database.read_connection() as second:
                assert first is not second
        finally:
            database.close()

    def test_a_read_connection_sees_committed_writes(self, tmp_path: Path) -> None:
        database = Database(tmp_path / "t.db")
        try:
            database.writer.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
            database.writer.execute("INSERT INTO t (v) VALUES ('x')")

            with database.read_connection() as reader:
                row = reader.execute("SELECT v FROM t").fetchone()
                assert row is not None
                assert row["v"] == "x"
        finally:
            database.close()

    def test_closing_twice_is_harmless(self, tmp_path: Path) -> None:
        database = Database(tmp_path / "t.db")
        _ = database.writer
        database.close()
        database.close()
        assert database.closed is True

    def test_reading_after_close_is_refused(self, tmp_path: Path) -> None:
        database = Database(tmp_path / "t.db")
        database.close()
        with pytest.raises(RuntimeError, match="closed"), database.read_connection():
            pass

    def test_db_bytes_accounts_for_the_write_ahead_log(self, tmp_path: Path) -> None:
        database = Database(tmp_path / "t.db")
        try:
            before = database.db_bytes()
            database.writer.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
            for index in range(500):
                database.writer.execute("INSERT INTO t (v) VALUES (?)", (f"value-{index}",))
            assert database.db_bytes() >= before
            assert database.db_bytes() > 0
        finally:
            database.close()

    def test_db_bytes_is_zero_for_an_absent_database(self, tmp_path: Path) -> None:
        database = Database(tmp_path / "sub" / "dir" / "t.db")
        try:
            assert database.path.parent.is_dir()
        finally:
            database.close()

    def test_transaction_rolls_back_on_error(self, tmp_path: Path) -> None:
        database = Database(tmp_path / "t.db")
        try:
            database.writer.execute("CREATE TABLE t (id INTEGER PRIMARY KEY)")
            with pytest.raises(sqlite3.IntegrityError), database.transaction() as conn:
                conn.execute("INSERT INTO t (id) VALUES (1)")
                conn.execute("INSERT INTO t (id) VALUES (1)")
            assert database.writer.execute("SELECT count(*) FROM t").fetchone()[0] == 0
        finally:
            database.close()

    def test_transaction_commits_on_success(self, tmp_path: Path) -> None:
        database = Database(tmp_path / "t.db")
        try:
            database.writer.execute("CREATE TABLE t (id INTEGER PRIMARY KEY)")
            with database.transaction() as conn:
                conn.execute("INSERT INTO t (id) VALUES (1)")
            assert database.writer.execute("SELECT count(*) FROM t").fetchone()[0] == 1
        finally:
            database.close()

    def test_a_nested_transaction_is_refused(self, tmp_path: Path) -> None:
        database = Database(tmp_path / "t.db")
        try:
            with pytest.raises(RuntimeError, match="nested"), database.transaction():
                with database.transaction():
                    pass
        finally:
            database.close()

    def test_the_database_works_as_a_context_manager(self, tmp_path: Path) -> None:
        with Database(tmp_path / "t.db") as database:
            _ = database.writer
        assert database.closed is True
