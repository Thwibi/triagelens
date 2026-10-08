"""Migration discovery, atomicity, idempotency and forward-only enforcement."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.db.connection import Database, SqliteTooNewError
from app.db.migrations import (
    Migration,
    MigrationError,
    applied_versions,
    apply_migrations,
    discover_migrations,
    iter_table_names,
    latest_known_version,
    pending_migrations,
    split_sql_statements,
)

BACKEND_ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS_DIR = BACKEND_ROOT / "migrations"


class TestStatementSplitting:
    def test_a_simple_script_splits_on_semicolons(self) -> None:
        script = "CREATE TABLE a (id INTEGER);\nCREATE TABLE b (id INTEGER);\n"
        assert split_sql_statements(script) == [
            "CREATE TABLE a (id INTEGER);",
            "CREATE TABLE b (id INTEGER);",
        ]

    def test_a_semicolon_inside_a_string_is_not_a_separator(self) -> None:
        script = "INSERT INTO t (v) VALUES ('a;b');"
        assert split_sql_statements(script) == ["INSERT INTO t (v) VALUES ('a;b');"]

    def test_a_trigger_body_stays_in_one_statement(self) -> None:
        """The reason ``sqlite3.complete_statement`` is used instead of ``split(';')``."""
        script = (
            "CREATE TRIGGER t_audit BEFORE DELETE ON audit_log\n"
            "BEGIN\n"
            "  SELECT RAISE(ABORT, 'append only');\n"
            "END;\n"
        )
        statements = split_sql_statements(script)
        assert len(statements) == 1
        assert "END" in statements[0]

    def test_a_leading_comment_travels_with_its_statement(self) -> None:
        """Comments are preserved so the applied SQL matches the file."""
        statements = split_sql_statements("-- a; comment\nSELECT 1;\n")
        assert len(statements) == 1
        assert statements[0].startswith("-- a; comment")

    def test_a_trailing_comment_is_not_mistaken_for_sql(self) -> None:
        """A comment-only file must look empty, not like an unterminated statement."""
        assert split_sql_statements("SELECT 1;\n-- trailing note\n") == ["SELECT 1;"]
        assert split_sql_statements("-- only a comment\n") == []
        assert split_sql_statements("-- a\n-- b\n") == []

    def test_a_double_dash_inside_a_string_is_not_a_comment(self) -> None:
        assert split_sql_statements("SELECT '--not a comment'") == ["SELECT '--not a comment'"]

    def test_an_empty_script_yields_nothing(self) -> None:
        assert split_sql_statements("") == []
        assert split_sql_statements("   \n\n") == []

    def test_trailing_content_without_a_semicolon_is_kept(self) -> None:
        """Returning the tail makes the caller fail on it instead of ignoring it."""
        assert split_sql_statements("SELECT 1") == ["SELECT 1"]


class TestDiscovery:
    def test_the_shipped_migrations_are_discovered_in_order(self) -> None:
        migrations = discover_migrations(MIGRATIONS_DIR)
        assert [entry.version for entry in migrations] == [1, 2]
        assert migrations[0].name == "init"
        assert migrations[0].label == "0001_init"

    def test_a_non_numeric_filename_is_rejected(self, tmp_path: Path) -> None:
        (tmp_path / "init.sql").write_text("SELECT 1;", encoding="utf-8")
        with pytest.raises(MigrationError, match="init.sql"):
            discover_migrations(tmp_path)

    def test_a_duplicate_version_is_rejected(self, tmp_path: Path) -> None:
        (tmp_path / "0001_a.sql").write_text("SELECT 1;", encoding="utf-8")
        (tmp_path / "0001_b.sql").write_text("SELECT 2;", encoding="utf-8")
        with pytest.raises(MigrationError, match="duplicate"):
            discover_migrations(tmp_path)

    def test_a_gap_in_the_version_sequence_is_allowed(self, tmp_path: Path) -> None:
        """Only uniqueness is required, so a partial migration set stays loadable."""
        (tmp_path / "0001_a.sql").write_text("SELECT 1;", encoding="utf-8")
        (tmp_path / "0003_c.sql").write_text("SELECT 3;", encoding="utf-8")
        assert [entry.version for entry in discover_migrations(tmp_path)] == [1, 3]

    def test_versions_come_back_in_ascending_order(self, tmp_path: Path) -> None:
        (tmp_path / "0002_b.sql").write_text("SELECT 2;", encoding="utf-8")
        (tmp_path / "0001_a.sql").write_text("SELECT 1;", encoding="utf-8")
        assert [entry.version for entry in discover_migrations(tmp_path)] == [1, 2]

    def test_an_empty_directory_is_valid(self, tmp_path: Path) -> None:
        assert discover_migrations(tmp_path) == []

    def test_non_sql_files_are_ignored(self, tmp_path: Path) -> None:
        (tmp_path / "0001_a.sql").write_text("SELECT 1;", encoding="utf-8")
        (tmp_path / "README.md").write_text("notes", encoding="utf-8")
        assert len(discover_migrations(tmp_path)) == 1

    def test_a_missing_directory_is_reported_clearly(self, tmp_path: Path) -> None:
        with pytest.raises(MigrationError, match="not found"):
            discover_migrations(tmp_path / "absent")


class TestApply:
    def test_applying_creates_every_expected_table(self, tmp_path: Path) -> None:
        database = Database(tmp_path / "t.db")
        try:
            assert apply_migrations(database.writer, MIGRATIONS_DIR) == [1, 2]
            names = set(iter_table_names(database.writer))
            for expected in (
                "schema_version",
                "settings",
                "cases",
                "sources",
                "parse_errors",
                "source_inventory",
                "events",
                "events_fts",
                "rules",
                "detection_runs",
                "rule_runs",
                "alerts",
                "alert_events",
                "iocs",
                "ioc_occurrences",
                "ioc_alerts",
                "allowlist",
                "mitre_tactics",
                "mitre_techniques",
                "mitre_groups_software",
                "mitre_meta",
                "jobs",
                "reports",
                "audit_log",
                "audit_tombstones",
            ):
                assert expected in names, f"{expected} missing from {sorted(names)}"
        finally:
            database.close()

    def test_the_fts5_index_exists_after_migrating(self, tmp_path: Path) -> None:
        """FTS5 is a startup requirement, so the virtual table must really exist."""
        database = Database(tmp_path / "t.db")
        try:
            apply_migrations(database.writer, MIGRATIONS_DIR)
            row = database.writer.execute(
                "SELECT sql FROM sqlite_master WHERE name = 'events_fts'"
            ).fetchone()
            assert row is not None
            assert "VIRTUAL TABLE" in str(row["sql"]).upper()
        finally:
            database.close()

    def test_the_detection_indexes_exist_after_migrating(self, tmp_path: Path) -> None:
        """Slice 1 adds the two detection hot-path indexes, so they must really exist."""
        database = Database(tmp_path / "t.db")
        try:
            apply_migrations(database.writer, MIGRATIONS_DIR)
            names = {
                str(row["name"])
                for row in database.writer.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'index' AND name LIKE 'idx_%'"
                ).fetchall()
            }
            assert "idx_ev_action" in names
            assert "idx_alert_events_event" in names
        finally:
            database.close()

    def test_applying_twice_is_a_no_op(self, tmp_path: Path) -> None:
        database = Database(tmp_path / "t.db")
        try:
            assert apply_migrations(database.writer, MIGRATIONS_DIR) == [1, 2]
            assert apply_migrations(database.writer, MIGRATIONS_DIR) == []
            assert applied_versions(database.writer) == {1, 2}
        finally:
            database.close()

    def test_the_version_and_timestamp_are_recorded(self, tmp_path: Path) -> None:
        database = Database(tmp_path / "t.db")
        try:
            apply_migrations(database.writer, MIGRATIONS_DIR)
            row = database.writer.execute(
                "SELECT version, applied_at FROM schema_version WHERE version = 1"
            ).fetchone()
            assert row is not None
            assert row["version"] == 1
            assert str(row["applied_at"]).endswith("Z")
        finally:
            database.close()

    def test_a_failing_migration_leaves_no_partial_schema(self, tmp_path: Path) -> None:
        migrations = tmp_path / "migrations"
        migrations.mkdir()
        (migrations / "0001_bad.sql").write_text(
            "CREATE TABLE keep_me (id INTEGER PRIMARY KEY);\nTHIS IS NOT SQL;",
            encoding="utf-8",
        )
        database = Database(tmp_path / "t.db")
        try:
            with pytest.raises(MigrationError):
                apply_migrations(database.writer, migrations)

            names = set(iter_table_names(database.writer))
            assert "keep_me" not in names
            assert applied_versions(database.writer) == set()
        finally:
            database.close()

    def test_an_empty_migration_is_rejected(self, tmp_path: Path) -> None:
        migrations = tmp_path / "migrations"
        migrations.mkdir()
        (migrations / "0001_empty.sql").write_text("-- nothing here\n", encoding="utf-8")
        database = Database(tmp_path / "t.db")
        try:
            with pytest.raises(MigrationError, match="no SQL statements"):
                apply_migrations(database.writer, migrations)
        finally:
            database.close()

    def test_earlier_migrations_survive_a_later_failure(self, tmp_path: Path) -> None:
        migrations = tmp_path / "migrations"
        migrations.mkdir()
        (migrations / "0001_ok.sql").write_text(
            "CREATE TABLE keep_me (id INTEGER PRIMARY KEY);", encoding="utf-8"
        )
        (migrations / "0002_bad.sql").write_text("NOT SQL AT ALL;", encoding="utf-8")
        database = Database(tmp_path / "t.db")
        try:
            with pytest.raises(MigrationError):
                apply_migrations(database.writer, migrations)

            assert applied_versions(database.writer) == {1}
            assert "keep_me" in set(iter_table_names(database.writer))
        finally:
            database.close()

    def test_the_runner_owns_the_version_table(self, tmp_path: Path) -> None:
        """Bookkeeping is the runner's job, so migration 1 need not create it."""
        migrations = tmp_path / "migrations"
        migrations.mkdir()
        (migrations / "0001_ok.sql").write_text(
            "CREATE TABLE payload (id INTEGER PRIMARY KEY);", encoding="utf-8"
        )
        database = Database(tmp_path / "t.db")
        try:
            assert apply_migrations(database.writer, migrations) == [1]
            names = set(iter_table_names(database.writer))
            assert "schema_version" in names
            assert "payload" in names
        finally:
            database.close()

    def test_an_empty_migration_set_still_creates_the_version_table(self, tmp_path: Path) -> None:
        migrations = tmp_path / "migrations"
        migrations.mkdir()
        database = Database(tmp_path / "t.db")
        try:
            assert apply_migrations(database.writer, migrations) == []
            assert "schema_version" in set(iter_table_names(database.writer))
        finally:
            database.close()

    def test_pending_lists_what_has_not_run(self, tmp_path: Path) -> None:
        database = Database(tmp_path / "t.db")
        try:
            migrations = discover_migrations(MIGRATIONS_DIR)
            assert [entry.version for entry in pending_migrations(database.writer, migrations)] == [
                1,
                2,
            ]
            apply_migrations(database.writer, MIGRATIONS_DIR)
            assert pending_migrations(database.writer, migrations) == []
        finally:
            database.close()

    def test_latest_known_version_is_the_highest_file(self) -> None:
        assert latest_known_version(discover_migrations(MIGRATIONS_DIR)) == 2

    def test_latest_known_version_of_nothing_is_zero(self) -> None:
        assert latest_known_version([]) == 0


class TestNewerSchemaIsRefused:
    def test_a_database_from_a_future_build_is_refused(self, tmp_path: Path) -> None:
        """An older binary must not touch a newer schema."""
        database = Database(tmp_path / "t.db")
        try:
            apply_migrations(database.writer, MIGRATIONS_DIR)
            database.writer.execute(
                "INSERT INTO schema_version (version, applied_at) "
                "VALUES (99, '2099-01-01T00:00:00Z')"
            )
            with pytest.raises(SqliteTooNewError, match="99"):
                apply_migrations(database.writer, MIGRATIONS_DIR)
        finally:
            database.close()

    def test_the_refusal_happens_before_any_statement_runs(self, tmp_path: Path) -> None:
        migrations = tmp_path / "migrations"
        migrations.mkdir()
        (migrations / "0001_ok.sql").write_text(
            "CREATE TABLE marker (id INTEGER PRIMARY KEY);", encoding="utf-8"
        )
        database = Database(tmp_path / "t.db")
        try:
            database.writer.execute(
                "CREATE TABLE schema_version ("
                "version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
            )
            database.writer.execute("INSERT INTO schema_version VALUES (5, '2099-01-01T00:00:00Z')")
            with pytest.raises(SqliteTooNewError):
                apply_migrations(database.writer, migrations)
            assert "marker" not in set(iter_table_names(database.writer))
        finally:
            database.close()


class TestMigrationModel:
    def test_a_migration_exposes_its_script(self, tmp_path: Path) -> None:
        (tmp_path / "0007_x.sql").write_text("SELECT 1;", encoding="utf-8")
        entry = discover_migrations(tmp_path)[0]
        assert isinstance(entry, Migration)
        assert entry.version == 7
        assert entry.name == "x"
        assert entry.label == "0007_x"
        assert entry.sql == "SELECT 1;"
        assert entry.path.name == "0007_x.sql"
