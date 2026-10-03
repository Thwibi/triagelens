"""Forward-only SQL migration runner (spec 02 section 7).

Rules implemented here:

* files are named ``NNNN_name.sql`` and applied in ascending numeric order,
* each file is applied inside one transaction, so a failure leaves no partial
  schema behind,
* ``schema_version`` records what has been applied,
* there are no down-migrations, and a database newer than this build refuses to
  open rather than being silently downgraded.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from app.db.connection import SqliteTooNewError

#: ``0001_init.sql`` -> version 1, name ``init``.
_FILENAME = re.compile(r"^(?P<version>\d{4})_(?P<name>[A-Za-z0-9_\-]+)\.sql$")

#: Table holding the applied versions; created by migration 1.
VERSION_TABLE = "schema_version"


@dataclass(frozen=True, slots=True)
class Migration:
    """One migration file."""

    version: int
    name: str
    path: Path
    sql: str

    @property
    def label(self) -> str:
        """``0001_init`` style label used in log messages."""
        return f"{self.version:04d}_{self.name}"


class MigrationError(RuntimeError):
    """A migration file is malformed or failed to apply."""


def _has_sql_content(fragment: str) -> bool:
    """True when ``fragment`` contains anything other than comments/whitespace.

    String literals are respected so a ``--`` inside a quoted value does not
    hide real SQL.
    """
    in_string: str | None = None
    index = 0
    length = len(fragment)
    while index < length:
        char = fragment[index]
        if in_string is not None:
            if char == in_string:
                in_string = None
            index += 1
            continue
        if char in {"'", '"', "`"}:
            in_string = char
            index += 1
            continue
        if fragment.startswith("--", index):
            newline = fragment.find("\n", index)
            if newline == -1:
                return False
            index = newline + 1
            continue
        if not char.isspace():
            return True
        index += 1
    return False


def split_sql_statements(script: str) -> list[str]:
    """Split a SQL script into complete statements.

    Uses SQLite's own ``sqlite3_complete()`` via :func:`sqlite3.complete_statement`
    rather than splitting on ``;``, because trigger bodies contain semicolons::

        CREATE TRIGGER x BEFORE DELETE ON t BEGIN SELECT RAISE(ABORT, 'x'); END;

    A trailing fragment that never forms a complete statement is returned as-is
    so the caller fails on it instead of silently ignoring it. A trailing fragment
    that is only comments is dropped, so a comment-only file is correctly seen as
    empty.
    """
    statements: list[str] = []
    buffer = ""
    for line in script.splitlines(keepends=True):
        buffer += line
        if sqlite3.complete_statement(buffer):
            candidate = buffer.strip()
            if candidate:
                statements.append(candidate)
            buffer = ""
    tail = buffer.strip()
    if tail and _has_sql_content(tail):
        statements.append(tail)
    return statements


def discover_migrations(directory: Path) -> list[Migration]:
    """Load and validate every migration file in ``directory``.

    Raises:
        MigrationError: on an unparseable filename or a duplicate version.
    """
    if not directory.is_dir():
        raise MigrationError(f"migrations directory not found: {directory}")
    migrations: list[Migration] = []
    seen: dict[int, Path] = {}
    for path in sorted(directory.iterdir()):
        if not path.is_file() or path.suffix.lower() != ".sql":
            continue
        match = _FILENAME.match(path.name)
        if match is None:
            raise MigrationError(f"migration filename must look like NNNN_name.sql: {path.name}")
        version = int(match.group("version"))
        if version in seen:
            raise MigrationError(
                f"duplicate migration version {version:04d}: {seen[version].name} and {path.name}"
            )
        seen[version] = path
        migrations.append(
            Migration(
                version=version,
                name=match.group("name"),
                path=path,
                sql=path.read_text(encoding="utf-8"),
            )
        )
    # ``sorted`` already guarantees ascending order; the invariant worth enforcing
    # is uniqueness, which the ``seen`` map above covers. Contiguity is
    # deliberately not required so a partial migration set stays loadable.
    return migrations


def _ensure_version_table(connection: sqlite3.Connection) -> None:
    """Create the runner's own bookkeeping table if it is absent.

    This table belongs to the migration runner, not to the application schema,
    so the runner creates it. Keeping it out of migration 1 removes the trap
    where a partially-ordered migration set fails on a missing table.
    """
    connection.execute(
        f"CREATE TABLE IF NOT EXISTS {VERSION_TABLE} ("
        "version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
    )


def _has_version_table(connection: sqlite3.Connection) -> bool:
    row = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (VERSION_TABLE,)
    ).fetchone()
    return row is not None


def applied_versions(connection: sqlite3.Connection) -> set[int]:
    """Versions recorded in ``schema_version`` (empty before migration 1)."""
    if not _has_version_table(connection):
        return set()
    rows = connection.execute(f"SELECT version FROM {VERSION_TABLE}").fetchall()
    return {int(row[0]) for row in rows}


def latest_known_version(migrations: Sequence[Migration]) -> int:
    """Highest migration version this build understands."""
    return max((migration.version for migration in migrations), default=0)


def _assert_not_newer(
    connection: sqlite3.Connection,
    migrations: Sequence[Migration],
) -> None:
    """Refuse to open a database written by a newer build."""
    known = latest_known_version(migrations)
    installed = max(applied_versions(connection), default=0)
    if installed > known:
        raise SqliteTooNewError(
            f"database schema version {installed} is newer than this build "
            f"understands ({known}). Upgrade TriageLens or restore an older "
            "data directory; down-migration is not supported."
        )


def _apply_one(connection: sqlite3.Connection, migration: Migration) -> None:
    """Apply one migration atomically and record its version."""
    statements = split_sql_statements(migration.sql)
    if not statements:
        raise MigrationError(f"{migration.path.name} contains no SQL statements")
    connection.execute("BEGIN IMMEDIATE")
    try:
        for statement in statements:
            try:
                connection.execute(statement)
            except sqlite3.Error as exc:
                raise MigrationError(f"migration {migration.label} failed: {exc}") from exc
        connection.execute(
            f"INSERT INTO {VERSION_TABLE} (version, applied_at) VALUES (?, ?)",
            (
                migration.version,
                datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            ),
        )
    except BaseException:
        connection.rollback()
        raise
    connection.commit()


def pending_migrations(
    connection: sqlite3.Connection,
    migrations: Sequence[Migration],
) -> list[Migration]:
    """Migrations that still need to run, in order."""
    done = applied_versions(connection)
    return [migration for migration in migrations if migration.version not in done]


def apply_migrations(
    connection: sqlite3.Connection,
    directory: Path,
    *,
    migrations: Sequence[Migration] | None = None,
) -> list[int]:
    """Bring the database up to date and return the versions applied.

    Returns an empty list when the schema is already current, which makes the
    call idempotent at every startup.
    """
    catalogue = list(migrations) if migrations is not None else discover_migrations(directory)
    _assert_not_newer(connection, catalogue)
    _ensure_version_table(connection)
    applied: list[int] = []
    for migration in pending_migrations(connection, catalogue):
        _apply_one(connection, migration)
        applied.append(migration.version)
    return applied


def iter_table_names(connection: sqlite3.Connection) -> Iterator[str]:
    """Every table and virtual table in the database, for verification."""
    rows = connection.execute(
        "SELECT name FROM sqlite_master WHERE type IN ('table', 'view') ORDER BY name"
    ).fetchall()
    for row in rows:
        yield str(row[0])


__all__ = [
    "VERSION_TABLE",
    "Migration",
    "MigrationError",
    "applied_versions",
    "apply_migrations",
    "discover_migrations",
    "iter_table_names",
    "latest_known_version",
    "pending_migrations",
    "split_sql_statements",
]
