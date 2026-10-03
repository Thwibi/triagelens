"""SQLite connection management (spec 01 section 5).

Every connection is opened with the pragmas the spec mandates. The process keeps
exactly one writer connection, owned by the writer thread; API handlers take
short-lived read connections, and long analytical reads (detection) open their
own.

FTS5 and JSON1 are verified before anything else touches the database: the
spec requires a clear failure rather than a confusing "no such module" later.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType

from app.util.hashing import audit_chain_hash

#: ``PRAGMA mmap_size`` from spec 01 section 5.
DEFAULT_MMAP_BYTES = 2 * 1024 * 1024 * 1024

#: ``PRAGMA busy_timeout`` from spec 01 section 5.
DEFAULT_BUSY_TIMEOUT_MS = 10_000


class SqliteCapabilityError(RuntimeError):
    """The SQLite build lacks a feature TriageLens requires."""


class SqliteTooNewError(RuntimeError):
    """The database was written by a newer TriageLens build."""


@dataclass(frozen=True, slots=True)
class SqliteCapabilities:
    """What the linked SQLite build can do."""

    sqlite_version: str
    fts5: bool
    json1: bool

    @property
    def missing(self) -> tuple[str, ...]:
        """Names of the required features that are unavailable."""
        absent: list[str] = []
        if not self.fts5:
            absent.append("FTS5")
        if not self.json1:
            absent.append("JSON1")
        return tuple(absent)

    def require(self) -> None:
        """Raise :class:`SqliteCapabilityError` unless FTS5 and JSON1 are present."""
        absent = self.missing
        if absent:
            raise SqliteCapabilityError(
                "this Python's SQLite build is missing required feature(s): "
                f"{', '.join(absent)} (sqlite {self.sqlite_version}). "
                "TriageLens needs FTS5 for event search and JSON1 for field "
                "fallbacks. Install a Python whose bundled SQLite enables them "
                "(on Debian/Ubuntu: apt install libsqlite3-0 with a Python built "
                "against it; on Windows use python.org builds or a PyPI Python)."
            )


def _probe_module(connection: sqlite3.Connection, name: str) -> bool:
    """True when an SQLite extension module is registered."""
    try:
        row = connection.execute(
            "SELECT 1 FROM pragma_module_list WHERE name = ?", (name,)
        ).fetchone()
    except sqlite3.OperationalError:
        # SQLite older than 3.16 has no pragma_module_list: probe a scratch
        # in-memory database instead so the real file is never written to.
        scratch = sqlite3.connect(":memory:")
        try:
            scratch.execute("CREATE VIRTUAL TABLE probe USING fts5(x)")
        except sqlite3.OperationalError:
            return False
        else:
            return True
        finally:
            scratch.close()
    return row is not None


def _probe_json1(connection: sqlite3.Connection) -> bool:
    """True when the JSON1 functions are callable."""
    try:
        row = connection.execute("SELECT json_valid('{}')").fetchone()
    except sqlite3.OperationalError:
        return False
    return row is not None and row[0] == 1


def probe_capabilities(connection: sqlite3.Connection) -> SqliteCapabilities:
    """Read-only feature probe; creates no tables and writes nothing."""
    version = str(connection.execute("SELECT sqlite_version()").fetchone()[0])
    return SqliteCapabilities(
        sqlite_version=version,
        fts5=_probe_module(connection, "fts5"),
        json1=_probe_json1(connection),
    )


def _register_audit_hash(connection: sqlite3.Connection) -> None:
    """Expose the audit chain hash to SQL so a row appends in one statement."""

    def audit_hash(prev_hash: str, ts: str, action: str, detail_json: str) -> str:
        return audit_chain_hash(prev_hash, ts, action, detail_json)

    connection.create_function("audit_hash", 4, audit_hash, deterministic=True)


def _apply_pragmas(
    connection: sqlite3.Connection,
    *,
    busy_timeout_ms: int,
    mmap_bytes: int,
    set_wal: bool,
) -> None:
    """Apply the pragmas from spec 01 section 5."""
    # PRAGMA does not accept bound parameters, so these are f-strings over ints
    # that are already validated by the config layer, never user input.
    connection.execute(f"PRAGMA busy_timeout = {busy_timeout_ms:d}")
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA temp_store = MEMORY")
    connection.execute(f"PRAGMA mmap_size = {mmap_bytes:d}")
    if set_wal:
        mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()
        if mode is not None and str(mode[0]).lower() not in {"wal", "memory"}:
            raise SqliteCapabilityError(
                f"could not enable WAL journalling (journal_mode={mode[0]!r}); "
                "the database must live on a filesystem that supports shared memory"
            )
    connection.execute("PRAGMA synchronous = NORMAL")


def connect(
    db_path: Path | str,
    *,
    busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
    mmap_bytes: int = DEFAULT_MMAP_BYTES,
    set_wal: bool = True,
) -> sqlite3.Connection:
    """Open a configured connection in autocommit mode.

    Autocommit (``isolation_level=None``) is deliberate: multi-statement units
    open ``BEGIN`` themselves, so transaction boundaries are visible in the
    code instead of being implied by the driver.
    """
    connection = sqlite3.connect(
        str(db_path),
        timeout=busy_timeout_ms / 1000,
        isolation_level=None,
        check_same_thread=False,
    )
    connection.row_factory = sqlite3.Row
    _apply_pragmas(
        connection,
        busy_timeout_ms=busy_timeout_ms,
        mmap_bytes=mmap_bytes,
        set_wal=set_wal,
    )
    return connection


class Database:
    """Owns the single writer connection and hands out read connections."""

    __slots__ = ("_busy_timeout_ms", "_closed", "_mmap_bytes", "_writer", "capabilities", "path")

    def __init__(
        self,
        db_path: Path | str,
        *,
        busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
        mmap_bytes: int = DEFAULT_MMAP_BYTES,
    ) -> None:
        self.path = Path(db_path)
        self._busy_timeout_ms = busy_timeout_ms
        self._mmap_bytes = mmap_bytes
        self._closed = False
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._writer = connect(
            self.path,
            busy_timeout_ms=busy_timeout_ms,
            mmap_bytes=mmap_bytes,
            set_wal=True,
        )
        _register_audit_hash(self._writer)
        self.capabilities: SqliteCapabilities = probe_capabilities(self._writer)

    @property
    def writer(self) -> sqlite3.Connection:
        """The one writer connection. Owned by the writer thread."""
        return self._writer

    @contextmanager
    def read_connection(self) -> Iterator[sqlite3.Connection]:
        """A short-lived read connection, closed on exit."""
        if self._closed:
            raise RuntimeError("database is closed")
        connection = connect(
            self.path,
            busy_timeout_ms=self._busy_timeout_ms,
            mmap_bytes=self._mmap_bytes,
            set_wal=False,
        )
        try:
            yield connection
        finally:
            connection.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Run a unit of work as one immediate transaction on the writer.

        ``IMMEDIATE`` takes the write lock up front so two writers fail fast
        instead of deadlocking halfway through.
        """
        connection = self._writer
        if connection.in_transaction:
            raise RuntimeError("nested transaction on the writer connection")
        connection.execute("BEGIN IMMEDIATE")
        try:
            yield connection
        except BaseException:
            connection.rollback()
            raise
        else:
            connection.commit()

    def db_bytes(self) -> int:
        """On-disk size of the database, including the WAL and shared-memory files."""
        total = 0
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(f"{self.path}{suffix}")
            if candidate.exists():
                total += candidate.stat().st_size
        return total

    def close(self) -> None:
        """Close the writer connection. Safe to call more than once."""
        if not self._closed:
            self._closed = True
            if self._writer.in_transaction:
                self._writer.rollback()
            self._writer.close()

    @property
    def closed(self) -> bool:
        """True once :meth:`close` has run."""
        return self._closed

    def __enter__(self) -> Database:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


__all__ = [
    "DEFAULT_BUSY_TIMEOUT_MS",
    "DEFAULT_MMAP_BYTES",
    "Database",
    "SqliteCapabilities",
    "SqliteCapabilityError",
    "SqliteTooNewError",
    "connect",
    "probe_capabilities",
]
