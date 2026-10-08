"""Request-scoped access to the objects stored on `app.state`.

The repository dependencies are plain generator functions rather than
``@contextmanager`` wrappers. FastAPI drives a generator dependency itself and
hands the endpoint the yielded value; wrapping one in ``contextmanager`` makes it
a factory that returns a context manager, which FastAPI then passes straight
through as the dependency value.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Iterator
from typing import TypeVar, cast

from fastapi import Request

from app.config import Settings
from app.db.connection import Database
from app.db.repositories.allowlist import AllowlistRepository
from app.db.repositories.cases import CaseRepository
from app.db.repositories.iocs import IocRepository
from app.db.repositories.jobs import JobRepository
from app.db.repositories.settings import SettingsRepository
from app.db.repositories.sources import (
    InventoryRepository,
    ParseErrorRepository,
    SourceRepository,
)
from app.jobs.manager import JobManager
from app.jobs.progress import ProgressBus
from app.jobs.writer import DBWriter
from app.util.logging import get_logger

logger = get_logger("api.deps")

#: How long a synchronous endpoint waits for the writer thread. A write is one
#: small transaction, so anything near this means the writer is stuck and the
#: request should fail loudly rather than hang.
WRITE_TIMEOUT = 30.0

T = TypeVar("T")


def get_progress(request: Request) -> ProgressBus:
    return cast(ProgressBus, request.app.state.progress)


def get_job_manager(request: Request) -> JobManager:
    return cast(JobManager, request.app.state.job_manager)


def get_settings(request: Request) -> Settings:
    return cast(Settings, request.app.state.settings)


def get_database(request: Request) -> Database:
    return cast(Database, request.app.state.database)


def get_writer(request: Request) -> DBWriter:
    """The single writer thread, for endpoints that mutate rows.

    Anything that writes goes through this rather than opening a transaction on
    the database directly. The write connection belongs to the writer thread, so
    a second thread issuing ``BEGIN`` on it fails with "cannot start a
    transaction within a transaction" -- an error that says nothing about what was
    actually wrong and, worse, can leave the outer transaction half applied.
    """
    return cast(DBWriter, request.app.state.writer)


def write_in(request: Request, work: Callable[[sqlite3.Connection], T]) -> T:
    """Run one unit of write work on the writer thread and return its result.

    For synchronous endpoints. ``run`` returns a future, which a ``def`` endpoint
    has no loop to await, so this blocks on the result with a bounded timeout
    rather than hanging the request forever if the writer is wedged.
    """
    writer = get_writer(request)
    return cast(T, writer.run(work).result(timeout=WRITE_TIMEOUT))


def read_connection(request: Request) -> Iterator[sqlite3.Connection]:
    """One read connection for the request, closed when the response is sent."""
    with get_database(request).read_connection() as connection:
        yield connection


def case_repository(request: Request) -> Iterator[CaseRepository]:
    """A case repository on a read connection closed after the response."""
    with get_database(request).read_connection() as connection:
        yield CaseRepository(connection)


def source_repository(request: Request) -> Iterator[SourceRepository]:
    with get_database(request).read_connection() as connection:
        yield SourceRepository(connection)


def parse_error_repository(request: Request) -> Iterator[ParseErrorRepository]:
    with get_database(request).read_connection() as connection:
        yield ParseErrorRepository(connection)


def inventory_repository(request: Request) -> Iterator[InventoryRepository]:
    with get_database(request).read_connection() as connection:
        yield InventoryRepository(connection)


def job_repository(request: Request) -> Iterator[JobRepository]:
    with get_database(request).read_connection() as connection:
        yield JobRepository(connection)


def settings_repository(request: Request) -> Iterator[SettingsRepository]:
    with get_database(request).read_connection() as connection:
        yield SettingsRepository(connection)


def ioc_repository(request: Request) -> Iterator[IocRepository]:
    with get_database(request).read_connection() as connection:
        yield IocRepository(connection)


def allowlist_repository(request: Request) -> Iterator[AllowlistRepository]:
    with get_database(request).read_connection() as connection:
        yield AllowlistRepository(connection)


__all__ = [
    "allowlist_repository",
    "case_repository",
    "get_database",
    "get_job_manager",
    "get_progress",
    "get_settings",
    "get_writer",
    "inventory_repository",
    "ioc_repository",
    "job_repository",
    "parse_error_repository",
    "read_connection",
    "settings_repository",
    "source_repository",
    "write_in",
]
