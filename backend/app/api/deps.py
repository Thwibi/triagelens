"""Request-scoped access to the objects stored on ``app.state``."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from typing import cast

from fastapi import Request

from app.config import Settings
from app.db.connection import Database
from app.db.repositories.cases import CaseRepository
from app.db.repositories.settings import SettingsRepository
from app.db.repositories.sources import (
    InventoryRepository,
    ParseErrorRepository,
    SourceRepository,
)
from app.util.logging import get_logger

logger = get_logger("api.deps")


def get_settings(request: Request) -> Settings:
    """The validated configuration this process started with."""
    return cast(Settings, request.app.state.settings)


def get_database(request: Request) -> Database:
    """The process-wide database handle."""
    return cast(Database, request.app.state.database)


@contextmanager
def read_connection(request: Request) -> Iterator[sqlite3.Connection]:
    """A short-lived read connection, per spec 01 section 5."""
    with get_database(request).read_connection() as connection:
        yield connection


@contextmanager
def case_repository(request: Request) -> Iterator[CaseRepository]:
    """Case repository bound to a short-lived read connection."""
    with read_connection(request) as connection:
        yield CaseRepository(connection)


@contextmanager
def source_repository(request: Request) -> Iterator[SourceRepository]:
    """Source repository bound to a short-lived read connection."""
    with read_connection(request) as connection:
        yield SourceRepository(connection)


@contextmanager
def parse_error_repository(request: Request) -> Iterator[ParseErrorRepository]:
    """Parse-error repository bound to a short-lived read connection."""
    with read_connection(request) as connection:
        yield ParseErrorRepository(connection)


@contextmanager
def inventory_repository(request: Request) -> Iterator[InventoryRepository]:
    """Inventory repository bound to a short-lived read connection."""
    with read_connection(request) as connection:
        yield InventoryRepository(connection)


@contextmanager
def settings_repository(request: Request) -> Iterator[SettingsRepository]:
    """Settings repository bound to a short-lived read connection."""
    with read_connection(request) as connection:
        yield SettingsRepository(connection)


__all__ = [
    "case_repository",
    "get_database",
    "get_settings",
    "inventory_repository",
    "parse_error_repository",
    "read_connection",
    "settings_repository",
    "source_repository",
]
