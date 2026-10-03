"""Database access: connections, migrations and typed repositories."""

from __future__ import annotations

from app.db.connection import (
    Database,
    SqliteCapabilities,
    SqliteCapabilityError,
    SqliteTooNewError,
    connect,
    probe_capabilities,
)

__all__ = [
    "Database",
    "SqliteCapabilities",
    "SqliteCapabilityError",
    "SqliteTooNewError",
    "connect",
    "probe_capabilities",
]
