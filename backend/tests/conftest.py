"""Shared fixtures.

Every test gets its own temporary data directory so no test can see another's
database, and the app is always built from an explicit :class:`Settings` object
rather than from discovery, which keeps the suite independent of the developer's
``config.toml`` and environment.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.db.connection import Database
from app.main import create_app

BACKEND_ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS_DIR = BACKEND_ROOT / "migrations"


@pytest.fixture(autouse=True)
def _isolated_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove ambient ``TRIAGELENS_*`` variables so tests cannot leak settings."""
    for name in list(os.environ):
        if name.startswith("TRIAGELENS_"):
            monkeypatch.delenv(name, raising=False)


@pytest.fixture
def data_dir(tmp_path: Path) -> Path:
    """An empty data directory for one test."""
    target = tmp_path / "data"
    target.mkdir()
    return target


@pytest.fixture
def settings(data_dir: Path) -> Settings:
    """Loopback settings pointing at the temporary data directory."""
    return Settings(
        server={"host": "127.0.0.1", "port": 8787},
        storage={"data_dir": str(data_dir)},
        logging={"console": False, "level": "CRITICAL"},
    )


@pytest.fixture
def database(settings: Settings) -> Iterator[Database]:
    """An opened, migrated database that is always closed afterwards."""
    db = Database(settings.db_path)
    from app.db.migrations import apply_migrations

    apply_migrations(db.writer, MIGRATIONS_DIR)
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def client(settings: Settings) -> Iterator[TestClient]:
    """A TestClient with the full lifespan, so migrations really run."""
    with TestClient(create_app(settings), base_url="http://127.0.0.1:8787") as test_client:
        yield test_client
