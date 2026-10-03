"""Performance benchmarks that are meaningful at Phase 0.

Spec 09 section 8 lists throughput targets. Most measure the ingest and detection
pipeline, which is built in later phases, so they cannot be measured yet. Rather
than assert nothing, these benchmarks cover the work that exists now and report
the real numbers:

- applying the migration set to an empty database
- audit chain append and full-chain verification
- event insert throughput, including FTS5 index upkeep through triggers
- indexed event filter latency and an FTS5 MATCH query
- ``/api/health`` latency through the real ASGI stack

Spec 09 requires results in ``docs/perf-results.md`` with device information;
``scripts/perf_report.py`` writes that after a run. Targets that cannot be
measured yet are listed in ``docs/DECISIONS.md`` with the reason.

Run with::

    make perf
"""

from __future__ import annotations

import json
import sqlite3
import statistics
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from app.config import load_settings
from app.db.connection import Database, connect
from app.db.migrations import apply_migrations
from app.db.repositories.audit import AuditRepository
from app.main import create_app

BACKEND_ROOT = Path(__file__).resolve().parents[2]
MIGRATIONS_DIR = BACKEND_ROOT / "migrations"

#: pytest's ``record_property`` fixture, which it does not export a type for.
RecordProperty = Callable[[str, object], None]

# Sizes are small enough to keep a run near a minute but large enough that
# per-call overhead does not dominate the result.
AUDIT_ROWS = 2000
EVENT_ROWS = 5000
QUERY_SAMPLES = 200


@dataclass(frozen=True)
class Measurement:
    """One benchmark result, in the shape the report writer consumes."""

    name: str
    unit: str
    samples: int
    best: float
    median: float
    worst: float

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "unit": self.unit,
            "samples": self.samples,
            "best": round(self.best, 6),
            "median": round(self.median, 6),
            "worst": round(self.worst, 6),
        }


@contextmanager
def _migrated(path: Path) -> Iterator[Database]:
    """A migrated database, closed on exit."""
    database = Database(path)
    apply_migrations(database.writer, MIGRATIONS_DIR)
    try:
        yield database
    finally:
        database.close()


def _record(record_property: RecordProperty, measurement: Measurement) -> None:
    """Publish a measurement so the run_perf.py collector can gather it.

    No printing: the numbers end up in docs/perf-results.md, and interleaving
    them with pytest's own output only makes the run harder to read.
    """
    record_property("perf", json.dumps([measurement.as_dict()]))


def _per_query(work: Callable[[], None], samples: int) -> list[float]:
    """Seconds for each of `samples` batches of queries."""
    timings = []
    for _ in range(samples):
        start = time.perf_counter()
        work()
        timings.append(time.perf_counter() - start)
    return timings


def _seed_case_and_source(connection: sqlite3.Connection) -> None:
    """Insert the case and source that events reference."""
    connection.execute(
        "INSERT INTO cases (id, name, created_at, updated_at)"
        " VALUES ('c', 'bench', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')"
    )
    connection.execute(
        "INSERT INTO sources (id, case_id, filename, stored_path, size_bytes, sha256,"
        " log_type, status, ingested_at)"
        " VALUES ('s', 'c', 'bench.log', 'data/sources/bench.log', 1, 'x',"
        " 'text', 'done', '2026-01-01T00:00:00Z')"
    )


def _insert_events(connection: sqlite3.Connection, count: int) -> None:
    """Insert `count` events spread across hosts, users and addresses."""
    connection.executemany(
        "INSERT INTO events (case_id, source_id, record_ref, ts_ms, ts_iso, log_type, host,"
        " user_name, src_ip, message, raw) VALUES ('c','s',?,1700000000000,"
        "'2026-01-01T00:00:00Z','text',?,?,?,?,?)",
        (
            (
                f"ref-{index}",
                f"HOST-{index % 20}",
                f"user-{index % 7}",
                f"10.0.{index % 255}.{index % 99}",
                "failed password for invalid user",
                "raw line",
            )
            for index in range(count)
        ),
    )


def test_measure_apply_migrations(tmp_path: Path, record_property: RecordProperty) -> None:
    """Applying every migration to an empty database."""
    timings = []
    for index in range(5):
        connection = connect(tmp_path / f"migrate-{index}.db")
        try:
            start = time.perf_counter()
            apply_migrations(connection, MIGRATIONS_DIR)
            timings.append(time.perf_counter() - start)
        finally:
            connection.close()

    measurement = Measurement(
        name="migrations.apply",
        unit="s/database",
        samples=len(timings),
        best=min(timings),
        median=statistics.median(timings),
        worst=max(timings),
    )
    _record(record_property, measurement)


def test_measure_audit_append(tmp_path: Path, record_property: RecordProperty) -> None:
    """Appending rows to the audit hash chain."""
    with _migrated(tmp_path / "audit-append.db") as database:
        repository = AuditRepository(database.writer)

        def append_many(count: int) -> None:
            for index in range(count):
                repository.append("settings_changed", detail={"benchmark": True, "i": index})

        rounds = []
        for _ in range(3):
            start = time.perf_counter()
            append_many(AUDIT_ROWS)
            rounds.append((time.perf_counter() - start) / AUDIT_ROWS)

        measurement = Measurement(
            name="audit.append",
            unit="s/row",
            samples=len(rounds),
            best=min(rounds),
            median=statistics.median(rounds),
            worst=max(rounds),
        )
        _record(record_property, measurement)


def test_measure_audit_verify(tmp_path: Path, record_property: RecordProperty) -> None:
    """Verifying a full chain of AUDIT_ROWS rows."""
    with _migrated(tmp_path / "audit-verify.db") as database:
        repository = AuditRepository(database.writer)
        for index in range(AUDIT_ROWS):
            repository.append("settings_changed", detail={"i": index})

        def verify() -> None:
            result = repository.verify()
            assert result.ok, "the chain must verify before it can be timed"

        timings = _per_query(verify, samples=5)
        measurement = Measurement(
            name="audit.verify",
            unit="s/row",
            samples=len(timings),
            best=min(timings) / AUDIT_ROWS,
            median=statistics.median(timings) / AUDIT_ROWS,
            worst=max(timings) / AUDIT_ROWS,
        )
        _record(record_property, measurement)


def test_measure_event_insert(tmp_path: Path, record_property: RecordProperty) -> None:
    """Inserting events in one transaction, which maintains the FTS5 index."""
    with _migrated(tmp_path / "events.db") as database:
        with database.transaction() as writer:
            _seed_case_and_source(writer)

        rounds = []
        for _ in range(3):
            start = time.perf_counter()
            with database.transaction() as writer:
                _insert_events(writer, EVENT_ROWS)
            rounds.append((time.perf_counter() - start) / EVENT_ROWS)

        measurement = Measurement(
            name="events.insert",
            unit="s/event",
            samples=len(rounds),
            best=min(rounds),
            median=statistics.median(rounds),
            worst=max(rounds),
        )
        _record(record_property, measurement)


def test_measure_indexed_filter(tmp_path: Path, record_property: RecordProperty) -> None:
    """An indexed equality filter, the shape the Events API uses."""
    with _migrated(tmp_path / "filter.db") as database:
        with database.transaction() as writer:
            _seed_case_and_source(writer)
            _insert_events(writer, EVENT_ROWS)

        hosts = [f"HOST-{index % 20}" for index in range(QUERY_SAMPLES)]

        def query() -> None:
            for host in hosts:
                writer.execute(
                    "SELECT id FROM events WHERE case_id = 'c' AND host = ?", (host,)
                ).fetchall()

        timings = _per_query(query, samples=3)
        measurement = Measurement(
            name="events.filter_indexed",
            unit="s/query",
            samples=QUERY_SAMPLES * 3,
            best=min(timings) / QUERY_SAMPLES,
            median=statistics.median(timings) / QUERY_SAMPLES,
            worst=max(timings) / QUERY_SAMPLES,
        )
        _record(record_property, measurement)


def test_measure_fts_query(tmp_path: Path, record_property: RecordProperty) -> None:
    """A MATCH query against the FTS5 index."""
    with _migrated(tmp_path / "fts.db") as database:
        with database.transaction() as writer:
            _seed_case_and_source(writer)
            _insert_events(writer, EVENT_ROWS)

        def query() -> None:
            for _ in range(QUERY_SAMPLES):
                writer.execute(
                    "SELECT e.id FROM events_fts f JOIN events e ON e.id = f.rowid"
                    " WHERE events_fts MATCH ? LIMIT 50",
                    ("failed",),
                ).fetchall()

        timings = _per_query(query, samples=3)
        measurement = Measurement(
            name="events.fts_query",
            unit="s/query",
            samples=QUERY_SAMPLES * 3,
            best=min(timings) / QUERY_SAMPLES,
            median=statistics.median(timings) / QUERY_SAMPLES,
            worst=max(timings) / QUERY_SAMPLES,
        )
        _record(record_property, measurement)


def test_measure_health_endpoint(tmp_path: Path, record_property: RecordProperty) -> None:
    """/api/health through the real ASGI stack, middleware included."""
    # A temporary data directory keeps the benchmark off the real database, and
    # base_url names a loopback Host the validation middleware accepts.
    settings = load_settings(
        environ={
            "TRIAGELENS_STORAGE__DATA_DIR": str(tmp_path / "data"),
            "TRIAGELENS_LOGGING__CONSOLE": "false",
        }
    )
    app = create_app(settings)
    with TestClient(app, base_url="http://127.0.0.1:8787") as client:

        def query() -> None:
            for _ in range(QUERY_SAMPLES):
                response = client.get("/api/health")
                assert response.status_code == 200

        timings = _per_query(query, samples=3)

    measurement = Measurement(
        name="api.health",
        unit="s/request",
        samples=QUERY_SAMPLES * 3,
        best=min(timings) / QUERY_SAMPLES,
        median=statistics.median(timings) / QUERY_SAMPLES,
        worst=max(timings) / QUERY_SAMPLES,
    )
    _record(record_property, measurement)
