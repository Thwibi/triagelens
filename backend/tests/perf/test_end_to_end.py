"""Spec 09 section 8: the end-to-end performance targets.

The primitives in ``test_benchmarks.py`` time one operation. This module measures
the *pipeline* against the numeric targets spec 09 section 8 lists:

1. text log parse + normalize + tier-1 IOC + persist,
2. EVTX parse + persist,
3. a 1M-event ``standard`` detection run,
4. the Events API first page under an indexed filter,
5. an FTS query,
6. ingest peak memory.

(The UI first-paint target is measured by the frontend Playwright harness, which
owns a browser; see ``docs/DECISIONS.md``.)

Sizing is chosen by ``TRIAGELENS_PERF_SCALE`` (``smoke`` by default, ``full`` for
the spec's reference machine). The tests only assert that the run was correct;
the pass/fail against each numeric target is recorded as a ``perf_target``
property and rendered by ``scripts/perf_report.py``. A smoke run on a laptop is a
regression baseline, not the reference verdict, so it is reported, not asserted.

Nothing here runs under the normal suite: the module skips unless
``TRIAGELENS_PERF_E2E=1``, which ``make perf-e2e`` sets. These tests are
deliberately excluded from ``task_backend_test`` (``--ignore=tests/perf``) because
wall-clock numbers are noise on a shared machine.
"""

from __future__ import annotations

import asyncio
import ctypes
import json
import math
import multiprocessing
import os
import platform
import queue as queue_module
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from app.config import Settings, load_settings
from app.db.connection import Database, atomic
from app.db.repositories.events import BATCH_SIZE, EventFilters, EventRepository
from app.ingest.events import INSERT_SQL, NormalizedEvent
from app.jobs.parsing import (
    TAG_BATCH,
    TAG_CANCELLED,
    TAG_DONE,
    TAG_ERROR,
    TAG_STARTED,
    ParseRequest,
    ParseSummary,
    WorkerBridge,
    parse_and_emit,
)
from app.jobs.writer import DBWriter

BACKEND_ROOT = Path(__file__).resolve().parents[2]
EVTX_FIXTURES = BACKEND_ROOT / "tests" / "fixtures" / "evtx"

#: Read at import time, before the conftest autouse fixture strips ambient
#: ``TRIAGELENS_*`` variables for the duration of each test.
_ENABLED = os.environ.get("TRIAGELENS_PERF_E2E") == "1"
_SCALE = os.environ.get("TRIAGELENS_PERF_SCALE", "smoke").strip().lower() or "smoke"

pytestmark = [
    pytest.mark.perf,
    pytest.mark.skipif(
        not _ENABLED,
        reason="end-to-end perf targets run via `make perf-e2e`",
    ),
]

#: pytest's ``record_property`` fixture, which it does not export a type for.
RecordProperty = Callable[[str, object], None]

#: A fixed epoch so generated events have a stable, sortable timestamp.
BASE_TS_MS = 1_700_000_000_000

#: How many concurrent workers the multi-worker target uses (spec 09 section 8).
TEXT_WORKERS = 4

# Sizes: small enough that a smoke run finishes in a couple of minutes, large
# enough that per-record overhead does not dominate. ``full`` is the spec size.
TEXT_SINGLE_RECORDS = 60_000 if _SCALE != "full" else 1_000_000
TEXT_MULTI_RECORDS = 30_000 if _SCALE != "full" else 1_000_000
DETECT_EVENTS = 30_000 if _SCALE != "full" else 1_000_000
QUERY_EVENTS = 120_000 if _SCALE != "full" else 5_000_000
MEMORY_RECORDS = 50_000 if _SCALE != "full" else 8_000_000
LATENCY_SAMPLES = 40


@dataclass(frozen=True, slots=True)
class Target:
    """One spec 09 section 8 target and whether this run met it."""

    name: str
    value: float
    unit: str
    limit: float
    comparator: str
    note: str = ""

    @property
    def passed(self) -> bool:
        """True when the measured value satisfies the comparator."""
        if self.comparator == "min":
            return self.value >= self.limit
        return self.value <= self.limit

    def as_dict(self) -> dict[str, Any]:
        """JSON-ready form for the collected property."""
        return {
            "name": self.name,
            "value": round(self.value, 3),
            "unit": self.unit,
            "limit": self.limit,
            "comparator": self.comparator,
            "passed": self.passed,
            "note": self.note,
        }


def record_targets(record_property: RecordProperty, *targets: Target) -> None:
    """Publish target verdicts so the run_perf.py collector can gather them."""
    record_property("perf_target", json.dumps([target.as_dict() for target in targets]))


def percentile(values: Sequence[float], pct: float) -> float:
    """Nearest-rank percentile of ``values`` (``pct`` in 0..100)."""
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, math.ceil(pct / 100 * len(ordered)) - 1)
    return ordered[index]


def latency_samples(work: Callable[[], object], samples: int) -> list[float]:
    """Seconds for each of ``samples`` runs of ``work``."""
    timings: list[float] = []
    for _ in range(samples):
        start = time.perf_counter()
        work()
        timings.append(time.perf_counter() - start)
    return timings


def peak_working_set_bytes() -> int:
    """This process's peak working set (Windows) or max RSS (POSIX), in bytes."""
    if platform.system() == "Windows":
        return _windows_working_set()
    import importlib

    # ``resource`` has no stubs on Windows, so it is loaded as an untyped module:
    # the branch is unreachable there, but the type checker still sees the import.
    resource: Any = importlib.import_module("resource")
    usage = resource.getrusage(resource.RUSAGE_SELF)
    # ru_maxrss is kibibytes on Linux and bytes on macOS.
    unit = 1024 if platform.system() == "Linux" else 1
    return int(usage.ru_maxrss) * unit


def _windows_working_set() -> int:
    """Peak working set via GetProcessMemoryInfo, or 0 when unavailable."""

    class _Counters(ctypes.Structure):
        _fields_ = [
            ("cb", ctypes.c_ulong),
            ("PageFaultCount", ctypes.c_ulong),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
        ]

    counters = _Counters()
    counters.cb = ctypes.sizeof(counters)
    kernel32 = ctypes.windll.kernel32
    # The pseudo-handle is (HANDLE)-1: without a pointer restype ctypes truncates
    # it to 32 bits and the call fails, silently reporting a zero working set.
    kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    get_memory_info = kernel32.K32GetProcessMemoryInfo
    get_memory_info.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(_Counters),
        ctypes.c_ulong,
    ]
    get_memory_info.restype = ctypes.c_bool
    handle = kernel32.GetCurrentProcess()
    ok = get_memory_info(handle, ctypes.byref(counters), counters.cb)
    return int(counters.PeakWorkingSetSize) if ok else 0


def _iso_second(index: int) -> str:
    """A distinct, increasing timestamp for each generated record."""
    second = index % 60
    minute = (index // 60) % 60
    hour = (index // 3600) % 24
    millisecond = index % 1000
    return f"2024-01-01T{hour:02d}:{minute:02d}:{second:02d}.{millisecond:03d}Z"


def write_ecs_ndjson(path: Path, count: int, *, host: str = "bench-host") -> int:
    """Write ``count`` ECS NDJSON records; return the total byte count.

    Each record carries a private-range source IP and a "failed login" message so
    tier-1 IOC extraction has real work to do on the worker's hot path.
    """
    total = 0
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for index in range(count):
            record = {
                "@timestamp": _iso_second(index),
                "ecs": {"version": "8.11.0"},
                "host": {"name": f"{host}-{index % 8}"},
                "log": {"level": "info"},
                "message": f"failed password for invalid user admin from 203.0.113.{index % 250}",
                "process": {"name": "sshd", "pid": 1000 + (index % 30000)},
                "event": {"category": "authentication", "dataset": "linux.auth"},
            }
            line = json.dumps(record) + "\n"
            handle.write(line)
            total += len(line)
    return total


def seed_case_and_source(
    connection: Any,
    *,
    case_id: str,
    source_id: str,
    filename: str = "bench.ndjson",
    log_type: str = "generic_json",
) -> None:
    """Insert the case and source rows that generated events reference."""
    connection.execute(
        "INSERT INTO cases (id, name, created_at, updated_at)"
        " VALUES (?, 'perf', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
        (case_id,),
    )
    connection.execute(
        "INSERT INTO sources (id, case_id, filename, stored_path, size_bytes, sha256,"
        " log_type, status, ingested_at)"
        " VALUES (?, ?, ?, ?, 1, 'x', ?, 'done', '2026-01-01T00:00:00Z')",
        (source_id, case_id, filename, f"data/sources/{filename}", log_type),
    )


def _benchmark_event(index: int, case_id: str, source_id: str, hosts: int) -> NormalizedEvent:
    """One stored event for the seed loader, spread across hosts and addresses."""
    return NormalizedEvent(
        case_id=case_id,
        source_id=source_id,
        record_ref=f"rec-{index}",
        log_type="linux_auth",
        raw="failed password for invalid user admin",
        ts_ms=BASE_TS_MS + index,
        host=f"HOST-{index % hosts:02d}",
        user_name="admin",
        message="failed password for invalid user admin",
        event_action="ssh_failed_password",
        src_ip=f"203.0.113.{index % 250}",
    )


def bulk_insert_events(
    database: Database,
    count: int,
    *,
    case_id: str,
    source_id: str,
    hosts: int = 20,
    rebuild_fts: bool = False,
) -> None:
    """Insert ``count`` events in batches, optionally rebuilding the FTS index.

    The events go straight through ``events.INSERT_SQL`` with
    :meth:`NormalizedEvent.values`, so the rows are identical to the ones the
    writer thread produces. FTS rows are built once at the end with ``rebuild``,
    which is far cheaper than per-row upkeep for a bulk seed.
    """
    connection = database.writer
    chunk: list[NormalizedEvent] = []
    for index in range(count):
        chunk.append(_benchmark_event(index, case_id, source_id, hosts))
        if len(chunk) >= BATCH_SIZE:
            with atomic(connection):
                connection.executemany(INSERT_SQL, [event.values() for event in chunk])
            chunk.clear()
    if chunk:
        with atomic(connection):
            connection.executemany(INSERT_SQL, [event.values() for event in chunk])
    if rebuild_fts:
        EventRepository(connection).rebuild_fts()


def sync_rules(database: Database, settings: Settings) -> int:
    """Load the shipped rule catalogue into the database; return the rule count."""
    from app.detect.sync import sync_catalogue

    report = sync_catalogue(database.writer, settings=settings, audit=False)
    return report.total


def run_detection(
    database: Database,
    settings: Settings,
    *,
    case_id: str,
    profile: str = "standard",
    job_id: str = "perf-detect",
) -> None:
    """Run the real detect runner over ``case_id`` with ``profile``."""
    from app.jobs.detect import DetectPayload, DetectRunner
    from app.jobs.progress import ProgressBus

    writer = DBWriter(database)
    try:
        runner = DetectRunner(writer=writer, progress=ProgressBus(), settings=settings)
        asyncio.run(runner.run(DetectPayload(job_id=job_id, case_id=case_id, profile=profile)))
    finally:
        writer.stop()


def _request(path: Path, *, case_id: str, source_id: str, log_type: str, name: str) -> ParseRequest:
    """A picklable worker request for one file."""
    return ParseRequest(
        case_id=case_id,
        source_id=source_id,
        path=str(path),
        filename=name,
        log_type=log_type,
        max_line_bytes=1 << 20,
    )


@dataclass(frozen=True, slots=True)
class IngestResult:
    """The outcome of one ingest run."""

    events: int
    errors: int
    elapsed: float
    rss_bytes: int = 0
    error: str = ""

    @property
    def rate(self) -> float:
        """Events per second, or 0 when the run recorded no time."""
        return self.events / self.elapsed if self.elapsed > 0 else 0.0


def ingest_files(database: Database, requests: Sequence[ParseRequest]) -> IngestResult:
    """Parse every request concurrently with the real worker/writer split.

    Each request gets its own worker process and bounded queue; every queue is
    drained by a thread that hands batches to the one :class:`DBWriter`. This is
    the production topology, so the measured rate reflects the single-writer
    ceiling rather than several independent databases.
    """
    if not requests:
        return IngestResult(events=0, errors=0, elapsed=0.0)
    context = multiprocessing.get_context("spawn")
    manager = context.Manager()
    writer = DBWriter(database)
    outcomes: dict[str, dict[str, Any]] = {}
    processes: list[Any] = []
    drainers: list[threading.Thread] = []
    # Manager proxies are deregistered when their last reference is collected, so
    # every bridge (and the proxies it wraps) is kept alive for the whole run.
    keepers: list[Any] = []
    try:
        for request in requests:
            message_queue = manager.Queue(maxsize=64)
            cancelled = manager.Event()
            bridge = WorkerBridge(message_queue, cancelled)
            keepers.append(bridge)
            drainer = threading.Thread(
                target=_drain,
                args=(message_queue, writer, request.source_id, outcomes),
                name=f"perf-drain-{request.source_id}",
                daemon=True,
            )
            drainer.start()
            drainers.append(drainer)
            process = context.Process(target=parse_and_emit, args=(request, bridge))
            process.start()
            processes.append(process)

        start = time.perf_counter()
        for process in processes:
            process.join()
        for drainer in drainers:
            drainer.join(timeout=600)
        elapsed = time.perf_counter() - start
        writer.flush(timeout=600)
    finally:
        writer.stop()
        manager.shutdown()
    return IngestResult(
        events=sum(int(outcome["events"]) for outcome in outcomes.values()),
        errors=sum(int(outcome["errors"]) for outcome in outcomes.values()),
        elapsed=elapsed,
        error="; ".join(
            f"{source}: {outcome['note']}"
            for source, outcome in outcomes.items()
            if outcome["note"]
        ),
    )


def _drain(
    message_queue: Any,
    writer: DBWriter,
    source_id: str,
    outcomes: dict[str, dict[str, Any]],
) -> None:
    """Forward one worker's batches to the shared writer until it stops."""
    while True:
        tag, payload = message_queue.get()
        if tag == TAG_BATCH:
            writer.submit(source_id, payload.events, payload.failures, payload.ioc_hits)
        elif tag == TAG_DONE:
            summary: ParseSummary = payload
            outcomes[source_id] = {"events": summary.events, "errors": summary.errors, "note": ""}
            return
        elif tag in (TAG_ERROR, TAG_CANCELLED):
            outcomes[source_id] = {"events": 0, "errors": 0, "note": f"{tag}: {payload}"}
            return
        elif tag == TAG_STARTED:
            continue


def ingest_isolated(db_path: Path, request: ParseRequest) -> IngestResult:
    """Run one ingest in a fresh process and report that process's peak RSS.

    A clean process is the only way to attribute memory to ingest: measuring the
    pytest process would include every earlier benchmark's allocations.
    """
    context = multiprocessing.get_context("spawn")
    parent, child = context.Pipe(duplex=False)
    process = context.Process(target=_isolated_worker, args=(str(db_path), request, child))
    process.start()
    child.close()
    try:
        payload: dict[str, Any] = parent.recv()
    finally:
        parent.close()
        process.join(timeout=600)
    return IngestResult(
        events=int(payload["events"]),
        errors=int(payload["errors"]),
        elapsed=float(payload["elapsed"]),
        rss_bytes=int(payload["rss_bytes"]),
        error=str(payload.get("error", "")),
    )


def _isolated_worker(db_path: str, request: ParseRequest, connection: Any) -> None:
    """Child entry point: ingest one file, then report peak memory over a pipe."""
    database = Database(Path(db_path))
    try:
        result = _ingest_once(database, request)
        connection.send(
            {
                "events": result.events,
                "errors": result.errors,
                "elapsed": result.elapsed,
                "rss_bytes": peak_working_set_bytes(),
                "error": result.error,
            }
        )
    finally:
        connection.close()
        database.close()


def _ingest_once(database: Database, request: ParseRequest) -> IngestResult:
    """Parse one file in this process, draining its queue into a local writer."""
    message_queue: queue_module.Queue[Any] = queue_module.Queue(maxsize=64)
    cancelled = threading.Event()
    bridge = WorkerBridge(message_queue, cancelled)
    writer = DBWriter(database)
    box: dict[str, Any] = {}
    done = threading.Event()

    def drain() -> None:
        while True:
            tag, payload = message_queue.get()
            if tag == TAG_BATCH:
                writer.submit(request.source_id, payload.events, payload.failures, payload.ioc_hits)
            elif tag == TAG_DONE:
                box["summary"] = payload
                done.set()
                return
            elif tag in (TAG_ERROR, TAG_CANCELLED):
                box["terminal"] = tag
                box["detail"] = str(payload)
                done.set()
                return

    thread = threading.Thread(target=drain, name="perf-drain-local", daemon=True)
    thread.start()
    elapsed = 0.0
    try:
        start = time.perf_counter()
        parse_and_emit(request, bridge)
        done.wait(timeout=600)
        writer.flush(timeout=600)
        elapsed = time.perf_counter() - start
    finally:
        writer.stop()
    summary: ParseSummary = box.get("summary", ParseSummary())
    return IngestResult(
        events=summary.events,
        errors=summary.errors,
        elapsed=elapsed,
        error=box.get("detail", ""),
    )


def detect_isolated(db_path: Path, case_id: str, *, profile: str = "standard") -> IngestResult:
    """Run the detect pipeline in a fresh process, timing it and its peak RSS."""
    context = multiprocessing.get_context("spawn")
    parent, child = context.Pipe(duplex=False)
    process = context.Process(
        target=_detection_worker, args=(str(db_path), case_id, profile, child)
    )
    process.start()
    child.close()
    try:
        payload: dict[str, Any] = parent.recv()
    finally:
        parent.close()
        process.join(timeout=900)
    return IngestResult(
        events=int(payload["events"]),
        errors=0,
        elapsed=float(payload["elapsed"]),
        rss_bytes=int(payload["rss_bytes"]),
    )


def _detection_worker(db_path: str, case_id: str, profile: str, connection: Any) -> None:
    """Child entry point: run detection over a migrated database, report resources."""
    settings = load_settings(
        environ={
            "TRIAGELENS_STORAGE__DATA_DIR": str(Path(db_path).parent),
            "TRIAGELENS_LOGGING__CONSOLE": "false",
            "TRIAGELENS_LOGGING__LEVEL": "CRITICAL",
        }
    )
    database = Database(Path(db_path))
    try:
        start = time.perf_counter()
        run_detection(database, settings, case_id=case_id, profile=profile)
        elapsed = time.perf_counter() - start
        row = database.writer.execute(
            "SELECT COUNT(*) AS n FROM alerts WHERE case_id = ?", (case_id,)
        ).fetchone()
        connection.send(
            {
                "events": int(row["n"]) if row else 0,
                "elapsed": elapsed,
                "rss_bytes": peak_working_set_bytes(),
            }
        )
    finally:
        connection.close()
        database.close()


def _case_and_source(database: Database, case_id: str, source_id: str, log_type: str) -> None:
    """Seed the case and source rows inside one transaction."""
    with atomic(database.writer):
        seed_case_and_source(
            database.writer, case_id=case_id, source_id=source_id, log_type=log_type
        )


def test_text_ingest_single_worker(
    database: Database, tmp_path: Path, record_property: RecordProperty
) -> None:
    """One worker: parse + normalize + tier-1 IOC + persist (spec 09 section 8)."""
    source_id = "src-text-single"
    case_id = "perf-text"
    path = tmp_path / "single.ndjson"
    write_ecs_ndjson(path, TEXT_SINGLE_RECORDS)
    _case_and_source(database, case_id, source_id, "generic_json")

    result = ingest_isolated(
        database.path,
        _request(
            path, case_id=case_id, source_id=source_id, log_type="generic_json", name=path.name
        ),
    )
    assert result.events == TEXT_SINGLE_RECORDS, (
        f"parsed {result.events} of {TEXT_SINGLE_RECORDS}: {result.error}"
    )

    record_targets(
        record_property,
        Target(
            name="ingest.text_single_worker",
            value=result.rate,
            unit="events/s",
            limit=30_000,
            comparator="min",
            note=f"{_SCALE} scale, {TEXT_SINGLE_RECORDS} records",
        ),
    )


def test_text_ingest_multi_worker(
    database: Database, tmp_path: Path, record_property: RecordProperty
) -> None:
    """Four workers, one writer: aggregate text throughput (spec 09 section 8)."""
    requests = []
    for worker in range(TEXT_WORKERS):
        case_id = f"perf-text-multi-{worker}"
        source_id = f"src-text-multi-{worker}"
        path = tmp_path / f"multi-{worker}.ndjson"
        write_ecs_ndjson(path, TEXT_MULTI_RECORDS, host=f"bench-{worker}")
        _case_and_source(database, case_id, source_id, "generic_json")
        requests.append(
            _request(
                path,
                case_id=case_id,
                source_id=source_id,
                log_type="generic_json",
                name=path.name,
            )
        )

    result = ingest_files(database, requests)
    expected = TEXT_MULTI_RECORDS * TEXT_WORKERS
    assert result.events == expected, f"parsed {result.events} of {expected}: {result.error}"

    record_targets(
        record_property,
        Target(
            name="ingest.text_multi_worker",
            value=result.rate,
            unit="events/s",
            limit=100_000,
            comparator="min",
            note=f"{_SCALE} scale, {TEXT_WORKERS} workers x {TEXT_MULTI_RECORDS} records",
        ),
    )


def test_evtx_ingest(database: Database, record_property: RecordProperty) -> None:
    """EVTX parse + persist (spec 09 section 8)."""
    requests = []
    source_ids: list[str] = []
    repository = EventRepository(database.writer)
    fixtures = ("security_logons.evtx", "sysmon_attack.evtx", "account_changes.evtx")
    for index, name in enumerate(fixtures):
        case_id = f"perf-evtx-{index}"
        source_id = f"src-evtx-{index}"
        _case_and_source(database, case_id, source_id, "windows_evtx")
        source_ids.append(source_id)
        requests.append(
            _request(
                EVTX_FIXTURES / name,
                case_id=case_id,
                source_id=source_id,
                log_type="windows_evtx",
                name=name,
            )
        )

    result = ingest_files(database, requests)
    stored = sum(repository.count_for_source(source_id) for source_id in source_ids)
    assert result.events == stored, f"worker reported {result.events}, database holds {stored}"
    assert stored > 0, "the EVTX fixtures must yield records"

    record_targets(
        record_property,
        Target(
            name="ingest.evtx",
            value=result.rate,
            unit="records/s",
            limit=8_000,
            comparator="min",
            note=f"{_SCALE} scale, {stored} records from the committed fixtures",
        ),
    )


def test_detection_large_case(
    database: Database, settings: Settings, record_property: RecordProperty
) -> None:
    """A large case through the ``standard`` profile (spec 09 section 8)."""
    case_id = "perf-detect-case"
    _case_and_source(database, case_id, "src-detect", "linux_auth")
    bulk_insert_events(database, DETECT_EVENTS, case_id=case_id, source_id="src-detect")
    total_rules = sync_rules(database, settings)
    assert total_rules > 0, "the shipped catalogue must load"

    result = detect_isolated(database.path, case_id, profile="standard")
    assert result.elapsed > 0

    record_targets(
        record_property,
        Target(
            name="detect.large_case_time",
            value=result.elapsed,
            unit="s",
            limit=300,
            comparator="max",
            note=f"{_SCALE} scale, {DETECT_EVENTS} events, {total_rules} rules",
        ),
        Target(
            name="detect.large_case_rss",
            value=result.rss_bytes / (1024 * 1024),
            unit="MB",
            limit=2048,
            comparator="max",
            note=f"{_SCALE} scale, {DETECT_EVENTS} events",
        ),
    )


def test_events_api_latency(database: Database, record_property: RecordProperty) -> None:
    """The Events first page and an FTS query (spec 09 section 8)."""
    case_id = "perf-query"
    _case_and_source(database, case_id, "src-query", "linux_auth")
    bulk_insert_events(
        database, QUERY_EVENTS, case_id=case_id, source_id="src-query", rebuild_fts=True
    )

    with database.read_connection() as reader:
        repository = EventRepository(reader)

        def first_page() -> None:
            rows, _ = repository.search(
                EventFilters(case_id=case_id, host="HOST-03"), sort="-ts", limit=100
            )
            assert len(rows) > 0, "the indexed filter must return a page"

        def fts() -> None:
            rows, _ = repository.search(
                EventFilters(case_id=case_id, q="failed"), sort="-ts", limit=50
            )
            assert len(rows) > 0, "the FTS query must return a page"

        page_p95 = percentile(latency_samples(first_page, LATENCY_SAMPLES), 95) * 1000
        fts_p95 = percentile(latency_samples(fts, LATENCY_SAMPLES), 95) * 1000

    record_targets(
        record_property,
        Target(
            name="api.events_first_page",
            value=page_p95,
            unit="ms",
            limit=300,
            comparator="max",
            note=f"{_SCALE} scale, p95 over {LATENCY_SAMPLES} samples, indexed host filter",
        ),
        Target(
            name="api.fts_query",
            value=fts_p95,
            unit="ms",
            limit=1000,
            comparator="max",
            note=f"{_SCALE} scale, p95 over {LATENCY_SAMPLES} samples",
        ),
    )


def test_ingest_peak_memory(
    database: Database, tmp_path: Path, record_property: RecordProperty
) -> None:
    """Peak memory while ingesting a large text file (spec 09 section 8)."""
    case_id = "perf-memory"
    source_id = "src-memory"
    path = tmp_path / "memory.ndjson"
    byte_count = write_ecs_ndjson(path, MEMORY_RECORDS)
    _case_and_source(database, case_id, source_id, "generic_json")

    result = ingest_isolated(
        database.path,
        _request(
            path, case_id=case_id, source_id=source_id, log_type="generic_json", name=path.name
        ),
    )
    assert result.events == MEMORY_RECORDS, (
        f"parsed {result.events} of {MEMORY_RECORDS}: {result.error}"
    )

    record_targets(
        record_property,
        Target(
            name="ingest.peak_memory",
            value=result.rss_bytes / (1024 * 1024),
            unit="MB",
            limit=1536,
            comparator="max",
            note=f"{_SCALE} scale, {byte_count / (1024 * 1024):.1f} MB input",
        ),
    )
