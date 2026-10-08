"""The ingest job: intake results in, stored events out (spec 01 section 3).

This is the parent half of the worker split described in
:mod:`app.jobs.parsing`. It owns everything a worker must not: job state, the
source rows, progress messages and the single writer thread.

Stages, each of which updates ``jobs.progress`` and emits a WebSocket frame:

1. **parse** - a worker process streams batches, which go straight to the writer.
2. **inventory** - distinct ``(log_type, channel, app_name, ls_category)``.
3. **finalize** - counters, status, audit entry.

Detection already ran at upload time, because that is when the bytes arrived and
the operator could still be asked. A source whose format was not decided is
parked in ``needs_input`` here rather than guessed at.

Cancellation is checked per batch rather than per file: a cancel that waits for
a 10 GB file to finish is not a cancel. When it fires, the events already written
for that source are removed, because partial events for a cancelled source would
look like complete evidence (spec 01 section 3).
"""

from __future__ import annotations

import asyncio
import multiprocessing
import queue as queue_lib
import sqlite3
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from app.db.connection import Database
from app.db.repositories.events import EventRepository
from app.db.repositories.iocs import IocRepository
from app.db.repositories.jobs import JobRepository
from app.db.repositories.sources import (
    InventoryRepository,
    ParseErrorRepository,
    SourceRepository,
)
from app.jobs.parsing import (
    TAG_BATCH,
    TAG_CANCELLED,
    TAG_DONE,
    TAG_ERROR,
    ParseBatch,
    ParseRequest,
    ParseSummary,
    WorkerBridge,
    parse_and_emit,
)
from app.jobs.progress import ProgressBus
from app.jobs.writer import DBWriter
from app.models.job import JobRecord, JobStatus
from app.models.source import SourceRecord, SourceStatus
from app.util.logging import get_logger

logger = get_logger("jobs.tasks")

#: How long the parent waits for the next worker message before checking whether
#: the worker is still alive. Generous, because one very long line can take a
#: while, but bounded so a dead worker does not hang the job forever.
WORKER_POLL_SECONDS = 2.0

#: Stage names published over the WebSocket.
STAGE_PARSE = "parsing"
STAGE_INVENTORY = "inventory"
STAGE_FINALIZE = "finalizing"

#: Batches allowed to sit between the worker and the parent. Small on purpose:
#: the worker's ``put`` blocks once this is full, which is what stops a fast
#: parse from filling the API process's memory with a whole 10 GB file.
WORKER_QUEUE_DEPTH = 2

#: How long the parent waits for the reader to forward the messages a worker has
#: already put on the queue, after that worker's future resolved. Long enough for
#: the worst-case queue drain, short enough that a lost reader fails the job
#: rather than hanging it.
WORKER_DRAIN_TIMEOUT = 10.0

#: How long the parent waits for the writer to drain before it reads counters.
WRITER_FLUSH_TIMEOUT = 60.0

#: Longest error_detail stored on a source row.
MAX_ERROR_DETAIL = 2000


class Outcome:
    """Result of one source's ingest."""

    DONE = "done"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass(frozen=True, slots=True)
class SourcePlan:
    """One file to parse: what intake stored and what detection decided."""

    source_id: str
    case_id: str
    path: str
    filename: str
    #: ``None`` when the operator must choose, which parks the source.
    log_type: str | None
    detect_confidence: float | None = None
    timezone: str | None = None
    assumed_year: int | None = None
    #: Candidates offered when ``log_type`` is ``None``.
    candidates: list[dict[str, Any]] = field(default_factory=list)
    #: The uploaded container, when this plan is one member of an archive.
    parent_source_id: str | None = None


@dataclass(frozen=True, slots=True)
class IngestPayload:
    """What the API hands the job manager when it enqueues an ingest."""

    job_id: str
    case_id: str
    plans: list[SourcePlan]


class IngestRunner:
    """Runs one ingest job end to end.

    Constructed once per application with the live dependencies, so the job
    manager can register it as a plain handler.
    """

    __slots__ = (
        "_cancelled",
        "_database",
        "_max_line_bytes",
        "_process_manager",
        "_progress",
        "_readers",
        "_submit",
        "_writer",
    )

    def __init__(
        self,
        *,
        database: Database,
        writer: DBWriter,
        progress: ProgressBus,
        submit: Callable[..., Any],
        max_line_bytes: int,
    ) -> None:
        self._database = database
        self._writer = writer
        self._progress = progress
        #: The manager's worker submission, injected so tests can run in-process.
        self._submit = submit
        self._max_line_bytes = max_line_bytes
        self._cancelled: set[str] = set()
        self._process_manager: Any = None
        self._readers: set[threading.Event] = set()

    async def shutdown(self) -> None:
        """Stop the reader threads and the manager process.

        Async because the manager is a child process: joining it from the event
        loop thread would block every request during shutdown.
        """
        for done in list(self._readers):
            done.set()
        self._readers.clear()
        if self._process_manager is not None:
            manager, self._process_manager = self._process_manager, None
            await asyncio.to_thread(manager.shutdown)

    def cancel(self, job_id: str) -> None:
        """Request cancellation; the parse loop checks it per record."""
        self._cancelled.add(job_id)

    def is_cancelled(self, job_id: str) -> bool:
        """True once :meth:`cancel` has been called for this job."""
        return job_id in self._cancelled

    async def __call__(self, payload: dict[str, Any]) -> None:
        """Job-manager handler entry point."""
        try:
            request = decode_payload(payload)
        except (KeyError, TypeError, ValueError) as error:
            logger.error("ingest payload was unusable", extra={"detail": str(error)})
            return
        await self.run(request)

    async def run(self, request: IngestPayload) -> None:
        """Parse every planned source, then finalize the job."""
        started = time.monotonic()
        # A cancel that arrived while the job was still queued has to stop it here.
        # Without this the job would start a worker, and only notice the flag at its
        # first batch -- so a cancelled upload still parsed the whole file.
        if self.is_cancelled(request.job_id):
            # A job cancelled before it starts still owns its sources, so they are
            # moved off "queued" here. Leaving them queued would show the analyst
            # files that no job will ever pick up again.
            await self._cancel_sources(request.plans, job_id=request.job_id)
            await self._finish(request.job_id, JobStatus.CANCELLED, "cancelled")
            self._cancelled.discard(request.job_id)
            return
        await self._start_job(request.job_id)
        try:
            await self._stage(request.job_id, STAGE_PARSE, 0.0, "parsing", case_id=request.case_id)
            # Park the sources whose format was not decided, then ingest the rest
            # anyway: one unrecognised member of an archive must not hold up the
            # files that were recognised.
            await self._park_undecided(request)
            parseable = [plan for plan in request.plans if plan.log_type is not None]
            total = len(parseable)
            for index, plan in enumerate(parseable):
                outcome = await self._ingest_source(request.job_id, plan)
                if outcome is Outcome.CANCELLED:
                    await self._finish(request.job_id, JobStatus.CANCELLED, "cancelled")
                    return
                await self._stage(
                    request.job_id,
                    STAGE_PARSE,
                    (index + 1) / total if total else 1.0,
                    f"parsed {index + 1} of {total}",
                    case_id=request.case_id,
                )
            # Inventory is accumulated per source inside _finalize_source, so the
            # stage is published here only to keep the WebSocket honest about
            # what the job is doing.
            await self._stage(
                request.job_id,
                STAGE_INVENTORY,
                1.0,
                "building inventory",
                case_id=request.case_id,
            )
            await self._stage(
                request.job_id,
                STAGE_FINALIZE,
                1.0,
                "finalizing",
                case_id=request.case_id,
            )
            status = JobStatus.DONE
            message = f"ingested {total} source(s)"
            if total != len(request.plans):
                status = JobStatus.NEEDS_INPUT
                message = f"ingested {total} of {len(request.plans)} source(s)"
            await self._finish(request.job_id, status, message)
        except Exception as error:
            logger.exception("ingest job failed", extra={"job_id": request.job_id})
            await self._fail_sources(request.plans, "ingest job failed")
            await self._finish(
                request.job_id,
                JobStatus.FAILED,
                "ingest failed",
                error=f"{type(error).__name__}: {error}",
            )
            await self._progress.error("INTERNAL", "ingest failed")
            return
        finally:
            self._cancelled.discard(request.job_id)
        logger.info(
            "ingest job finished",
            extra={
                "job_id": request.job_id,
                "case_id": request.case_id,
                "seconds": round(time.monotonic() - started, 3),
            },
        )

    async def _park_undecided(self, request: IngestPayload) -> None:
        """Park every source whose format was not decided.

        The source waits in ``needs_input`` until the operator resolves it, which
        re-parses it under a new job (spec 06 section 3). No guess is made: a
        confidently wrong format would silently corrupt the event stream.
        """
        for plan in request.plans:
            if plan.log_type is not None:
                continue
            record = await self._set_status_and_read(plan.source_id, SourceStatus.NEEDS_INPUT)
            if record is not None:
                await self._progress.source_update(source_payload(record), job_id=request.job_id)
            await self._progress.needs_input(
                request.job_id,
                plan.source_id,
                plan.candidates,
                case_id=request.case_id,
            )

    async def _ingest_source(self, job_id: str, plan: SourcePlan) -> str:
        """Parse one source to completion, writing batches as they arrive."""
        request = ParseRequest(
            case_id=plan.case_id,
            source_id=plan.source_id,
            path=plan.path,
            filename=plan.filename,
            log_type=plan.log_type or "",
            max_line_bytes=self._max_line_bytes,
            timezone=plan.timezone,
            assumed_year=plan.assumed_year,
            forced_log_type=plan.log_type,
        )
        await self._writer.run_async(
            lambda connection: SourceRepository(connection).set_status(
                plan.source_id, SourceStatus.PARSING
            )
        )

        bridge, messages, reader = self._open_bridge(plan)
        # The pool hands back a concurrent.futures.Future; wrap_future adapts it to
        # the event loop so this code can await it like any other awaitable.
        future = asyncio.wrap_future(self._submit(parse_and_emit, request, bridge))

        inventory: list[tuple[str, str, str, str, int]] = []
        try:
            outcome, inventory = await self._drain_worker(job_id, plan, bridge, messages, future)
        except asyncio.CancelledError:
            bridge.cancel()
            await self._discard_source(plan.source_id, SourceStatus.CANCELLED)
            raise
        except Exception as error:
            # A worker that segfaults or is killed leaves the job running but the
            # parse unfinished. The job is failed, the server is untouched.
            logger.warning(
                "ingest worker failed",
                extra={"source_id": plan.source_id, "detail": f"{type(error).__name__}"},
            )
            await self._fail_source(plan, f"worker failed: {type(error).__name__}", job_id)
            return Outcome.FAILED
        finally:
            self._close_bridge(reader)

        if outcome is not Outcome.DONE:
            return outcome

        # The parser's tally can be ahead of what is stored, because the writer
        # is asynchronous. Counters are read from the database, so they are only
        # taken after the queue has actually drained.
        await self._writer.flush_async(WRITER_FLUSH_TIMEOUT)
        await self._finalize_source(plan, inventory)
        return Outcome.DONE

    async def _drain_worker(
        self,
        job_id: str,
        plan: SourcePlan,
        bridge: WorkerBridge,
        messages: asyncio.Queue[tuple[str, Any]],
        future: asyncio.Future[Any],
    ) -> tuple[str, list[tuple[str, str, str, str, int]]]:
        """Read worker messages until the source ends, writing batches as they land.

        Returns the outcome and, when the parse finished normally, the worker's
        inventory tally.
        """
        events = errors = 0
        started = time.monotonic()
        inventory: list[tuple[str, str, str, str, int]] = []
        # Set once the worker has returned and only the reader may still be
        # holding messages. The queue is ordered, so whatever the worker sent is
        # already behind TAG_DONE; this window is the time the reader needs to
        # forward it, not a guess about whether the worker is alive.
        draining_since: float | None = None
        while True:
            if self.is_cancelled(job_id):
                bridge.cancel()
            try:
                tag, payload = await asyncio.wait_for(messages.get(), timeout=WORKER_POLL_SECONDS)
            except TimeoutError:
                if not future.done():
                    continue
                # The worker has returned. If the reader delivers nothing within
                # the grace window there is nothing left to deliver, and waiting
                # longer would turn a finished source into a hung job.
                if draining_since is None:
                    draining_since = time.monotonic()
                elif time.monotonic() - draining_since >= WORKER_DRAIN_TIMEOUT:
                    await future
                    return Outcome.DONE, inventory
                continue
            draining_since = None

            if tag == TAG_BATCH and isinstance(payload, ParseBatch):
                self._writer.submit(
                    plan.source_id, payload.events, payload.failures, payload.ioc_hits
                )
                events += len(payload.events)
                errors += len(payload.failures)
                await self._progress.job_stage(
                    job_id,
                    STAGE_PARSE,
                    0.0,
                    events=events,
                    errors=errors,
                    rate_eps=_rate(events, started),
                    case_id=plan.case_id,
                )
            elif tag == TAG_CANCELLED:
                await self._discard_source(plan.source_id, SourceStatus.CANCELLED)
                return Outcome.CANCELLED, []
            elif tag == TAG_ERROR:
                await self._fail_source(plan, str(payload), job_id)
                return Outcome.FAILED, []
            elif tag == TAG_DONE:
                # The worker's tally of (log_type, channel, app_name,
                # ls_category) counts is what source_inventory stores; it cannot
                # be recovered from the events afterwards without a second scan.
                if isinstance(payload, ParseSummary):
                    inventory = payload.inventory
                await future
                return Outcome.DONE, inventory

    def _open_bridge(
        self, plan: SourcePlan
    ) -> tuple[WorkerBridge, asyncio.Queue[tuple[str, Any]], threading.Event]:
        """Set up the worker's channel and the queue the parent reads from.

        The worker blocks in ``put`` while the parent is behind, and a reader
        thread moves each message onto the event loop. No message is ever dropped:
        dropping a batch would silently lose evidence, which is the one failure
        mode this pipeline must not have.
        """
        manager = self._manager()
        queue = manager.Queue(maxsize=WORKER_QUEUE_DEPTH)
        cancel = manager.Event()
        bridge = WorkerBridge(queue, cancel)
        messages: asyncio.Queue[tuple[str, Any]] = asyncio.Queue()
        loop = asyncio.get_running_loop()
        done = threading.Event()
        self._readers.add(done)

        def pump() -> None:
            """Forward worker messages onto the event loop until the job is over.

            This thread is the only reader of the manager queue, so it must not
            exit early: a dropped message is dropped evidence. It stops when the
            caller's ``done`` event is set (see :meth:`_close_bridge`), which
            happens after the worker has finished and the queue has drained.
            """
            try:
                while not done.is_set():
                    try:
                        message = queue.get(timeout=WORKER_POLL_SECONDS)
                    except queue_lib.Empty:
                        # Silence from the worker is normal between batches; the
                        # event loop decides whether that silence means "slow" or
                        # "dead" by looking at the worker's future.
                        continue
                    except (EOFError, OSError, BrokenPipeError):
                        # The manager process went away, so no more messages can
                        # arrive. The loop notices via the failed future.
                        break
                    loop.call_soon_threadsafe(messages.put_nowait, message)
            finally:
                self._readers.discard(done)

        threading.Thread(target=pump, name="ingest-reader", daemon=True).start()
        del plan  # the bridge is per-source but does not need the plan itself
        return bridge, messages, done

    def _close_bridge(self, done: threading.Event) -> None:
        """Stop a source's reader thread once its worker is finished with it."""
        done.set()

    def _manager(self) -> Any:
        """Return the process manager, creating it once on first use."""
        if self._process_manager is None:
            self._process_manager = multiprocessing.Manager()
        return self._process_manager

    async def _finalize_source(
        self, plan: SourcePlan, inventory: list[tuple[str, str, str, str, int]]
    ) -> None:
        """Store inventory and counters once the worker has drained.

        The counts come from the database rather than from the parser's tally:
        the writer is asynchronous, so the parser's number can be ahead of what
        is actually stored, and a source row that disagrees with its events is
        worse than a slightly stale progress frame.
        """
        await self._writer.run_async(
            lambda connection: _finalize_on_connection(connection, plan.source_id, inventory)
        )

    async def _discard_source(self, source_id: str, status: SourceStatus) -> None:
        """Remove partial events so a stopped source shows no half-ingest."""
        await self._writer.run_async(
            lambda connection: _discard_on_connection(connection, source_id, status)
        )

    async def _set_status_and_read(
        self, source_id: str, status: SourceStatus, **extra: Any
    ) -> SourceRecord | None:
        """Set a source's status and read the row back, on the writer thread.

        Read-your-write matters here: the row is about to be published over the
        WebSocket, and a frame showing a status the row does not have is worse than
        a slightly late one.
        """
        record: SourceRecord | None = await self._writer.run_async(
            lambda connection: _set_status_and_get(connection, source_id, status, **extra)
        )
        return record

    async def _fail_source(self, plan: SourcePlan, detail: str, job_id: str) -> None:
        """Mark one source failed and say why, without guessing the reason code."""
        record = await self._set_status_and_read(
            plan.source_id, SourceStatus.FAILED, error_detail=detail[:MAX_ERROR_DETAIL]
        )
        if record is not None:
            await self._progress.source_update(source_payload(record), job_id=job_id)
        await self._progress.error(_error_code_for(detail), detail[:MAX_ERROR_DETAIL])

    async def _fail_sources(self, plans: Sequence[SourcePlan], detail: str) -> None:
        """Mark every planned source failed, used when the job itself could not run."""
        for plan in plans:
            await self._set_status(plan.source_id, SourceStatus.FAILED, error_detail=detail)

    async def _cancel_sources(self, plans: Sequence[SourcePlan], *, job_id: str) -> None:
        """Move never-started sources to cancelled and publish each one."""
        for plan in plans:
            record = await self._set_status_and_read(plan.source_id, SourceStatus.CANCELLED)
            if record is not None:
                await self._progress.source_update(source_payload(record), job_id=job_id)

    async def _set_status(self, source_id: str, status: SourceStatus, **extra: Any) -> None:
        """Set one source's status on the writer thread."""
        await self._writer.run_async(
            lambda connection: SourceRepository(connection).set_status(source_id, status, **extra)
        )

    async def _start_job(self, job_id: str) -> None:
        record = await self._writer.run_async(
            lambda connection: _start_on_connection(connection, job_id)
        )
        if record is not None:
            await self._progress.job_update(record)

    async def _stage(
        self,
        job_id: str,
        stage: str,
        progress: float,
        message: str,
        case_id: str | None = None,
    ) -> None:
        """Persist a stage and publish it, in that order."""
        await self._writer.run_async(
            lambda connection: JobRepository(connection).progress(
                job_id, progress=progress, stage=stage, message=message
            )
        )
        await self._progress.job_stage(job_id, stage, progress, case_id=case_id)

    async def _finish(
        self,
        job_id: str,
        status: JobStatus,
        message: str | None = None,
        *,
        error: str | None = None,
    ) -> None:
        record = await self._writer.run_async(
            lambda connection: _finish_on_connection(connection, job_id, status, message, error)
        )
        if record is not None:
            await self._progress.job_update(record)


def _set_status_and_get(
    connection: sqlite3.Connection,
    source_id: str,
    status: SourceStatus,
    **extra: Any,
) -> SourceRecord | None:
    """Set a source's status and hand back the row the UI should be shown."""
    sources = SourceRepository(connection)
    sources.set_status(source_id, status, **extra)
    return sources.get(source_id)


def _start_on_connection(connection: sqlite3.Connection, job_id: str) -> JobRecord | None:
    """Move a job into running and return it, for the first progress frame."""
    jobs = JobRepository(connection)
    jobs.start(job_id, stage=STAGE_PARSE)
    return jobs.get(job_id)


def _finish_on_connection(
    connection: sqlite3.Connection,
    job_id: str,
    status: JobStatus,
    message: str | None,
    error: str | None,
) -> JobRecord | None:
    """Move a job to its terminal status and return it, for the final frame."""
    jobs = JobRepository(connection)
    jobs.finish(job_id, status=status, message=message, error=error)
    return jobs.get(job_id)


def _finalize_on_connection(
    connection: sqlite3.Connection,
    source_id: str,
    inventory: list[tuple[str, str, str, str, int]],
) -> None:
    """Write one source's counters, status and inventory in one transaction.

    All three are read or written together on purpose: a source marked ``done``
    with counters from a different transaction is worse than a slightly late one.
    """
    events = EventRepository(connection)
    sources = SourceRepository(connection)
    sources.set_counters(
        source_id,
        event_count=events.count_for_source(source_id),
        error_count=ParseErrorRepository(connection).count_for_source(source_id),
        first_event_ms=events.time_range_for_source(source_id)[0],
        last_event_ms=events.time_range_for_source(source_id)[1],
    )
    sources.set_status(source_id, SourceStatus.DONE)
    InventoryRepository(connection).replace_for_source(source_id, inventory)


def _discard_on_connection(
    connection: sqlite3.Connection, source_id: str, status: SourceStatus
) -> None:
    """Remove a source's partial events and zero its counters.

    The affected indicators are snapshotted before the events go: deleting them
    cascades the occurrence rows away, and the ``iocs.occurrences`` count would
    otherwise keep a number that no longer has a row behind it. Indicators left
    with no occurrence anywhere are dropped entirely.
    """
    iocs = IocRepository(connection)
    affected = iocs.snapshot_for_source(source_id)
    EventRepository(connection).delete_for_source(source_id)
    iocs.recompute(affected)
    ParseErrorRepository(connection).clear_for_source(source_id)
    sources = SourceRepository(connection)
    sources.set_counters(
        source_id, event_count=0, error_count=0, first_event_ms=None, last_event_ms=None
    )
    sources.set_status(source_id, status)


def _error_code_for(detail: str) -> str:
    """Pick the spec 06 code that matches why a source failed.

    The UI decides whether to offer a retry or a different format from this code,
    so an unrecognised format must not be reported as an internal error or the
    other way round.
    """
    lowered = detail.lower()
    if "parser" in lowered or "out of memory" in lowered or "worker failed" in lowered:
        return "INTERNAL"
    return "UNSUPPORTED_FORMAT"


def _rate(events: int, started: float) -> int:
    """Events per second so far, never a division by zero."""
    elapsed = time.monotonic() - started
    return int(events / elapsed) if elapsed > 0 else 0


def source_payload(record: SourceRecord) -> dict[str, Any]:
    """Source row as the WebSocket ``source.update`` frame carries it."""
    return {
        "id": record.id,
        "case_id": record.case_id,
        "filename": record.filename,
        "parent_source_id": record.parent_source_id,
        "log_type": record.log_type,
        "detect_confidence": record.detect_confidence,
        "timezone": record.timezone,
        "assumed_year": record.assumed_year,
        "status": record.status.value,
        "event_count": record.event_count,
        "error_count": record.error_count,
        "first_event_ms": record.first_event_ms,
        "last_event_ms": record.last_event_ms,
        "error_detail": record.error_detail,
    }


def decode_payload(payload: dict[str, Any]) -> IngestPayload:
    """Rebuild the payload the manager queued."""
    plans: list[SourcePlan] = []
    for item in payload.get("plans") or []:
        log_type = item.get("log_type")
        plans.append(
            SourcePlan(
                source_id=str(item["source_id"]),
                case_id=str(item["case_id"]),
                path=str(item["path"]),
                filename=str(item["filename"]),
                log_type=str(log_type) if log_type else None,
                detect_confidence=item.get("detect_confidence"),
                timezone=item.get("timezone"),
                assumed_year=item.get("assumed_year"),
                candidates=list(item.get("candidates") or []),
                parent_source_id=item.get("parent_source_id"),
            )
        )
    return IngestPayload(
        job_id=str(payload["job_id"]),
        case_id=str(payload["case_id"]),
        plans=plans,
    )


def encode_payload(job_id: str, case_id: str, plans: Sequence[SourcePlan]) -> dict[str, Any]:
    """Flatten a payload for the job queue, which is JSON-ish in tests."""
    return {
        "job_id": job_id,
        "case_id": case_id,
        "plans": [
            {
                "source_id": plan.source_id,
                "case_id": plan.case_id,
                "path": plan.path,
                "filename": plan.filename,
                "log_type": plan.log_type,
                "detect_confidence": plan.detect_confidence,
                "timezone": plan.timezone,
                "assumed_year": plan.assumed_year,
                "candidates": plan.candidates,
                "parent_source_id": plan.parent_source_id,
            }
            for plan in plans
        ],
    }


__all__ = [
    "IngestPayload",
    "IngestRunner",
    "Outcome",
    "SourcePlan",
    "decode_payload",
    "encode_payload",
    "source_payload",
]
