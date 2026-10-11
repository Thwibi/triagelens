"""The single writer thread (spec 01 section 5, spec 02 section 4).

One connection writes, and it writes on one thread. Everything that persists
goes through :class:`DBWriter`'s queue, so a transaction is never open on two
threads at once and no caller has to know which thread owns the connection.

A batch is one transaction: the events, their FTS rows and their parse errors
commit together or not at all. A crash halfway through therefore leaves a source
with either all of its events or none, never a subset that silently becomes
evidence.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import sqlite3
import threading
from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import Future
from dataclasses import dataclass, field
from queue import Empty, Queue
from typing import Any

from app.db.connection import Database
from app.db.repositories.events import BATCH_SIZE, EventRepository
from app.db.repositories.iocs import IocRepository
from app.db.repositories.sources import ParseErrorRepository
from app.ingest.events import NormalizedEvent
from app.ingest.parsers.base import ParseFailure
from app.ioc import IocHit, aggregate

logger = logging.getLogger("jobs.writer")


@dataclass(slots=True)
class WriterTask:
    """One unit of work for the writer thread: events plus their failures.

    ``ioc_hits[i]`` carries the tier-1 IOC hits for ``events[i]``, if the worker
    produced any. They are stored in the same transaction as their events, so an
    indicator can never point at an event that was rolled back.
    """

    source_id: str
    events: list[NormalizedEvent] = field(default_factory=list)
    failures: list[ParseFailure] = field(default_factory=list)
    ioc_hits: list[list[IocHit]] | None = None

    def __bool__(self) -> bool:
        """False when there is nothing to write, so empty batches cost nothing."""
        return bool(self.events or self.failures)


@dataclass(slots=True)
class _Call:
    """A unit of work that is code rather than rows, run on the writer thread.

    Metadata writes (job progress, source status, counters) go through here for
    the same reason events do. SQLite has one connection in this process, and two
    threads issuing ``BEGIN`` on it produce "cannot start a transaction within a
    transaction" rather than any useful error. Routing every write through one
    thread makes that impossible by construction.
    """

    work: Callable[[sqlite3.Connection], Any]
    future: Future[Any] = field(default_factory=Future)
    #: False when the work failed, so the caller gets the exception it raised.
    transactional: bool = True


class _Flush:
    """A barrier: nothing queued before it is still uncommitted."""

    __slots__ = ("event",)

    def __init__(self) -> None:
        self.event = threading.Event()


class DBWriter:
    """Batched writer running on its own thread."""

    def __init__(self, database: Database, *, queue_size: int = 1000) -> None:
        self._database = database
        self._queue: Queue[Any] = Queue(maxsize=queue_size)
        self._running = True
        self._thread = threading.Thread(target=self._run, name="db-writer", daemon=True)
        self._thread.start()

    def submit(
        self,
        source_id: str,
        events: Sequence[NormalizedEvent],
        failures: Sequence[ParseFailure] = (),
        ioc_hits: list[list[IocHit]] | None = None,
    ) -> None:
        """Queue a batch. Returns immediately; the ingest loop is never blocked.

        ``source_id`` is explicit rather than read off the first event because a
        batch of pure parse failures has no event to read it from, and losing
        those failures would hide exactly the records an analyst needs to see.
        """
        task = WriterTask(
            source_id=source_id,
            events=list(events),
            failures=list(failures),
            ioc_hits=ioc_hits,
        )
        if task:
            self._queue.put(task)

    def flush(self, timeout: float = 30.0) -> bool:
        """Block until everything queued so far is committed.

        Used by shutdown and by tests that assert on stored rows. Returns False
        when the timeout expired, which means the writer is stuck rather than
        slow and the caller should treat the state as unknown.
        """
        barrier = _Flush()
        try:
            self._queue.put(barrier, timeout=timeout)
        except Exception:
            return False
        return barrier.event.wait(timeout)

    async def flush_async(self, timeout: float = 30.0) -> bool:  # noqa: ASYNC109
        """:meth:`flush` without blocking the event loop.

        The ingest loop calls this before reading source counters, and blocking
        the loop for the length of a write would stall every other request.
        """
        return await asyncio.to_thread(self.flush, timeout)

    def run(
        self,
        work: Callable[[sqlite3.Connection], Any],
        *,
        transactional: bool = True,
    ) -> Future[Any]:
        """Run ``work(connection)`` on the writer thread inside a transaction.

        Returns a future carrying the work's return value, or the exception it
        raised. Every write in the process goes through here or through
        :meth:`submit`, which is what makes the single-writer rule true rather
        than merely intended.

        ``transactional=False`` runs the work with no surrounding transaction on
        the writer thread. It exists for statements SQLite forbids inside a
        transaction (``VACUUM``); the work must then manage its own atomicity.
        """
        call = _Call(work=work, transactional=transactional)
        self._queue.put(call)
        return call.future

    async def run_async(self, work: Callable[[sqlite3.Connection], Any]) -> Any:
        """:meth:`run` awaited from the event loop."""
        return await asyncio.wrap_future(self.run(work))

    def stop(self, timeout: float = 30.0) -> None:
        """Drain what is queued, then stop the thread."""
        if not self._running:
            return
        self._running = False
        self.flush(timeout=timeout)
        with contextlib.suppress(Exception):
            self._queue.put(None)
        self._thread.join(timeout=timeout)

    def _run(self) -> None:
        """Drain the queue until asked to stop."""
        while True:
            try:
                item = self._queue.get(timeout=0.5)
            except Empty:
                if not self._running:
                    return
                continue
            try:
                if isinstance(item, _Flush):
                    item.event.set()
                elif item is None:
                    return
                elif isinstance(item, _Call):
                    self._call(item)
                elif isinstance(item, WriterTask):
                    self._write(item)
            except Exception:
                logger.exception("writer batch failed; continuing")
                if isinstance(item, _Flush):
                    item.event.set()

    def _call(self, call: _Call) -> None:
        """Run one piece of work on this thread and hand back what it produced."""
        try:
            if call.transactional:
                with self._database.transaction() as connection:
                    result = call.work(connection)
            else:
                # Statements SQLite forbids inside a transaction (VACUUM) run on
                # the bare writer connection; the work owns its own atomicity.
                result = call.work(self._database.writer)
        except BaseException as error:
            # The error travels back through the future rather than only being
            # logged: the caller asked for this work and can act on it.
            if not call.future.set_running_or_notify_cancel():
                return
            call.future.set_exception(error)
            return
        if not call.future.set_running_or_notify_cancel():
            return
        call.future.set_result(result)

    def _write(self, task: WriterTask) -> None:
        """Persist one batch as a single transaction."""
        with self._database.transaction() as connection:
            events_repo = EventRepository(connection)
            errors_repo = ParseErrorRepository(connection)
            for failure in task.failures:
                record_ref, reason, excerpt = failure.as_row()
                errors_repo.add(
                    source_id=task.source_id,
                    record_ref=record_ref,
                    reason=reason,
                    raw_excerpt=excerpt,
                )
            for start in range(0, len(task.events), BATCH_SIZE):
                chunk = task.events[start : start + BATCH_SIZE]
                # FTS rows share the transaction with their events, so a search
                # can never return a rowid whose event was rolled back.
                rowids = events_repo.insert_many(chunk)
                for event_id, event in zip(rowids, chunk, strict=True):
                    events_repo.add_fts(event_id, event)
                self._store_iocs(connection, task, chunk, rowids, start)

    @staticmethod
    def _store_iocs(
        connection: sqlite3.Connection,
        task: WriterTask,
        chunk: Sequence[NormalizedEvent],
        rowids: Sequence[int],
        start: int,
    ) -> None:
        """Persist this chunk's indicators against the events just inserted.

        Aggregation happens here rather than in the worker because only this
        thread knows the rowids, and ``ioc_occurrences.event_id`` needs them.
        """
        if not task.ioc_hits:
            return
        records: list[tuple[int, int | None, Iterable[IocHit]]] = []
        for offset, event in enumerate(chunk):
            index = start + offset
            if index >= len(task.ioc_hits) or not task.ioc_hits[index]:
                continue
            records.append((rowids[index], event.ts_ms, task.ioc_hits[index]))
        if not records:
            return
        groups = aggregate(records)
        case_id = chunk[0].case_id
        IocRepository(connection).store(case_id, groups)


__all__ = ["DBWriter", "WriterTask"]
