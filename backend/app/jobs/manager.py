"""The asyncio job manager (spec 01 sections 1 and 3).

One queue, one dispatcher, and worker processes for the CPU-bound parts.

Three rules shape this class:

- **A worker crash is not a server crash.** Parsing runs in a child process, so a
  parser that segfaults, exhausts memory or hits a pathological input kills only
  that worker. The manager notices the broken future and fails the job.
- **Exactly one writer.** Workers never touch the database; they stream batches
  to the API process, and :class:`~app.jobs.writer.DBWriter` persists them.
- **Cancellation is cooperative.** :meth:`cancel` sets a flag the ingest loop
  checks per batch, and the job's own cleanup removes partial events.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import contextlib
import logging
import threading
from collections.abc import Callable
from typing import Any

from app.jobs.progress import ProgressBus

logger = logging.getLogger("jobs.manager")

#: How long :meth:`stop` waits for the dispatcher to drain before cancelling it.
SHUTDOWN_TIMEOUT = 30.0


class JobManager:
    """Runs registered handlers for queued jobs, off the request thread."""

    __slots__ = (
        "_broken",
        "_cancelled",
        "_cancellers",
        "_executor",
        "_handlers",
        "_max_workers",
        "_progress",
        "_queue",
        "_running",
        "_tasks",
    )

    def __init__(
        self,
        progress: ProgressBus | None = None,
        *,
        max_workers: int | None = None,
    ) -> None:
        self._progress = progress
        self._max_workers = max_workers
        self._executor: concurrent.futures.ProcessPoolExecutor | None = None
        self._broken = False
        self._queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue()
        self._handlers: dict[str, Callable[[dict[str, Any]], Any]] = {}
        self._cancellers: dict[str, Callable[[str], None]] = {}
        self._cancelled: set[str] = set()
        self._tasks: set[asyncio.Task[None]] = set()
        self._running = False

    def register_handler(
        self,
        kind: str,
        handler: Callable[[dict[str, Any]], Any],
        *,
        on_cancel: Callable[[str], None] | None = None,
    ) -> None:
        """Bind a job kind to its handler, replacing any earlier binding.

        ``on_cancel`` is how a handler learns about a cancel it did not receive
        directly: the manager calls it with the job id, so a handler that owns
        its own cancellation set does not have to be reachable from here.
        """
        self._handlers[kind] = handler
        if on_cancel is not None:
            self._cancellers[kind] = on_cancel

    async def start(self) -> None:
        """Start the dispatcher and create the worker pool."""
        if self._running:
            return
        self._running = True
        self._executor = _make_executor(self._max_workers)
        self._tasks.add(asyncio.create_task(self._dispatch(), name="job-dispatcher"))

    async def stop(self) -> None:
        """Stop accepting work, let running jobs finish, then shut the pool down."""
        if not self._running:
            return
        self._running = False
        await self._queue.put(None)
        dispatcher = next(
            (task for task in self._tasks if task.get_name() == "job-dispatcher"), None
        )
        if dispatcher is not None:
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(dispatcher, timeout=SHUTDOWN_TIMEOUT)
            dispatcher.cancel()
        running = [task for task in self._tasks if task is not dispatcher]
        if running:
            done, pending = await asyncio.wait(running, timeout=SHUTDOWN_TIMEOUT)
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
            del done
        self._tasks.clear()
        if self._executor is not None:
            self._executor.shutdown(wait=True, cancel_futures=True)
            self._executor = None

    async def enqueue(self, job_id: str, payload: dict[str, Any]) -> None:
        """Queue a job. Returns as soon as it is on the queue, not when it starts."""
        await self._queue.put({**payload, "job_id": job_id})

    def cancel(self, job_id: str, kind: str | None = None) -> None:
        """Ask a running job to stop at its next checkpoint.

        The flag is kept here as well as in the handler so a cancel that arrives
        before the job starts is not lost.

        With no ``kind`` every registered canceller is told. The alternative --
        looking up ``cancellers.get(kind or "")`` -- silently matched nothing for a
        job id alone, so the API's cancel endpoint set the flag and the running
        ingest never saw it. Each canceller only ever adds a job id to its own
        set, so broadcasting is harmless and a cancel cannot be dropped by not
        knowing which kind it belongs to.
        """
        self._cancelled.add(job_id)
        cancellers = [self._cancellers[kind]] if kind in self._cancellers else []
        if not cancellers:
            cancellers = list(self._cancellers.values())
        for canceller in cancellers:
            canceller(job_id)

    def is_cancelled(self, job_id: str) -> bool:
        """True once :meth:`cancel` has been called for this job."""
        return job_id in self._cancelled

    def submit(self, function: Callable[..., Any], *args: Any) -> Any:
        """Run a CPU-bound function in a worker process.

        Returns whatever the caller needs to await it; the ingest runner wraps
        this so the choice of pool stays out of the handler.

        A pool whose worker died is rebuilt here rather than raising. Once
        ``ProcessPoolExecutor`` goes into its broken state every later ``submit``
        raises ``BrokenProcessPool`` too, so one parser that segfaults would
        otherwise take out every job queued after it -- the opposite of "a worker
        crash is not a server crash". The job that hit the crash still fails,
        which is what its own handler does with the exception.
        """
        if not self._running:
            raise RuntimeError("job manager is not started")
        if self._executor is None or self._broken:
            self._replace_executor()
        assert self._executor is not None
        future = self._executor.submit(function, *args)
        # Watch the future rather than the pool: ``_broken`` is private, and the
        # exception is the same signal. Marking here means the *next* submit gets a
        # fresh pool, and this job still sees the crash it caused.
        future.add_done_callback(self._note_pool_failure)
        return future

    def _note_pool_failure(self, future: concurrent.futures.Future[Any]) -> None:
        """Remember that the pool has lost a worker, so it gets rebuilt."""
        if future.cancelled():
            return
        error = future.exception()
        if isinstance(error, concurrent.futures.process.BrokenProcessPool):
            self._broken = True
            logger.warning("worker process died; the pool will be rebuilt")

    def _replace_executor(self) -> None:
        """Swap in a fresh pool, shutting the broken one down off the loop."""
        broken, self._executor = self._executor, _make_executor(self._max_workers)
        self._broken = False
        if broken is None:
            return
        # ``shutdown(wait=True)`` joins processes, which blocks, so it must not run
        # on the event loop.
        threading.Thread(
            target=broken.shutdown, kwargs={"wait": False}, name="pool-reaper", daemon=True
        ).start()

    async def _dispatch(self) -> None:
        """One job at a time, in queue order.

        Sequential on purpose: the writer thread is the bottleneck, so running
        jobs concurrently would only make each one slower and the progress
        frames less truthful.
        """
        while True:
            item = await self._queue.get()
            if item is None:
                return
            try:
                await self._run_one(item)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("job failed", extra={"job_id": item.get("job_id")})

    async def _run_one(self, item: dict[str, Any]) -> None:
        """Dispatch one job to its handler."""
        kind = str(item.get("kind", "ingest"))
        handler = self._handlers.get(kind)
        if handler is None:
            logger.error("no handler registered for job kind", extra={"kind": kind})
            return
        result = handler(item)
        if asyncio.iscoroutine(result):
            await result


def _make_executor(max_workers: int | None) -> concurrent.futures.ProcessPoolExecutor:
    """Build the worker pool.

    ``max_workers=None`` lets the pool size itself from the CPU count, which is
    what ``limits.worker_processes = 0`` means (cpu_count - 1).
    """
    return concurrent.futures.ProcessPoolExecutor(max_workers=max_workers)


__all__ = ["JobManager"]
