"""CPU-bound parsing in worker processes (spec 01 sections 1 and 3).

Parsing is the one part of ingest that must not run in the API process. A
malformed file, a pathological regex or a memory blow-up in a parser has to kill
a worker, never the server holding the analyst's case.

So the split is:

- **Worker process** (:func:`parse_and_emit`): reads a file through a
  :class:`~app.ingest.parsers.base.LogParser` and emits batches of events plus
  parse failures over a queue. It never touches the database: the writer
  connection belongs to one thread in the API process and a second writer would
  mean lock contention on every batch.
- **API process** (:mod:`app.jobs.tasks`): drains the queue, hands batches to the
  writer thread, publishes progress and owns job state.

The queue is bounded, which is what caps worker memory: a fast producer blocks
once the consumer falls behind instead of accumulating the whole file in RAM.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.ingest.events import NormalizedEvent
from app.ingest.parsers.base import (
    ParseContext,
    ParseFailure,
    load_builtin_parsers,
)
from app.ioc import Allowlist, IocHit, default_allowlist, extract_fields

#: Most IOC hits kept for one event, so a pathological record cannot balloon a
#: batch before it crosses the process boundary.
MAX_HITS_PER_EVENT = 100

#: ``(allowlist, decode_depth, keep_private_ips)`` loaded once per worker process.
#: ``Settings()`` is a full config parse and this sits on the hot path, so it is
#: cached in a box rather than rebuilt, and tests may reset it explicitly.
_SETTINGS_BOX: dict[str, tuple[Allowlist, int, bool]] = {}


def _extraction_settings() -> tuple[Allowlist, int, bool]:
    """The three extraction settings this process needs, loaded on first use."""
    if "cfg" not in _SETTINGS_BOX:
        from app.config import Settings

        settings = Settings()
        _SETTINGS_BOX["cfg"] = (
            default_allowlist(),
            settings.ioc.decode_depth,
            settings.ioc.extract_private_ips,
        )
    return _SETTINGS_BOX["cfg"]


def reset_extraction_settings() -> None:
    """Drop the cached settings so the next extraction re-reads configuration."""
    _SETTINGS_BOX.clear()


def extract_event_hits(event: NormalizedEvent) -> list[IocHit]:
    """Tier-1 IOC hits for one event (spec 05 section 1).

    Runs in the worker because it is CPU-bound text processing and belongs next
    to the parse loop, not in the API process holding the database connection.
    """
    allowlist, decode_depth, keep_private = _extraction_settings()
    hits = extract_fields(
        event.ioc_fields(),
        allowlist=allowlist,
        decode_depth=decode_depth,
        max_hits=MAX_HITS_PER_EVENT,
    )
    if keep_private:
        return hits
    return [hit for hit in hits if not hit.candidate.is_private]


#: Events per batch crossing the process boundary. Matches the writer's own
#: batch size so one emit maps to one transaction.
BATCH_SIZE = 5000

#: Message tags put on the queue by the worker.
TAG_STARTED = "started"
TAG_BATCH = "batch"
TAG_DONE = "done"
TAG_ERROR = "error"
TAG_CANCELLED = "cancelled"


@dataclass(frozen=True, slots=True)
class ParseRequest:
    """Everything a worker needs to parse one file, in picklable form.

    A dataclass of plain values rather than the live objects, because this
    crosses a process boundary and a ``Path`` or ``str`` survives pickling where
    a database connection does not.
    """

    case_id: str
    source_id: str
    #: Where the bytes are. Absolute, resolved at upload time.
    path: str
    #: The name as uploaded, used for format hints and error messages.
    filename: str
    log_type: str
    max_line_bytes: int
    timezone: str | None = None
    assumed_year: int | None = None
    forced_log_type: str | None = None
    batch_size: int = BATCH_SIZE


@dataclass(slots=True)
class ParseBatch:
    """One unit of work handed to the writer thread.

    ``ioc_hits[i]`` holds the tier-1 IOC hits for ``events[i]``; it is None only
    when nothing in the batch produced a hit, which keeps an empty list rather
    than 5000 empty ones on the wire.
    """

    events: list[NormalizedEvent] = field(default_factory=list)
    failures: list[ParseFailure] = field(default_factory=list)
    ioc_hits: list[list[IocHit]] | None = None


@dataclass(slots=True)
class ParseSummary:
    """What a completed parse produced, for the source counters."""

    events: int = 0
    errors: int = 0
    first_ts_ms: int | None = None
    last_ts_ms: int | None = None
    inventory: list[tuple[str, str, str, str, int]] = field(default_factory=list)


class WorkerBridge:
    """The worker's only way back to the API process.

    Everything in here has to survive pickling, because it is handed to a
    worker process. That rules out closures and lambdas, so the queue and the
    cancel event are manager proxies wrapped in a small class with methods
    instead of functions.

    The queue is bounded and every ``put`` blocks until the parent takes the
    batch. That is the memory guarantee: a file that parses faster than SQLite
    can store it cannot outrun the writer.
    """

    __slots__ = ("_cancelled", "_queue")

    def __init__(self, queue: Any, cancelled: Any) -> None:
        self._queue = queue
        self._cancelled = cancelled

    def put(self, tag: str, payload: Any) -> None:
        """Hand a message to the parent, blocking while the queue is full."""
        self._queue.put((tag, payload))

    def cancel(self) -> None:
        """Ask the worker to stop at its next record.

        Called from the parent process on the same proxy the worker polls, which
        is why the flag is a shared event rather than a copied dict.
        """
        self._cancelled.set()

    def is_cancelled(self) -> bool:
        """True once the parent has asked this job to stop."""
        return bool(self._cancelled.is_set())


def parse_and_emit(request: ParseRequest, bridge: WorkerBridge) -> ParseSummary:
    """Parse one file in a worker process, emitting batches over ``bridge``.

    Args:
        request: The file and how to read it.
        bridge: Picklable channel back to the parent. Cancellation is checked
            once per record, so a cancelled job stops without waiting for the
            file to end.

    Returns:
        Totals for the source counters. A cancelled or failed parse returns
        whatever it managed to count, which is what the parent reports before
        cleaning up.
    """
    bridge.put(TAG_STARTED, None)
    parser = load_builtin_parsers().get(request.log_type)
    if parser is None:
        bridge.put(
            TAG_ERROR,
            f"no parser is registered for log_type {request.log_type!r} in this build",
        )
        return ParseSummary()

    context = ParseContext(
        case_id=request.case_id,
        source_id=request.source_id,
        filename=request.filename,
        path=Path(request.path),
        max_line_bytes=request.max_line_bytes,
        timezone=request.timezone,
        assumed_year=request.assumed_year,
        forced_log_type=request.forced_log_type,
    )

    batch = ParseBatch()
    hits: list[list[IocHit]] = []
    try:
        for item in parser.parse(context):
            if bridge.is_cancelled():
                bridge.put(TAG_CANCELLED, None)
                return _summary(context)
            if isinstance(item, ParseFailure):
                batch.failures.append(item)
            else:
                batch.events.append(item)
                # Tier 1 runs here, next to the parse loop: it is CPU-bound and
                # must not sit in the API process holding the writer's connection.
                hits.append(extract_event_hits(item))
            # Both lists are measured: a file of nothing but malformed records
            # produces failures only, and those have to cross the boundary too.
            if len(batch.events) + len(batch.failures) >= request.batch_size:
                batch.ioc_hits = hits or None
                bridge.put(TAG_BATCH, _drain(batch))
                hits = []
    except MemoryError:
        # A hostile file drove the worker out of memory. Reporting rather than
        # dying silently lets the parent mark the source failed with a reason an
        # analyst can act on.
        bridge.put(TAG_ERROR, "parser ran out of memory reading this file")
        return _summary(context)
    except Exception as error:
        bridge.put(TAG_ERROR, f"{type(error).__name__}: {error}")
        return _summary(context)

    if batch.events or batch.failures:
        batch.ioc_hits = hits or None
        bridge.put(TAG_BATCH, _drain(batch))
    summary = _summary(context)
    bridge.put(TAG_DONE, summary)
    return summary


def _drain(batch: ParseBatch) -> ParseBatch:
    """Hand this batch over and leave the caller's empty, ready for the next one.

    Both halves are required, and getting either one wrong duplicates evidence:

    - The emitted batch is a *copy*. Handing over the caller's own lists would let
      the clearing below empty the batch the parent is about to store, so the
      parent would write nothing while the counters reported every event.
    - The caller's lists are cleared. Copying without clearing leaves the source
      batch full, so the next record trips the size check again and the batch grows
      by one on every emit -- a file of 2x the batch size stored every event twice,
      and a larger one emitted quadratically many events and never finished.

    ``ioc_hits`` needs no clearing: the caller builds it fresh for every batch and
    hands it over whole, so it cannot be re-used behind the parent's back.

    Evidence is counted once. Storing the same record twice is not a rounding
    error, it is a different case.
    """
    emitted = ParseBatch(
        events=list(batch.events),
        failures=list(batch.failures),
        ioc_hits=batch.ioc_hits,
    )
    batch.events.clear()
    batch.failures.clear()
    batch.ioc_hits = None
    return emitted


def _summary(context: ParseContext) -> ParseSummary:
    """Read the running totals off the parse context."""
    counters = context.counters
    return ParseSummary(
        events=counters.events,
        errors=counters.errors,
        first_ts_ms=counters.first_ts_ms,
        last_ts_ms=counters.last_ts_ms,
        inventory=counters.inventory_rows(),
    )


__all__ = [
    "BATCH_SIZE",
    "MAX_HITS_PER_EVENT",
    "TAG_BATCH",
    "TAG_CANCELLED",
    "TAG_DONE",
    "TAG_ERROR",
    "TAG_STARTED",
    "ParseBatch",
    "ParseRequest",
    "ParseSummary",
    "WorkerBridge",
    "extract_event_hits",
    "parse_and_emit",
    "reset_extraction_settings",
]
