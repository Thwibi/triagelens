"""The parser contract (spec 03 sections 1 and 7).

Every format is a small object with two jobs: say how much it recognizes a file
looks like (:meth:`LogParser.sniff`), and turn that file into events
(:meth:`LogParser.parse`). Detection asks the first; ingest asks the second.

The one rule a parser cannot bend is spec 03 section 7 item 2: every input record
produces exactly one event *or* one ``parse_errors`` row. A parser that silently
drops a malformed line loses evidence without recording that it did, so
:meth:`LogParser.parse` yields a :class:`ParseFailure` instead.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from app.ingest.events import NormalizedEvent
from app.ingest.text import TextHead


@dataclass(slots=True)
class ParseCounters:
    """Running totals for a parse pass, for the source row and the UI."""

    events: int = 0
    errors: int = 0
    first_ts_ms: int | None = None
    last_ts_ms: int | None = None
    truncated_lines: int = 0
    #: (log_type, channel, app_name, ls_category) -> count, for source_inventory.
    inventory: dict[tuple[str, str, str, str], int] = field(default_factory=dict)

    def record_event(self, event: NormalizedEvent) -> None:
        """Fold one event into the counters and the inventory."""
        self.events += 1
        if event.ts_ms is not None:
            if self.first_ts_ms is None or event.ts_ms < self.first_ts_ms:
                self.first_ts_ms = event.ts_ms
            if self.last_ts_ms is None or event.ts_ms > self.last_ts_ms:
                self.last_ts_ms = event.ts_ms
        key = (event.log_type, event.channel or "", event.app_name or "", event.ls_category or "")
        self.inventory[key] = self.inventory.get(key, 0) + 1

    def record_failure(self) -> None:
        """Count one malformed record."""
        self.errors += 1

    def inventory_rows(self) -> list[tuple[str, str, str, str, int]]:
        """Inventory tuples for ``InventoryRepository.replace_for_source``."""
        return [
            (log_type, channel, app_name, ls_category, count)
            for (log_type, channel, app_name, ls_category), count in sorted(self.inventory.items())
        ]


@dataclass(slots=True)
class ParseContext:
    """Everything a parser may need that is not in the file itself."""

    case_id: str
    source_id: str
    #: The filename as uploaded, used for format hints and error messages. It is
    #: never used as a path on disk.
    filename: str
    #: Where the bytes actually are.
    path: Path
    max_line_bytes: int
    #: Timezone used to interpret timestamps that carry no offset.
    timezone: str | None = None
    #: Year assumed for syslog timestamps that omit one.
    assumed_year: int | None = None
    #: Set when the user overrode detection for this source.
    forced_log_type: str | None = None
    #: Filled in as the parser yields, so the ingest stage can report totals
    #: without the parser having to return them.
    counters: ParseCounters = field(default_factory=ParseCounters)


@dataclass(slots=True)
class ParseFailure:
    """One input record that could not be turned into an event."""

    record_ref: str
    reason: str
    raw_excerpt: str | None = None

    def as_row(self) -> tuple[str, str, str | None]:
        """Values for the ``parse_errors`` insert."""
        return (self.record_ref, self.reason, self.raw_excerpt)


@runtime_checkable
class LogParser(Protocol):
    """A format handler.

    Implementations must be stateless with respect to a run: all per-source
    state belongs in local variables, because a parser instance may be reused
    across sources and lives in a worker process.
    """

    #: One of the ``log_type`` values in spec 02 section 3.
    log_type: str

    def sniff(self, head: TextHead) -> float:
        """How much this file looks like this format, from 0.0 to 1.0.

        Only the bounded prefix is supplied, so an implementation must not read
        the file. Returning 0.0 means "not this format"; anything at or above
        0.6 is a candidate worth showing (spec 03 section 1 step 4).
        """
        ...

    def parse(self, context: ParseContext) -> Iterator[NormalizedEvent | ParseFailure]:
        """Stream the file into events and failures.

        Memory use must not depend on file size. Implementations that read a whole
        structure at once are limited to JSON-array inputs, which spec 03
        section 7 item 1 permits.
        """
        ...


@dataclass(slots=True)
class Candidate:
    """One parser's opinion during detection."""

    log_type: str
    confidence: float
    #: Why this parser scored, for the needs_input list the UI shows.
    reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        """JSON-ready form."""
        payload: dict[str, Any] = {
            "log_type": self.log_type,
            "confidence": round(self.confidence, 4),
        }
        if self.reason:
            payload["reason"] = self.reason
        return payload


class ParserRegistry:
    """The parsers available in this build.

    Registration is explicit rather than by scanning the package, so a broken
    parser module cannot half-load and leave detection working with a subset
    that nobody chose.
    """

    __slots__ = ("_parsers",)

    def __init__(self) -> None:
        self._parsers: dict[str, LogParser] = {}

    def register(self, parser: LogParser) -> None:
        """Add a parser, rejecting a duplicate ``log_type``."""
        existing = self._parsers.get(parser.log_type)
        if existing is not None and type(existing) is not type(parser):
            raise ValueError(f"log_type {parser.log_type!r} is already registered")
        self._parsers[parser.log_type] = parser

    def get(self, log_type: str) -> LogParser | None:
        """The parser for a ``log_type``, or ``None`` when not built yet."""
        return self._parsers.get(log_type)

    def __contains__(self, log_type: object) -> bool:
        return log_type in self._parsers

    def __len__(self) -> int:
        return len(self._parsers)

    def all(self) -> list[LogParser]:
        """Every registered parser, in a stable order."""
        return [self._parsers[key] for key in sorted(self._parsers)]


#: Process-wide registry, populated by :func:`load_builtin_parsers`.
REGISTRY = ParserRegistry()


def load_builtin_parsers() -> ParserRegistry:
    """Import and register every parser that exists in this build.

    Import order does not matter because each module registers itself on import
    through :func:`_register`.
    """
    from app.ingest.parsers import generic_json  # noqa: F401

    return REGISTRY


def _register(parser: LogParser) -> None:
    """Register a parser at import time."""
    REGISTRY.register(parser)


__all__ = [
    "REGISTRY",
    "Candidate",
    "LogParser",
    "ParseContext",
    "ParseCounters",
    "ParseFailure",
    "ParserRegistry",
    "load_builtin_parsers",
]
