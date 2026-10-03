"""Source records (spec 02 section 4, ``sources``)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class SourceStatus(StrEnum):
    """Lifecycle of one ingested file, mirroring the schema CHECK constraint."""

    QUEUED = "queued"
    NEEDS_INPUT = "needs_input"
    PARSING = "parsing"
    DETECTING = "detecting"
    DONE = "done"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass(frozen=True, slots=True)
class ParseErrorRecord:
    """One row of ``parse_errors``.

    A malformed record never aborts a parse: it lands here instead, and parsing
    continues (spec 01 section 3, stage 3).
    """

    id: int
    source_id: str
    record_ref: str
    reason: str
    raw_excerpt: str | None

    @classmethod
    def from_row(cls, row: Any) -> ParseErrorRecord:
        """Build a record from a repository row."""
        return cls(
            id=int(row["id"]),
            source_id=row["source_id"],
            record_ref=row["record_ref"],
            reason=row["reason"],
            raw_excerpt=row["raw_excerpt"],
        )


@dataclass(frozen=True, slots=True)
class InventoryRow:
    """One row of ``source_inventory``: what a source actually contained.

    Computed after parsing and used to prune rules that cannot match anything
    (spec 01 section 3, stage 6; spec 04 section 2).
    """

    log_type: str
    channel: str
    app_name: str
    ls_category: str
    event_count: int

    @classmethod
    def from_row(cls, row: Any) -> InventoryRow:
        """Build a row from a joined repository row."""
        return cls(
            log_type=row["log_type"],
            channel=row["channel"],
            app_name=row["app_name"],
            ls_category=row["ls_category"],
            event_count=int(row["event_count"]),
        )


@dataclass(frozen=True, slots=True)
class SourceRecord:
    """One row of ``sources``."""

    id: str
    case_id: str
    filename: str
    parent_source_id: str | None
    stored_path: str
    size_bytes: int
    sha256: str
    log_type: str | None
    detect_confidence: float | None
    timezone: str | None
    assumed_year: int | None
    status: SourceStatus
    event_count: int
    error_count: int
    first_event_ms: int | None
    last_event_ms: int | None
    error_detail: str | None
    ingested_at: str

    @classmethod
    def from_row(cls, row: Any) -> SourceRecord:
        """Build a record from a repository row."""
        return cls(
            id=row["id"],
            case_id=row["case_id"],
            filename=row["filename"],
            parent_source_id=row["parent_source_id"],
            stored_path=row["stored_path"],
            size_bytes=int(row["size_bytes"]),
            sha256=row["sha256"],
            log_type=row["log_type"],
            detect_confidence=row["detect_confidence"],
            timezone=row["timezone"],
            assumed_year=row["assumed_year"],
            status=SourceStatus(row["status"]),
            event_count=int(row["event_count"]),
            error_count=int(row["error_count"]),
            first_event_ms=row["first_event_ms"],
            last_event_ms=row["last_event_ms"],
            error_detail=row["error_detail"],
            ingested_at=row["ingested_at"],
        )


__all__ = [
    "InventoryRow",
    "ParseErrorRecord",
    "SourceRecord",
    "SourceStatus",
]
