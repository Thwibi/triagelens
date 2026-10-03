"""Job records (spec 02 section 4, ``jobs``)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class JobKind(StrEnum):
    """Kind of background work, mirroring the schema CHECK constraint."""

    INGEST = "ingest"
    DETECT = "detect"
    REPORT = "report"
    RULES_IMPORT = "rules_import"


class JobStatus(StrEnum):
    """Job lifecycle, mirroring the schema CHECK constraint."""

    QUEUED = "queued"
    RUNNING = "running"
    NEEDS_INPUT = "needs_input"
    DONE = "done"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass(frozen=True, slots=True)
class JobRecord:
    """One row of ``jobs``."""

    id: str
    case_id: str | None
    kind: JobKind
    source_id: str | None
    status: JobStatus
    stage: str | None
    progress: float
    message: str | None
    error: str | None
    created_at: str
    started_at: str | None
    finished_at: str | None

    @classmethod
    def from_row(cls, row: Any) -> JobRecord:
        """Build a record from a repository row."""
        return cls(
            id=row["id"],
            case_id=row["case_id"],
            kind=JobKind(row["kind"]),
            source_id=row["source_id"],
            status=JobStatus(row["status"]),
            stage=row["stage"],
            progress=float(row["progress"]),
            message=row["message"],
            error=row["error"],
            created_at=row["created_at"],
            started_at=row["started_at"],
            finished_at=row["finished_at"],
        )
