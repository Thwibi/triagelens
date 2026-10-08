"""Job records (spec 02 section 4, ``jobs``)."""

from __future__ import annotations

from dataclasses import asdict, dataclass
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

    @property
    def is_terminal(self) -> bool:
        """True when no further progress happens without new input.

        ``needs_input`` counts, and that is the easy one to get wrong. The job has
        already stopped -- it wrote ``finished_at`` and is waiting on the operator
        -- so treating it as still running makes a poll spin forever and lets a
        cancel request accept a job that will never notice it. Resolving the source
        starts the work again, but under a new job.
        """
        return self in _TERMINAL_STATUSES


#: Statuses a job cannot leave on its own. Declared after the enum so the members
#: exist, and used by both the API and the ingest runner so "finished" means one
#: thing in the whole codebase.
_TERMINAL_STATUSES = frozenset(
    {
        JobStatus.NEEDS_INPUT,
        JobStatus.DONE,
        JobStatus.FAILED,
        JobStatus.CANCELLED,
    }
)


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

    def model_dump(self, **kwargs: Any) -> dict[str, Any]:  # noqa: ARG002
        """Serialize to JSON-serializable dict."""
        data = asdict(self)
        data["kind"] = self.kind.value
        data["status"] = self.status.value
        return data
