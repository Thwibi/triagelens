"""Job repository (spec 02 section 4, ``jobs``).

Backing store for the asyncio job manager that arrives in Phase 1; written now so
the lifecycle is fixed by the schema rather than invented later.
"""

from __future__ import annotations

import sqlite3

from app.models.job import JobKind, JobRecord, JobStatus
from app.util.ids import new_id
from app.util.time import utc_now_iso

#: Columns a caller may change on a job.
_UPDATABLE: frozenset[str] = frozenset(
    {"status", "stage", "progress", "message", "error", "started_at", "finished_at"}
)

_SELECT = "SELECT * FROM jobs"


class JobRepository:
    """Create, read and update background jobs."""

    __slots__ = ("_conn",)

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._conn = connection

    @property
    def connection(self) -> sqlite3.Connection:
        """The underlying connection."""
        return self._conn

    def create(
        self,
        *,
        kind: JobKind,
        case_id: str | None = None,
        source_id: str | None = None,
        status: JobStatus = JobStatus.QUEUED,
        message: str | None = None,
        job_id: str | None = None,
    ) -> JobRecord:
        """Insert a job row and return it."""
        identifier = job_id or new_id()
        self._conn.execute(
            "INSERT INTO jobs (id, case_id, kind, source_id, status, stage, progress, "
            "message, error, created_at) VALUES (?, ?, ?, ?, ?, NULL, 0, ?, NULL, ?)",
            (identifier, case_id, str(kind), source_id, str(status), message, utc_now_iso()),
        )
        created = self.get(identifier)
        if created is None:  # pragma: no cover - the INSERT above always produces a row
            raise RuntimeError(f"job {identifier} vanished immediately after insert")
        return created

    def get(self, job_id: str) -> JobRecord | None:
        """One job by id, or ``None``."""
        row = self._conn.execute(f"{_SELECT} WHERE id = ?", (job_id,)).fetchone()
        return JobRecord.from_row(row) if row is not None else None

    def list_by_case(
        self,
        case_id: str,
        *,
        limit: int = 100,
        offset: int = 0,
        status: JobStatus | None = None,
    ) -> list[JobRecord]:
        """Jobs of one case, newest first."""
        if status is None:
            rows = self._conn.execute(
                f"{_SELECT} WHERE case_id = ? ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
                (case_id, limit, offset),
            ).fetchall()
        else:
            rows = self._conn.execute(
                f"{_SELECT} WHERE case_id = ? AND status = ? "
                "ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
                (case_id, str(status), limit, offset),
            ).fetchall()
        return [JobRecord.from_row(row) for row in rows]

    def list_active(self, *, limit: int = 100) -> list[JobRecord]:
        """Jobs that have not reached a terminal state."""
        rows = self._conn.execute(
            f"{_SELECT} WHERE status IN (?, ?, ?) ORDER BY created_at, id LIMIT ?",
            (str(JobStatus.QUEUED), str(JobStatus.RUNNING), str(JobStatus.NEEDS_INPUT), limit),
        ).fetchall()
        return [JobRecord.from_row(row) for row in rows]

    def count_by_case(self, case_id: str) -> int:
        """Number of jobs in a case."""
        row = self._conn.execute(
            "SELECT COUNT(*) FROM jobs WHERE case_id = ?", (case_id,)
        ).fetchone()
        return int(row[0]) if row else 0

    def update(self, job_id: str, **changes: object) -> bool:
        """Update the supplied columns. Unknown keys are rejected."""
        unknown = set(changes) - _UPDATABLE
        if unknown:
            raise ValueError(f"columns not updatable on jobs: {sorted(unknown)}")
        if not changes:
            return self.get(job_id) is not None
        assignments = ", ".join(f"{column} = ?" for column in changes)
        values: list[object] = [changes[column] for column in changes]
        values.append(job_id)
        cursor = self._conn.execute(f"UPDATE jobs SET {assignments} WHERE id = ?", values)
        return cursor.rowcount > 0

    def start(self, job_id: str, *, stage: str | None = None) -> bool:
        """Mark a job running and stamp ``started_at``."""
        changes: dict[str, object] = {"status": str(JobStatus.RUNNING), "started_at": utc_now_iso()}
        if stage is not None:
            changes["stage"] = stage
        return self.update(job_id, **changes)

    def progress(
        self,
        job_id: str,
        *,
        progress: float,
        stage: str | None = None,
        message: str | None = None,
    ) -> bool:
        """Record progress, clamped to ``[0.0, 1.0]``."""
        changes: dict[str, object] = {"progress": max(0.0, min(1.0, float(progress)))}
        if stage is not None:
            changes["stage"] = stage
        if message is not None:
            changes["message"] = message
        return self.update(job_id, **changes)

    def finish(
        self,
        job_id: str,
        *,
        status: JobStatus = JobStatus.DONE,
        message: str | None = None,
        error: str | None = None,
    ) -> bool:
        """Move a job to a terminal state and stamp ``finished_at``."""
        return self.update(
            job_id,
            status=str(status),
            finished_at=utc_now_iso(),
            message=message,
            error=error,
        )


__all__ = ["JobRepository"]
