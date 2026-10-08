"""Job endpoints (spec 06 section 3, "Jobs").

Cancellation is the only mutating job route in phase 1. It records the request
and hands the flag to the running job; the job itself writes the terminal status
once it has actually stopped and cleaned up, so this endpoint never claims a job
is cancelled before it is.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from app.api.deps import get_job_manager, job_repository
from app.db.repositories.jobs import JobRepository
from app.errors import ApiError, ErrorCode
from app.jobs.manager import JobManager

router = APIRouter(tags=["jobs"])


@router.get("/jobs/{job_id}")
def get_job(job_id: str, jobs: JobRepository = Depends(job_repository)) -> dict[str, Any]:
    """One job with its progress, stage and terminal error."""
    record = jobs.get(job_id)
    if record is None:
        raise ApiError(ErrorCode.NOT_FOUND, "job not found", job_id=job_id)
    return record.model_dump(mode="json")


@router.get("/cases/{case_id}/jobs")
def list_jobs_case(case_id: str, jobs: JobRepository = Depends(job_repository)) -> dict[str, Any]:
    """Jobs for one case, newest first."""
    rows = jobs.list_by_case(case_id)
    return {"items": [row.model_dump(mode="json") for row in rows], "total": len(rows)}


@router.delete("/jobs/{job_id}")
def cancel_job(
    job_id: str,
    jobs: JobRepository = Depends(job_repository),
    manager: JobManager = Depends(get_job_manager),
) -> dict[str, Any]:
    """Request cancellation of a job.

    A job that already finished is reported as such rather than silently
    accepted: the caller asked to stop something that is not running, and
    pretending otherwise hides a client bug.
    """
    record = jobs.get(job_id)
    if record is None:
        raise ApiError(ErrorCode.NOT_FOUND, "job not found", job_id=job_id)
    # ``needs_input`` is finished too: it already stopped and is waiting on the
    # operator, so accepting a cancel for it would report progress that cannot
    # happen. Resolving the source starts the work again under a new job.
    if record.status.is_terminal:
        raise ApiError(
            ErrorCode.CONFLICT,
            "job has already finished",
            job_id=job_id,
            status=record.status.value,
        )
    manager.cancel(job_id)
    return {"id": job_id, "cancelling": True}


__all__ = ["router"]
