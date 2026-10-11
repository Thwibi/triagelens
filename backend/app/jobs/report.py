"""The report job: gather, render and persist one report (spec 08).

Unlike ingest and detect, report generation is a bounded, read-mostly
operation that runs on the writer connection inside one transaction: the data
is gathered, the bytes are rendered, the file is written and the ``reports``
row plus the ``report_created`` audit entry commit together or not at all.
"""

from __future__ import annotations

import sqlite3
from typing import Any

from app.config import Settings
from app.db.repositories.jobs import JobRepository
from app.jobs.progress import ProgressBus
from app.jobs.writer import DBWriter
from app.models.job import JobRecord, JobStatus
from app.reports.options import ReportOptions, options_from_dict
from app.reports.service import generate_report
from app.util.logging import get_logger

logger = get_logger("jobs.report")

STAGE_GATHERING = "gathering"
STAGE_RENDERING = "rendering"


class ReportRunner:
    """Generates one report per job, fully off the request thread."""

    __slots__ = ("_progress", "_settings", "_writer")

    def __init__(self, *, writer: DBWriter, progress: ProgressBus, settings: Settings) -> None:
        self._writer = writer
        self._progress = progress
        self._settings = settings

    async def __call__(self, payload: dict[str, Any]) -> None:
        try:
            job_id = str(payload["job_id"])
            case_id = str(payload["case_id"])
            options = options_from_dict(payload.get("options") or {})
        except (KeyError, TypeError, ValueError) as error:
            logger.error("report payload was unusable", extra={"detail": str(error)})
            return
        await self.run(job_id, case_id, options)

    async def run(self, job_id: str, case_id: str, options: ReportOptions) -> None:
        await self._start(job_id)
        await self._stage(job_id, STAGE_GATHERING, 0.3, "gathering data", case_id)
        try:
            record, size = await self._writer.run_async(
                lambda connection: generate_report(
                    connection,
                    case_id=case_id,
                    options=options,
                    settings=self._settings,
                )
            )
        except Exception as error:
            logger.exception("report job failed", extra={"job_id": job_id, "case_id": case_id})
            await self._finish(
                job_id,
                JobStatus.FAILED,
                "report generation failed",
                error=f"{type(error).__name__}: {error}",
            )
            return
        await self._stage(job_id, STAGE_RENDERING, 1.0, "rendering html/pdf", case_id)
        await self._finish(
            job_id,
            JobStatus.DONE,
            f"generated {record.format} report {record.id} ({size} bytes)",
        )
        logger.info(
            "report job finished",
            extra={
                "job_id": job_id,
                "case_id": case_id,
                "report_id": record.id,
                "format": record.format,
                "size": size,
            },
        )

    async def _start(self, job_id: str) -> None:
        record = await self._writer.run_async(
            lambda connection: _start_on_connection(connection, job_id)
        )
        if record is not None:
            await self._progress.job_update(record)

    async def _stage(
        self, job_id: str, stage: str, progress: float, message: str, case_id: str | None = None
    ) -> None:
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


def _start_on_connection(connection: sqlite3.Connection, job_id: str) -> JobRecord | None:
    """Move a job into running and return it, for the first progress frame."""
    jobs = JobRepository(connection)
    jobs.start(job_id, stage=STAGE_GATHERING)
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


def encode_payload(job_id: str, case_id: str, options: ReportOptions) -> dict[str, Any]:
    """Flatten a report request for the job queue."""
    return {
        "kind": "report",
        "job_id": job_id,
        "case_id": case_id,
        "options": options.as_dict(),
    }


__all__ = ["STAGE_GATHERING", "STAGE_RENDERING", "ReportRunner", "encode_payload"]
