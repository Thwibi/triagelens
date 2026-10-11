"""Detection endpoints (spec 06 section 3, "Detection").

``POST /cases/{id}/detect`` enqueues a detect job that runs the whole engine
pipeline; the job id is how the UI follows progress. Reads of prior runs and
their per-rule rows are served straight off a read connection.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field

from app.api.deps import (
    detection_run_repository,
    get_job_manager,
    get_settings,
    rule_repository,
    settings_repository,
    write_in,
)
from app.config import Settings, profile_values
from app.db.repositories.jobs import JobRepository
from app.db.repositories.rules import RuleRepository
from app.db.repositories.runs import DetectionRunRepository
from app.db.repositories.settings import SettingsRepository
from app.errors import ApiError, ErrorCode
from app.jobs.detect import encode_payload
from app.jobs.manager import JobManager
from app.models.job import JobKind
from app.settings_schema import detection_profile

PROFILE_NAMES = tuple(profile_values())

router = APIRouter(tags=["detection"])


class DetectRequest(BaseModel):
    """Body of ``POST /cases/{id}/detect``."""

    profile: str | None = Field(default=None, pattern=r"^(fast|standard|full)$")
    rule_ids: list[str] = Field(default_factory=list)


@router.post("/cases/{case_id}/detect", status_code=202)
async def run_detection(  # noqa: PLR0917 - one parameter per documented concern
    request: Request,
    case_id: str,
    body: DetectRequest,
    settings: Settings = Depends(get_settings),
    manager: JobManager = Depends(get_job_manager),
    rules: RuleRepository = Depends(rule_repository),
    stored: SettingsRepository = Depends(settings_repository),
) -> dict[str, Any]:
    """Enqueue a detect job that runs the whole engine pipeline."""
    profile = body.profile or detection_profile(stored.get_all(), settings.detection.profile)
    if profile not in PROFILE_NAMES:
        raise ApiError(ErrorCode.VALIDATION_ERROR, f"unknown detection profile: {profile!r}")
    if not case_id.strip():
        raise ApiError(ErrorCode.VALIDATION_ERROR, "case_id is required")
    wanted = list(dict.fromkeys(body.rule_ids))
    known = {row.id for row in rules.list()}
    if [rule_id for rule_id in wanted if rule_id not in known]:
        unknown = sorted(set(wanted) - known)
        raise ApiError(ErrorCode.VALIDATION_ERROR, "unknown rule id(s)", rule_ids=unknown)
    job = write_in(
        request,
        lambda connection: JobRepository(connection).create(
            kind=JobKind.DETECT, case_id=case_id, message=f"detection ({profile})"
        ),
    )
    await manager.enqueue(job.id, encode_payload(job.id, case_id, profile=profile, rule_ids=wanted))
    return job.model_dump(mode="json")


@router.get("/cases/{case_id}/detection-runs")
def list_detection_runs(
    case_id: str,
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    runs: DetectionRunRepository = Depends(detection_run_repository),
) -> dict[str, Any]:
    """Runs for one case, newest first, with per-run counts (spec 06)."""
    rows = runs.list_for_case(case_id, limit=limit, offset=offset)
    return {
        "items": [_run_detail(run, runs) for run in rows],
        "total": _run_count(runs, case_id),
        "limit": limit,
        "offset": offset,
    }


@router.get("/detection-runs/{run_id}/rules")
def detection_run_rules(
    run_id: str,
    runs: DetectionRunRepository = Depends(detection_run_repository),
) -> dict[str, Any]:
    """Per-rule outcomes of one run (spec 06)."""
    if runs.get(run_id) is None:
        raise ApiError(ErrorCode.NOT_FOUND, "detection run not found", run_id=run_id)
    rows = runs.rule_runs(run_id)
    return {"items": [_rule_run_detail(row) for row in rows], "total": len(rows)}


def _rule_run_detail(row: Any) -> dict[str, Any]:
    """One ``rule_runs`` row, JSON-ready."""
    return {
        "run_id": row.run_id,
        "rule_id": row.rule_id,
        "status": row.status,
        "match_count": row.match_count,
        "duration_ms": row.duration_ms,
        "error": row.error,
    }


def _run_detail(
    run: Any,
    runs: DetectionRunRepository,
) -> dict[str, Any]:
    """One run row plus the counts reports embed."""
    return {
        "id": run.id,
        "case_id": run.case_id,
        "profile": run.profile,
        "tool_version": run.tool_version,
        "ruleset_hash": run.ruleset_hash,
        "attack_version": run.attack_version,
        "started_at": run.started_at,
        "finished_at": run.finished_at,
        "status": run.status,
        "counts": {
            "rules": _rules_run_count(runs, run.id),
            "alerts": _alerts_run_count(runs, run.id),
        },
    }


def _run_count(runs: DetectionRunRepository, case_id: str) -> int:
    connection = runs.connection
    row = connection.execute(
        "SELECT COUNT(*) FROM detection_runs WHERE case_id = ?", (case_id,)
    ).fetchone()
    return int(row[0]) if row else 0


def _rules_run_count(runs: DetectionRunRepository, run_id: str) -> int:
    connection = runs.connection
    row = connection.execute(
        "SELECT COUNT(*) FROM rule_runs WHERE run_id = ?", (run_id,)
    ).fetchone()
    return int(row[0]) if row else 0


def _alerts_run_count(runs: DetectionRunRepository, run_id: str) -> int:
    connection = runs.connection
    row = connection.execute("SELECT COUNT(*) FROM alerts WHERE run_id = ?", (run_id,)).fetchone()
    return int(row[0]) if row else 0


__all__ = ["DetectRequest", "router"]
