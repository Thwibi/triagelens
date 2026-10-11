"""The detect job: one engine pass over a case (spec 04 section 2).

Detection runs entirely on the writer connection inside a single transaction,
so a run row, its per-rule rows, its alerts and their evidence commit together
or not at all - a crash halfway through leaves no half-written run to report.

The pipeline order is fixed (spec 04 section 2):

1. **execute_rules** - route, prune, compile and fetch every base rule.
2. **execute_correlations** - evaluate the correlation rules over the base
   matches.
3. **record_run_alerts** - group matches into deterministic alerts and score
   them.
4. **enrich_run_alerts** - resolve each alert's ATT&CK mapping.
5. **link_alert_iocs** - extract tier-2 IOCs from the alert evidence events and
   link every evidence IOC to its alert (spec 01 section 8).

Cancellation is cooperative: the runner owns a job-id set the engine polls
between rules, so a cancel stops the pass at the next rule boundary and the
run is recorded as ``cancelled`` rather than silently dropped.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from app.config import Settings
from app.db.repositories.jobs import JobRepository
from app.db.repositories.rules import RuleRepository
from app.db.repositories.runs import DetectionRunRepository, attack_version
from app.detect.correlation import execute_correlations, record_run_alerts
from app.detect.engine import EngineResult, RuleExecution, execute_rules
from app.detect.ioc_link import link_alert_iocs
from app.detect.profiles import select_for_profile
from app.detect.routing import load_logsource_map
from app.jobs.progress import ProgressBus
from app.jobs.writer import DBWriter
from app.mitre.enrich import enrich_run_alerts
from app.mitre.fallbacks import FallbackEntry, load_fallbacks
from app.models.job import JobRecord, JobStatus
from app.models.rule import RULE_TYPE_CORRELATION, RuleRecord
from app.models.run import (
    RUN_STATUS_CANCELLED,
    RUN_STATUS_DONE,
    DetectionRunRecord,
)
from app.util.logging import get_logger
from app.version import APP_VERSION

logger = get_logger("jobs.detect")

#: Stage names published over the WebSocket while a run is executing.
STAGE_RUNNING = "detecting"
STAGE_FINALIZE = "finalizing"


@dataclass(frozen=True, slots=True)
class DetectPayload:
    """What the API hands the job manager when it enqueues a detection run."""

    job_id: str
    case_id: str
    profile: str
    #: Explicit rule selection; empty means "the profile decides".
    rule_ids: tuple[str, ...] = ()


class DetectRunner:
    """Runs one detection job end to end.

    Constructed once per application so the job manager can register it as a
    plain handler, exactly like the ingest runner.
    """

    __slots__ = ("_cancelled", "_fallbacks", "_progress", "_settings", "_writer")

    def __init__(
        self,
        *,
        writer: DBWriter,
        progress: ProgressBus,
        settings: Settings,
    ) -> None:
        self._writer = writer
        self._progress = progress
        self._settings = settings
        self._cancelled: set[str] = set()
        self._fallbacks: tuple[FallbackEntry, ...] = load_fallbacks(
            settings.bundled_data_dir / "mitre_fallbacks.yaml"
        )

    def cancel(self, job_id: str) -> None:
        """Request cancellation; the engine checks it between rules."""
        self._cancelled.add(job_id)

    def is_cancelled(self, job_id: str) -> bool:
        """True once :meth:`cancel` has been called for this job."""
        return job_id in self._cancelled

    async def __call__(self, payload: dict[str, Any]) -> None:
        """Job-manager handler entry point."""
        try:
            request = decode_payload(payload)
        except (KeyError, TypeError, ValueError) as error:
            logger.error("detect payload was unusable", extra={"detail": str(error)})
            return
        await self.run(request)

    async def run(self, request: DetectPayload) -> None:
        """Run the whole detection pipeline, then finalize the job."""
        if self.is_cancelled(request.job_id):
            await self._finish(request.job_id, JobStatus.CANCELLED, "cancelled")
            self._cancelled.discard(request.job_id)
            return
        await self._start_job(request.job_id)
        await self._stage(request.job_id, STAGE_RUNNING, 0.0, "detecting", request.case_id)
        try:
            summary = await self._writer.run_async(
                lambda connection: self._execute(connection, request)
            )
        except Exception as error:
            logger.exception("detect job failed", extra={"job_id": request.job_id})
            await self._finish(
                request.job_id,
                JobStatus.FAILED,
                "detection failed",
                error=f"{type(error).__name__}: {error}",
            )
            await self._progress.error("INTERNAL", "detection failed")
            return
        finally:
            self._cancelled.discard(request.job_id)

        await self._stage(request.job_id, STAGE_FINALIZE, 1.0, "finalizing", request.case_id)
        status = _job_status(str(summary["status"]))
        message = (
            f"detected {summary['rules']} rule(s), {summary['alerts']} alert(s)"
            if status is JobStatus.DONE
            else "detection cancelled"
        )
        await self._finish(request.job_id, status, message)
        if summary["alerts"]:
            await self._progress.publish(
                {
                    "type": "alerts.changed",
                    "case_id": request.case_id,
                    "new_alerts": summary["alerts"],
                }
            )
        logger.info(
            "detect job finished",
            extra={
                "job_id": request.job_id,
                "case_id": request.case_id,
                "run_id": summary["run_id"],
                "rules": summary["rules"],
                "alerts": summary["alerts"],
                "status": summary["status"],
            },
        )

    def _execute(self, connection: sqlite3.Connection, request: DetectPayload) -> dict[str, Any]:
        """The whole single-transaction pipeline; returns a run summary."""
        catalogue = RuleRepository(connection).enabled_rules()
        selected = _selected_rules(catalogue, request)
        base_rules = [rule for rule in selected if rule.rule_type != RULE_TYPE_CORRELATION]
        correlation_rules = [rule for rule in selected if rule.rule_type == RULE_TYPE_CORRELATION]
        rules_by_id = {rule.id: rule for rule in selected}
        logsource_map = load_logsource_map(self._settings.rules_dir / "logsource_map.yaml")
        runs = DetectionRunRepository(connection)
        run = runs.start(
            case_id=request.case_id,
            profile=request.profile,
            tool_version=APP_VERSION,
            ruleset_hash=RuleRepository(connection).ruleset_hash(),
            attack_version=attack_version(connection),
        )
        cancelled = lambda: self.is_cancelled(request.job_id)  # noqa: E731

        engine = execute_rules(
            connection,
            case_id=request.case_id,
            rules=base_rules,
            logsource_map=logsource_map,
            timeout_seconds=self._settings.detection.rule_timeout_seconds,
            is_cancelled=cancelled,
        )
        if engine.cancelled:
            return self._cancel_run(runs, run, engine)

        correlation = execute_correlations(
            connection,
            case_id=request.case_id,
            rules=correlation_rules,
            catalogue=selected,
            base_executions=_by_rule(engine.executions),
            logsource_map=logsource_map,
            is_cancelled=cancelled,
        )
        outcomes = list(engine.outcomes)
        outcomes.extend(execution.outcome for execution in correlation.executions)
        runs.record_rules(run.id, outcomes)
        if correlation.cancelled:
            runs.finish(run.id, status=RUN_STATUS_CANCELLED)
            return _summary(run, RUN_STATUS_CANCELLED, len(outcomes), 0)

        alerts = record_run_alerts(
            connection,
            case_id=request.case_id,
            run_id=run.id,
            rules=rules_by_id,
            base_executions=engine.executions,
            correlation_result=correlation,
            window_minutes=self._settings.detection.alert_group_window_minutes,
            max_sample_events=self._settings.detection.max_sample_events_per_alert,
        )
        enrich_run_alerts(
            connection,
            case_id=request.case_id,
            run_id=run.id,
            rules=rules_by_id,
            fallback_entries=self._fallbacks,
        )
        link_alert_iocs(connection, case_id=request.case_id, settings=self._settings)
        runs.finish(run.id, status=RUN_STATUS_DONE)
        return _summary(run, RUN_STATUS_DONE, len(outcomes), len(alerts))

    def _cancel_run(
        self,
        runs: DetectionRunRepository,
        run: DetectionRunRecord,
        engine: EngineResult,
    ) -> dict[str, Any]:
        """Record the rules evaluated before a cancel and close the run."""
        runs.record_rules(run.id, engine.outcomes)
        runs.finish(run.id, status=RUN_STATUS_CANCELLED)
        return _summary(run, RUN_STATUS_CANCELLED, len(engine.outcomes), 0)

    async def _start_job(self, job_id: str) -> None:
        record = await self._writer.run_async(
            lambda connection: _start_on_connection(connection, job_id)
        )
        if record is not None:
            await self._progress.job_update(record)

    async def _stage(
        self,
        job_id: str,
        stage: str,
        progress: float,
        message: str,
        case_id: str | None = None,
    ) -> None:
        """Persist a stage and publish it, in that order."""
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


def _selected_rules(catalogue: Sequence[RuleRecord], request: DetectPayload) -> list[RuleRecord]:
    """The rules a run evaluates.

    An explicit ``rule_ids`` selection wins over the profile; the catalogue is
    already enabled-only, so a rule switched off can never be run by naming it.
    """
    if request.rule_ids:
        wanted = set(request.rule_ids)
        return [rule for rule in catalogue if rule.id in wanted]
    return select_for_profile(catalogue, request.profile)


def _by_rule(executions: Sequence[RuleExecution]) -> dict[str, RuleExecution]:
    """Base executions keyed by rule id for the correlation stage."""
    return {execution.outcome.rule_id: execution for execution in executions}


def _summary(run: DetectionRunRecord, status: str, rules: int, alerts: int) -> dict[str, Any]:
    """A JSON-friendly summary of one finished run."""
    return {"run_id": run.id, "status": status, "rules": rules, "alerts": alerts}


def _job_status(run_status: str) -> JobStatus:
    """Map a run status onto the job status the UI shows."""
    if run_status == RUN_STATUS_DONE:
        return JobStatus.DONE
    if run_status == RUN_STATUS_CANCELLED:
        return JobStatus.CANCELLED
    return JobStatus.FAILED


def _start_on_connection(connection: sqlite3.Connection, job_id: str) -> JobRecord | None:
    """Move a job into running and return it, for the first progress frame."""
    jobs = JobRepository(connection)
    jobs.start(job_id, stage=STAGE_RUNNING)
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


def decode_payload(payload: dict[str, Any]) -> DetectPayload:
    """Rebuild the payload the manager queued."""
    rule_ids = payload.get("rule_ids") or []
    return DetectPayload(
        job_id=str(payload["job_id"]),
        case_id=str(payload["case_id"]),
        profile=str(payload.get("profile") or "standard"),
        rule_ids=tuple(str(rule_id) for rule_id in rule_ids),
    )


def encode_payload(
    job_id: str, case_id: str, *, profile: str, rule_ids: Sequence[str] = ()
) -> dict[str, Any]:
    """Flatten a payload for the job queue.

    The manager picks the handler from the ``kind`` key (defaulting to
    ``ingest``), so detect must spell its own.
    """
    return {
        "kind": "detect",
        "job_id": job_id,
        "case_id": case_id,
        "profile": profile,
        "rule_ids": list(rule_ids),
    }


__all__ = [
    "STAGE_FINALIZE",
    "STAGE_RUNNING",
    "DetectPayload",
    "DetectRunner",
    "decode_payload",
    "encode_payload",
]
