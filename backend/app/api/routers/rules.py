"""Rule catalogue endpoints (spec 06 "Rules").

Everything mutating goes through the single writer thread; only reads use the
request-scoped read connection (the API dependency conventions in deps.py).
"Custom" is the only kind the API may create, replace or delete - built-in and
vendored SigmaHQ rules are owned by the loader (spec 04 section 9).
"""

from __future__ import annotations

import io
import re
import sqlite3
import zipfile
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, File, Query, UploadFile
from fastapi import Request as FastAPIRequest
from fastapi.responses import Response
from pydantic import BaseModel, Field

from app.api.deps import get_settings, rule_repository, write_in
from app.config import Settings
from app.db.repositories.audit import AuditRepository
from app.db.repositories.jobs import JobRepository
from app.db.repositories.rules import RuleRepository
from app.detect.engine import execute_rules
from app.detect.routing import load_logsource_map
from app.detect.rules import LoadedRule, LoadProblem, load_rules_from_text
from app.detect.sync import sync_catalogue
from app.errors import ApiError, ErrorCode, validation_error
from app.models.job import JobKind
from app.models.rule import KIND_CUSTOM, KIND_SIGMA, RULE_TYPE_CORRELATION, RuleRecord

router = APIRouter(tags=["rules"])

_KINDS: frozenset[str] = frozenset({"builtin", KIND_CUSTOM, KIND_SIGMA})
_LEVELS: frozenset[str] = frozenset({"informational", "low", "medium", "high", "critical"})
_HEALTHS: frozenset[str] = frozenset({"ok", "compile_error", "unroutable"})
#: Upload limits for ``POST /rules/import`` (spec 06).
_MAX_UPLOAD_FILES = 100
_MAX_UPLOAD_BYTES = 8 * 1024 * 1024
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*\.(yml|yaml)$")

_PROBLEM_FIELDS = ("where", "error")


class RuleYamlBody(BaseModel):
    """A rule document (or documents) the API is validating or creating."""

    yaml: str = Field(min_length=1, max_length=2_000_000)


class RuleEnabledBody(BaseModel):
    """``PATCH /rules/{id}``: the new enabled flag."""

    enabled: bool


class RuleTestBody(BaseModel):
    """``POST /rules/test``: run one rule against a case's events."""

    yaml: str = Field(min_length=1, max_length=2_000_000)
    case_id: str = Field(min_length=1, max_length=64)
    limit: int = Field(default=50, ge=1, le=1000)


@router.get("/rules")
def list_rules(  # noqa: PLR0917 - one parameter per documented API filter
    kind: str | None = Query(None),
    level: str | None = Query(None),
    status: str | None = Query(None, max_length=40),
    enabled: bool | None = Query(None),  # noqa: FBT001 - FastAPI query flag
    tag: str | None = Query(None, max_length=200),
    technique: str | None = Query(None, max_length=20),
    health: str | None = Query(None),
    q: str | None = Query(None, max_length=200),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    rules: RuleRepository = Depends(rule_repository),
) -> dict[str, Any]:
    """The rule catalogue with the spec 06 filters."""
    _require_filters(kind=kind, level=level, status=status, health=health)
    try:
        items, total = _page(
            rules,
            kind=kind,
            level=level,
            status=status,
            enabled=enabled,
            tag=tag,
            technique=technique,
            health=health,
            q=q,
            limit=limit,
            offset=offset,
        )
    except ValueError as error:
        raise validation_error(str(error)) from error
    return {
        "items": [_rule_summary(rule) for rule in items],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/rules/health")
def rules_health(rules: RuleRepository = Depends(rule_repository)) -> dict[str, Any]:
    """Catalogue health bucket counts (spec 06)."""
    counts = rules.health_counts()
    return {"total": sum(counts.values()), **counts}


@router.get("/rules/export")
def export_rules(
    rules: RuleRepository = Depends(rule_repository),
) -> Response:
    """A zip of every catalogue rule's YAML, by kind and file (spec 06).

    Registered before ``/rules/{rule_id}`` so the static segment wins.
    """
    records = rules.list(limit=100_000)
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        used: set[str] = set()
        for record in records:
            name = _zip_name(record, used)
            used.add(name)
            archive.writestr(name, record.yaml)
    return Response(
        content=stream.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": "attachment; filename=rules.zip"},
    )


@router.get("/rules/{rule_id}")
def get_rule(
    rule_id: str,
    rules: RuleRepository = Depends(rule_repository),
) -> dict[str, Any]:
    """One rule, YAML included (spec 06 ``RuleDetail``)."""
    record = rules.get(rule_id)
    if record is None:
        raise ApiError(ErrorCode.NOT_FOUND, "rule not found", id=rule_id)
    payload = _rule_summary(record)
    payload["yaml"] = record.yaml
    return payload


@router.post("/rules")
def create_rule(
    body: RuleYamlBody,
    request: FastAPIRequest,
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    """Validate and create custom rule(s) from YAML (spec 06)."""
    loaded, problems = load_rules_from_text(
        body.yaml, kind=KIND_CUSTOM, source="api", logsource_map=_logsource_map_path(settings)
    )
    _reject_problems(problems, loaded)

    def work(conn: sqlite3.Connection) -> dict[str, Any]:
        repository = RuleRepository(conn)
        for rule in loaded:
            existing = repository.get(rule.id)
            if existing is not None and existing.kind != KIND_CUSTOM:
                raise ApiError(
                    ErrorCode.CONFLICT,
                    "rule id already exists with a different kind",
                    id=rule.id,
                )
        repository.upsert_many(loaded)
        AuditRepository(conn).append(
            "rules_imported",
            detail={"action": "create", "count": len(loaded), "ids": [rule.id for rule in loaded]},
        )
        return {
            "items": [_rule_summary(_to_record(rule)) for rule in loaded],
            "created": len(loaded),
        }

    return write_in(request, work)


@router.put("/rules/{rule_id}")
def replace_rule(
    rule_id: str,
    body: RuleYamlBody,
    request: FastAPIRequest,
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    """Replace one custom rule's YAML (spec 06)."""
    loaded, problems = load_rules_from_text(
        body.yaml, kind=KIND_CUSTOM, source="api", logsource_map=_logsource_map_path(settings)
    )
    _reject_problems(problems, loaded)
    if len(loaded) != 1:
        raise validation_error("exactly one rule document required", count=len(loaded))
    if loaded[0].id != rule_id:
        raise validation_error(
            "rule id does not match the path parameter",
            document_id=loaded[0].id,
            path_id=rule_id,
        )

    def work(conn: sqlite3.Connection) -> dict[str, Any]:
        repository = RuleRepository(conn)
        existing = repository.get(rule_id)
        if existing is None:
            raise ApiError(ErrorCode.NOT_FOUND, "rule not found", id=rule_id)
        if existing.kind != KIND_CUSTOM:
            raise ApiError(ErrorCode.CONFLICT, "only custom rules can be replaced", id=rule_id)
        repository.upsert_many(loaded)
        stored = repository.get(rule_id)
        if stored is None:  # pragma: no cover - the upsert just wrote it
            raise RuntimeError(f"rule {rule_id} vanished immediately after upsert")
        return {"item": _rule_summary(stored)}

    return write_in(request, work)


@router.patch("/rules/{rule_id}")
def set_rule_enabled(
    rule_id: str,
    body: RuleEnabledBody,
    request: FastAPIRequest,
) -> dict[str, Any]:
    """Enable or disable a rule; every kind allows this (spec 04 section 9)."""

    def work(conn: sqlite3.Connection) -> dict[str, Any]:
        repository = RuleRepository(conn)
        if repository.get(rule_id) is None:
            raise ApiError(ErrorCode.NOT_FOUND, "rule not found", id=rule_id)
        if not repository.set_enabled(rule_id, enabled=body.enabled):
            raise ApiError(ErrorCode.NOT_FOUND, "rule not found", id=rule_id)  # pragma: no cover
        stored = repository.get(rule_id)
        if stored is None:  # pragma: no cover
            raise RuntimeError(f"rule {rule_id} vanished immediately after enable toggle")
        return {"item": _rule_summary(stored)}

    return write_in(request, work)


@router.delete("/rules/{rule_id}")
def delete_rule(
    rule_id: str,
    request: FastAPIRequest,
) -> dict[str, Any]:
    """Delete one custom rule (spec 06); built-in/sigma rules are owned by the loader."""

    def work(conn: sqlite3.Connection) -> dict[str, Any]:
        repository = RuleRepository(conn)
        existing = repository.get(rule_id)
        if existing is None:
            raise ApiError(ErrorCode.NOT_FOUND, "rule not found", id=rule_id)
        if existing.kind != KIND_CUSTOM:
            raise ApiError(ErrorCode.CONFLICT, "only custom rules can be deleted", id=rule_id)
        repository.delete(rule_id)
        return {"deleted": rule_id}

    return write_in(request, work)


@router.post("/rules/validate")
def validate_rule(
    body: RuleYamlBody,
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    """Validate YAML without persisting anything (spec 06)."""
    loaded, problems = load_rules_from_text(
        body.yaml, kind=KIND_CUSTOM, source="api", logsource_map=_logsource_map_path(settings)
    )
    return {
        "valid": not problems and bool(loaded),
        "rules": [_rule_summary(_to_record(rule)) for rule in loaded],
        "problems": [_problem_payload(problem) for problem in problems],
    }


@router.post("/rules/test")
def preview_rule(
    body: RuleTestBody,
    rules: RuleRepository = Depends(rule_repository),
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    """Run one rule against a case's events and return a sample (spec 06)."""
    loaded, problems = load_rules_from_text(
        body.yaml, kind=KIND_CUSTOM, source="api", logsource_map=_logsource_map_path(settings)
    )
    _reject_problems(problems, loaded)
    if len(loaded) != 1:
        raise validation_error("exactly one rule document required", count=len(loaded))
    candidate = loaded[0]
    if candidate.rule_type == RULE_TYPE_CORRELATION:
        raise validation_error("correlation rules cannot be tested with an ad-hoc run")
    record = _to_record(candidate)
    if record.compile_error is not None:
        raise validation_error("rule does not compile", error=record.compile_error)
    if record.unroutable:
        raise validation_error("rule cannot be routed to any logsource")
    result = execute_rules(
        rules.connection,
        case_id=body.case_id,
        rules=[record],
        logsource_map=load_logsource_map(_logsource_map_path(settings)),
        timeout_seconds=settings.detection.rule_timeout_seconds,
    )
    matched = []
    if result.executions:
        matches = result.executions[0].matches[: body.limit]
        matched = _event_rows(rules.connection, tuple(match.event_id for match in matches))
    sample = _rule_summary(record)
    sample["compile_error"] = record.compile_error
    return {
        "rule": sample,
        "executed": not result.cancelled,
        "total_matches": sum(len(execution.matches) for execution in result.executions),
        "items": matched,
    }


@router.post("/rules/import")
async def import_rules(
    request: FastAPIRequest,
    files: list[UploadFile] = File(...),
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    """Upload rule files into the custom directory and refresh the catalogue
    synchronously (spec 06)."""
    if not files:
        raise validation_error("no rule files supplied")
    if len(files) > _MAX_UPLOAD_FILES:
        raise validation_error("too many files", max_allowed=_MAX_UPLOAD_FILES)
    uploads: list[tuple[str, bytes]] = []
    total_bytes = 0
    for upload in files:
        name = _safe_upload_name(upload.filename or "")
        if name is None:
            raise validation_error("unsafe or unsupported file name", filename=upload.filename)
        data = await upload.read()
        total_bytes += len(data)
        if total_bytes > _MAX_UPLOAD_BYTES:
            raise validation_error("upload exceeds the size limit", max_bytes=_MAX_UPLOAD_BYTES)
        uploads.append((name, data))

    def work(conn: sqlite3.Connection) -> dict[str, Any]:
        custom_dir = settings.custom_rules_dir
        custom_dir.mkdir(parents=True, exist_ok=True)
        written: list[str] = []
        for name, data in uploads:
            (custom_dir / name).write_bytes(data)
            written.append(name)

        report = sync_catalogue(conn, settings=settings, audit=False)
        changed = report.kinds.get(KIND_CUSTOM, 0)
        jobs = JobRepository(conn)
        job = jobs.create(kind=JobKind.RULES_IMPORT, message=f"importing {len(written)} file(s)")
        message = f"imported {changed} custom rule(s)"
        jobs.finish(str(job.id), message=message)
        settled = jobs.get(str(job.id))
        AuditRepository(conn).append(
            "rules_imported",
            detail={
                "action": "import",
                "files": written,
                "count": changed,
                "synced": report.total,
                "stale_removed": report.stale_removed,
            },
        )
        return {
            "job": (settled or job).model_dump(),
            "imported": changed,
            "synced": report.total,
            "stale_removed": report.stale_removed,
            "files": written,
            "problems": [_problem_payload(problem) for problem in report.problems],
        }

    return write_in(request, work)


def _page(
    rules: RuleRepository,
    *,
    kind: str | None,
    level: str | None,
    status: str | None,
    enabled: bool | None,
    tag: str | None,
    technique: str | None,
    health: str | None,
    q: str | None,
    limit: int,
    offset: int,
) -> tuple[list[RuleRecord], int]:
    """One filtered, paginated page of the catalogue."""
    return (
        rules.list(
            kind=kind,
            level=level,
            status=status,
            enabled=enabled,
            tag=tag,
            technique=technique,
            health=health,
            q=q,
            limit=limit,
            offset=offset,
        ),
        rules.count(
            kind=kind,
            level=level,
            status=status,
            enabled=enabled,
            tag=tag,
            technique=technique,
            health=health,
            q=q,
        ),
    )


def _require_filters(
    *, kind: str | None, level: str | None, status: str | None, health: str | None
) -> None:
    if kind is not None and kind not in _KINDS:
        raise validation_error("unsupported rule kind", kind=kind, allowed=sorted(_KINDS))
    if level is not None and level not in _LEVELS:
        raise validation_error("unsupported rule level", level=level, allowed=sorted(_LEVELS))
    known_statuses = ("stable", "test", "experimental", "unsupported", "deprecated")
    if status is not None and status not in known_statuses:
        raise validation_error("unsupported rule status", status=status)
    if health is not None and health not in _HEALTHS:
        raise validation_error("unsupported rule health", health=health, allowed=sorted(_HEALTHS))


def _reject_problems(problems: list[LoadProblem], loaded: list[LoadedRule]) -> None:
    """Turn load problems into a validation error when nothing usable loaded."""
    if problems or not loaded:
        fallback = [{"where": "api", "error": "no rules"}]
        detail = [_problem_payload(problem) for problem in problems] or fallback
        raise validation_error("rule document failed validation", problems=detail)


def _to_record(loaded: LoadedRule) -> RuleRecord:
    """A loaded rule as a catalogue record; ``updated_at`` is stamped on write."""
    return RuleRecord(
        id=loaded.id,
        title=loaded.title,
        kind=loaded.kind,
        rule_type=loaded.rule_type,
        level=loaded.level,
        status=loaded.status,
        enabled=True,
        yaml=loaded.yaml,
        tags=loaded.tags,
        logsource=loaded.logsource,
        file_path=loaded.file_path,
        sha256=loaded.sha256,
        compile_error=loaded.compile_error,
        unroutable=loaded.unroutable,
        updated_at="",
    )


def _rule_summary(record: RuleRecord) -> dict[str, Any]:
    """One catalogue row as the API returns it."""
    return {
        "id": record.id,
        "title": record.title,
        "kind": record.kind,
        "rule_type": record.rule_type,
        "level": record.level,
        "status": record.status,
        "enabled": record.enabled,
        "tags": list(record.tags),
        "logsource": record.logsource,
        "file_path": record.file_path,
        "sha256": record.sha256,
        "compile_error": record.compile_error,
        "unroutable": record.unroutable,
        "healthy": record.healthy,
        "updated_at": record.updated_at,
    }


def _problem_payload(problem: LoadProblem) -> dict[str, str]:
    return {"where": problem.where, "error": problem.error}


def _logsource_map_path(settings: Settings) -> Path:
    return settings.rules_dir / "logsource_map.yaml"


def _safe_upload_name(filename: str) -> str | None:
    """The basename when it is a benign rule file name; ``None`` otherwise."""
    base = Path(filename).name
    return base if _SAFE_NAME.match(base) else None


def _zip_name(record: RuleRecord, used: set[str]) -> str:
    """A unique archive path per rule: kind/relative, then id if needed."""
    stem = _safe_upload_name(record.file_path or "") if record.file_path else None
    if stem is None:
        stem = f"{record.id}.yml"
    name = f"{record.kind}/{stem}"
    if name in used:
        name = f"{record.kind}/{record.id}.yml"
    return name


def _event_rows(connection: sqlite3.Connection, event_ids: tuple[int, ...]) -> list[dict[str, Any]]:
    """A brief, raw-free view of the given events."""
    if not event_ids:
        return []
    # Placeholders are only "?", never caller text; the ids are bound values.
    placeholders = ", ".join("?" for _ in event_ids)
    rows = connection.execute(
        f"SELECT * FROM events WHERE id IN ({placeholders}) ORDER BY ts_ms, id",  # noqa: S608 - count is bound, ids are parameters
        tuple(event_ids),
    ).fetchall()
    return [_event_brief(row) for row in rows]


def _event_brief(row: Any) -> dict[str, Any]:
    """An event row without its raw field."""
    return {
        "id": row["id"],
        "source_id": row["source_id"],
        "record_ref": row["record_ref"],
        "ts_ms": row["ts_ms"],
        "ts_iso": row["ts_iso"],
        "log_type": row["log_type"],
        "ls_category": row["ls_category"],
        "host": row["host"],
        "channel": row["channel"],
        "app_name": row["app_name"],
        "event_id": row["event_id"],
        "level": row["level"],
        "event_action": row["event_action"],
        "user_name": row["user_name"],
        "src_ip": row["src_ip"],
        "dst_ip": row["dst_ip"],
        "message": row["message"],
    }


__all__ = ["router"]
