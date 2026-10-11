"""Ingestion endpoints (spec 06 section 3, "Sources and ingestion").

The upload path is synchronous up to the point where the bytes are safe and
detected, and asynchronous past that. The client gets ``202`` with the job and
source rows as soon as the files are stored; parsing happens in worker processes
and reports over the WebSocket.

Detection runs here rather than in the worker because the answer can be
``needs_input``, and the operator has to be asked before anything is parsed. A
member of an archive that is not recognised is parked on its own source row while
the recognised members of the same upload still ingest.

Archive members become their own source rows with ``parent_source_id`` pointing at
the uploaded container, so a case view can show the bundle and its parts and
deleting the container cascades (spec 02 section 4).
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, File, Form, Query, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from app.api.deps import (
    get_job_manager,
    get_settings,
    get_writer,
    parse_error_repository,
    source_repository,
    write_in,
)
from app.config import Settings
from app.db.repositories.audit import AuditRepository
from app.db.repositories.events import EventRepository
from app.db.repositories.iocs import IocRepository
from app.db.repositories.jobs import JobRepository
from app.db.repositories.sources import (
    ParseErrorRepository,
    SourceRepository,
)
from app.errors import ApiError, ErrorCode
from app.ingest.import_from_path import import_candidates
from app.ingest.intake import (
    IntakeResult,
    StoredFile,
    intake_path,
    intake_stream,
    remove_stored,
)
from app.ingest.parsers.base import load_builtin_parsers
from app.jobs.manager import JobManager
from app.jobs.tasks import SourcePlan, encode_payload, source_payload
from app.jobs.writer import DBWriter
from app.models.job import JobKind, JobRecord
from app.models.source import SourceStatus
from app.util.ids import new_id

router = APIRouter(tags=["sources"])

#: Largest number of sources one request may create, so a single request cannot
#: produce an unbounded amount of work.
MAX_SOURCES_PER_REQUEST = 500


class FromPathRequest(BaseModel):
    """Body of ``POST /cases/{id}/sources/from-path``."""

    paths: list[str] = Field(min_length=1)
    recursive: bool = False


class SourceUpdate(BaseModel):
    """Body of ``PATCH /sources/{id}``."""

    log_type: str | None = None
    timezone: str | None = None
    assumed_year: int | None = Field(default=None, ge=1900, le=2100)


class ResolveRequest(BaseModel):
    """Body of ``POST /sources/{id}/resolve``: the operator's ``needs_input`` answer."""

    log_type: str
    timezone: str | None = None
    assumed_year: int | None = Field(default=None, ge=1900, le=2100)


@router.get("/cases/{case_id}/sources")
def list_sources(
    case_id: str,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    status: str | None = Query(None),
    sources: SourceRepository = Depends(source_repository),
) -> dict[str, Any]:
    """Sources of one case, with the unpaginated total for the UI."""
    wanted = _status_or_400(status)
    rows = sources.list_by_case(case_id, limit=limit, offset=offset, status=wanted)
    return {
        "items": [_source_detail(row) for row in rows],
        "total": sources.count_by_case(case_id),
        "limit": limit,
        "offset": offset,
    }


@router.post("/cases/{case_id}/sources", status_code=202)
async def upload_sources(  # noqa: PLR0917 - one parameter per documented API field
    case_id: str,
    files: list[UploadFile] = File(default_factory=list),
    log_type: str | None = Form(None),
    timezone: str | None = Form(None),
    assumed_year: int | None = Form(None),
    settings: Settings = Depends(get_settings),
    writer: DBWriter = Depends(get_writer),
    manager: JobManager = Depends(get_job_manager),
) -> dict[str, Any]:
    """Store uploads, detect every stored file, and queue ingest.

    Returns ``202`` with ``{"jobs": [...], "sources": [...]}`` as spec 06 requires.
    """
    if not files:
        raise ApiError(ErrorCode.VALIDATION_ERROR, "at least one file is required")
    _check_request_size(len(files))

    sources: list[dict[str, Any]] = []
    jobs: list[dict[str, Any]] = []
    for upload in files:
        container, container_id, plans = _intake_upload(
            case_id,
            upload,
            settings=settings,
            log_type=log_type,
            timezone=timezone,
            assumed_year=assumed_year,
        )
        job, rows = await _record_plans(case_id, container, container_id, plans, writer)
        jobs.append(job)
        sources.extend(rows)
        await manager.enqueue(job["id"], encode_payload(job["id"], case_id, plans))
    return {"jobs": jobs, "sources": sources}


@router.post("/cases/{case_id}/sources/from-path", status_code=202)
async def import_from_paths(
    case_id: str,
    body: FromPathRequest,
    settings: Settings = Depends(get_settings),
    writer: DBWriter = Depends(get_writer),
    manager: JobManager = Depends(get_job_manager),
) -> dict[str, Any]:
    """Import files already on the server, under the allowed import roots.

    Paths are resolved and containment-checked before anything is read, and each
    original is copied rather than moved: importing must never be able to destroy
    an analyst's evidence (spec 03 section 5).
    """
    _check_request_size(len(body.paths))

    # Expand every supplied path before anything is stored. A directory named
    # with ``recursive=true`` can expand to many files, and the request must be
    # judged by the total amount of work it creates, not by how few paths it
    # used to say it. Expanding first also means a listing error cannot leave
    # half a batch stored.
    candidates: list[Any] = []
    for raw in body.paths:
        candidates.extend(import_candidates(raw, settings, recursive=body.recursive))
    _check_request_size(len(candidates))

    sources: list[dict[str, Any]] = []
    jobs: list[dict[str, Any]] = []
    for resolved in candidates:
        container, container_id, plans = _intake_import(case_id, resolved.path, settings)
        job, rows = await _record_plans(case_id, container, container_id, plans, writer)
        jobs.append(job)
        sources.extend(rows)
        await manager.enqueue(job["id"], encode_payload(job["id"], case_id, plans))
    return {"jobs": jobs, "sources": sources}


@router.get("/sources/{source_id}")
def get_source(
    source_id: str,
    sources: SourceRepository = Depends(source_repository),
) -> dict[str, Any]:
    """One source, with the paths an operator needs to open the original."""
    record = _require_source(sources, source_id)
    return _source_detail(record)


@router.get("/sources/{source_id}/parse-errors")
def parse_errors(
    source_id: str,
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=500),
    errors: ParseErrorRepository = Depends(parse_error_repository),
) -> dict[str, Any]:
    """One page of malformed records for a source."""
    rows = errors.list_for_source(source_id, offset=(page - 1) * limit, limit=limit)
    return {
        "items": [
            {
                "record_ref": row.record_ref,
                "reason": row.reason,
                "raw_excerpt": row.raw_excerpt,
            }
            for row in rows
        ],
        "total": errors.count_for_source(source_id),
        "page": page,
        "limit": limit,
    }


@router.patch("/sources/{source_id}")
async def patch_source(
    source_id: str,
    update: SourceUpdate,
    writer: DBWriter = Depends(get_writer),
    manager: JobManager = Depends(get_job_manager),
) -> dict[str, Any]:
    """Update detection and timestamp hints.

    Any changed field that affects parsing (log_type, timezone, assumed_year)
    triggers a re-parse that replaces the source's events, as spec 06 requires;
    the response is then ``202`` with the new job, like resolve. A no-op patch or
    one that only tunes hints on a source with no parser yet returns ``200``.
    """
    if update.log_type is not None and update.log_type not in load_builtin_parsers():
        raise ApiError(
            ErrorCode.UNSUPPORTED_FORMAT,
            "no parser is available for that log type",
            log_type=update.log_type,
        )

    record, updated, job = await writer.run_async(
        lambda connection: _patch_on_connection(connection, source_id, update)
    )

    if job is None:
        return _source_detail(updated)

    plan = SourcePlan(
        source_id=source_id,
        case_id=record.case_id,
        path=record.stored_path,
        filename=record.filename,
        log_type=updated.log_type,
        detect_confidence=None,
        timezone=updated.timezone,
        assumed_year=updated.assumed_year,
    )
    await manager.enqueue(job.id, encode_payload(job.id, record.case_id, [plan]))
    return JSONResponse(  # type: ignore[return-value]  # Response bypasses FastAPI's response model
        content={"job": _job_detail(job), "source": _source_detail(updated)},
        status_code=202,
    )


def _patch_on_connection(
    connection: sqlite3.Connection, source_id: str, update: SourceUpdate
) -> tuple[Any, Any, JobRecord | None]:
    """Apply a source patch; open a re-parse job when parsing-relevant fields
    changed, as one writer transaction.

    Returns ``(record, updated, job)`` where ``job`` is ``None`` when the patch is
    a no-op or only tunes hints on a source that no parser can read yet.
    """
    sources = SourceRepository(connection)
    record = _require_source(sources, source_id)

    effective_log_type = update.log_type or record.log_type
    changed = any(
        (
            update.log_type is not None and update.log_type != record.log_type,
            update.timezone is not None and update.timezone != record.timezone,
            update.assumed_year is not None and update.assumed_year != record.assumed_year,
        )
    )
    if changed and effective_log_type is not None:
        return _reparse_on_connection(
            connection,
            source_id,
            log_type=effective_log_type,
            timezone=update.timezone or record.timezone,
            assumed_year=update.assumed_year or record.assumed_year,
        )

    # No field reaching the re-parser moved: a no-op patch, or hint-only tuning
    # of a source that is parked waiting for a parser name. Update whatever was
    # offered and leave the row's state alone.
    changes: dict[str, Any] = {}
    if update.log_type is not None:
        changes["log_type"] = update.log_type
        # A manual choice is not a detection result, so the old confidence
        # would be a lie about where the value came from.
        changes["detect_confidence"] = None
    if update.timezone is not None:
        changes["timezone"] = update.timezone
    if update.assumed_year is not None:
        changes["assumed_year"] = update.assumed_year
    sources.update(source_id, **changes)
    updated = _require_source(sources, source_id)
    return record, updated, None


def _reparse_on_connection(
    connection: sqlite3.Connection,
    source_id: str,
    *,
    log_type: str,
    timezone: str | None,
    assumed_year: int | None,
) -> tuple[Any, Any, JobRecord]:
    """Reset a source for re-parse and open the job that will do it.

    All of it in one writer transaction: clearing the old events, arming the new
    job and flipping the source back to ``queued`` have to be atomic, or a crash
    mid-way leaves a source that is queued with no job to queue it, or a job whose
    source already holds the previous attempt's events.
    """
    sources = SourceRepository(connection)
    record = _require_source(sources, source_id)
    EventRepository(connection).delete_for_source(source_id)
    ParseErrorRepository(connection).clear_for_source(source_id)
    sources.update(
        source_id,
        log_type=log_type,
        timezone=timezone,
        assumed_year=assumed_year,
        detect_confidence=None,
    )
    sources.set_counters(
        source_id,
        event_count=0,
        error_count=0,
        first_event_ms=None,
        last_event_ms=None,
    )
    sources.set_status(source_id, SourceStatus.QUEUED)
    job = JobRepository(connection).create(
        kind=JobKind.INGEST, case_id=record.case_id, source_id=source_id
    )
    updated = _require_source(sources, source_id)
    return record, updated, job


@router.post("/sources/{source_id}/resolve", status_code=202)
async def resolve_source(
    source_id: str,
    body: ResolveRequest,
    writer: DBWriter = Depends(get_writer),
    manager: JobManager = Depends(get_job_manager),
) -> dict[str, Any]:
    """Answer a ``needs_input`` source and resume ingesting it.

    Events from the previous attempt are removed first. Replacing rather than
    appending is what makes a re-parse idempotent: asking twice must not double
    the case's event count.
    """
    if body.log_type not in load_builtin_parsers():
        raise ApiError(
            ErrorCode.UNSUPPORTED_FORMAT,
            "no parser is available for that log type",
            log_type=body.log_type,
        )

    record, updated, job = await writer.run_async(
        lambda connection: _reparse_on_connection(
            connection,
            source_id,
            log_type=body.log_type,
            timezone=body.timezone,
            assumed_year=body.assumed_year,
        )
    )

    plan = SourcePlan(
        source_id=source_id,
        case_id=record.case_id,
        path=record.stored_path,
        filename=record.filename,
        log_type=body.log_type,
        detect_confidence=None,
        timezone=body.timezone,
        assumed_year=body.assumed_year,
    )
    await manager.enqueue(job.id, encode_payload(job.id, record.case_id, [plan]))
    return {"job": _job_detail(job), "source": _source_detail(updated)}


@router.delete("/sources/{source_id}")
def delete_source(
    source_id: str,
    request: Request,
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    """Delete a source, its events, and the bytes intake stored for it."""
    case_id = write_in(
        request,
        lambda connection: _delete_on_connection(connection, source_id),
    )
    remove_stored(
        _source_dir(settings, case_id, source_id),
        secure=settings.storage.secure_delete,
    )
    return {"id": source_id, "deleted": True}


def _delete_on_connection(connection: sqlite3.Connection, source_id: str) -> str:
    """Delete one source row and return the case it belonged to.

    The case id comes back so the caller can remove the stored bytes, which is
    the filesystem half of the delete and cannot happen in the transaction.

    The indicators this source's events touched are snapshotted first and
    recounted after: the delete cascades their occurrence rows away, and an
    indicator left with none is orphaned rather than merely stale. A
    ``source_deleted`` row is appended to the audit chain in the same
    transaction (spec 02 section 4).
    """
    sources = SourceRepository(connection)
    record = _require_source(sources, source_id)
    iocs = IocRepository(connection)
    affected = iocs.snapshot_for_source(source_id)
    sources.delete(source_id)
    iocs.recompute(affected)
    AuditRepository(connection).append(
        "source_deleted",
        case_id=str(record.case_id),
        detail={"source_id": source_id, "filename": record.filename},
    )
    return str(record.case_id)


@router.get("/sources/{source_id}/download")
def download_source(
    source_id: str,
    sources: SourceRepository = Depends(source_repository),
) -> FileResponse:
    """Serve the original file with its integrity hash in a header (spec 06)."""
    record = _require_source(sources, source_id)
    path = Path(record.stored_path)
    if not path.is_file():
        raise ApiError(ErrorCode.NOT_FOUND, "stored file is missing", source_id=source_id)
    return FileResponse(
        path,
        media_type="application/octet-stream",
        filename=record.filename,
        headers={"X-SHA256": record.sha256},
    )


# ---------------------------------------------------------------------------
# Intake
# ---------------------------------------------------------------------------


def _source_dir(settings: Settings, case_id: str, source_id: str) -> Path:
    """Where intake stores one source's bytes."""
    return settings.cases_dir / case_id / "sources" / source_id


def _check_request_size(count: int) -> None:
    """Refuse a request that would create an unbounded amount of work."""
    if count > MAX_SOURCES_PER_REQUEST:
        raise ApiError(
            ErrorCode.VALIDATION_ERROR,
            "too many files in one request",
            count=count,
            maximum=MAX_SOURCES_PER_REQUEST,
        )


def _intake_upload(
    case_id: str,
    upload: UploadFile,
    *,
    settings: Settings,
    log_type: str | None,
    timezone: str | None,
    assumed_year: int | None,
) -> tuple[StoredFile | None, str, list[SourcePlan]]:
    """Store one uploaded stream and turn it into source plans.

    The returned ``StoredFile`` is the container, and is ``None`` for a plain
    upload: there is no separate parent to record when the file is its own source.
    """
    container_id = new_id()
    destination = _source_dir(settings, case_id, container_id)
    try:
        result = intake_stream(
            upload.file,
            destination,
            upload.filename or "upload.bin",
            settings=settings,
            log_type_override=log_type,
            expected_bytes=getattr(upload, "size", None),
        )
    except ApiError:
        remove_stored(destination)
        raise
    except OSError as error:
        remove_stored(destination)
        raise ApiError(
            ErrorCode.INTERNAL, "upload could not be stored", detail=type(error).__name__
        ) from error
    finally:
        upload.file.close()
    container = result.stored if result.archive is not None else None
    return container, container_id, _plans(case_id, container_id, result, timezone, assumed_year)


def _intake_import(
    case_id: str, path: Path, settings: Settings
) -> tuple[StoredFile | None, str, list[SourcePlan]]:
    """Copy one on-disk file into storage and turn it into source plans."""
    container_id = new_id()
    destination = _source_dir(settings, case_id, container_id)
    try:
        result = intake_path(path, destination, settings=settings)
    except ApiError:
        remove_stored(destination)
        raise
    except OSError as error:
        remove_stored(destination)
        raise ApiError(
            ErrorCode.INTERNAL, "file could not be imported", detail=type(error).__name__
        ) from error
    container = result.stored if result.archive is not None else None
    return (
        container,
        container_id,
        _plans(case_id, container_id, result, timezone=None, assumed_year=None),
    )


def _plans(
    case_id: str,
    container_id: str,
    result: IntakeResult,
    timezone: str | None,
    assumed_year: int | None,
) -> list[SourcePlan]:
    """One plan per stored file, each with the id its source row will use.

    ``IntakeResult.files`` and ``IntakeResult.detections`` are the same length in
    the same order, so zipping them cannot pair a member with another member's
    detection decision.

    For an archive the members become the sources and the container does not: the
    archive itself has no records to parse, and giving it a source row would park
    it in ``needs_input`` forever.
    """
    expanded = result.archive is not None
    plans: list[SourcePlan] = []
    for stored, detection in zip(result.files, result.detections, strict=True):
        plans.append(
            SourcePlan(
                # A plain upload is its own container; only archive members need
                # an id of their own alongside the container they came from.
                source_id=container_id if not expanded else new_id(),
                case_id=case_id,
                path=str(stored.path),
                filename=stored.filename,
                # A needs_input decision parks this source rather than guessing a
                # format: a confidently wrong parse silently corrupts the stream.
                log_type=None if detection.needs_input else detection.log_type,
                detect_confidence=detection.confidence,
                timezone=timezone,
                assumed_year=assumed_year,
                candidates=[c.as_dict() for c in detection.candidates],
                parent_source_id=container_id if expanded else None,
            )
        )
    return plans


async def _record_plans(
    case_id: str,
    container: StoredFile | None,
    container_id: str,
    plans: list[SourcePlan],
    writer: DBWriter,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Insert the job and one source row per plan, on the writer thread.

    ``container`` is the archive that was expanded, when the upload was one. Its
    row exists so ``sources.parent_source_id`` has something to point at, which is
    also what makes deleting the bundle delete its members (spec 02 section 4,
    ``ON DELETE CASCADE``). The container is not parsed and is not reported as an
    ingestable source, so it is stored as already ``done`` with no events.

    The job is linked to the container so a caller can find the job that produced
    a given source; for a plain upload the container *is* the source, and its plan
    carries the same id.

    One transaction, on the writer thread: the job and the source rows it refers
    to are inserted together or not at all, and they do not race the ingest job's
    own writes to the same rows.
    """
    job, rows = await writer.run_async(
        lambda connection: _insert_plans(connection, case_id, container, container_id, plans)
    )
    return _job_detail(job), [_source_detail(row) for row in rows]


def _insert_plans(
    connection: sqlite3.Connection,
    case_id: str,
    container: StoredFile | None,
    container_id: str,
    plans: list[SourcePlan],
) -> tuple[JobRecord, list[Any]]:
    """Write the container row, the job and every planned source row."""
    jobs = JobRepository(connection)
    sources = SourceRepository(connection)
    if container is not None:
        sources.create(
            case_id=case_id,
            filename=container.filename,
            stored_path=str(container.path),
            size_bytes=container.size,
            sha256=container.sha256,
            status=SourceStatus.DONE,
            log_type=None,
            source_id=container_id,
        )
    job = jobs.create(kind=JobKind.INGEST, case_id=case_id, source_id=container_id)
    rows = [
        sources.create(
            case_id=case_id,
            filename=plan.filename,
            stored_path=plan.path,
            size_bytes=Path(plan.path).stat().st_size,
            sha256=_sha256_of(Path(plan.path)),
            status=SourceStatus.QUEUED if plan.log_type else SourceStatus.NEEDS_INPUT,
            parent_source_id=plan.parent_source_id,
            log_type=plan.log_type,
            detect_confidence=plan.detect_confidence,
            timezone=plan.timezone,
            assumed_year=plan.assumed_year,
            source_id=plan.source_id,
        )
        for plan in plans
    ]
    return jobs.get(job.id) or job, rows


def _sha256_of(path: Path) -> str:
    """SHA-256 of a stored file, for the source row's integrity hash."""
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _require_source(sources: SourceRepository, source_id: str) -> Any:
    """The source row, or a 404."""
    record = sources.get(source_id)
    if record is None:
        raise ApiError(ErrorCode.NOT_FOUND, "source not found", source_id=source_id)
    return record


def _status_or_400(status: str | None) -> SourceStatus | None:
    """Parse a status filter, refusing an unknown value rather than ignoring it."""
    if not status:
        return None
    try:
        return SourceStatus(status)
    except ValueError as error:
        raise ApiError(
            ErrorCode.VALIDATION_ERROR, "unknown source status", status=status
        ) from error


def _source_detail(record: Any) -> dict[str, Any]:
    """A source row as the API returns it: counters plus identity and hashes."""
    return {**source_payload(record), "size_bytes": record.size_bytes, "sha256": record.sha256}


def _job_detail(job: JobRecord) -> dict[str, Any]:
    """A job row as the API returns it."""
    return job.model_dump()


__all__ = [
    "FromPathRequest",
    "ResolveRequest",
    "SourceUpdate",
    "import_from_paths",
    "router",
    "upload_sources",
]
