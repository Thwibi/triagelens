"""Report endpoints (spec 06 "Reports" and spec 08 section 1 and 2).

``POST /cases/{id}/reports`` validates the request synchronously -- including the
"PDF is an optional feature" rule from spec 08 section 2, answering
``422 PDF_UNAVAILABLE`` when WeasyPrint is absent -- then enqueues a ``report``
job whose 202 response is the job the UI polls. The generated file is recorded
in ``reports`` with its SHA-256, and ``GET /reports/{id}/download`` serves the
bytes only after re-hashing them against that row (spec 08 sections 1 and 2).

``GET /cases/{id}/reports/alerts.csv`` is the alert-overview export (spec 08
section 4): bounded pages, formula-injection-guarded cells, and the total in
the ``X-Total`` header so a client can walk the whole case.
"""

from __future__ import annotations

import importlib.util
import json
import sqlite3
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field

from app.api.deps import (
    alert_repository,
    case_repository,
    get_job_manager,
    read_connection,
    report_repository,
    write_in,
)
from app.db.repositories.alerts import AlertRepository
from app.db.repositories.cases import CaseRepository
from app.db.repositories.jobs import JobRepository
from app.db.repositories.reports import ReportRepository
from app.errors import ApiError, ErrorCode, validation_error
from app.jobs.manager import JobManager
from app.jobs.report import encode_payload
from app.mitre.catalogue import MitreCatalogue
from app.mitre.tactics import TACTIC_NAMES
from app.models.job import JobKind
from app.reports.options import MAX_EVENTS_PER_ALERT, REPORT_FORMATS, options_from_dict
from app.reports.render import render_alerts_csv
from app.reports.service import report_file
from app.util.time import iso_from_ms

router = APIRouter(tags=["reports"])

#: Media type per report format, for the download endpoint.
_MEDIA_TYPE: dict[str, str] = {
    "html": "text/html; charset=utf-8",
    "pdf": "application/pdf",
    "md": "text/markdown; charset=utf-8",
    "json": "application/json; charset=utf-8",
}
#: File extension per report format, for the download's filename.
_EXTENSION: dict[str, str] = {"html": "html", "pdf": "pdf", "md": "md", "json": "json"}
#: Default page size of the alert CSV export (spec 08 section 4).
_CSV_LIMIT = 2000


class ReportIncludeBody(BaseModel):
    """Every section toggle of the report request (spec 08 section 1).

    ``alerts`` is the list of alert statuses to include; absent means every
    status, and an empty list turns the alert sections off. Sections 1 (cover)
    and 9 (integrity) are fixed and cannot be switched off, so they are not here.
    """

    model_config = ConfigDict(extra="forbid")

    alerts: list[str] | None = None
    iocs: bool = True
    mitre: bool = True
    timeline: bool = True
    entities: bool = True
    appendix_raw: bool = False
    events_per_alert: int = Field(default=0, ge=0, le=MAX_EVENTS_PER_ALERT)


class ReportRequest(BaseModel):
    """Body of ``POST /cases/{id}/reports``."""

    model_config = ConfigDict(extra="forbid")

    format: str = "html"
    title: str | None = Field(default=None, max_length=200)
    analyst: str | None = Field(default=None, max_length=200)
    include: ReportIncludeBody | None = None


@router.post("/cases/{case_id}/reports", status_code=202)
async def create_report(
    request: Request,
    case_id: str,
    body: ReportRequest,
    manager: JobManager = Depends(get_job_manager),
    cases: CaseRepository = Depends(case_repository),
) -> dict[str, Any]:
    """Enqueue a report job; ``202`` carries the job the UI polls."""
    fmt = body.format
    if fmt not in REPORT_FORMATS:
        raise ApiError(
            ErrorCode.UNSUPPORTED_FORMAT,
            "unsupported report format",
            format=fmt,
            allowed=sorted(REPORT_FORMATS),
        )
    if fmt == "pdf" and not _pdf_available():
        raise ApiError(
            ErrorCode.PDF_UNAVAILABLE,
            "PDF rendering needs the optional WeasyPrint dependency; "
            "install it or choose HTML, Markdown or JSON",
            format="pdf",
        )
    if cases.get(case_id) is None:
        raise ApiError(ErrorCode.NOT_FOUND, "case not found", id=case_id)
    include = body.include
    options_dict: dict[str, Any] = {
        "format": fmt,
        "title": body.title,
        "analyst": body.analyst,
        "events_per_alert": include.events_per_alert if include is not None else 0,
        "iocs": include.iocs if include is not None else True,
        "mitre": include.mitre if include is not None else True,
        "timeline": include.timeline if include is not None else True,
        "entities": include.entities if include is not None else True,
        "appendix_raw": include.appendix_raw if include is not None else False,
    }
    if include is not None and include.alerts is not None:
        options_dict["statuses"] = list(include.alerts)
    try:
        options = options_from_dict(options_dict)
    except ValueError as error:
        raise validation_error(str(error)) from error
    job = write_in(
        request,
        lambda connection: JobRepository(connection).create(
            kind=JobKind.REPORT, case_id=case_id, message=f"report ({fmt})"
        ),
    )
    await manager.enqueue(job.id, encode_payload(job.id, case_id, options))
    return job.model_dump(mode="json")


@router.get("/cases/{case_id}/reports")
def list_reports(
    case_id: str,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    reports: ReportRepository = Depends(report_repository),
) -> dict[str, Any]:
    """Reports of one case, newest first, with the unpaginated total."""
    rows = reports.list_by_case(case_id, limit=limit, offset=offset)
    return {
        "items": [_report_detail(row) for row in rows],
        "total": reports.count_by_case(case_id),
        "limit": limit,
        "offset": offset,
    }


@router.get("/reports/{report_id}/download")
def download_report(
    report_id: str,
    connection: sqlite3.Connection = Depends(read_connection),
) -> Response:
    """Serve a generated report, re-hashed against its recorded SHA-256."""
    record, payload = report_file(connection, report_id)
    return Response(
        content=payload,
        media_type=_MEDIA_TYPE[record.format],
        headers={
            "Content-Disposition": f"attachment; filename={record.id}.{_EXTENSION[record.format]}",
            "X-SHA256": record.sha256,
        },
    )


@router.get("/cases/{case_id}/reports/alerts.csv")
def alerts_csv(
    case_id: str,
    limit: int = Query(_CSV_LIMIT, ge=1, le=10_000),
    offset: int = Query(0, ge=0),
    alerts: AlertRepository = Depends(alert_repository),
) -> Response:
    """One bounded page of the alert overview as CSV (spec 08 section 4).

    Cells are guarded against spreadsheet formula injection, and ``X-Total``
    carries the unpaginated row count so a client can walk the whole export.
    """
    text, total = render_alerts_csv(_csv_page(alerts, case_id), limit=limit, offset=offset)
    return Response(
        content=text,
        media_type="text/csv; charset=utf-8",
        headers={"X-Total": str(total)},
    )


def _csv_page(alerts: AlertRepository, case_id: str) -> Any:
    """A page callable for :func:`render_alerts_csv` over the wire alert shape."""
    connection = alerts.connection
    catalogue = MitreCatalogue.load(connection)

    def _page(limit: int, offset: int) -> tuple[list[dict[str, Any]], int]:
        rows, total = alerts.search(case_id, limit=limit, offset=offset)
        return [_csv_alert(row, catalogue) for row in rows], int(total)

    return _page


def _csv_alert(record: Any, catalogue: Any) -> dict[str, Any]:
    """The alert CSV's columns, ISO timestamps converted for spreadsheets."""
    tactics = [str(item) for item in json.loads(record.tactics_json)]
    return {
        "id": record.id,
        "rule_id": record.rule_id,
        "rule_title": record.rule_title,
        "level": record.level,
        "score": record.score,
        "status": record.status,
        "tactics": [
            {
                "shortname": shortname,
                "name": catalogue.tactics.get(shortname, TACTIC_NAMES.get(shortname, shortname)),
            }
            for shortname in tactics
        ],
        "techniques": json.loads(record.techniques_json),
        "host": record.host,
        "user_name": record.user_name,
        "first_seen": iso_from_ms(record.first_seen_ms),
        "last_seen": iso_from_ms(record.last_seen_ms),
        "match_count": record.match_count,
        "analyst_notes": record.analyst_notes,
    }


def _report_detail(record: Any) -> dict[str, Any]:
    """A ``reports`` row as the API returns it, options parsed back."""
    return {
        "id": record.id,
        "case_id": record.case_id,
        "format": record.format,
        "sha256": record.sha256,
        "created_at": record.created_at,
        "options": json.loads(record.options_json),
    }


def _pdf_available() -> bool:
    """True when the optional WeasyPrint extra is importable (spec 08 section 2)."""
    try:
        return importlib.util.find_spec("weasyprint") is not None
    except (ImportError, ValueError):  # pragma: no cover - defensive
        return False


__all__ = [
    "ReportRequest",
    "alerts_csv",
    "create_report",
    "download_report",
    "list_reports",
    "router",
]
