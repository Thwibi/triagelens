"""Write a rendered report to disk and record it (spec 08 sections 1, 2 and 10).

One unit of work for the writer thread: gather the data, render the chosen
format, hash the bytes, write ``data/reports/<case_id>/<report_id>.<ext>``,
insert the ``reports`` row and append a ``report_created`` audit entry, all in
the same transaction the job's caller owns.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from app.config import Settings
from app.db.repositories.audit import AuditRepository
from app.db.repositories.reports import ReportRecord, ReportRepository
from app.errors import ApiError, ErrorCode
from app.reports import render as _render
from app.reports.model import ReportData
from app.reports.options import ReportOptions
from app.util.hashing import sha256_bytes

#: File extension for each supported format (spec 06 "Reports").
_EXTENSION: dict[str, str] = {"html": ".html", "pdf": ".pdf", "md": ".md", "json": ".json"}


def render_bytes(data: ReportData, fmt: str) -> bytes:
    """Render a report as bytes for the requested format."""
    if fmt == "json":
        return _render.render_json(data).encode("utf-8")
    if fmt == "md":
        return _render.render_markdown(data).encode("utf-8")
    html = _render.render_html(data)
    if fmt == "pdf":
        return _render.render_pdf(html)
    return html.encode("utf-8")


def generate_report(
    connection: sqlite3.Connection,
    *,
    case_id: str,
    options: ReportOptions,
    settings: Settings,
) -> tuple[ReportRecord, int]:
    """Gather, render, write and record one report; returns ``(record, size)``.

    The file is written with the report id as its name so the on-disk name never
    reflects client input (spec 10 section 1). Returns the record and the byte
    size for logs.
    """
    from app.reports.gather import gather_report

    data = gather_report(connection, case_id=case_id, options=options)
    payload = render_bytes(data, options.fmt)
    report_id = data.meta.report_id
    directory = settings.reports_dir / case_id
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{report_id}{_EXTENSION[options.fmt]}"
    digest = sha256_bytes(payload)
    path.write_bytes(payload)
    record = ReportRepository(connection).create(
        case_id=case_id,
        fmt=options.fmt,
        options_json=_options_json(options),
        path=str(path),
        sha256=digest,
        report_id=report_id,
    )
    AuditRepository(connection).append(
        "report_created",
        case_id=case_id,
        detail={"report_id": report_id, "format": options.fmt, "sha256": digest},
    )
    return record, len(payload)


def report_file(connection: sqlite3.Connection, report_id: str) -> tuple[ReportRecord, bytes]:
    """The stored bytes of one report, verified against the recorded hash."""
    record = ReportRepository(connection).get(report_id)
    if record is None:
        raise ApiError(ErrorCode.NOT_FOUND, "report not found", id=report_id)
    path = Path(record.path)
    if not path.is_file():
        raise ApiError(ErrorCode.NOT_FOUND, "report file is missing", id=report_id)
    payload = path.read_bytes()
    if sha256_bytes(payload) != record.sha256:
        raise ApiError(ErrorCode.INTERNAL, "report file failed its SHA-256 check", id=report_id)
    return record, payload


def _options_json(options: ReportOptions) -> str:

    return json.dumps(options.as_dict(), sort_keys=True)


__all__ = ["generate_report", "render_bytes", "report_file"]
