"""Report generation (spec 08).

``gather`` builds the shared data model from a case, ``render`` turns it into
HTML/Markdown/PDF/JSON, and ``service`` writes and records the result. The
public entry points are :func:`app.reports.gather.gather_report`,
:func:`app.reports.service.generate_report` and the ``/cases/{id}/reports`` and
``/reports/{id}/download`` endpoints.
"""

from __future__ import annotations

from app.reports.model import (
    ReportAlert,
    ReportData,
    ReportIoc,
    ReportMeta,
    ReportRun,
    ReportSource,
)
from app.reports.options import MAX_EVENTS_PER_ALERT, REPORT_FORMATS, ReportOptions
from app.reports.render import PdfUnavailableError
from app.reports.service import generate_report, render_bytes, report_file

__all__ = [
    "MAX_EVENTS_PER_ALERT",
    "REPORT_FORMATS",
    "PdfUnavailableError",
    "ReportAlert",
    "ReportData",
    "ReportIoc",
    "ReportMeta",
    "ReportOptions",
    "ReportRun",
    "ReportSource",
    "generate_report",
    "render_bytes",
    "report_file",
]
