"""Report generation options (spec 06 "Reports", spec 08 section 1).

Mirrors the ``POST /cases/{id}/reports`` body: a format, an optional title and
analyst name, and the set of toggled include sections. Every section except the
cover and the integrity/methodology table can be switched off (spec 08 1); the
alert section is driven by the statuses in ``include.alerts``.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from app.models.alert import ALERT_STATUSES

#: Formats a report can be rendered as.
REPORT_FORMATS: tuple[str, ...] = ("html", "pdf", "md", "json")

#: Upper bound on evidence events kept per alert.
MAX_EVENTS_PER_ALERT = 50


def options_from_dict(values: Mapping[str, Any]) -> ReportOptions:
    """Rebuild options from a serialised mapping (job payload or stored JSON).

    Raises ``ValueError`` on anything out of range so a bad payload fails the
    job with a clear message rather than minting a malformed report.
    """
    fmt = str(values.get("format") or "html")
    if fmt not in REPORT_FORMATS:
        raise ValueError(f"unsupported report format: {fmt!r}")
    events_per_alert = int(values.get("events_per_alert") or 0)
    if not 0 <= events_per_alert <= MAX_EVENTS_PER_ALERT:
        raise ValueError(f"events_per_alert must be between 0 and {MAX_EVENTS_PER_ALERT}")
    statuses = values.get("statuses")
    if statuses is None:
        # Absent means "every alert status" (spec 08 section 1); an explicit
        # empty list means "no alert sections", and must stay empty.
        status_list = sorted(ALERT_STATUSES)
    elif isinstance(statuses, (list, tuple)):
        status_list = [str(status) for status in statuses]
    else:
        raise ValueError("alerts must be a list of alert statuses")
    unknown = sorted(set(status_list) - set(ALERT_STATUSES))
    if unknown:
        raise ValueError(f"unsupported alert status(es): {', '.join(unknown)}")
    return ReportOptions(
        fmt=fmt,
        title=(str(values["title"]) if values.get("title") is not None else None),
        analyst=(str(values["analyst"]) if values.get("analyst") is not None else None),
        alert_statuses=tuple(sorted(status_list)),
        include_iocs=bool(values.get("iocs", True)),
        include_mitre=bool(values.get("mitre", True)),
        include_timeline=bool(values.get("timeline", True)),
        include_entities=bool(values.get("entities", True)),
        include_appendix_raw=bool(values.get("appendix_raw", False)),
        events_per_alert=events_per_alert,
    )


@dataclass(frozen=True, slots=True)
class ReportOptions:
    """Normalised options for one report."""

    fmt: str = "html"
    title: str | None = None
    analyst: str | None = None
    alert_statuses: tuple[str, ...] = field(default_factory=lambda: tuple(sorted(ALERT_STATUSES)))
    include_iocs: bool = True
    include_mitre: bool = True
    include_timeline: bool = True
    include_entities: bool = True
    include_appendix_raw: bool = False
    events_per_alert: int = 10

    def as_dict(self) -> dict[str, object]:
        """Options as the JSON stored in ``reports.options_json``."""
        return {
            "format": self.fmt,
            "statuses": list(self.alert_statuses),
            "events_per_alert": self.events_per_alert,
            "iocs": self.include_iocs,
            "mitre": self.include_mitre,
            "timeline": self.include_timeline,
            "entities": self.include_entities,
            "appendix_raw": self.include_appendix_raw,
        }


__all__ = ["MAX_EVENTS_PER_ALERT", "REPORT_FORMATS", "ReportOptions", "options_from_dict"]
