"""Render one :class:`~app.reports.model.ReportData` into HTML, Markdown, PDF or JSON.

* **HTML**: a self-contained Jinja2 document with ``autoescape=True`` -- inline
  CSS, inline SVG charts, no external requests and no JavaScript (spec 08 2).
* **Markdown**: GitHub-flavoured; code fences are widened to exceed any backtick
  run in the content and table cells escape ``|`` (spec 08 2).
* **PDF**: WeasyPrint over the same HTML; ``PdfUnavailableError`` when the
  optional dependency is absent and the endpoint answers ``422 PDF_UNAVAILABLE``.
* **JSON**: ``data.as_dict()``.

All four share the one neutral data model, so the acceptance rule -- "generated
twice from the same data differs only in the generation timestamp and report
id" -- holds across formats for one model instance and within a format across
two generations.
"""

from __future__ import annotations

import csv
import json
from io import StringIO
from typing import Any

from jinja2 import Environment, PackageLoader

from app.reports.model import ReportData
from app.util.csv import safe_cell as _safe_cell

#: How long a table cell may be before the ``…`` marker replaces the tail.
_TRUNCATE_CELL = 120
_LEVEL_COLOR: dict[str, str] = {
    "informational": "#e8e8e8",
    "low": "#ffe766",
    "medium": "#ffb347",
    "high": "#ff8c69",
    "critical": "#ff6666",
}


class PdfUnavailableError(RuntimeError):
    """WeasyPrint is not installed; the API answers ``422 PDF_UNAVAILABLE``."""


def render_json(data: ReportData) -> str:
    """The JSON report body (spec 08 section 1)."""
    return json.dumps(data.as_dict(), indent=2, ensure_ascii=False)


def render_markdown(data: ReportData) -> str:
    """GitHub-flavoured Markdown, GFM tables escaped."""
    lines: list[str] = []
    lines.append(_heading(1, data.meta.title))
    lines.append("")
    lines.append(
        f"*Contains evidence-derived data* — {data.meta.tool_version}, "
        f"ATT&CK {data.meta.attack_version}, ruleset {data.meta.ruleset_hash}."
    )
    lines.append("")

    lines.extend(_md_executive(data))
    if data.include.get("alerts"):
        lines.extend(_md_alerts(data))
    if data.include.get("iocs") and data.iocs:
        lines.extend(_md_iocs(data))
    if data.include.get("mitre") and data.mitre.get("matrix"):
        lines.extend(_md_mitre(data))
    if data.include.get("timeline") and data.timeline.get("buckets"):
        lines.extend(_md_timeline(data))
    if data.include.get("entities") and data.entities:
        lines.extend(_md_entities(data))
    lines.extend(_md_integrity(data))
    if data.include.get("appendix") and data.appendix_raw:
        lines.extend(_md_appendix(data))
    return "\n".join(lines).rstrip() + "\n"


def render_html(data: ReportData) -> str:
    """A self-contained HTML document (Jinja2, autoescape, no JS)."""
    environment = _environment()
    template = environment.get_template("report.html.j2")
    return template.render(
        data=data,
        level_color=_LEVEL_COLOR,
        timeline=_timeline_chart(data),
        heatgrid=_heatgrid(data),
    )


def _timeline_chart(data: ReportData) -> dict[str, Any]:
    """SVG geometry for the timeline chart (spec 08 section 1.7)."""
    buckets = data.timeline.get("buckets") or []
    height, bar_w = 220, 4
    max_count = max((int(bucket["count"]) for bucket in buckets), default=1)
    bars: list[dict[str, Any]] = []
    for index, bucket in enumerate(buckets):
        count = int(bucket["count"])
        bar_h = max(2, round(count / max_count * (height - 20)))
        bars.append(
            {
                "x": 30 + index * (bar_w + 1),
                "y": height - 20 - bar_h,
                "h": bar_h,
                "count": count,
                "alerts": int(bucket.get("alert_count") or 0),
                "t_ms": int(bucket.get("t_ms") or 0),
            }
        )
    return {"width": 30 + len(bars) * (bar_w + 1), "height": height, "bars": bars}


def _heatgrid(data: ReportData) -> dict[str, Any]:
    """Static SVG heat-grid geometry for the MITRE coverage section (spec 08 1.5)."""
    columns: list[dict[str, Any]] = []
    max_rows = 0
    for tactic in (data.mitre.get("matrix") or {}).get("tactics") or []:
        techniques = tactic.get("techniques") or []
        cells: list[dict[str, Any]] = []
        for technique in techniques:
            sub = technique.get("subtechniques") or []
            trees: list[dict[str, Any]] = [
                {
                    "id": technique.get("id", ""),
                    "name": technique.get("name", ""),
                    "level": technique.get("max_level", ""),
                    "count": technique.get("alert_count", 0),
                }
            ]
            trees.extend(
                {
                    "id": child.get("id", ""),
                    "name": child.get("name", ""),
                    "level": child.get("max_level", ""),
                    "count": child.get("alert_count", 0),
                }
                for child in sub
            )
            cells.extend(trees)
        max_rows = max(max_rows, len(cells))
        columns.append({"name": tactic.get("name", ""), "cells": cells})
    width, row_h, col_w, label = 90 * len(columns) + 30, 22, 90, 16
    return {
        "width": width,
        "height": label + max_rows * row_h,
        "row_h": row_h,
        "col_w": col_w,
        "label": label,
        "columns": columns,
    }


def render_pdf(html: str) -> bytes:
    """Render ``html`` to PDF bytes via WeasyPrint when available."""
    try:
        from weasyprint import HTML
    except ImportError as error:  # pragma: no cover - exercised by the 422 path
        raise PdfUnavailableError(
            "PDF rendering needs the optional WeasyPrint dependency; "
            "install it or choose HTML, Markdown or JSON"
        ) from error
    pdf: bytes = HTML(string=html).write_pdf()
    return pdf


def render_alerts_csv(rows: Any, limit: int = 2000, offset: int = 0) -> tuple[str, int]:
    """The alert overview CSV (spec 08 section 4) with formula-injection guard.

    Returns ``(csv_text, total)``; ``rows`` is the repository's ``search`` page.
    """
    stream = StringIO()
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(
        [
            "alert_id",
            "level",
            "score",
            "status",
            "rule_id",
            "rule_title",
            "tactics",
            "techniques",
            "host",
            "user",
            "first_seen",
            "last_seen",
            "match_count",
            "analyst_notes",
        ]
    )
    items, total = rows(limit=limit, offset=offset)
    for alert in items:
        writer.writerow(
            [
                _safe_cell(alert["id"]),
                _safe_cell(alert["level"]),
                _safe_cell(alert["score"]),
                _safe_cell(alert["status"]),
                _safe_cell(alert["rule_id"]),
                _safe_cell(alert["rule_title"]),
                _safe_cell(";".join(_tactic_names(alert))),
                _safe_cell(";".join(_technique_ids(alert))),
                _safe_cell(alert["host"] or ""),
                _safe_cell(alert["user_name"] or ""),
                _safe_cell(alert.get("first_seen") or ""),
                _safe_cell(alert.get("last_seen") or ""),
                _safe_cell(str(alert["match_count"])),
                _safe_cell(alert["analyst_notes"] or ""),
            ]
        )
    return stream.getvalue(), int(total)


def _md_executive(data: ReportData) -> list[str]:
    summary = data.summary
    lines = [_heading(2, "Executive summary"), "", summary.paragraph, ""]
    lines.append("| Metric | Value |")
    lines.append("|---|---|")
    rows = [
        ("Time span", f"{summary.first_seen or '-'} to {summary.last_seen or '-'}"),
        ("Sources", str(summary.source_count)),
        ("Events", str(summary.event_count)),
        ("Parse errors", str(summary.error_count)),
        ("Alerts", str(summary.alert_total)),
    ]
    for name, value in rows:
        lines.append(f"| {_cell(name)} | {_cell(value)} |")
    if summary.alerts_by_level:
        lines.append(f"| By level | {_esc_cells(_join_levels(summary.alerts_by_level))} |")
    if summary.top_techniques:
        values = ", ".join(f"{t['name']} ({t['alerts']})" for t in summary.top_techniques)
        lines.append(f"| Top techniques | {_esc_cells(values)} |")
    if summary.top_iocs:
        values = ", ".join(f"{i['type']} {i['value']}" for i in summary.top_iocs)
        lines.append(f"| Top indicators | {_esc_cells(values)} |")
    lines.append("")
    return lines


def _md_alerts(data: ReportData) -> list[str]:
    lines = [_heading(2, "Alerts"), ""]
    lines.append("| Level | Score | Title | Technique(s) | Host | User | Count | Status |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for alert in data.alerts:
        lines.append(
            "| {level} | {score} | {title} | {tech} | {host} | {user} | "
            "{count} | {status} |".format(
                level=_cell(alert.level),
                score=str(alert.score),
                title=_cell(alert.rule_title),
                tech=_esc_cells(_technique_summary(alert.techniques)),
                host=_cell(alert.host or ""),
                user=_cell(alert.user_name or ""),
                count=str(alert.match_count),
                status=_cell(alert.status),
            )
        )
    lines.append("")
    return lines


def _md_iocs(data: ReportData) -> list[str]:
    lines = [_heading(2, "Indicators of compromise"), ""]
    lines.append("| Type | Value | Confidence | Occurrences | First seen | Last seen | State |")
    lines.append("|---|---|---|---|---|---|---|")
    for ioc in data.iocs:
        lines.append(
            "| {type} | {value} | {conf} | {occ} | {first} | {last} | {state} |".format(
                type=_cell(ioc.type),
                value=_cell(ioc.defanged),
                conf=str(ioc.confidence),
                occ=str(ioc.occurrences),
                first=_cell(ioc.first_seen or ""),
                last=_cell(ioc.last_seen or ""),
                state=_cell(ioc.analyst_state),
            )
        )
    lines.append("")
    return lines


def _md_mitre(data: ReportData) -> list[str]:
    lines = [_heading(2, "ATT&CK coverage"), ""]
    matrix = data.mitre["matrix"]
    for tactic in matrix["tactics"]:
        lines.append(f"### {_cell(tactic['name'])}")
        lines.append("")
        for technique in tactic["techniques"]:
            lines.append(f"- {_cell(technique['name'])} `{technique['id']}`")
    lines.append("")
    return lines


def _md_timeline(data: ReportData) -> list[str]:
    lines = [_heading(2, "Timeline"), ""]
    total = sum(bucket["count"] for bucket in data.timeline["buckets"])
    lines.append(f"{total} events across {len(data.timeline['buckets'])} bucket(s).")
    lines.append("")
    return lines


def _md_entities(data: ReportData) -> list[str]:
    lines = [_heading(2, "Entities"), ""]
    lines.append("| Kind | Name | Events | Alerts |")
    lines.append("|---|---|---|---|")
    for entity in data.entities:
        lines.append(
            "| {kind} | {name} | {events} | {alerts} |".format(
                kind=_cell(str(entity["kind"])),
                name=_cell(str(entity["name"])),
                events=str(entity["event_count"]),
                alerts=str(entity["alert_count"]),
            )
        )
    lines.append("")
    return lines


def _md_integrity(data: ReportData) -> list[str]:
    lines = [_heading(2, "Evidence integrity and methodology"), ""]
    lines.append("| Source | Log type | Status | Size | SHA-256 | Event errors |")
    lines.append("|---|---|---|---|---|---|")
    for source in data.sources:
        lines.append(
            "| {file} | {logtype} | {status} | {size} | `{sha}` | {errors} |".format(
                file=_cell(source.filename),
                logtype=_cell(source.log_type or ""),
                status=_cell(source.status),
                size=str(source.size_bytes),
                sha=source.sha256[:16],
                errors=str(source.error_count),
            )
        )
    lines.append("")
    lines.append("Detection runs:")
    for run in data.runs:
        lines.append(
            f"- {_cell(run.id)} ({_cell(run.profile)}): {run.rules_run} rules "
            f"({run.rules_ok} ok, {run.rules_skipped} skipped, "
            f"{run.rules_timeout} timeout, {run.rules_error} error)"
        )
    verification = data.audit_verification
    lines.append("")
    lines.append(
        f"Audit chain: {verification.get('chain_ok', False)} "
        f"({verification.get('rows_checked')} rows checked)"
    )
    lines.append("All logs were processed locally.")
    lines.append("")
    return lines


def _md_appendix(data: ReportData) -> list[str]:
    lines = [_heading(2, "Appendix — raw events"), ""]
    for entry in data.appendix_raw:
        lines.append(f"### Alert {_cell(entry['alert_id'])}")
        lines.append("")
        for event in entry["events"]:
            raw = str(event.get("raw") or "(no raw)")
            fence = _fence(raw)
            lines.append(f"```{fence}")
            lines.append(raw)
            lines.append(fence)
            lines.append("")
    return lines


def _heading(level: int, text: str) -> str:
    return f"{'#' * level} {text}"


def _cell(value: str) -> str:
    """A table cell: pipe-escaped and truncated with the ellipsis marker."""
    if len(value) > _TRUNCATE_CELL:
        value = f"{value[: _TRUNCATE_CELL - 1]}…"
    return _esc_cells(value)


def _esc_cells(value: str) -> str:
    """Escape a table cell per GFM (``|`` -> ``\\|``)."""
    return value.replace("|", "\\|").replace("\n", " ")


def _join_levels(levels: dict[str, int]) -> str:
    return ", ".join(f"{count} {level}" for level, count in sorted(levels.items()))


def _technique_summary(techniques: list[dict[str, Any]]) -> str:
    return "; ".join(f"{t.get('name', t.get('id', ''))} ({t.get('id', '')})" for t in techniques)


def _technique_ids(alert: Any) -> list[str]:
    return [str(item.get("id", "")) for item in alert["techniques"] if isinstance(item, dict)]


def _tactic_names(alert: Any) -> list[str]:
    return [str(item.get("name", "")) for item in alert["tactics"] if isinstance(item, dict)]


def _fence(contents: str) -> str:
    """A code fence strictly longer than any backtick run in ``contents``."""
    longest = 0
    run = 0
    for char in contents:
        if char == "`":
            run += 1
            longest = max(longest, run)
        else:
            run = 0
    return "`" * max(3, longest + 1)


def _environment() -> Environment:
    environment = Environment(
        loader=PackageLoader("app.reports", "templates"),
        autoescape=True,  # the only template is HTML; escape every log-derived value
        trim_blocks=True,
        lstrip_blocks=True,
    )
    environment.filters["cell"] = _truncate_cell
    return environment


def _truncate_cell(value: str) -> str:
    """A table cell truncated with the ellipsis marker (spec 08 section 2)."""
    if len(value) > _TRUNCATE_CELL:
        return f"{value[: _TRUNCATE_CELL - 1]}…"
    return value


__all__ = [
    "PdfUnavailableError",
    "render_alerts_csv",
    "render_html",
    "render_json",
    "render_markdown",
    "render_pdf",
]
