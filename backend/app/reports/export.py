"""Streaming event exports (spec 08 section 4, spec 07 section 3.7).

``GET /cases/{id}/events/export`` walks the *current filter result* in keyset
pages and yields text chunks, so a multi-million-row case is never built in
memory (spec 06 section 5). Two formats share one column set:

* **CSV** -- every normalized column plus ``fields_json`` as a JSON string, with
  each cell passed through the spreadsheet-injection guard (spec 10 section 1).
* **JSONL** -- one JSON object per line, the normalized columns plus the parsed
  ``fields`` mapping, so a consumer gets structured values rather than a string.

The scan is bounded by ``max_rows`` (the UI's 1M-row ceiling); when the cap is
hit the stream simply stops, so a caller who needs the rest can narrow filters.
"""

from __future__ import annotations

import csv
import json
from collections.abc import Iterator
from io import StringIO
from typing import Any

from app.ingest.events import EVENT_COLUMNS
from app.util.csv import safe_cell

#: Formats the endpoint accepts (spec 07 section 3.7).
EXPORT_FORMATS: tuple[str, ...] = ("csv", "jsonl")
#: Response media type per export format.
EXPORT_MEDIA_TYPE: dict[str, str] = {
    "csv": "text/csv; charset=utf-8",
    "jsonl": "application/x-ndjson",
}
#: Rows per keyset fetch; keeps the working set bounded on a huge case.
PAGE_SIZE = 1000
#: Uploaded ceiling -- the UI promises at most one million rows (spec 07 3.7).
MAX_ROWS = 1_000_000

#: CSV/JSONL columns: the normalized event model plus the raw-field blob. The
#: ``id`` is included first because it is the stable handle a follow-up pivot
#: uses; ``fields_json`` is the only column not in ``EVENT_COLUMNS``.
EXPORT_COLUMNS: tuple[str, ...] = ("id", *EVENT_COLUMNS, "fields_json")


def iter_events_export(
    events: Any,
    filters: Any,
    *,
    fmt: str,
    sort: str = "-ts",
    max_rows: int = MAX_ROWS,
    page_size: int = PAGE_SIZE,
) -> Iterator[str]:
    """Yield one event export as text chunks, page by page.

    ``events`` is an :class:`~app.db.repositories.events.EventRepository` bound to
    a connection that outlives this iterator; ``filters`` is the same
    ``EventFilters`` the list endpoint uses, so the export is exactly the current
    result set. Raises ``ValueError`` for invalid FTS syntax, which the endpoint
    turns into ``422`` before the response body starts.
    """
    if fmt == "csv":
        yield _csv_line(EXPORT_COLUMNS)
    emitted = 0
    cursor: tuple[int, int] | None = None
    while emitted < max_rows:
        want = min(page_size, max_rows - emitted)
        rows, cursor = events.search(filters, sort=sort, cursor=cursor, limit=want)
        if not rows:
            return
        for row in rows:
            yield _csv_row(row) if fmt == "csv" else _jsonl_row(row)
            emitted += 1
        if cursor is None:
            return


def _csv_line(values: Any) -> str:
    """One CSV record, guarded and newline-terminated, without a trailing BOM."""
    stream = StringIO()
    csv.writer(stream, lineterminator="\n").writerow(values)
    return stream.getvalue()


def _csv_row(row: Any) -> str:
    """One event as a guarded CSV record; null columns become empty cells."""
    stream = StringIO()
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow([safe_cell(_text(row[column])) for column in EXPORT_COLUMNS])
    return stream.getvalue()


def _jsonl_row(row: Any) -> str:
    """One event as a JSON object line (normalized columns + parsed fields)."""
    payload: dict[str, Any] = {"id": row["id"]}
    for column in EVENT_COLUMNS:
        payload[column] = row[column]
    payload["fields"] = json.loads(row["fields_json"])
    return json.dumps(payload, ensure_ascii=False, default=str) + "\n"


def _text(value: Any) -> str:
    """A cell's text: SQL ``NULL`` and JSON ``null`` render as an empty string."""
    if value is None:
        return ""
    return str(value)


__all__ = [
    "EXPORT_COLUMNS",
    "EXPORT_FORMATS",
    "EXPORT_MEDIA_TYPE",
    "MAX_ROWS",
    "PAGE_SIZE",
    "iter_events_export",
]
