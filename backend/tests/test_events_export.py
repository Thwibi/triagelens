"""Event exports (spec 08 section 4, spec 07 section 3.7).

The endpoint streams the current filter result as CSV or JSONL. These tests pin
the four rules the download has to keep: the CSV carries every normalized column
plus ``fields_json`` as a string and is formula-injection safe, both formats walk
keyset pages without materialising the whole result, the filters and the row cap
are honoured, and bad input is refused before the body starts.
"""

from __future__ import annotations

import csv
import io
import json
from typing import Any

from app.db.connection import Database
from app.db.repositories.events import EventFilters, EventRepository
from app.reports.export import EXPORT_COLUMNS, iter_events_export

_TS = 1_700_000_000_000
_ISO = "2026-01-01T00:00:00.000Z"

_MESSAGE_COLUMN = EXPORT_COLUMNS.index("message")


def _seed_case(database: Database) -> None:
    database.writer.execute(
        "INSERT INTO cases (id, name, description, default_timezone, created_at, updated_at) "
        "VALUES ('case-1', 'scene', NULL, 'UTC', ?, ?)",
        (_ISO, _ISO),
    )
    database.writer.execute(
        "INSERT INTO sources (id, case_id, filename, stored_path, size_bytes, sha256, "
        "status, ingested_at) VALUES ('src-1', 'case-1', 'auth.log', '/tmp/auth.log', 0, "
        "'deadbeef', 'done', ?)",
        (_ISO,),
    )


def _add_event(
    database: Database,
    *,
    index: int,
    host: str,
    message: str,
    fields: dict[str, Any] | None = None,
) -> None:
    cursor = database.writer.execute(
        "INSERT INTO events (case_id, source_id, record_ref, ts_ms, ts_iso, log_type, "
        "ls_category, host, channel, app_name, user_name, message, raw, fields_json) "
        "VALUES ('case-1', 'src-1', ?, ?, NULL, 'linux_auth', '', ?, '', 'sshd', "
        "'victim', ?, '{}', ?)",
        (str(index), _TS + index * 1000, host, message, json.dumps(fields or {})),
    )
    rowid = int(cursor.lastrowid or 0)
    database.writer.execute(
        "INSERT INTO events_fts (rowid, message, process_cmdline, parent_process_cmdline, "
        "url, user_agent, file_path, raw) VALUES (?, ?, '', '', '', '', '', '{}')",
        (rowid, message),
    )


def _seed_scene(database: Database) -> None:
    """Four events: a formula cell, a comma/quote cell, an @ cell, and a plain one."""
    _seed_case(database)
    _add_event(database, index=0, host="web-01", message="normal login")
    _add_event(database, index=1, host="web-01", message="=cmd|'/C calc'!A1")
    _add_event(database, index=2, host="db-02", message='has, comma and "quote"')
    _add_event(database, index=3, host="db-02", message="@handle mention", fields={"foo": "bar"})


def test_events_export_csv_streams_and_guards(client: Any, database: Database) -> None:
    """The CSV carries every column, guards formulas and round-trips through csv."""
    _seed_scene(database)

    response = client.get("/api/cases/case-1/events/export?format=csv")
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("text/csv")
    assert response.headers["content-disposition"] == 'attachment; filename="events-case-1.csv"'

    rows = list(csv.reader(io.StringIO(response.text)))
    assert rows[0] == list(EXPORT_COLUMNS)
    data = rows[1:]
    assert len(data) == 4
    for row in data:
        assert len(row) == len(EXPORT_COLUMNS)

    by_host = {row[EXPORT_COLUMNS.index("host")] for row in data}
    assert by_host == {"web-01", "db-02"}
    messages = {row[_MESSAGE_COLUMN] for row in data}
    assert "'=cmd|'/C calc'!A1" in messages
    assert 'has, comma and "quote"' in messages
    assert "'@handle mention" in messages
    assert "normal login" in messages


def test_events_export_jsonl_shape(client: Any, database: Database) -> None:
    """JSONL emits one object per event with parsed fields, unguarded text."""
    _seed_scene(database)

    response = client.get("/api/cases/case-1/events/export?format=jsonl")
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("application/x-ndjson")

    lines = [line for line in response.text.splitlines() if line]
    assert len(lines) == 4
    events = [json.loads(line) for line in lines]
    sample = events[0]
    for column in EXPORT_COLUMNS:
        if column == "fields_json":
            continue
        assert column in sample
    assert json.loads(lines[-1])["message"] == "normal login"
    assert "@handle mention" in {event["message"] for event in events}
    assert any(event["fields"] == {"foo": "bar"} for event in events)


def test_events_export_filters_and_limit(client: Any, database: Database) -> None:
    """The export is the current result set and stops at ``limit`` rows."""
    _seed_scene(database)

    filtered = client.get("/api/cases/case-1/events/export?format=csv&host=db-02")
    rows = list(csv.reader(io.StringIO(filtered.text)))
    assert len(rows) == 3  # header + two db-02 events
    assert all(row[EXPORT_COLUMNS.index("host")] == "db-02" for row in rows[1:])

    capped = client.get("/api/cases/case-1/events/export?format=csv&limit=2")
    capped_rows = list(csv.reader(io.StringIO(capped.text)))
    assert len(capped_rows) == 3  # header + two, even though four match


def test_events_export_validation(client: Any, database: Database) -> None:
    """Bad format, unknown case and invalid FTS syntax are refused."""
    _seed_scene(database)

    bad_format = client.get("/api/cases/case-1/events/export?format=xml")
    assert bad_format.status_code == 422, bad_format.text
    assert bad_format.json()["error"]["code"] == "VALIDATION_ERROR"

    missing = client.get("/api/cases/ghost/events/export?format=csv")
    assert missing.status_code == 404

    bad_query = client.get("/api/cases/case-1/events/export?format=csv&q=NEAR(")
    assert bad_query.status_code == 422, bad_query.text
    assert "invalid search query" in bad_query.json()["error"]["message"]


def test_iter_events_export_pages_and_caps(database: Database) -> None:
    """The iterator walks keyset pages and never exceeds ``max_rows``."""
    _seed_scene(database)
    with database.read_connection() as connection:
        events = EventRepository(connection)
        chunks = list(
            iter_events_export(
                events, EventFilters(case_id="case-1"), fmt="csv", page_size=2, max_rows=3
            )
        )
    rows = list(csv.reader(io.StringIO("".join(chunks))))
    assert rows[0] == list(EXPORT_COLUMNS)
    assert len(rows) == 4  # header + exactly the three-row cap
