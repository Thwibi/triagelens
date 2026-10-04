"""The normalized event every parser emits (spec 02 section 1).

One shape for every format, so the detection engine, the UI, FTS search and CSV
export never need to know where a record came from. The column list here is the
``events`` table in ``0001_init.sql``, in the same order.

Two fields carry weight beyond the obvious:

``fields_json``
    Every original field, original names and casing intact. Sigma rules match
    against these keys, so a field the columns do not model is still evidence.
    Nothing is dropped; anything not mapped lands here.

``raw``
    The original record text. Truncated at ``limits.max_line_bytes`` with an
    explicit marker, so a single enormous line cannot blow up memory or storage.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from dataclasses import fields as dataclass_fields
from typing import Any

from app.ingest.normalize import TRUNCATION_MARKER, clean_text, truncate
from app.util.time import iso_from_ms

#: Columns in ``events`` order, excluding the row id. Kept as a tuple so the
#: insert path and the dataclass cannot drift apart silently.
EVENT_COLUMNS: tuple[str, ...] = (
    "case_id",
    "source_id",
    "record_ref",
    "ts_ms",
    "ts_iso",
    "log_type",
    "ls_category",
    "host",
    "channel",
    "provider",
    "app_name",
    "event_id",
    "level",
    "event_action",
    "event_outcome",
    "user_name",
    "target_user_name",
    "domain",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
    "process_pid",
    "process_path",
    "process_cmdline",
    "parent_process_path",
    "parent_process_cmdline",
    "file_path",
    "registry_key",
    "registry_value",
    "url",
    "url_path",
    "url_query",
    "http_method",
    "http_status",
    "user_agent",
    "bytes_out",
    "message",
)

#: String columns cleaned by :func:`app.ingest.normalize.clean_text` on the way in.
_TEXT_FIELDS: frozenset[str] = frozenset(
    {
        "record_ref",
        "ls_category",
        "host",
        "channel",
        "provider",
        "app_name",
        "level",
        "event_action",
        "event_outcome",
        "user_name",
        "target_user_name",
        "domain",
        "src_ip",
        "dst_ip",
        "protocol",
        "process_path",
        "process_cmdline",
        "parent_process_path",
        "parent_process_cmdline",
        "file_path",
        "registry_key",
        "registry_value",
        "url",
        "url_path",
        "url_query",
        "http_method",
        "user_agent",
        "message",
    }
)

#: Integer columns coerced by :func:`app.ingest.normalize.to_int`.
_INT_FIELDS: frozenset[str] = frozenset(
    {
        "ts_ms",
        "event_id",
        "src_port",
        "dst_port",
        "process_pid",
        "http_status",
        "bytes_out",
    }
)

#: Columns that the INSERT binds beyond :data:`EVENT_COLUMNS`. ``raw`` is listed
#: because the table declares it NOT NULL: an INSERT that omits it fails the
#: constraint and no event is ever stored. Order matches the table.
_EXTRA_COLUMNS: tuple[str, ...] = ("fields_json", "raw")

#: Built once from the module-level column tuple, so no request value ever
#: reaches the SQL text.
INSERT_SQL = (
    f"INSERT INTO events ({', '.join((*EVENT_COLUMNS, *_EXTRA_COLUMNS))}) "
    f"VALUES ({', '.join('?' * (len(EVENT_COLUMNS) + len(_EXTRA_COLUMNS)))})"
)


@dataclass(slots=True)
class NormalizedEvent:
    """One stored event.

    ``fields_json`` and ``raw`` are the only required arguments beyond the
    identity of the source: a record is only useful if the original is kept.
    """

    case_id: str
    source_id: str
    record_ref: str
    log_type: str
    raw: str
    ts_ms: int | None = None
    ts_iso: str | None = None
    ls_category: str | None = None
    host: str | None = None
    channel: str | None = None
    provider: str | None = None
    app_name: str | None = None
    event_id: int | None = None
    level: str | None = None
    event_action: str | None = None
    event_outcome: str | None = None
    user_name: str | None = None
    target_user_name: str | None = None
    domain: str | None = None
    src_ip: str | None = None
    src_port: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    protocol: str | None = None
    process_pid: int | None = None
    process_path: str | None = None
    process_cmdline: str | None = None
    parent_process_path: str | None = None
    parent_process_cmdline: str | None = None
    file_path: str | None = None
    registry_key: str | None = None
    registry_value: str | None = None
    url: str | None = None
    url_path: str | None = None
    url_query: str | None = None
    http_method: str | None = None
    http_status: int | None = None
    user_agent: str | None = None
    bytes_out: int | None = None
    message: str | None = None
    fields_json: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Normalize in place so a parser cannot bypass the rules."""
        for name in _TEXT_FIELDS:
            value = getattr(self, name)
            if value is not None:
                setattr(self, name, clean_text(value))
        for name in _INT_FIELDS:
            value = getattr(self, name)
            if value is not None and not isinstance(value, int):
                setattr(self, name, int(value))
        if self.protocol is not None:
            self.protocol = self.protocol.lower()
        # ts_iso is derived, never trusted from a parser: storing both a
        # millisecond epoch and a hand-written ISO string invites disagreement.
        self.ts_iso = iso_from_ms(self.ts_ms)

    @property
    def has_timestamp(self) -> bool:
        """False when the record was stored without a usable timestamp.

        Such an event is still stored; it is counted in ``error_count`` so the
        case view can show that something was lost.
        """
        return self.ts_ms is not None

    def split_url(self) -> None:
        """Split ``url`` into path and query on the first ``?`` (spec 02 section 1)."""
        if self.url is None or self.url_path is not None:
            return
        url = self.url
        base, separator, query = url.partition("?")
        self.url_path = base or None
        # An empty query is stored as NULL, like every other empty text field.
        self.url_query = (query or None) if separator else None

    def clip_raw(self, max_bytes: int) -> bool:
        """Truncate ``raw`` to ``max_bytes``. Returns whether it was clipped."""
        clipped, was_clipped = truncate(self.raw, max_bytes)
        self.raw = clipped
        return was_clipped

    def row(self) -> tuple[Any, ...]:
        """Values in ``EVENT_COLUMNS`` order, ready for an INSERT."""
        return tuple(getattr(self, name) for name in EVENT_COLUMNS)

    def insert_sql(self) -> str:
        """Parameterized INSERT for this event, with ``fields_json`` serialized."""
        return INSERT_SQL

    def values(self) -> tuple[Any, ...]:
        """Bind values in :data:`INSERT_SQL` order.

        That is ``EVENT_COLUMNS`` first, then ``fields_json`` and ``raw``, so the
        tuple can be splatted straight into the statement's parameters.
        """
        return (*self.row(), self.as_json(), self.raw)

    def to_dict(self) -> dict[str, Any]:
        """Full event as a JSON-ready mapping, for API output and tests."""
        payload: dict[str, Any] = {
            item.name: getattr(self, item.name)
            for item in dataclass_fields(self)
            if item.name != "fields_json"
        }
        payload["fields_json"] = dict(self.fields_json)
        payload["raw_truncated"] = self.raw.endswith(TRUNCATION_MARKER)
        return payload

    def as_json(self) -> str:
        """``fields_json`` serialized deterministically."""
        return json.dumps(self.fields_json, ensure_ascii=False, sort_keys=True, default=str)


__all__ = ["EVENT_COLUMNS", "NormalizedEvent"]
