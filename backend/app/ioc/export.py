"""IOC export rendering (spec 05 section 8, spec 06 ``/export``).

Pure functions so the formats are unit-testable without an HTTP client. The
router wraps the results in a download response.

STIX 2.1 is generated as a dict bundle (spec 02/05: ``type`` ``bundle`` with one
``indicator`` object per countable IOC and one ``note`` carrying
``x-triagelens-observable`` values for the types that have no STIX pattern). The
spec's ``labels`` rule maps ``analyst_state='malicious'`` to
``malicious-activity`` and everything else to ``anomalous-activity``.
"""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from app.db.repositories.iocs import IocRecord
from app.ioc.refang import defang

_STIX_PATTERN: dict[str, str] = {
    "ipv4": "[ipv4-addr:value = '{v}']",
    "ipv6": "[ipv6-addr:value = '{v}']",
    "domain": "[domain-name:value = '{v}']",
    "url": "[url:value = '{v}']",
    "email": "[email-addr:value = '{v}']",
    "md5": "[file:hashes.'MD5' = '{v}']",
    "sha1": "[file:hashes.'SHA-1' = '{v}']",
    "sha256": "[file:hashes.'SHA-256' = '{v}']",
    "registry": "[windows-registry-key:key = '{v}']",
    "filename": "[file:name = '{v}']",
}

#: Types without a STIX pattern: exported as ``x-triagelens-observable`` in a note.
_NOTE_TYPES: frozenset[str] = frozenset({"filepath", "cve", "user_agent", "command"})


def _iso(ms: int | None) -> str | None:
    """Render epoch milliseconds as a UTC ISO-8601 string with Z suffix."""
    if ms is None:
        return None
    rendered = datetime.fromtimestamp(ms / 1000, tz=UTC).isoformat(timespec="milliseconds")
    return rendered.replace("+00:00", "Z")


def render_csv(
    records: list[IocRecord],
    *,
    defanged: bool = False,
    hosts: Callable[[IocRecord], list[str]] | None = None,
) -> str:
    """CSV export with the spec 05 columns."""
    stream = io.StringIO()
    writer = csv.DictWriter(
        stream,
        fieldnames=[
            "type",
            "value",
            "confidence",
            "occurrences",
            "first_seen",
            "last_seen",
            "hosts",
            "alerts",
            "mitre_techniques",
            "analyst_state",
            "tags",
        ],
        lineterminator="\n",
    )
    writer.writeheader()
    for record in records:
        writer.writerow(
            {
                "type": record.type,
                "value": defang(record.value) if defanged else record.value,
                "confidence": record.confidence,
                "occurrences": record.occurrences,
                "first_seen": _iso(record.first_seen_ms),
                "last_seen": _iso(record.last_seen_ms),
                "hosts": ",".join(hosts(record) if hosts else []),
                "alerts": "",
                "mitre_techniques": "",
                "analyst_state": record.analyst_state,
                "tags": "|".join(record.tags),
            }
        )
    return stream.getvalue()


def render_txt(records: list[IocRecord], *, defanged: bool = False) -> str:
    """One indicator value per line."""
    values = [defang(r.value) if defanged else r.value for r in records]
    return "\n".join(values) + ("\n" if values else "")


def render_stix(records: list[IocRecord], *, defanged: bool = False) -> dict[str, Any]:
    """A STIX 2.1 bundle of ``indicator``/``note`` objects."""
    objects: list[dict[str, Any]] = []
    notes: list[dict[str, Any]] = []
    for record in records:
        value = defang(record.value) if defanged else record.value
        common = {
            "type": "indicator",
            "id": f"indicator--{record.id}",
            "name": f"{record.type}: {value}",
            "pattern_type": "stix",
            "valid_from": _iso(record.first_seen_ms),
            "created": _iso(record.first_seen_ms),
            "modified": _iso(record.last_seen_ms),
            "labels": (
                ["malicious-activity"]
                if record.analyst_state == "malicious"
                else ["anomalous-activity"]
            ),
        }
        pattern = _STIX_PATTERN.get(record.type)
        if pattern is not None:
            objects.append({**common, "pattern": pattern.replace("{v}", value)})
        elif record.type in _NOTE_TYPES:
            notes.append(
                {
                    "type": "note",
                    "id": f"note--{record.id}",
                    "created": _iso(record.first_seen_ms),
                    "modified": _iso(record.last_seen_ms),
                    "object_refs": [],
                    "x-triagelens-observable": [{"type": record.type, "value": value}],
                }
            )
    objects.extend(notes)
    return {
        "type": "bundle",
        "id": "bundle--triagelens-export",
        "spec_version": "2.1",
        "objects": objects,
    }


def render_json(
    records: list[IocRecord],
    *,
    defanged: bool = False,
    occurrences_of: Callable[[str], list[dict[str, Any]]] | None = None,
) -> str:
    """Full IOC records with occurrences, as JSON."""
    items: list[dict[str, Any]] = []
    for record in records:
        value = defang(record.value) if defanged else record.value
        item: dict[str, Any] = {
            "id": record.id,
            "case_id": record.case_id,
            "type": record.type,
            "value": value,
            "value_norm": record.value_norm,
            "first_seen_ms": record.first_seen_ms,
            "last_seen_ms": record.last_seen_ms,
            "occurrences": record.occurrences,
            "confidence": record.confidence,
            "is_private": record.is_private,
            "is_allowlisted": record.is_allowlisted,
            "analyst_state": record.analyst_state,
            "tags": record.tags,
        }
        if occurrences_of is not None:
            item["occurrences_meta"] = occurrences_of(record.id)
        items.append(item)
    return json.dumps(items, indent=2)


MEDIA_TYPES: dict[str, str] = {
    "csv": "text/csv; charset=utf-8",
    "txt": "text/plain; charset=utf-8",
    "stix": "application/json; charset=utf-8",
    "json": "application/json; charset=utf-8",
}


__all__ = [
    "MEDIA_TYPES",
    "render_csv",
    "render_json",
    "render_stix",
    "render_txt",
]
