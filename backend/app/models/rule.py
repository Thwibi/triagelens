"""Rule record (spec 04 section 1, ``rules``).

The ``rules`` table is the materialized rule catalogue: every YAML document
from the built-in, vendored SigmaHQ and custom directories, parsed once and
stored with its compile and routing health so the API can list and filter
rules without touching pySigma.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

#: Rule kinds accepted by the schema (spec 04 section 1).
KIND_BUILTIN = "builtin"
KIND_SIGMA = "sigma"
KIND_CUSTOM = "custom"

#: Rule types accepted by the schema.
RULE_TYPE_DETECTION = "detection"
RULE_TYPE_CORRELATION = "correlation"


@dataclass(frozen=True, slots=True)
class RuleRecord:
    """One row of ``rules``."""

    id: str
    title: str
    #: ``builtin``, ``sigma`` (vendored SigmaHQ) or ``custom``.
    kind: str
    #: ``detection`` or ``correlation``.
    rule_type: str
    level: str
    status: str | None
    enabled: bool
    yaml: str
    tags: tuple[str, ...]
    logsource: dict[str, Any]
    file_path: str | None
    sha256: str
    compile_error: str | None
    unroutable: bool
    updated_at: str

    @property
    def healthy(self) -> bool:
        """True when the rule compiles and its logsource routes."""
        return self.compile_error is None and not self.unroutable

    @classmethod
    def from_row(cls, row: Any) -> RuleRecord:
        """Build a record from a ``sqlite3.Row``-like mapping."""
        return cls(
            id=str(row["id"]),
            title=str(row["title"]),
            kind=str(row["kind"]),
            rule_type=str(row["rule_type"]),
            level=str(row["level"]),
            status=str(row["status"]) if row["status"] is not None else None,
            enabled=bool(row["enabled"]),
            yaml=str(row["yaml"]),
            tags=tuple(json.loads(row["tags_json"])),
            logsource=json.loads(row["logsource_json"]),
            file_path=str(row["file_path"]) if row["file_path"] is not None else None,
            sha256=str(row["sha256"]),
            compile_error=str(row["compile_error"]) if row["compile_error"] is not None else None,
            unroutable=bool(row["unroutable"]),
            updated_at=str(row["updated_at"]),
        )


__all__ = [
    "KIND_BUILTIN",
    "KIND_CUSTOM",
    "KIND_SIGMA",
    "RULE_TYPE_CORRELATION",
    "RULE_TYPE_DETECTION",
    "RuleRecord",
]
