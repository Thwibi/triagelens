"""Allowlist records (spec 02 section 4, ``allowlist``)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class AllowlistRecord:
    """One row of ``allowlist``: a global or case-scoped suppression entry."""

    id: int | None
    scope: str
    case_id: str | None
    kind: str
    value: str
    note: str | None

    @classmethod
    def from_row(cls, row: Any) -> AllowlistRecord:
        """Build a record from a repository row."""
        return cls(
            id=int(row["id"]) if row["id"] is not None else None,
            scope=str(row["scope"]),
            case_id=row["case_id"],
            kind=str(row["kind"]),
            value=str(row["value"]),
            note=row["note"],
        )


__all__ = ["AllowlistRecord"]
