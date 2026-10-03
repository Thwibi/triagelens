"""Case records (spec 02 section 4, ``cases``)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class CaseCounts:
    """Rollup counts returned with every case (spec 06 ``Case.counts``)."""

    sources: int = 0
    events: int = 0
    alerts: int = 0
    iocs: int = 0

    @classmethod
    def from_row(cls, row: Any) -> CaseCounts:
        """Build counts from a joined repository row."""
        return cls(
            sources=int(row["sources_count"] or 0),
            events=int(row["events_count"] or 0),
            alerts=int(row["alerts_count"] or 0),
            iocs=int(row["iocs_count"] or 0),
        )

    def as_dict(self) -> dict[str, int]:
        """JSON representation used by the API."""
        return {
            "sources": self.sources,
            "events": self.events,
            "alerts": self.alerts,
            "iocs": self.iocs,
        }


@dataclass(frozen=True, slots=True)
class CaseRecord:
    """One row of ``cases``."""

    id: str
    name: str
    description: str | None
    default_timezone: str
    created_at: str
    updated_at: str
    counts: CaseCounts

    @classmethod
    def from_row(cls, row: Any) -> CaseRecord:
        """Build a record from a joined repository row."""
        return cls(
            id=row["id"],
            name=row["name"],
            description=row["description"],
            default_timezone=row["default_timezone"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            counts=CaseCounts.from_row(row),
        )
