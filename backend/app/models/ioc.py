"""IOC and entity models for the API layer (spec 05, spec 06).

The storage row type is ``IocRecord`` in :mod:`app.db.repositories.iocs`;
this module holds the analyst-facing types that are not a direct table row.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class AnalystState(StrEnum):
    """Analyst disposition of an IOC, mirroring the schema CHECK constraint."""

    NONE = "none"
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"


@dataclass(frozen=True, slots=True)
class Entity:
    """One host or user seen in a case, with its case-wide counts.

    Usernames and hostnames are entities, not IOCs (spec 05 section 1). ``user``
    entities are aggregated over both ``user_name`` and ``target_user_name`` so a
    username appears once regardless of which side of the event it was on.
    """

    kind: str
    name: str
    event_count: int
    alert_count: int


__all__ = ["AnalystState", "Entity"]
