"""Collapse per-event hits into one row per indicator (spec 05 section 7).

A batch of 5000 events can mention the same address thousands of times. Storing
one ``iocs`` row and one occurrence per ``(event, field)`` keeps the table small
and makes "where was this seen" a cheap query, while the occurrence count still
reflects how often it actually appeared.

Occurrences are capped at :data:`DEFAULT_OCCURRENCE_CAP` rows per indicator per
batch: the count keeps rising, but the evidence list stops growing, so a noisy
indicator cannot blow up the database. The analyzer front-end shows the cap.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from app.ioc.score import confidence
from app.ioc.types import IocCandidate, IocHit, Role

#: Most occurrence rows stored per indicator per parse batch (spec 05 section 7).
DEFAULT_OCCURRENCE_CAP = 50


@dataclass(frozen=True, slots=True)
class Occurrence:
    """One place an indicator was seen: an event, a field, and how."""

    event_id: int
    field: str
    role: Role
    decoded_from: str | None


@dataclass(slots=True)
class AggregatedIoc:
    """One indicator and every occurrence of it in a batch."""

    ioc: IocCandidate
    base: int
    occurrences: int = 0
    first_seen_ms: int | None = None
    last_seen_ms: int | None = None
    rows: list[Occurrence] = field(default_factory=list)
    seen_rows: set[tuple[int, str]] = field(default_factory=set)

    def add_occurrence(
        self,
        *,
        event_id: int,
        field_name: str,
        role: Role,
        decoded_from: str | None,
        ts_ms: int | None,
        cap: int,
    ) -> None:
        """Record one occurrence, advancing timestamps and honouring the cap.

        ``occurrences`` counts distinct ``(event, field)`` placements, so a value
        found again by a decode pass of the same field does not inflate it.
        """
        row_key = (event_id, field_name)
        if row_key in self.seen_rows:
            return
        self.seen_rows.add(row_key)
        self.occurrences += 1
        if ts_ms is not None:
            if self.first_seen_ms is None or ts_ms < self.first_seen_ms:
                self.first_seen_ms = ts_ms
            if self.last_seen_ms is None or ts_ms > self.last_seen_ms:
                self.last_seen_ms = ts_ms
        if len(self.rows) >= cap:
            return
        self.rows.append(Occurrence(event_id, field_name, role, decoded_from))

    def confidence_score(self) -> int:
        """The stored confidence, before any alert linkage (Phase 6)."""
        return confidence(
            self.base,
            occurrences=self.occurrences,
            is_private=self.ioc.is_private,
            is_allowlisted=self.ioc.is_allowlisted,
            ambiguous=self.ioc.ambiguous_tld,
        )


def aggregate(
    records: Iterable[tuple[int, int | None, Iterable[IocHit]]],
    *,
    occurrence_cap: int = DEFAULT_OCCURRENCE_CAP,
) -> list[AggregatedIoc]:
    """Collapse ``(event_id, ts_ms, hits)`` records into one group per indicator.

    Order is the order indicators are first seen, which is deterministic because
    the input is.
    """
    groups: dict[tuple[object, str], AggregatedIoc] = {}
    for event_id, ts_ms, hits in records:
        for hit in hits:
            candidate = hit.candidate
            key = candidate.key()
            group = groups.get(key)
            if group is None:
                group = AggregatedIoc(ioc=candidate, base=candidate.base)
                groups[key] = group
            elif candidate.base > group.base:
                # Prefer the structured (higher-confidence) spelling of a value.
                group.base = candidate.base
                group.ioc = candidate
            group.add_occurrence(
                event_id=event_id,
                field_name=hit.field,
                role=hit.role,
                decoded_from=hit.decoded_from,
                ts_ms=ts_ms,
                cap=occurrence_cap,
            )
    return list(groups.values())


__all__ = ["DEFAULT_OCCURRENCE_CAP", "AggregatedIoc", "Occurrence", "aggregate"]
