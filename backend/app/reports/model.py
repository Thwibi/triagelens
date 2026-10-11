"""The neutral report data model shared by every renderer (spec 08 section 1).

HTML, Markdown, PDF and JSON all render from one :class:`ReportData` built once
per report. Nothing here touches the database or the file system: :mod:`app.reports.gather`
fills it in, and :mod:`app.reports.render` turns it into bytes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

#: Version of the JSON report schema (spec 08 section 1).
SCHEMA_VERSION = "1.0"


@dataclass(frozen=True, slots=True)
class ReportMeta:
    """Cover data (spec 08 section 1.1)."""

    report_id: str
    case_id: str
    case_name: str
    title: str
    analyst: str
    generated_at: str
    timezone: str
    tool_version: str
    attack_version: str
    ruleset_hash: str
    detection_profile: str
    schema_version: str = SCHEMA_VERSION
    contains_evidence_derived_data: bool = True

    def as_dict(self) -> dict[str, Any]:
        """JSON representation."""
        return {
            "schema_version": self.schema_version,
            "report_id": self.report_id,
            "case_id": self.case_id,
            "case_name": self.case_name,
            "title": self.title,
            "analyst": self.analyst,
            "generated_at": self.generated_at,
            "timezone": self.timezone,
            "tool_version": self.tool_version,
            "attack_version": self.attack_version,
            "ruleset_hash": self.ruleset_hash,
            "detection_profile": self.detection_profile,
            "contains_evidence_derived_data": self.contains_evidence_derived_data,
        }


@dataclass(frozen=True, slots=True)
class ReportSummary:
    """Executive summary, generated deterministically from the data (spec 08 1.2)."""

    first_seen_ms: int | None
    last_seen_ms: int | None
    first_seen: str | None
    last_seen: str | None
    source_count: int
    event_count: int
    error_count: int
    alert_total: int
    alerts_by_level: dict[str, int]
    top_techniques: list[dict[str, Any]]
    top_iocs: list[dict[str, Any]]
    hosts: list[str]
    users: list[str]
    paragraph: str

    def as_dict(self) -> dict[str, Any]:
        """JSON representation."""
        return {
            "first_seen_ms": self.first_seen_ms,
            "last_seen_ms": self.last_seen_ms,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "source_count": self.source_count,
            "event_count": self.event_count,
            "error_count": self.error_count,
            "alert_total": self.alert_total,
            "alerts_by_level": dict(self.alerts_by_level),
            "top_techniques": self.top_techniques,
            "top_iocs": self.top_iocs,
            "hosts": self.hosts,
            "users": self.users,
            "paragraph": self.paragraph,
        }


@dataclass(frozen=True, slots=True)
class ReportAlert:
    """One alert with its details and evidence (spec 08 sections 1.3 and 1.4)."""

    id: str
    rule_id: str
    rule_title: str
    rule_kind: str
    rule_type: str
    level: str
    score: int
    status: str
    description: str | None
    tactics: list[dict[str, Any]]
    techniques: list[dict[str, Any]]
    host: str | None
    user_name: str | None
    first_seen_ms: int | None
    last_seen_ms: int | None
    match_count: int
    false_positives: list[str]
    references: list[str]
    analyst_notes: str | None
    score_breakdown: list[dict[str, Any]]
    events: list[dict[str, Any]]
    iocs: list[dict[str, Any]]

    def as_dict(self) -> dict[str, Any]:
        """JSON representation."""
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "rule_title": self.rule_title,
            "rule_kind": self.rule_kind,
            "rule_type": self.rule_type,
            "level": self.level,
            "score": self.score,
            "status": self.status,
            "description": self.description,
            "tactics": self.tactics,
            "techniques": self.techniques,
            "host": self.host,
            "user_name": self.user_name,
            "first_seen_ms": self.first_seen_ms,
            "last_seen_ms": self.last_seen_ms,
            "match_count": self.match_count,
            "false_positives": self.false_positives,
            "references": self.references,
            "analyst_notes": self.analyst_notes,
            "score_breakdown": self.score_breakdown,
            "events": self.events,
            "iocs": self.iocs,
        }


@dataclass(frozen=True, slots=True)
class ReportIoc:
    """One external indicator row (spec 08 section 1.6)."""

    id: str
    type: str
    value: str
    defanged: str
    confidence: int
    occurrences: int
    first_seen_ms: int | None
    last_seen_ms: int | None
    first_seen: str | None
    last_seen: str | None
    analyst_state: str
    is_private: bool
    allowlisted: bool
    tags: list[str]

    def as_dict(self) -> dict[str, Any]:
        """JSON representation (value kept undefanged in JSON)."""
        return {
            "id": self.id,
            "type": self.type,
            "value": self.value,
            "defanged": self.defanged,
            "confidence": self.confidence,
            "occurrences": self.occurrences,
            "first_seen_ms": self.first_seen_ms,
            "last_seen_ms": self.last_seen_ms,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "analyst_state": self.analyst_state,
            "is_private": self.is_private,
            "allowlisted": self.allowlisted,
            "tags": self.tags,
        }


@dataclass(frozen=True, slots=True)
class ReportSource:
    """One ingested source for the integrity table (spec 08 section 1.9)."""

    id: str
    filename: str
    size_bytes: int
    sha256: str
    log_type: str | None
    status: str
    event_count: int
    error_count: int
    first_seen: str | None
    last_seen: str | None

    def as_dict(self) -> dict[str, Any]:
        """JSON representation."""
        return {
            "id": self.id,
            "filename": self.filename,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "log_type": self.log_type,
            "status": self.status,
            "event_count": self.event_count,
            "error_count": self.error_count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


@dataclass(frozen=True, slots=True)
class ReportRun:
    """One detection run's provenance and per-status rule counts (spec 08 1.9)."""

    id: str
    profile: str
    tool_version: str
    ruleset_hash: str
    attack_version: str
    started_at: str
    finished_at: str | None
    status: str
    rules_ok: int
    rules_skipped: int
    rules_timeout: int
    rules_error: int

    @property
    def rules_run(self) -> int:
        """Total rules evaluated in this run."""
        return self.rules_ok + self.rules_skipped + self.rules_timeout + self.rules_error

    def as_dict(self) -> dict[str, Any]:
        """JSON representation."""
        return {
            "id": self.id,
            "profile": self.profile,
            "tool_version": self.tool_version,
            "ruleset_hash": self.ruleset_hash,
            "attack_version": self.attack_version,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "status": self.status,
            "rules_ok": self.rules_ok,
            "rules_skipped": self.rules_skipped,
            "rules_timeout": self.rules_timeout,
            "rules_error": self.rules_error,
            "rules_run": self.rules_run,
        }


@dataclass(frozen=True, slots=True)
class ReportData:
    """Everything a report renderer needs, and nothing else (spec 08 1.x)."""

    meta: ReportMeta
    summary: ReportSummary
    alerts: list[ReportAlert]
    iocs: list[ReportIoc]
    mitre: dict[str, Any]
    timeline: dict[str, Any]
    entities: list[dict[str, Any]]
    sources: list[ReportSource]
    runs: list[ReportRun]
    audit_verification: dict[str, Any]
    include: dict[str, bool] = field(default_factory=dict)
    appendix_raw: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        """The JSON report body (spec 08 section 1)."""
        return {
            "schema_version": SCHEMA_VERSION,
            "meta": self.meta.as_dict(),
            "summary": self.summary.as_dict(),
            "alerts": [alert.as_dict() for alert in self.alerts],
            "iocs": [ioc.as_dict() for ioc in self.iocs],
            "mitre": self.mitre,
            "timeline": self.timeline,
            "entities": self.entities,
            "sources": [source.as_dict() for source in self.sources],
            "integrity": {
                "sources": [source.as_dict() for source in self.sources],
                "runs": [run.as_dict() for run in self.runs],
                "audit": self.audit_verification,
                "processed_locally": True,
            },
            "appendix": self.appendix_raw,
        }


__all__ = [
    "SCHEMA_VERSION",
    "ReportAlert",
    "ReportData",
    "ReportIoc",
    "ReportMeta",
    "ReportRun",
    "ReportSource",
    "ReportSummary",
]
