"""Typed records for the tables owned by the Phase 0 repositories.

These mirror the SQLite schema in spec 02 section 4 exactly. Later phases add
their own record types (``NormalizedEvent``, ``IocRecord``, ...) next to these.
"""

from __future__ import annotations

from app.models.alert import AlertDraft, AlertRecord
from app.models.case import CaseCounts, CaseRecord
from app.models.job import JobKind, JobRecord, JobStatus
from app.models.rule import RuleRecord
from app.models.run import DetectionRunRecord, RuleRunRecord
from app.models.setting import SettingRecord
from app.models.source import SourceRecord, SourceStatus

__all__ = [
    "AlertDraft",
    "AlertRecord",
    "CaseCounts",
    "CaseRecord",
    "DetectionRunRecord",
    "JobKind",
    "JobRecord",
    "JobStatus",
    "RuleRecord",
    "RuleRunRecord",
    "SettingRecord",
    "SourceRecord",
    "SourceStatus",
]
