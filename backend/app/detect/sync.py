"""Catalogue bootstrap: disk -> ``rules`` table (spec 04 section 1, spec 06).

The shipped rule tree and the custom directory are the source of truth for the
catalogue. ``sync_catalogue`` loads all three sources through the engine's own
loader (so parse, compile and routing health are computed exactly as the API
reports them), upserts every rule and reconciles the shipped sets with disk.
Existing ``enabled`` choices always survive, because ``upsert_many`` only
refreshes metadata; a rule the operator switched off stays off.

The sync is idempotent by rule id, so re-running it against an unchanged tree
is a no-op apart from touching nothing. Custom rows are never auto-deleted: a
custom rule leaves the catalogue only through ``DELETE /rules/{id}``, which
also removes its file.
"""

from __future__ import annotations

import sqlite3
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from app.config import Settings
from app.db.connection import atomic
from app.db.repositories.audit import AuditRepository
from app.db.repositories.rules import RuleRepository
from app.detect.rules import LoadProblem, load_rules
from app.models.rule import KIND_BUILTIN, KIND_SIGMA

#: Kinds the sync reconciles against disk: anything shipped, never custom.
SHIPPED_KINDS: tuple[str, str] = (KIND_BUILTIN, KIND_SIGMA)


@dataclass(frozen=True, slots=True)
class SyncReport:
    """What one catalogue sync did."""

    upserted: int
    #: Files or documents that could not load at all.
    problems: tuple[LoadProblem, ...]
    stale_removed: int
    #: Loaded rules per kind, the post-sync catalogue composition.
    kinds: dict[str, int]

    @property
    def total(self) -> int:
        """Rules loaded from disk this run (the upserted batch)."""
        return sum(self.kinds.values())


def sync_catalogue(
    connection: sqlite3.Connection,
    *,
    settings: Settings | None = None,
    builtin_dir: Path | None = None,
    sigma_dir: Path | None = None,
    custom_dir: Path | None = None,
    logsource_map: Path | None = None,
    audit: bool = True,
) -> SyncReport:
    """Load every rule source and reconcile the catalogue on ``connection``.

    Directory arguments default from ``settings``; when ``settings`` is None,
    directories are taken as given (explicit scratch trees in tests). A ``None``
    directory is skipped, exactly as :func:`load_rules` skips it. ``audit=False``
    suppresses the ``rules_imported`` audit entry, for callers that append their
    own (the rules import endpoint keeps one import entry for the whole batch).
    """
    if settings is not None:
        builtin_dir = builtin_dir or settings.rules_dir / "builtin"
        sigma_dir = sigma_dir or settings.rules_dir / "sigma"
        custom_dir = custom_dir or settings.custom_rules_dir
        logsource_map = logsource_map or settings.rules_dir / "logsource_map.yaml"
    loaded, load_problems = load_rules(
        builtin_dir=builtin_dir,
        sigma_dir=sigma_dir,
        custom_dir=custom_dir,
        logsource_map=logsource_map,
    )
    keep = {rule.id for rule in loaded if rule.kind in SHIPPED_KINDS}
    with atomic(connection):
        upserted = RuleRepository(connection).upsert_many(loaded)
        stale_removed = RuleRepository(connection).delete_outside(SHIPPED_KINDS, keep)
        if audit:
            AuditRepository(connection).append(
                "rules_imported",
                detail={
                    "action": "sync",
                    "count": len(loaded),
                    "upserted": upserted,
                    "stale_removed": stale_removed,
                    "problems": len(load_problems),
                },
            )
    return SyncReport(
        upserted=upserted,
        problems=tuple(load_problems),
        stale_removed=stale_removed,
        kinds=dict(Counter(rule.kind for rule in loaded)),
    )


__all__ = ["SHIPPED_KINDS", "SyncReport", "sync_catalogue"]
