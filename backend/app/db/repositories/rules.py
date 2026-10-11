"""Rule repository (spec 04 sections 1 and 9, ``rules``).

The catalogue the API lists, filters and enables rules from, and the input
the detection engine reads at run start. Loads upsert into it while always
preserving the operator's ``enabled`` choice: a file reload must never
re-enable a rule someone switched off.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence

from app.db.connection import atomic
from app.detect.rules import LoadedRule
from app.models.rule import RuleRecord
from app.util.hashing import canonical_json, hash_mapping
from app.util.time import utc_now_iso

_SELECT = "SELECT * FROM rules"

#: Aliases for annotations inside the class: a method is named ``list`` there,
#: so the builtin ``list`` cannot be referenced in class-body annotations.
_RuleRows = list[RuleRecord]
_Filter = tuple[list[str], list[object]]

#: Health buckets for ``GET /rules/health`` and the ``health`` filter.
#: Precedence keeps the counts summing to the total: a rule that fails to
#: compile is reported as a compile error even when it is also unroutable.
#: Rows purged per statement in ``delete_outside``. SQLite's default parameter
#: cap is far above this, and the shipped sets are a few hundred rows, so both
#: stays comfortably inside the limit even for a much larger vendored tree.
_DELETE_BATCH = 400

_HEALTH_SQL: dict[str, str] = {
    "ok": "compile_error IS NULL AND unroutable = 0",
    "compile_error": "compile_error IS NOT NULL",
    "unroutable": "compile_error IS NULL AND unroutable = 1",
}

_INSERT = """
INSERT INTO rules (
  id, title, kind, rule_type, level, status, enabled, yaml, tags_json,
  logsource_json, file_path, sha256, compile_error, unroutable, updated_at
) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
  title = excluded.title,
  kind = excluded.kind,
  rule_type = excluded.rule_type,
  level = excluded.level,
  status = excluded.status,
  yaml = excluded.yaml,
  tags_json = excluded.tags_json,
  logsource_json = excluded.logsource_json,
  file_path = excluded.file_path,
  sha256 = excluded.sha256,
  compile_error = excluded.compile_error,
  unroutable = excluded.unroutable,
  enabled = rules.enabled,
  updated_at = excluded.updated_at
"""


class RuleRepository:
    """Create, read, filter and enable catalogue rules."""

    __slots__ = ("_conn",)

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._conn = connection

    @property
    def connection(self) -> sqlite3.Connection:
        """The underlying connection."""
        return self._conn

    def upsert_many(self, rules: Sequence[LoadedRule]) -> int:
        """Insert or refresh ``rules``; existing ``enabled`` flags survive."""
        now = utc_now_iso()
        rows = [
            (
                rule.id,
                rule.title,
                rule.kind,
                rule.rule_type,
                rule.level,
                rule.status,
                rule.yaml,
                canonical_json(list(rule.tags)),
                canonical_json(rule.logsource),
                rule.file_path,
                rule.sha256,
                rule.compile_error,
                int(rule.unroutable),
                now,
            )
            for rule in rules
        ]
        if not rows:
            return 0
        with atomic(self._conn):
            self._conn.executemany(_INSERT, rows)
        return len(rows)

    def get(self, rule_id: str) -> RuleRecord | None:
        """One rule by id, or ``None``."""
        row = self._conn.execute(f"{_SELECT} WHERE id = ?", (rule_id,)).fetchone()
        return RuleRecord.from_row(row) if row is not None else None

    def list(
        self,
        *,
        kind: str | None = None,
        level: str | None = None,
        status: str | None = None,
        enabled: bool | None = None,
        tag: str | None = None,
        technique: str | None = None,
        health: str | None = None,
        q: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> _RuleRows:
        """One page of rules matching every supplied filter (spec 06)."""
        where, params = self._where(
            kind=kind,
            level=level,
            status=status,
            enabled=enabled,
            tag=tag,
            technique=technique,
            health=health,
            q=q,
        )
        sql = _SELECT
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY title COLLATE NOCASE, id LIMIT ? OFFSET ?"
        params.extend((limit, offset))
        rows = self._conn.execute(sql, params).fetchall()
        return [RuleRecord.from_row(row) for row in rows]

    def count(
        self,
        *,
        kind: str | None = None,
        level: str | None = None,
        status: str | None = None,
        enabled: bool | None = None,
        tag: str | None = None,
        technique: str | None = None,
        health: str | None = None,
        q: str | None = None,
    ) -> int:
        """Total rules matching the filters, ignoring pagination."""
        where, params = self._where(
            kind=kind,
            level=level,
            status=status,
            enabled=enabled,
            tag=tag,
            technique=technique,
            health=health,
            q=q,
        )
        sql = "SELECT COUNT(*) FROM rules"
        if where:
            sql += " WHERE " + " AND ".join(where)
        row = self._conn.execute(sql, params).fetchone()
        return int(row[0]) if row else 0

    def enabled_rules(self) -> _RuleRows:
        """Every enabled rule for the engine, in evaluation seed order.

        Detection bases come first and correlations last (spec 04 section
        2: correlation base rules before the rest); the engine then
        topologically orders the correlations among themselves.
        """
        rows = self._conn.execute(
            f"{_SELECT} WHERE enabled = 1 "
            "ORDER BY CASE rule_type WHEN 'correlation' THEN 1 ELSE 0 END, "
            "title COLLATE NOCASE, id"
        ).fetchall()
        return [RuleRecord.from_row(row) for row in rows]

    def set_enabled(self, rule_id: str, *, enabled: bool) -> bool:
        """Enable or disable one rule; every kind allows this (spec 04 9)."""
        cursor = self._conn.execute(
            "UPDATE rules SET enabled = ?, updated_at = ? WHERE id = ?",
            (int(enabled), utc_now_iso(), rule_id),
        )
        return cursor.rowcount > 0

    def ruleset_hash(self) -> str:
        """SHA-256 over the sorted file hashes of enabled rules (spec 01 9).

        Stable regardless of file-system enumeration order; the hash of the
        empty set is well defined, so reports always embed one.
        """
        rows = self._conn.execute(
            "SELECT id, sha256 FROM rules WHERE enabled = 1 ORDER BY id"
        ).fetchall()
        return hash_mapping({str(row["id"]): str(row["sha256"]) for row in rows})

    def delete(self, rule_id: str) -> bool:
        """Remove one rule; the API restricts this to custom rules."""
        cursor = self._conn.execute("DELETE FROM rules WHERE id = ?", (rule_id,))
        return cursor.rowcount > 0

    def delete_outside(self, kinds: Sequence[str], keep: set[str]) -> int:
        """Delete rows of ``kinds`` whose id is not in ``keep``.

        The catalogue sync reconciles the shipped sets against disk, so a rule
        removed by ``scripts/update_rules.py`` disappears from the catalogue on
        the next full load. Custom rows are never purged this way: the sync is
        idempotent by id, and a custom file's absence means it was deleted
        explicitly, not forgotten.
        """
        if not kinds or not keep:
            return 0
        kind_slots = ",".join("?" for _ in kinds)
        deleted = 0
        ordered = sorted(keep)
        for start in range(0, len(ordered), _DELETE_BATCH):
            batch = ordered[start : start + _DELETE_BATCH]
            slots = ",".join("?" for _ in batch)
            cursor = self._conn.execute(
                f"DELETE FROM rules WHERE kind IN ({kind_slots}) AND id NOT IN ({slots})",
                (*kinds, *batch),
            )
            deleted += cursor.rowcount
        return deleted

    def health_counts(self) -> dict[str, int]:
        """Counts per health bucket, summing to the catalogue size."""
        row = self._conn.execute(
            "SELECT "
            "SUM(CASE WHEN compile_error IS NULL AND unroutable = 0 THEN 1 ELSE 0 END), "
            "SUM(CASE WHEN compile_error IS NOT NULL THEN 1 ELSE 0 END), "
            "SUM(CASE WHEN compile_error IS NULL AND unroutable = 1 THEN 1 ELSE 0 END) "
            "FROM rules"
        ).fetchone()
        if row is None or row[0] is None:  # empty table
            return {"ok": 0, "compile_error": 0, "unroutable": 0}
        return {"ok": int(row[0]), "compile_error": int(row[1]), "unroutable": int(row[2])}

    def _where(
        self,
        *,
        kind: str | None,
        level: str | None,
        status: str | None,
        enabled: bool | None,
        tag: str | None,
        technique: str | None,
        health: str | None,
        q: str | None,
    ) -> _Filter:
        where: list[str] = []
        params: list[object] = []
        if kind is not None:
            where.append("kind = ?")
            params.append(kind)
        if level is not None:
            where.append("level = ?")
            params.append(level)
        if status is not None:
            where.append("status = ?")
            params.append(status)
        if enabled is not None:
            where.append("enabled = ?")
            params.append(int(enabled))
        if tag is not None:
            where.append("EXISTS (SELECT 1 FROM json_each(rules.tags_json) WHERE value = ?)")
            params.append(tag)
        if technique is not None:
            where.append(
                "EXISTS (SELECT 1 FROM json_each(rules.tags_json) "
                "WHERE lower(value) = ? OR lower(value) LIKE ?)"
            )
            tag = f"attack.{technique.lower()}"
            params.extend((tag, f"{tag}.%"))
        if health is not None:
            if health not in _HEALTH_SQL:
                raise ValueError(f"unknown rule health filter: {health!r}")
            where.append(_HEALTH_SQL[health])
        if q is not None:
            where.append("title LIKE ? ESCAPE '\\'")
            params.append(f"%{_like_pattern(q)}%")
        return where, params


def _like_pattern(value: str) -> str:
    """Escape LIKE wildcards so a search for ``50%`` is literal."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


__all__ = ["RuleRepository"]
