"""Append-only audit log with a SHA-256 hash chain (spec 10 section 2).

Each row stores ``hash = sha256(prev_hash || ts || action || detail_json)``.
``GET /cases/{id}/audit-log`` re-walks the chain and reports the first row that
does not match, so silent edits to history are detectable.

The table is append-only twice over: application code issues no ``UPDATE`` or
``DELETE`` against it, and triggers in migration 0001 abort any such statement
at the storage layer.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from app.util.hashing import AUDIT_GENESIS
from app.util.time import utc_now_iso

#: Actions named in spec 02 section 4, plus the chain-continuity actions.
KNOWN_ACTIONS: frozenset[str] = frozenset(
    {
        "case_created",
        "case_updated",
        "case_deleted",
        "source_ingested",
        "source_deleted",
        "source_resolved",
        "detection_run",
        "alert_status",
        "alert_notes",
        "ioc_state",
        "report_created",
        "rules_imported",
        "settings_changed",
        "allowlist_changed",
        "attack_imported",
    }
)

_INSERT_SQL = """
INSERT INTO audit_log (ts, case_id, action, detail_json, prev_hash, hash)
VALUES (
    ?1, ?2, ?3, ?4,
    COALESCE((SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1), ?5),
    audit_hash(
        COALESCE((SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1), ?5),
        ?1, ?3, ?4
    )
)
"""


@dataclass(frozen=True, slots=True)
class AuditEntry:
    """One immutable audit row."""

    id: int
    ts: str
    case_id: str | None
    action: str
    detail: dict[str, Any]
    prev_hash: str
    hash: str

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> AuditEntry:
        """Build an entry from a repository row."""
        return cls(
            id=int(row["id"]),
            ts=row["ts"],
            case_id=row["case_id"],
            action=row["action"],
            detail=json.loads(row["detail_json"]),
            prev_hash=row["prev_hash"],
            hash=row["hash"],
        )


@dataclass(frozen=True, slots=True)
class ChainVerification:
    """Result of walking the hash chain."""

    ok: bool
    rows_checked: int
    head_hash: str
    broken_at: int | None = None
    broken_reason: str | None = None

    def as_dict(self) -> dict[str, Any]:
        """JSON body for ``GET /cases/{id}/audit-log``."""
        payload: dict[str, Any] = {"chain_ok": self.ok, "rows_checked": self.rows_checked}
        if self.broken_at is not None:
            payload["broken_at"] = self.broken_at
        if self.broken_reason is not None:
            payload["broken_reason"] = self.broken_reason
        return payload


@dataclass(frozen=True, slots=True)
class AuditTombstone:
    """Final chain head recorded when a case is deleted (spec 10 section 2)."""

    case_id: str
    deleted_at: str
    last_hash: str
    row_count: int


def canonical_detail(detail: Mapping[str, Any] | None) -> str:
    """Deterministic JSON encoding of a detail payload.

    Hashed into the chain, so key order and whitespace must not vary between
    runs or verification would fail on identical data.
    """
    return json.dumps(
        dict(detail) if detail else {},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )


class AuditRepository:
    """Typed access to ``audit_log`` and ``audit_tombstones``.

    Only ``INSERT`` and ``SELECT`` statements are issued against ``audit_log``.
    """

    __slots__ = ("_conn",)

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._conn = connection

    @property
    def connection(self) -> sqlite3.Connection:
        """The underlying connection."""
        return self._conn

    def append(
        self,
        action: str,
        *,
        case_id: str | None = None,
        detail: Mapping[str, Any] | None = None,
        ts: str | None = None,
    ) -> AuditEntry:
        """Append one row and extend the chain.

        The previous hash is read inside the same statement that writes the row,
        so the chain cannot interleave even if another writer exists.
        """
        timestamp = ts or utc_now_iso()
        detail_json = canonical_detail(detail)
        cursor = self._conn.execute(
            _INSERT_SQL, (timestamp, case_id, action, detail_json, AUDIT_GENESIS)
        )
        row_id = int(cursor.lastrowid or 0)
        row = self._conn.execute(
            "SELECT id, ts, case_id, action, detail_json, prev_hash, hash "
            "FROM audit_log WHERE id = ?",
            (row_id,),
        ).fetchone()
        if row is None:  # pragma: no cover - the INSERT above always produces a row
            raise RuntimeError(f"audit row {row_id} vanished immediately after insert")
        return AuditEntry.from_row(row)

    def iter_all(self) -> Iterator[AuditEntry]:
        """Every row, oldest first."""
        for row in self._conn.execute(
            "SELECT id, ts, case_id, action, detail_json, prev_hash, hash "
            "FROM audit_log ORDER BY id"
        ):
            yield AuditEntry.from_row(row)

    def list_page(
        self,
        *,
        case_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
        order: str = "desc",
    ) -> list[AuditEntry]:
        """One page of entries, newest first by default."""
        direction = "ASC" if order.lower() == "asc" else "DESC"
        if case_id is None:
            cursor = self._conn.execute(
                "SELECT id, ts, case_id, action, detail_json, prev_hash, hash "
                f"FROM audit_log ORDER BY id {direction} LIMIT ? OFFSET ?",
                (limit, offset),
            )
        else:
            cursor = self._conn.execute(
                "SELECT id, ts, case_id, action, detail_json, prev_hash, hash "
                f"FROM audit_log WHERE case_id = ? ORDER BY id {direction} LIMIT ? OFFSET ?",
                (case_id, limit, offset),
            )
        return [AuditEntry.from_row(row) for row in cursor]

    def count(self, *, case_id: str | None = None) -> int:
        """Number of rows, optionally for one case."""
        if case_id is None:
            row = self._conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()
        else:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM audit_log WHERE case_id = ?", (case_id,)
            ).fetchone()
        return int(row[0]) if row else 0

    def head(self) -> str:
        """Hash of the newest row, or the genesis value when empty."""
        row = self._conn.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
        return str(row[0]) if row else AUDIT_GENESIS

    def verify(self, *, case_id: str | None = None) -> ChainVerification:
        """Walk the chain and report the first inconsistency.

        The whole chain is always walked, even when ``case_id`` is given: a row
        of another case sitting between two of ours would otherwise change our
        own hashes and go unnoticed.
        """
        expected_prev = AUDIT_GENESIS
        checked = 0
        for entry in self.iter_all():
            if case_id is not None and entry.case_id != case_id:
                expected_prev = entry.hash
                continue
            checked += 1
            if entry.prev_hash != expected_prev:
                return ChainVerification(
                    ok=False,
                    rows_checked=checked,
                    head_hash=expected_prev,
                    broken_at=entry.id,
                    broken_reason="prev_hash does not match the previous row",
                )
            recomputed = _recompute(entry)
            if recomputed != entry.hash:
                return ChainVerification(
                    ok=False,
                    rows_checked=checked,
                    head_hash=expected_prev,
                    broken_at=entry.id,
                    broken_reason=(
                        "hash does not match sha256(prev_hash || ts || action || detail_json)"
                    ),
                )
            expected_prev = entry.hash
        return ChainVerification(ok=True, rows_checked=checked, head_hash=expected_prev)

    def write_tombstone(
        self,
        *,
        case_id: str,
        last_hash: str,
        row_count: int,
        deleted_at: str | None = None,
    ) -> AuditTombstone:
        """Record the chain head at the moment a case is deleted."""
        stamp = deleted_at or utc_now_iso()
        self._conn.execute(
            "INSERT INTO audit_tombstones (case_id, deleted_at, last_hash, row_count) "
            "VALUES (?, ?, ?, ?)",
            (case_id, stamp, last_hash, row_count),
        )
        return AuditTombstone(
            case_id=case_id, deleted_at=stamp, last_hash=last_hash, row_count=row_count
        )

    def tombstones(self, *, case_id: str | None = None) -> list[AuditTombstone]:
        """Deletion tombstones, newest first."""
        if case_id is None:
            rows: Sequence[sqlite3.Row] = self._conn.execute(
                "SELECT case_id, deleted_at, last_hash, row_count "
                "FROM audit_tombstones ORDER BY id DESC"
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT case_id, deleted_at, last_hash, row_count "
                "FROM audit_tombstones WHERE case_id = ? ORDER BY id DESC",
                (case_id,),
            ).fetchall()
        return [
            AuditTombstone(
                case_id=row["case_id"],
                deleted_at=row["deleted_at"],
                last_hash=row["last_hash"],
                row_count=int(row["row_count"]),
            )
            for row in rows
        ]

    def assert_append_only(self) -> None:
        """Fail loudly if the storage-layer triggers were removed.

        Called by the test suite to prove the immutability guarantee is enforced
        by SQLite itself and not only by the absence of statements in this file.
        """
        triggers = {
            str(row[0])
            for row in self._conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'audit_log'"
            )
        }
        missing = {"audit_log_block_update", "audit_log_block_delete"} - triggers
        if missing:
            raise RuntimeError(
                "audit_log immutability triggers missing: " + ", ".join(sorted(missing))
            )


def _recompute(entry: AuditEntry) -> str:
    """Recompute an entry's hash from its stored columns."""
    from app.util.hashing import audit_chain_hash

    return audit_chain_hash(entry.prev_hash, entry.ts, entry.action, canonical_detail(entry.detail))


__all__ = [
    "KNOWN_ACTIONS",
    "AuditEntry",
    "AuditRepository",
    "AuditTombstone",
    "ChainVerification",
    "canonical_detail",
]
