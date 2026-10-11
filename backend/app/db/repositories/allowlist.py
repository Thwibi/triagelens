"""Allowlist entries (spec 05 section 5, spec 06 "Health and settings").

The extractor always ships with a bundled default allowlist. Analysts can
additionally mark an IOC benign straight from the IOC table ("mark benign"),
which records ``analyst_state='benign'`` on the row and, at the analyst's
option, adds a *case-scoped* entry so the indicator is not re-raised on future
ingests of the same case. ``GET/POST/DELETE /settings/allowlist`` manages the
*global* half of the same table, which suppresses an indicator for every case.
"""

from __future__ import annotations

import sqlite3

from app.models.allowlist import AllowlistRecord

#: IOC type -> allowlist kind. Types we cannot map cleanly (url, email, cve,
#: registry, ...) are skipped; the ``analyst_state='benign'`` flag still
#: suppresses them in the UI and exports.
_KIND_BY_TYPE: dict[str, str] = {
    "ipv4": "ip",
    "ipv6": "ip",
    "domain": "domain",
    "md5": "hash",
    "sha1": "hash",
    "sha256": "hash",
}

#: Kinds the storage layer accepts (spec 02 section 4), usable by the API to
#: reject a bad ``POST /settings/allowlist`` body before it reaches SQLite.
ALLOWLIST_KINDS: tuple[str, ...] = (
    "domain",
    "domain_suffix",
    "ip",
    "cidr",
    "hash",
    "regex",
)


class AllowlistRepository:
    __slots__ = ("_conn",)

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._conn = connection

    @property
    def connection(self) -> sqlite3.Connection:
        return self._conn

    def add_case_entry(
        self, *, case_id: str, kind: str, value: str, note: str | None = None
    ) -> None:
        """Record a case-scoped allowlist entry (idempotent per value).

        Caller owns the transaction (the writer thread wraps this in one).
        """
        self._conn.execute(
            "INSERT OR IGNORE INTO allowlist (scope, case_id, kind, value, note) "
            "VALUES ('case', ?, ?, ?, ?)",
            (case_id, kind, value, note),
        )

    def entry_for_ioc(self, ioc: object) -> tuple[str, str] | None:
        """Derive ``(kind, value)`` to allowlist for a stored IOC, else ``None``."""
        kind = _KIND_BY_TYPE.get(getattr(ioc, "type", ""))
        if kind is None:
            return None
        return kind, getattr(ioc, "value_norm", "")

    def add_global_entry(
        self, *, kind: str, value: str, note: str | None = None
    ) -> tuple[AllowlistRecord, bool]:
        """Add a global allowlist entry, returning ``(row, created)``.

        Idempotent per ``(kind, value)``: the ``allowlist`` table has no unique
        index, so a value already present is returned unchanged with
        ``created=False`` rather than inserted a second time. The flag lets the
        caller skip the audit row for an add that changed nothing. Caller owns
        the transaction (the writer thread wraps this in one).
        """
        existing = self._conn.execute(
            "SELECT id, scope, case_id, kind, value, note FROM allowlist "
            "WHERE scope = 'global' AND kind = ? AND value = ?",
            (kind, value),
        ).fetchone()
        if existing is not None:
            return AllowlistRecord.from_row(existing), False
        self._conn.execute(
            "INSERT INTO allowlist (scope, case_id, kind, value, note) "
            "VALUES ('global', NULL, ?, ?, ?)",
            (kind, value, note),
        )
        row = self._conn.execute(
            "SELECT id, scope, case_id, kind, value, note FROM allowlist "
            "WHERE id = last_insert_rowid()"
        ).fetchone()
        if row is None:  # pragma: no cover - the INSERT above guarantees a row
            raise RuntimeError("global allowlist entry vanished immediately after insert")
        return AllowlistRecord.from_row(row), True

    def list_global(self) -> list[AllowlistRecord]:
        """Every global allowlist entry, oldest first."""
        rows = self._conn.execute(
            "SELECT id, scope, case_id, kind, value, note FROM allowlist "
            "WHERE scope = 'global' ORDER BY id"
        ).fetchall()
        return [AllowlistRecord.from_row(row) for row in rows]

    def get(self, entry_id: int) -> AllowlistRecord | None:
        """One allowlist entry by id, global or case-scoped."""
        row = self._conn.execute(
            "SELECT id, scope, case_id, kind, value, note FROM allowlist WHERE id = ?",
            (entry_id,),
        ).fetchone()
        return AllowlistRecord.from_row(row) if row is not None else None

    def delete(self, entry_id: int) -> bool:
        """Remove one entry. Returns ``False`` when it did not exist."""
        cursor = self._conn.execute("DELETE FROM allowlist WHERE id = ?", (entry_id,))
        return cursor.rowcount > 0


__all__ = ["ALLOWLIST_KINDS", "AllowlistRecord", "AllowlistRepository"]
