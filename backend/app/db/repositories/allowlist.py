"""Case-scoped allowlist entries (spec 05 section 5, spec 06 IOC PATCH).

The extractor always ships with a bundled default allowlist. Analysts can
additionally mark an IOC benign straight from the IOC table ("mark benign"),
which records ``analyst_state='benign'`` on the row and, at the analyst's
option, adds a *case-scoped* allowlist entry so the indicator is not re-raised
on future ingests of the same case.
"""

from __future__ import annotations

import sqlite3

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


__all__ = ["AllowlistRepository"]
