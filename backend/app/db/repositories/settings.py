"""Settings repository (spec 02 section 4, ``settings``).

Stores analyst-adjustable settings as JSON under string keys. The read-only
values from ``config.toml`` (limits, bind address) are deliberately not stored
here: they are deployment configuration, not case data.
"""

from __future__ import annotations

import sqlite3
from typing import Any

from app.db.connection import atomic
from app.models.setting import SettingRecord
from app.util.time import utc_now_iso


class SettingsRepository:
    """Read and write the key/value settings table."""

    __slots__ = ("_conn",)

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._conn = connection

    @property
    def connection(self) -> sqlite3.Connection:
        """The underlying connection."""
        return self._conn

    def get(self, key: str, default: Any = None) -> Any:
        """One decoded setting value, or ``default`` when unset."""
        row = self._conn.execute(
            "SELECT key, value_json FROM settings WHERE key = ?", (key,)
        ).fetchone()
        if row is None:
            return default
        return SettingRecord.from_row(row).value

    def set(self, key: str, value: Any) -> SettingRecord:
        """Insert or replace one setting."""
        record = SettingRecord(key=key, value=value)
        self._conn.execute(
            "INSERT INTO settings (key, value_json) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json",
            (key, record.to_json()),
        )
        return record

    def get_all(self) -> dict[str, Any]:
        """Every setting as a plain mapping."""
        rows = self._conn.execute("SELECT key, value_json FROM settings ORDER BY key").fetchall()
        return {str(row["key"]): SettingRecord.from_row(row).value for row in rows}

    def delete(self, key: str) -> bool:
        """Remove one setting. Returns ``False`` when it was not set."""
        cursor = self._conn.execute("DELETE FROM settings WHERE key = ?", (key,))
        return cursor.rowcount > 0

    def update_many(self, values: dict[str, Any]) -> list[SettingRecord]:
        """Apply several settings in one transaction and return them."""
        if not values:
            return []
        records = [SettingRecord(key=key, value=value) for key, value in sorted(values.items())]
        with atomic(self._conn):
            for record in records:
                self._conn.execute(
                    "INSERT INTO settings (key, value_json) VALUES (?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json",
                    (record.key, record.to_json()),
                )
        return records

    def seed_defaults(self, values: dict[str, Any]) -> list[SettingRecord]:
        """Insert defaults without overwriting analyst choices."""
        written: list[SettingRecord] = []
        for key, value in sorted(values.items()):
            row = self._conn.execute("SELECT 1 FROM settings WHERE key = ?", (key,)).fetchone()
            if row is None:
                written.append(self.set(key, value))
        return written

    def touch(self, key: str) -> None:
        """Record that a setting changed at ``now`` (used by the audit trail)."""
        stamp = utc_now_iso()
        self._conn.execute(
            "INSERT INTO settings (key, value_json) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json",
            (f"{key}__changed_at", SettingRecord(key=key, value=stamp).to_json()),
        )


__all__ = ["SettingsRepository"]
