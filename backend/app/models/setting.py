"""Setting records (spec 02 section 4, ``settings``)."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class SettingRecord:
    """One row of ``settings``: a JSON-encoded value under a string key."""

    key: str
    value: Any

    @classmethod
    def from_row(cls, row: Any) -> SettingRecord:
        """Build a record from a repository row, decoding the JSON value."""
        return cls(key=row["key"], value=json.loads(row["value_json"]))

    def to_json(self) -> str:
        """Canonical JSON encoding stored in ``settings.value_json``."""
        return json.dumps(self.value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
