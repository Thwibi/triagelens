"""Spreadsheet-safe CSV helpers (spec 10 section 1).

A cell whose text begins with ``= + - @ \\t \\r`` can be executed as a formula by
a spreadsheet that opens the export, so every exporter prefixes such a cell with
a single quote. One rule, one implementation, shared by the report and event
exports so they cannot drift apart.
"""

from __future__ import annotations

from typing import Any

#: Leading characters a spreadsheet treats as the start of a formula (spec 10 1).
INJECTION_PREFIX = ("=", "+", "-", "@", "\t", "\r")


def safe_cell(value: Any) -> str:
    """Return ``value`` as text, prefixed with ``'`` when it could be a formula."""
    text = str(value)
    if text.startswith(INJECTION_PREFIX):
        return "'" + text
    return text


__all__ = ["INJECTION_PREFIX", "safe_cell"]
