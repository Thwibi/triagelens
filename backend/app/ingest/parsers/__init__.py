"""Format parsers.

Importing :mod:`app.ingest.parsers.base` gives the contract and the registry.
:func:`load_builtin_parsers` imports every parser module, which is how each one
gets registered.
"""

from __future__ import annotations

from app.ingest.parsers.base import (
    REGISTRY,
    Candidate,
    LogParser,
    ParseContext,
    ParseCounters,
    ParseFailure,
    ParserRegistry,
    load_builtin_parsers,
)

__all__ = [
    "REGISTRY",
    "Candidate",
    "LogParser",
    "ParseContext",
    "ParseCounters",
    "ParseFailure",
    "ParserRegistry",
    "load_builtin_parsers",
]
