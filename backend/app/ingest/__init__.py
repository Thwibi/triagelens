"""Ingest: turning uploaded or imported evidence into normalized events.

The pipeline runs in one direction and each stage has a single job:

- :mod:`app.ingest.text` reads a file into lines under one set of rules, so
  every parser sees identical bytes.
- :mod:`app.ingest.detect` decides which parser should read a file, or reports
  that the operator must choose.
- :mod:`app.ingest.profiles` loads mapping profiles for the generic parsers.
- :mod:`app.ingest.parsers` contains the format parsers themselves.
- :mod:`app.ingest.archive` extracts archives under hard limits.
- :mod:`app.ingest.intake` stores uploads and runs the stages above.
- :mod:`app.ingest.import_from_path` validates operator-supplied server paths.

Nothing here touches the database. Parsing produces events and failures; storing
them is the job of the repositories in :mod:`app.db.repositories`.
"""

from __future__ import annotations

from app.ingest.archive import (
    ArchiveLimits,
    ArchiveResult,
    ExtractedFile,
    extract_archive,
    is_archive,
)
from app.ingest.detect import DetectionResult, detect
from app.ingest.events import EVENT_COLUMNS, NormalizedEvent
from app.ingest.import_from_path import ImportCandidate, resolve_import_path
from app.ingest.intake import IntakeResult, StoredFile, intake_path, intake_stream
from app.ingest.parsers.base import (
    Candidate,
    LogParser,
    ParseContext,
    ParseCounters,
    ParseFailure,
    ParserRegistry,
    load_builtin_parsers,
)
from app.ingest.profiles import Profile, ProfileError, load_profiles
from app.ingest.text import TextHead, iter_text_lines, read_head

__all__ = [
    "EVENT_COLUMNS",
    "ArchiveLimits",
    "ArchiveResult",
    "Candidate",
    "DetectionResult",
    "ExtractedFile",
    "ImportCandidate",
    "IntakeResult",
    "LogParser",
    "NormalizedEvent",
    "ParseContext",
    "ParseCounters",
    "ParseFailure",
    "ParserRegistry",
    "Profile",
    "ProfileError",
    "StoredFile",
    "TextHead",
    "detect",
    "extract_archive",
    "intake_path",
    "intake_stream",
    "is_archive",
    "iter_text_lines",
    "load_builtin_parsers",
    "load_profiles",
    "read_head",
    "resolve_import_path",
]
