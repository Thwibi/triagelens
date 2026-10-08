"""IOC extraction, canonicalization and aggregation (spec 05).

The package is deliberately free of database and API imports so it can run inside
the parse worker on a hot path. The flow is:

``refang`` -> ``decode`` -> ``scan`` (:mod:`app.ioc.extract`) -> ``validate`` ->
``aggregate`` (:mod:`app.ioc.aggregate`) -> stored by the job writer.

``default_allowlist()`` loads the bundled allowlist once; call
:func:`app.ioc.validate.set_tlds` to install the TLD set at startup (the extractor
loads it lazily if it has not been set).
"""

from __future__ import annotations

from functools import lru_cache

from app.ioc.aggregate import (
    DEFAULT_OCCURRENCE_CAP,
    AggregatedIoc,
    Occurrence,
    aggregate,
)
from app.ioc.allowlist import Allowlist, entries_to_allowlist, load_default_allowlist
from app.ioc.canonical import canonical_value
from app.ioc.decode import decode_all
from app.ioc.extract import extract_fields, extract_text, scan_text
from app.ioc.refang import defang, refang
from app.ioc.score import confidence
from app.ioc.types import (
    BASE_DECODED,
    BASE_FREETEXT,
    BASE_STRUCTURED,
    TIER1_TYPES,
    TIER2_TYPES,
    IocCandidate,
    IocHit,
    IocType,
    Role,
)
from app.ioc.validate import classify_ip, load_tlds, set_tlds, tlds


@lru_cache(maxsize=1)
def default_allowlist() -> Allowlist:
    """The bundled allowlist, loaded from the data directory once and cached."""
    from app.config import Settings

    return load_default_allowlist(Settings().bundled_data_dir / "default_allowlist.yaml")


__all__ = [
    "BASE_DECODED",
    "BASE_FREETEXT",
    "BASE_STRUCTURED",
    "DEFAULT_OCCURRENCE_CAP",
    "TIER1_TYPES",
    "TIER2_TYPES",
    "AggregatedIoc",
    "Allowlist",
    "IocCandidate",
    "IocHit",
    "IocType",
    "Occurrence",
    "Role",
    "aggregate",
    "canonical_value",
    "classify_ip",
    "confidence",
    "decode_all",
    "defang",
    "default_allowlist",
    "entries_to_allowlist",
    "extract_fields",
    "extract_text",
    "load_default_allowlist",
    "load_tlds",
    "refang",
    "scan_text",
    "set_tlds",
    "tlds",
]
