"""MITRE ATT&CK mapping: offline STIX loading, tag resolution, fallbacks.

The pipeline is: a STIX 2.1 bundle is loaded once into the MITRE tables
(:mod:`app.mitre.loader`); detection tags and evidence events are then
resolved against that catalogue per alert (:mod:`app.mitre.enrich`), and
case-level rollups are served from :mod:`app.mitre.matrix` and
:mod:`app.mitre.navigator`. Nothing here touches the network.
"""

from __future__ import annotations

from app.mitre.catalogue import (
    GroupSoftwareInfo,
    MitreCatalogue,
    ResolvedTags,
    TechniqueInfo,
    resolve_rule_tags,
)
from app.mitre.enrich import (
    AlertMitre,
    EntityRef,
    TechniqueRef,
    enrich_run_alerts,
    resolve_alert_mitre,
)
from app.mitre.fallbacks import FallbackEntry, load_fallbacks, match_fallback
from app.mitre.loader import AttackBundleError, load_bundle
from app.mitre.matrix import AlertMapping, load_alert_mappings, matrix_for_case
from app.mitre.navigator import build_layer
from app.mitre.tags import ParsedTags, parse_sigma_tags

__all__ = [
    "AlertMapping",
    "AlertMitre",
    "AttackBundleError",
    "EntityRef",
    "FallbackEntry",
    "GroupSoftwareInfo",
    "MitreCatalogue",
    "ParsedTags",
    "ResolvedTags",
    "TechniqueInfo",
    "TechniqueRef",
    "build_layer",
    "enrich_run_alerts",
    "load_alert_mappings",
    "load_bundle",
    "load_fallbacks",
    "match_fallback",
    "matrix_for_case",
    "parse_sigma_tags",
    "resolve_alert_mitre",
    "resolve_rule_tags",
]
