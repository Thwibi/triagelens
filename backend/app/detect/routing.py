"""Logsource routing (spec 04 section 3).

``rules/logsource_map.yaml`` turns a Sigma ``logsource`` into a static SQL
predicate over ``log_type``, ``channel``, ``app_name`` and ``ls_category``. A
rule's predicate is the AND of the matching entries for each key it carries;
several entries for the same key are OR'ed, and missing keys are unconstrained.
The same predicate filters ``events`` during execution and ``source_inventory``
during pruning, because the map only ever touches columns both tables share.

Rules whose logsource references an unknown product/service/category are
``unroutable`` instead - never matched against all events silently.

The map file ships with the build, but it is still validated at load: every
entry must be a boolean expression of the exact ``column = 'value'`` /
``column IN ('a','b')`` shape, so a typo cannot widen a route.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

#: Columns a routing entry is allowed to reference.
_ROUTE_COLUMNS = frozenset({"log_type", "channel", "app_name", "ls_category"})

#: Sections the map file may contain (spec 04 section 3 table).
_SECTIONS = frozenset({"product", "service", "category"})

#: One routing atom: ``column = 'value'`` or ``column IN ('a', 'b', ...)``.
_ATOM = re.compile(
    r"^(?:log_type|channel|app_name|ls_category)\s*="
    r"\s*'[^']*'|"
    r"^(?:log_type|channel|app_name|ls_category)\s+IN\s*"
    r"\(\s*'[^']*'(?:\s*,\s*'[^']*')*\s*\)$"
)

#: Splits the top-level ``OR`` inside a map entry. Entries never nest, so a
#: plain split on `` OR `` is exact.
_OR = re.compile(r"\s+OR\s+")

#: Extracts the ``log_type`` literals a statement constrains to, for sampling
#: hints. Multi-value ``IN`` lists are read by the inner quoted-literal pass.
_LOG_TYPE_EQ = re.compile(r"^log_type\s*=\s*'([^']*)'$")
_LOG_TYPE_IN = re.compile(r"^log_type\s+IN\s*\((?P<body>.*)\)$", re.S)


class RoutingError(ValueError):
    """The routing map file is malformed and must not be used."""


@dataclass(frozen=True, slots=True)
class Route:
    """The compiled routing predicate for one rule.

    ``sql`` is ``None`` for unroutable rules: nothing here may match against
    all events. ``log_types`` is a sampling hint (never a filter) of every
    ``log_type`` the route can reach.
    """

    sql: str
    log_types: tuple[str, ...]
    logsource: dict[str, str]

    @property
    def unroutable(self) -> bool:
        return False


@dataclass(frozen=True, slots=True)
class Unroutable:
    """A rule whose logsource has no entry in the map."""

    reason: str
    logsource: dict[str, str]

    @property
    def unroutable(self) -> bool:
        return True


def load_logsource_map(path: Path) -> dict[str, dict[str, str]]:
    """Load and validate ``rules/logsource_map.yaml``.

    Raises:
        RoutingError: if the file is missing, has unknown sections, or any
            entry is not a boolean of the allowed atom shape.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RoutingError(f"cannot read logsource map {path}: {exc}") from exc
    try:
        raw = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise RoutingError(f"logsource map {path} is not valid YAML: {exc}") from exc

    if not isinstance(raw, dict):
        raise RoutingError(f"logsource map {path} must be a mapping of sections")
    unknown = set(raw) - _SECTIONS
    if unknown:
        raise RoutingError(f"unknown logsource map section(s): {', '.join(sorted(unknown))}")

    table: dict[str, dict[str, str]] = {}
    for section in _SECTIONS:
        entries = raw.get(section, {})
        if not isinstance(entries, dict):
            raise RoutingError(f"logsource map section {section!r} must be a mapping")
        table[section] = {}
        for key, statement in entries.items():
            if not isinstance(key, str) or not isinstance(statement, str):
                raise RoutingError(f"logsource map section {section!r} has a non-string entry")
            _validate_statement(section, key, statement)
            table[section][key] = statement
    return table


def _validate_statement(section: str, key: str, statement: str) -> None:
    for atom in _OR.split(statement.strip()):
        if not atom or not _ATOM.fullmatch(atom):
            raise RoutingError(
                f"logsource map {section}/{key!r}: {atom!r} is not a routing predicate "
                "(expected `column = 'value'` or `column IN ('a', 'b')`)"
            )


def build_route(
    table: dict[str, dict[str, str]],
    product: str | None,
    service: str | None,
    category: str | None,
) -> Route | Unroutable:
    """Compile the route for one logsource.

    ``product``, ``service``, ``category`` are the raw Sigma logsource values
    (``None`` for absent). The service lookup prefers the product-scoped key
    ``<product>/<service>`` and falls back to the bare service name.
    """
    logsource: dict[str, str] = {}
    log_types: set[str] = set()
    sections: list[tuple[str | None, str, list[str] | None]] = []

    sections.append((product, "product", _product_entries(table, product, logsource)))
    sections.append((service, "service", _service_entries(table, product, service, logsource)))
    sections.append((category, "category", _category_entries(table, category, logsource)))

    section_sqls: list[str] = []
    for key, section, entries in sections:
        if entries is None:
            return Unroutable(f"unknown logsource {section} {key!r}", logsource)
        if not entries:
            continue  # absent key: unconstrained
        group = " OR ".join(entries)
        log_types.update(_log_type_values(group))
        section_sqls.append(group if len(entries) == 1 else f"({group})")

    return Route(" AND ".join(section_sqls), _sorted_tuple(log_types), logsource)


def _product_entries(
    table: dict[str, dict[str, str]],
    product: str | None,
    logsource: dict[str, str],
) -> list[str] | None:
    if product is None:
        return []
    key = str(product).lower()
    if key not in table["product"]:
        return None
    logsource["product"] = key
    return [table["product"][key]]


def _service_entries(
    table: dict[str, dict[str, str]],
    product: str | None,
    service: str | None,
    logsource: dict[str, str],
) -> list[str] | None:
    if service is None:
        return []
    service_key = str(service).lower()
    logsource["service"] = service_key
    candidates: list[str] = []
    if product is not None:
        candidates.append(f"{str(product).lower()}/{service_key}")
    candidates.append(service_key)
    entries = [table["service"].get(key) for key in candidates]
    found = [entry for entry in entries if entry is not None]
    return found or None


def _category_entries(
    table: dict[str, dict[str, str]],
    category: str | None,
    logsource: dict[str, str],
) -> list[str] | None:
    if category is None:
        return []
    key = str(category).lower()
    if key not in table["category"]:
        return None
    logsource["category"] = key
    return [table["category"][key]]


def _sorted_tuple(values: set[str]) -> tuple[str, ...]:
    return tuple(sorted(values))


def _log_type_values(statement: str) -> set[str]:
    """The log_types a routing statement reaches."""
    found: set[str] = set()
    for atom in _OR.split(statement.strip()):
        match = _LOG_TYPE_EQ.fullmatch(atom)
        if match:
            found.add(match.group(1))
            continue
        match = _LOG_TYPE_IN.fullmatch(atom)
        if match:
            found.update(re.findall(r"'([^']*)'", match.group("body")))
    return found


__all__ = [
    "Route",
    "RoutingError",
    "Unroutable",
    "build_route",
    "load_logsource_map",
]
