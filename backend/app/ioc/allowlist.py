"""Allowlisting (spec 05 section 5).

The default allowlist lives in ``data/default_allowlist.yaml``. Matching
indicators are never dropped: they are stored with ``is_allowlisted=1`` so the
analyst can still see them, and excluded from exports and scoring by default.

The matcher supports all the ``allowlist`` table kinds (``domain``,
``domain_suffix``, ``ip``, ``cidr``, ``hash``, ``regex``) so the same class serves
both the bundled defaults and the case-scoped entries an analyst adds.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from app.ioc.canonical import extract_host, normalize_domain
from app.ioc.types import IocType

#: Types the domain rules apply to.
_DOMAIN_TYPES = frozenset({IocType.DOMAIN, IocType.URL})
_IP_TYPES = frozenset({IocType.IPV4, IocType.IPV6})
_HASH_TYPES = frozenset({IocType.MD5, IocType.SHA1, IocType.SHA256})


@dataclass(frozen=True, slots=True)
class Allowlist:
    """A compiled allowlist; all entries are lowercase-normalized on build."""

    domain_suffix: frozenset[str] = field(default_factory=frozenset)
    domain: frozenset[str] = field(default_factory=frozenset)
    ip: frozenset[str] = field(default_factory=frozenset)
    cidr: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()
    hash: frozenset[str] = field(default_factory=frozenset)
    regex: tuple[re.Pattern[str], ...] = ()

    def matches(self, ioc_type: IocType, value: str, value_norm: str) -> bool:
        """True when this indicator is allowlisted under any entry."""
        if self._matches_regex(value, value_norm):
            return True
        if ioc_type in _DOMAIN_TYPES:
            return self._matches_domain(ioc_type, value, value_norm)
        if ioc_type in _IP_TYPES:
            return self._matches_ip(value_norm)
        if ioc_type in _HASH_TYPES:
            return value_norm.lower() in self.hash
        return False

    def _matches_regex(self, value: str, value_norm: str) -> bool:
        """Whether any regex entry matches either form of the value."""
        return any(p.search(value) or p.search(value_norm) for p in self.regex)

    def _matches_domain(self, ioc_type: IocType, value: str, value_norm: str) -> bool:
        """Whether a domain (or a URL's host) is on the allowlist."""
        host = value_norm
        if ioc_type is IocType.URL:
            host = extract_host(value) or value_norm
        host = host.lower().rstrip(".")
        if host in self.domain:
            return True
        return any(host == suffix or host.endswith("." + suffix) for suffix in self.domain_suffix)

    def _matches_ip(self, value_norm: str) -> bool:
        """Whether an address is listed exactly or falls in a listed network."""
        if value_norm in self.ip:
            return True
        try:
            address = ipaddress.ip_address(value_norm)
        except ValueError:
            return False
        return any(address in network for network in self.cidr)

    def combined(self, other: Allowlist) -> Allowlist:
        """A new allowlist with both sets of entries."""
        return Allowlist(
            domain_suffix=self.domain_suffix | other.domain_suffix,
            domain=self.domain | other.domain,
            ip=self.ip | other.ip,
            cidr=(*self.cidr, *other.cidr),
            hash=self.hash | other.hash,
            regex=(*self.regex, *other.regex),
        )


#: An empty allowlist, used when nothing is configured.
EMPTY = Allowlist()


def _as_str_set(value: Any) -> frozenset[str]:
    """Lowercase strings from a YAML list, ignoring blanks and non-strings."""
    if not isinstance(value, list):
        return frozenset()
    return frozenset(str(item).strip().lower() for item in value if str(item).strip())


def load_default_allowlist(path: Path) -> Allowlist:
    """Read ``default_allowlist.yaml``; a missing file yields an empty list."""
    if not path.is_file():
        return EMPTY
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError):
        return EMPTY
    if not isinstance(document, dict):
        return EMPTY
    suffixes = _as_str_set(document.get("domain_suffix"))
    return Allowlist(
        domain_suffix=frozenset(normalize_domain(v) for v in suffixes),
        domain=frozenset(normalize_domain(v) for v in _as_str_set(document.get("domain"))),
        ip=_as_str_set(document.get("ip")),
        cidr=_compile_cidrs(document.get("cidr")),
        hash=_as_str_set(document.get("hash")),
        regex=_compile_regexes(document.get("regex")),
    )


def entries_to_allowlist(entries: list[tuple[str, str]]) -> Allowlist:
    """Build an allowlist from ``(kind, value)`` rows, e.g. from the DB table."""
    suffixes: list[str] = []
    domains: list[str] = []
    ips: list[str] = []
    cidrs: list[str] = []
    hashes: list[str] = []
    regexes: list[str] = []
    for kind, value in entries:
        cleaned = value.strip()
        if not cleaned:
            continue
        if kind == "domain_suffix":
            suffixes.append(cleaned)
        elif kind == "domain":
            domains.append(cleaned)
        elif kind == "ip":
            ips.append(cleaned)
        elif kind == "cidr":
            cidrs.append(cleaned)
        elif kind == "hash":
            hashes.append(cleaned)
        elif kind == "regex":
            regexes.append(cleaned)
    return Allowlist(
        domain_suffix=frozenset(normalize_domain(v) for v in suffixes),
        domain=frozenset(normalize_domain(v) for v in domains),
        ip=frozenset(v.lower() for v in ips),
        cidr=_compile_cidrs(cidrs),
        hash=frozenset(v.lower() for v in hashes),
        regex=_compile_regexes(regexes),
    )


def _compile_cidrs(values: Any) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    """Parse CIDR strings, skipping any that do not parse."""
    if not isinstance(values, list):
        return ()
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for value in values:
        try:
            networks.append(ipaddress.ip_network(str(value).strip(), strict=False))
        except ValueError:
            continue
    return tuple(networks)


def _compile_regexes(values: Any) -> tuple[re.Pattern[str], ...]:
    """Compile regex entries, skipping any that do not compile."""
    if not isinstance(values, list):
        return ()
    compiled: list[re.Pattern[str]] = []
    for value in values:
        try:
            compiled.append(re.compile(str(value)))
        except re.error:
            continue
    return tuple(compiled)


__all__ = [
    "EMPTY",
    "Allowlist",
    "entries_to_allowlist",
    "load_default_allowlist",
]
