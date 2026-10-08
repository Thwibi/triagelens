"""Candidate validation and classification (spec 05 sections 3 and 5).

A regex match is only a *candidate*. This module decides whether it is a real
indicator, and what kind:

- Addresses are parsed with :mod:`ipaddress`; leading-zero octets, version
  strings and clock/MAC-shaped IPv6 candidates are rejected.
- Domains must end in a TLD from ``iana_tlds.txt``, be a legal length, and pass
  the ambiguous-TLD rule (a TLD that is also a common file extension is accepted
  only from a structured field or with two or more labels in front of it).
- URLs must split, and their host must be a valid address or domain.
- Hashes must have enough distinct characters and not be an id field.

Classification marks private/reserved addresses, treating the RFC 5737
documentation ranges as public so the fixtures and demos behave like real data.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from app.ioc import patterns
from app.ioc.types import IocType

#: RFC 5737 documentation ranges, treated as public (spec 05 section 5).
DOCUMENTATION_NETS: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)

#: Extra public-but-unroutable ranges that must still read as private.
_RESERVED_NETS: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
)

#: Directories that make a file path worth extracting (spec 05 section 3).
SUSPICIOUS_DIRS: tuple[str, ...] = (
    "\\temp\\",
    "\\appdata\\",
    "\\programdata\\",
    "\\users\\public\\",
    "\\downloads\\",
    "\\windows\\temp\\",
    "\\$recycle.bin\\",
    "/tmp/",  # noqa: S108 - detection literal, not a filesystem path
    "/var/tmp/",  # noqa: S108
    "/dev/shm/",  # noqa: S108
    "/var/www/",
)

#: Executable and script extensions worth extracting a path for.
EXECUTABLE_EXTENSIONS: frozenset[str] = frozenset(
    {
        "exe",
        "dll",
        "sys",
        "scr",
        "bat",
        "cmd",
        "ps1",
        "psm1",
        "vbs",
        "vbe",
        "js",
        "jse",
        "hta",
        "lnk",
        "jar",
        "msi",
        "iso",
        "img",
        "one",
        "docm",
        "xlsm",
        "py",
        "sh",
        "elf",
    }
)

#: Registry substrings that indicate persistence or defense evasion.
PERSISTENCE_REGISTRY: tuple[str, ...] = (
    "\\run",
    "\\runonce",
    "\\services\\",
    "\\winlogon",
    "\\image file execution options",
    "\\policies\\",
    "\\windows defender",
    "\\schedule\\taskcache",
    "\\environment",
    "\\explorer\\",
    "\\classes\\clsid",
    "\\lsa",
)

#: Longest legal fully-qualified domain name, in characters (RFC 1035).
MAX_DOMAIN_LENGTH = 253

#: Longest legal single label, in characters.
MAX_LABEL_LENGTH = 63

#: A name needs at least a label and a TLD.
MIN_DOMAIN_LABELS = 2

#: Labels needed to accept an ambiguous TLD outside a structured field.
MIN_LABELS_FOR_AMBIGUOUS = 3

#: Longest legal email local part (RFC 5321).
MAX_EMAIL_LOCAL = 64

#: A hash with this few distinct characters is not real evidence.
MIN_DISTINCT_HASH_CHARS = 3

#: TLDs loaded once from the bundled list. A one-key box, not a module global,
#: so the loader stays testable without a ``global`` rebind.
_TLD_BOX: dict[str, frozenset[str]] = {}


def load_tlds(path: Path) -> frozenset[str]:
    """Read the bundled TLD list; missing or empty yields an empty set."""
    if not path.is_file():
        return frozenset()
    entries: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        text = line.strip().lower()
        if text and not text.startswith("#"):
            entries.add(text)
    return frozenset(entries)


def set_tlds(tlds: frozenset[str]) -> None:
    """Install a TLD set, used by tests and by startup to load the bundled file."""
    _TLD_BOX["value"] = tlds


def tlds() -> frozenset[str]:
    """The active TLD set, loading the bundled list on first use."""
    if "value" not in _TLD_BOX:
        from app.config import Settings

        _TLD_BOX["value"] = load_tlds(Settings().bundled_data_dir / "iana_tlds.txt")
    return _TLD_BOX["value"]


#: Trailing punctuation stripped from a URL unless it would unbalance a bracket.
_TRAILING = ".,;:\"'"


def _strip_trailing_url(text: str) -> str:
    """Drop sentence punctuation a URL was wrapped in."""
    result = text
    while result and result[-1] in _TRAILING:
        result = result[:-1]
    pairs = {")": "(", "]": "[", "}": "{"}
    while result and result[-1] in pairs:
        closer = result[-1]
        if result.count(pairs[closer]) < result.count(closer):
            result = result[:-1]
        else:
            break
    return result


def classify_ip(value: str) -> bool:
    """True when an address is private, reserved or otherwise not routable."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv4Address) and any(
        address in net for net in DOCUMENTATION_NETS
    ):
        return False
    if isinstance(address, ipaddress.IPv4Address) and any(address in net for net in _RESERVED_NETS):
        return True
    return bool(
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
    )


def validate_ipv4(token: str, *, prefix: str = "", suffix: str = "") -> str | None:
    """Return the canonical IPv4 string, or ``None`` when the token is not one."""
    if patterns.LEADING_ZERO.search(token):
        return None
    if prefix.lower().endswith(("v", "version ", "ver ")):
        return None
    if suffix[:1] == "-" and suffix[1:2].isalpha():
        # A dotted quad with a version tag, e.g. 10.1.2.3-beta.
        return None
    try:
        return str(ipaddress.IPv4Address(token))
    except ValueError:
        return None


def validate_ipv6(token: str) -> str | None:
    """Return a canonical IPv6 string, or ``None`` when the token is not one."""
    if patterns.MAC.fullmatch(token) or patterns.CLOCK.fullmatch(token):
        return None
    if ":" not in token:
        return None
    try:
        address = ipaddress.IPv6Address(token)
    except ValueError:
        return None
    if address.ipv4_mapped is not None:
        # ``::ffff:1.2.3.4`` is an IPv4 address wearing an IPv6 coat.
        return None
    return str(address)


def is_ip_like(token: str) -> bool:
    """True when a token parses as an IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(token)
    except ValueError:
        return False
    return True


def _looks_like_filename(token: str) -> bool:
    """True when a token's final label is a file extension, e.g. ``update.sh``."""
    final = token.rsplit(".", 1)[-1].lower()
    return final in patterns.FILENAME_EXTENSIONS


@dataclass(frozen=True, slots=True)
class DomainMatch:
    """A validated domain and how it was accepted."""

    value: str
    ambiguous: bool


def _labels_valid(labels: list[str]) -> bool:
    """Whether every domain label is non-empty, short, and correctly hyphenated."""
    for label in labels:
        if not label or len(label) > MAX_LABEL_LENGTH:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
    return True


def validate_domain(token: str, *, structured: bool = False) -> DomainMatch | None:  # noqa: PLR0911
    """Validate a domain, applying the ambiguous-TLD rule.

    ``structured=True`` for a host taken from a URL, DNS query, ``Host`` header or
    email domain: an ambiguous TLD is accepted there even with one label.
    """
    candidate = token.strip().lower().rstrip(".")
    if not candidate or is_ip_like(candidate):
        return None
    if len(candidate) > MAX_DOMAIN_LENGTH:
        return None
    labels = candidate.split(".")
    if len(labels) < MIN_DOMAIN_LABELS:
        return None
    if not _labels_valid(labels):
        return None
    tld = labels[-1]
    ambiguous = tld in patterns.AMBIGUOUS_TLDS
    if not tld.startswith("xn--") and tld not in tlds():
        return None
    if _looks_like_filename(candidate):
        return None
    if ambiguous and not structured and len(labels) < MIN_LABELS_FOR_AMBIGUOUS:
        # One label plus an extension-like TLD is far more likely a filename.
        return None
    try:
        normalized = candidate.encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        normalized = candidate
    return DomainMatch(value=normalized, ambiguous=ambiguous)


def validate_url(token: str) -> tuple[str, str] | None:  # noqa: PLR0911
    """Validate a URL, returning ``(url, host)`` or ``None``.

    The host is returned so the caller can emit it as its own IOC with role
    ``url_request`` (spec 05 section 3).
    """
    cleaned = _strip_trailing_url(token)
    if not cleaned:
        return None
    try:
        parts = urlsplit(cleaned)
    except ValueError:
        return None
    if not parts.scheme or not parts.netloc:
        return None
    host = parts.hostname
    if not host:
        return None
    if is_ip_like(host):
        return None
    if validate_domain(host, structured=True) is None:
        return None
    return cleaned, host


def validate_email(token: str) -> str | None:
    """Validate an email address, or ``None``."""
    local, separator, domain = token.partition("@")
    if not separator or not local or len(local) > MAX_EMAIL_LOCAL:
        return None
    if validate_domain(domain, structured=True) is None:
        return None
    return token.lower()


def validate_hash(token: str, *, prefix: str = "") -> str | None:
    """Validate a hex hash, or ``None`` when it is too regular or an id."""
    lowered = token.lower()
    if len(set(lowered)) < MIN_DISTINCT_HASH_CHARS:
        return None
    if patterns.ID_CONTEXT.search(prefix):
        return None
    return lowered


def validate_cve(token: str) -> str:
    """Normalize a CVE id to uppercase."""
    return token.upper()


@dataclass(frozen=True, slots=True)
class PathMatch:
    """A path kept for extraction, with its basename."""

    path: str
    filename: str


#: An extension inside a candidate, used to cut command-line arguments away.
_EXTENSION_IN_TOKEN = re.compile(r"\.[A-Za-z0-9]{1,10}(?![A-Za-z0-9])")


def validate_path(token: str) -> PathMatch | None:
    """Keep a path only when its directory or extension is suspicious (tier 2)."""
    cleaned = token.strip().rstrip("\"'>|")
    lowered = cleaned.lower().replace("/", "\\")
    suspicious_dir = any(dir_.replace("/", "\\") in lowered for dir_ in SUSPICIOUS_DIRS)
    cut = _cut_at_extension(cleaned)
    if cut is not None:
        cleaned = cut
    elif not suspicious_dir:
        return None
    if not cleaned:
        return None
    filename = cleaned.replace("\\", "/").rsplit("/", 1)[-1]
    if not filename:
        return None
    return PathMatch(path=cleaned, filename=filename)


def _cut_at_extension(token: str) -> str | None:
    """Cut ``token`` after its first executable extension, or ``None`` if it has none.

    A command line reads ``C:\\Users\\Public\\evil.exe -enc ...``; keeping the
    arguments as part of the path would store a file that does not exist.
    """
    for match in _EXTENSION_IN_TOKEN.finditer(token):
        extension = match.group(0).lstrip(".").lower()
        if extension in EXECUTABLE_EXTENSIONS:
            return token[: match.end()]
    return None


def validate_registry(token: str) -> str | None:
    """Keep a registry key only when it is persistence- or evasion-relevant."""
    cleaned = token.strip().rstrip("\"'")
    lowered = cleaned.lower()
    if any(marker in lowered for marker in PERSISTENCE_REGISTRY):
        return cleaned
    return None


#: Maps a network indicator type to its classifier, for reuse.
PRIVATE_TYPES: frozenset[IocType] = frozenset({IocType.IPV4, IocType.IPV6})


__all__ = [
    "DOCUMENTATION_NETS",
    "EXECUTABLE_EXTENSIONS",
    "PERSISTENCE_REGISTRY",
    "SUSPICIOUS_DIRS",
    "DomainMatch",
    "PathMatch",
    "classify_ip",
    "is_ip_like",
    "load_tlds",
    "set_tlds",
    "tlds",
    "validate_cve",
    "validate_domain",
    "validate_email",
    "validate_hash",
    "validate_ipv4",
    "validate_ipv6",
    "validate_path",
    "validate_registry",
    "validate_url",
]
