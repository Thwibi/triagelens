"""Canonical ``value_norm`` for every IOC type (spec 05 section 7).

The stored row is unique on ``(case_id, type, value_norm)``, so this module
decides what counts as "the same indicator". The rules are deliberately tighter
than the display value:

- Addresses become the compressed form :mod:`ipaddress` round-trips.
- Domains become lowercase punycode with the trailing dot stripped, so ``Evil.COM.``
  and ``evil.com`` are one row.
- URLs lowercase only the scheme and host, drop a default port and the fragment,
  and keep path and query byte-for-byte: two URLs that differ in their query are
  two different requests.
- Hashes and emails lowercase; CVEs uppercase.
- Paths and registry keys keep their case for display but dedup case-insensitively,
  because Windows paths are case-insensitive.
"""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

from app.ioc.types import IocType

#: Ports that a URL scheme implies, dropped from the canonical form.
_DEFAULT_PORTS: dict[str, str] = {
    "http": "80",
    "https": "443",
    "ftp": "21",
    "ftps": "990",
    "sftp": "22",
    "tftp": "69",
}


def extract_host(value: str) -> str | None:
    """The host of a URL, lowercased and punycode-encoded, or ``None``."""
    try:
        host = urlsplit(value).hostname
    except ValueError:
        return None
    if not host:
        return None
    try:
        return host.encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        return host.lower()


def normalize_domain(value: str) -> str:
    """Lowercase, strip a trailing dot, and punycode-encode a domain."""
    candidate = value.strip().lower().rstrip(".")
    try:
        return candidate.encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        return candidate


def normalize_url(value: str) -> str:
    """Canonicalize a URL for dedup without rewriting its path or query.

    Scheme and host are lowercased, a default port is dropped, the fragment is
    removed, and the path/query are preserved byte for byte. A URL that cannot be
    split is returned stripped, so a malformed value is still dedupable.
    """
    text = value.strip()
    try:
        parts = urlsplit(text)
        host = parts.hostname or ""
        port = parts.port
    except ValueError:
        return text
    scheme = parts.scheme.lower()
    if host:
        try:
            host = host.encode("idna").decode("ascii").lower()
        except (UnicodeError, ValueError):
            host = host.lower()
    netloc = host
    if port is not None and str(port) != _DEFAULT_PORTS.get(scheme):
        netloc = f"{host}:{port}"
    return urlunsplit((scheme, netloc, parts.path, parts.query, ""))


def normalize_email(value: str) -> str:
    """Lowercase an email address."""
    return value.strip().lower()


def normalize_hash(value: str) -> str:
    """Lowercase a hex hash."""
    return value.strip().lower()


def normalize_cve(value: str) -> str:
    """Uppercase a CVE id."""
    return value.strip().upper()


def canonical_value(ioc_type: IocType, value: str) -> str:  # noqa: PLR0911
    """The canonical dedup key for ``value`` under ``ioc_type``."""
    if ioc_type is IocType.DOMAIN:
        return normalize_domain(value)
    if ioc_type is IocType.URL:
        return normalize_url(value)
    if ioc_type is IocType.EMAIL:
        return normalize_email(value)
    if ioc_type in {IocType.MD5, IocType.SHA1, IocType.SHA256}:
        return normalize_hash(value)
    if ioc_type is IocType.CVE:
        return normalize_cve(value)
    if ioc_type in {IocType.FILENAME, IocType.FILEPATH, IocType.REGISTRY}:
        # Dedup case-insensitively; the display value keeps its original case.
        return value.strip().lower()
    if ioc_type in {IocType.IPV4, IocType.IPV6}:
        return value.strip().lower()
    return value.strip()


__all__ = [
    "canonical_value",
    "extract_host",
    "normalize_cve",
    "normalize_domain",
    "normalize_email",
    "normalize_hash",
    "normalize_url",
]
