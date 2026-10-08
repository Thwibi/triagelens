"""Tier-1 IOC extraction from event fields (spec 05 sections 2-3).

``extract_fields`` is the entry point the parse worker calls for every event: it
walks the event's text fields, refangs and decodes each, and returns an
:class:`~app.ioc.types.IocHit` for every indicator it is confident about. The
aggregator (in :mod:`app.ioc`) collapses the hits into one row per
``(case_id, type, value_norm)`` and a bounded occurrence list.

Two properties matter here:

- **Determinism.** Given the same event and options, the same hits come out in the
  same order. No clock, no randomness, no global mutable state beyond the TLD set.
- **Cost control.** The scanners are linear in the text, decoding is capped and
  depth-limited, and repeated field values inside one event are decoded once.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from app.ioc import patterns
from app.ioc.allowlist import Allowlist
from app.ioc.canonical import canonical_value
from app.ioc.decode import DEFAULT_DEPTH, decode_all
from app.ioc.refang import refang
from app.ioc.types import (
    BASE_DECODED,
    BASE_FREETEXT,
    BASE_STRUCTURED,
    TIER1_TYPES,
    IocCandidate,
    IocHit,
    IocType,
    Role,
)
from app.ioc.validate import (
    classify_ip,
    validate_cve,
    validate_domain,
    validate_email,
    validate_hash,
    validate_ipv4,
    validate_ipv6,
    validate_path,
    validate_registry,
    validate_url,
)

#: Fields whose value is free text, so an indicator in them is a "mention".
_MENTION_FIELDS: frozenset[str] = frozenset(
    {
        "message",
        "raw",
        "_raw",
        "command",
        "commandline",
        "command_line",
        "process_cmdline",
        "parent_process_cmdline",
        "script",
        "cmd",
        "payload",
    }
)

#: Substrings in a field name that mark it as a dedicated indicator field.
_INDICATOR_HINTS: tuple[str, ...] = (
    "ip",
    "addr",
    "hash",
    "md5",
    "sha",
    "domain",
    "url",
    "uri",
    "fqdn",
    "email",
    "cve",
)

#: Field name -> role. Unknown fields fall back to ``Role.MENTIONED``.
_ROLE_BY_FIELD: dict[str, Role] = {
    "src_ip": Role.SOURCE,
    "source_ip": Role.SOURCE,
    "src_addr": Role.SOURCE,
    "dst_ip": Role.DESTINATION,
    "dest_ip": Role.DESTINATION,
    "destination_ip": Role.DESTINATION,
    "dst_addr": Role.DESTINATION,
    "url": Role.URL_REQUEST,
    "url_path": Role.URL_REQUEST,
    "url_query": Role.URL_REQUEST,
    "domain": Role.DNS_QUERY,
    "dns_query": Role.DNS_QUERY,
    "query": Role.DNS_QUERY,
    "process_path": Role.PROCESS,
    "process_cmdline": Role.PROCESS,
    "parent_process_path": Role.PROCESS,
    "parent_process_cmdline": Role.PROCESS,
    "file_path": Role.PROCESS,
    "registry_key": Role.PROCESS,
    "registry_value": Role.PROCESS,
    "md5": Role.IMAGE_HASH,
    "sha1": Role.IMAGE_HASH,
    "sha256": Role.IMAGE_HASH,
    "hash": Role.IMAGE_HASH,
}

#: Fields whose MD5 value is almost never a file hash.
_MD5_BLOCKED_FIELDS: frozenset[str] = frozenset({"randomseed", "sessionid"})

#: Skip decoding values shorter than this; a short token is never real base64.
_MIN_DECODE_LENGTH = 16


@dataclass(frozen=True, slots=True)
class _Context:
    """Everything a scanner needs about where a value came from."""

    field: str
    role: Role
    structured: bool
    allowlist: Allowlist
    decoded_from: str | None = None


def _role_for(field: str) -> Role:
    """The role for a field name, defaulting to a mention."""
    return _ROLE_BY_FIELD.get(field.lower(), Role.MENTIONED)


def _is_structured(field: str, value: str) -> bool:
    """Whether a value is a dedicated single-indicator field rather than prose."""
    lowered = field.lower()
    if lowered in _MENTION_FIELDS:
        return False
    if any(char.isspace() for char in value.strip()):
        return False
    return any(hint in lowered for hint in _INDICATOR_HINTS) or lowered in _ROLE_BY_FIELD


def _make_candidate(
    ioc_type: IocType,
    value: str,
    *,
    ctx: _Context,
    ambiguous: bool = False,
) -> IocCandidate:
    """Build a candidate, computing its norm, classification and base score."""
    value_norm = canonical_value(ioc_type, value)
    if ctx.decoded_from is not None:
        base = BASE_DECODED
    else:
        base = BASE_STRUCTURED if ctx.structured else BASE_FREETEXT
    is_private = classify_ip(value_norm) if ioc_type in {IocType.IPV4, IocType.IPV6} else False
    is_allowlisted = ctx.allowlist.matches(ioc_type, value, value_norm)
    return IocCandidate(
        type=ioc_type,
        value=value,
        value_norm=value_norm,
        base=base,
        is_private=is_private,
        is_allowlisted=is_allowlisted,
        ambiguous_tld=ambiguous,
    )


def _hit(ioc_type: IocType, value: str, ctx: _Context, *, ambiguous: bool = False) -> IocHit:
    """One hit for a validated value."""
    return IocHit(
        candidate=_make_candidate(ioc_type, value, ctx=ctx, ambiguous=ambiguous),
        field=ctx.field,
        role=ctx.role,
        decoded_from=ctx.decoded_from,
    )


def _scan_ipv4(text: str, ctx: _Context) -> Iterable[IocHit]:
    for match in patterns.IPV4.finditer(text):
        token = match.group(0)
        value = validate_ipv4(
            token,
            prefix=text[max(0, match.start() - 4) : match.start()],
            suffix=text[match.end() : match.end() + 2],
        )
        if value is not None:
            yield _hit(IocType.IPV4, value, ctx)


def _scan_ipv6(text: str, ctx: _Context) -> Iterable[IocHit]:
    for match in patterns.IPV6.finditer(text):
        value = validate_ipv6(match.group(0))
        if value is not None:
            yield _hit(IocType.IPV6, value, ctx)


def _scan_url(text: str, ctx: _Context) -> Iterable[IocHit]:
    for match in patterns.URL.finditer(text):
        result = validate_url(match.group(0))
        if result is None:
            continue
        url, host = result
        yield _hit(IocType.URL, url, ctx)
        domain = validate_domain(host, structured=True)
        if domain is not None:
            # A URL host is always accepted through the structured-field path,
            # so the ambiguous-TLD penalty never applies (spec 05 section 6).
            yield _hit(IocType.DOMAIN, host, _replace_field(ctx, "url"))


def _scan_email(text: str, ctx: _Context) -> Iterable[IocHit]:
    for match in patterns.EMAIL.finditer(text):
        value = validate_email(match.group(0))
        if value is not None:
            yield _hit(IocType.EMAIL, value, ctx)


def _scan_domain(text: str, ctx: _Context) -> Iterable[IocHit]:
    for match in patterns.DOMAIN.finditer(text):
        domain = validate_domain(match.group(0), structured=ctx.structured)
        if domain is not None:
            # The ambiguous-TLD penalty applies only when acceptance rode on the
            # "two or more labels" rule, which is the free-text path; a dedicated
            # indicator field accepted the value without it (spec 05 section 6).
            yield _hit(
                IocType.DOMAIN,
                domain.value,
                ctx,
                ambiguous=domain.ambiguous and not ctx.structured,
            )


def _scan_hash(
    text: str,
    ctx: _Context,
    ioc_type: IocType,
    pattern: re.Pattern[str],
) -> Iterable[IocHit]:
    if ioc_type is IocType.MD5 and ctx.field.lower() in _MD5_BLOCKED_FIELDS:
        return
    for match in pattern.finditer(text):
        value = validate_hash(
            match.group(0), prefix=text[max(0, match.start() - 12) : match.start()]
        )
        if value is not None:
            yield _hit(ioc_type, value, ctx)


def _scan_cve(text: str, ctx: _Context) -> Iterable[IocHit]:
    for match in patterns.CVE.finditer(text):
        yield _hit(IocType.CVE, validate_cve(match.group(0)), ctx)


def _scan_path(text: str, ctx: _Context) -> Iterable[IocHit]:
    seen: set[str] = set()
    for pattern in (patterns.WINPATH, patterns.UNC_PATH, patterns.NIXPATH):
        for match in pattern.finditer(text):
            result = validate_path(match.group(0))
            if result is None or result.filename in seen:
                continue
            seen.add(result.filename)
            yield _hit(IocType.FILEPATH, result.path, ctx)
            yield _hit(IocType.FILENAME, result.filename, ctx)


def _scan_registry(text: str, ctx: _Context) -> Iterable[IocHit]:
    seen: set[str] = set()
    for match in patterns.REGKEY.finditer(text):
        value = validate_registry(match.group(0))
        if value is not None and value not in seen:
            seen.add(value)
            yield _hit(IocType.REGISTRY, value, ctx)


def _replace_field(ctx: _Context, field: str) -> _Context:
    """A copy of ``ctx`` with a different field name (for a URL's host)."""
    return _Context(
        field=field,
        role=ctx.role,
        structured=ctx.structured,
        allowlist=ctx.allowlist,
        decoded_from=ctx.decoded_from,
    )


#: A scanner takes refanged text and the field context, and yields hits.
_Scanner = Callable[[str, "_Context"], Iterable[IocHit]]

#: Scanners run in this order; each declares the type it produces.
_SCANNERS: tuple[tuple[IocType, _Scanner], ...] = (
    (IocType.IPV4, _scan_ipv4),
    (IocType.IPV6, _scan_ipv6),
    (IocType.URL, _scan_url),
    (IocType.EMAIL, _scan_email),
    (IocType.DOMAIN, _scan_domain),
    (IocType.MD5, lambda text, ctx: _scan_hash(text, ctx, IocType.MD5, patterns.MD5)),
    (IocType.SHA1, lambda text, ctx: _scan_hash(text, ctx, IocType.SHA1, patterns.SHA1)),
    (IocType.SHA256, lambda text, ctx: _scan_hash(text, ctx, IocType.SHA256, patterns.SHA256)),
    (IocType.CVE, _scan_cve),
    (IocType.FILEPATH, _scan_path),
    (IocType.REGISTRY, _scan_registry),
)


def scan_text(
    text: str,
    *,
    ctx: _Context,
    types: frozenset[IocType] = TIER1_TYPES,
) -> Iterable[IocHit]:
    """Every hit in ``text`` for the allowed ``types``, in scanner order."""
    if not text:
        return
    refanged = refang(text)
    for ioc_type, scanner in _SCANNERS:
        if ioc_type not in types:
            continue
        yield from scanner(refanged, ctx)


def _decode_layers(text: str, depth: int) -> Iterable[tuple[str, str]]:
    """``(text, provenance)`` for every decoded child of ``text``.

    The input is refanged first so a defanged URL ``hxxp://x/%2e`` is recognisable
    as a URL before its percent escapes are decoded.
    """
    for decoded in decode_all(refang(text), depth=depth):
        yield decoded.text, decoded.provenance


def extract_text(
    text: str,
    *,
    field: str,
    role: Role,
    structured: bool,
    allowlist: Allowlist,
    types: frozenset[IocType] = TIER1_TYPES,
    decode_depth: int = DEFAULT_DEPTH,
) -> list[IocHit]:
    """Extract from one text value, including decoded children."""
    ctx = _Context(field=field, role=role, structured=structured, allowlist=allowlist)
    hits = list(scan_text(text, ctx=ctx, types=types))
    if decode_depth > 0 and len(text) >= _MIN_DECODE_LENGTH:
        for child, provenance in _decode_layers(text, decode_depth):
            decoded_ctx = _Context(
                field=field,
                role=role,
                structured=False,
                allowlist=allowlist,
                decoded_from=provenance,
            )
            hits.extend(scan_text(child, ctx=decoded_ctx, types=types))
    return hits


def extract_fields(
    fields: Mapping[str, Any],
    *,
    allowlist: Allowlist,
    types: frozenset[IocType] = TIER1_TYPES,
    decode_depth: int = DEFAULT_DEPTH,
    max_hits: int | None = None,
) -> list[IocHit]:
    """Extract IOC hits from an event's field mapping (column names or raw keys).

    Values are scanned in the mapping's order. ``max_hits`` bounds the result for
    a pathologically large record; when it is reached, scanning stops early.
    """
    hits: list[IocHit] = []
    decoded_cache: dict[str, list[tuple[str, str]]] = {}
    for field, raw in fields.items():
        if raw is None:
            continue
        text = raw if isinstance(raw, str) else str(raw)
        if not text:
            continue
        role = _role_for(field)
        structured = _is_structured(field, text)
        ctx = _Context(field=field, role=role, structured=structured, allowlist=allowlist)
        hits.extend(scan_text(text, ctx=ctx, types=types))
        if decode_depth > 0 and len(text) >= _MIN_DECODE_LENGTH:
            children = decoded_cache.get(text)
            if children is None:
                children = list(_decode_layers(text, decode_depth))
                decoded_cache[text] = children
            for child, provenance in children:
                decoded_ctx = _Context(
                    field=field,
                    role=role,
                    structured=False,
                    allowlist=allowlist,
                    decoded_from=provenance,
                )
                hits.extend(scan_text(child, ctx=decoded_ctx, types=types))
        if max_hits is not None and len(hits) >= max_hits:
            return hits[:max_hits]
    return hits


__all__ = ["extract_fields", "extract_text", "scan_text"]
