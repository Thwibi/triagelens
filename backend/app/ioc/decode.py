"""Decoding passes (spec 05 section 2.2).

Obfuscated command lines hide indicators behind base64 or percent-encoding. The
extractor runs each text value through these decoders and scans the decoded
children too, up to ``decode_depth`` (default 2). Every decoded child is capped
and must be mostly printable, which is what stops a random blob from producing a
mountain of false candidates.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from urllib.parse import unquote

#: The default depth from :class:`app.config.IocConfig`.
DEFAULT_DEPTH = 2

#: Longest decoded text kept, in bytes; anything larger is dropped, not truncated
#: mid-token, because a truncated base64 string is not evidence.
MAX_DECODED_BYTES = 256 * 1024

#: Minimum share of printable characters for a decode to be kept.
PRINTABLE_RATIO = 0.85

#: ``-EncodedCommand`` and friends, followed by the base64 payload.
_PS_ENCODED = re.compile(
    r"-(?:e|ec|en|enc|enco|encod|encode|encoded|encodedcommand)\s+([A-Za-z0-9+/=]{16,})",
    re.IGNORECASE,
)

#: ``[Convert]::FromBase64String('...')``.
_FROM_BASE64 = re.compile(r"\[Convert\]::FromBase64String\(['\"]([^'\"]+)['\"]\)", re.IGNORECASE)
_GET_STRING = re.compile(r"GetString", re.IGNORECASE)

#: A standalone base64 token long enough that decoding it is worth trying.
_B64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])")

#: A single percent-escape, used to decide whether to attempt URL decoding.
_PERCENT = re.compile(r"%[0-9A-Fa-f]{2}")


@dataclass(frozen=True, slots=True)
class Decoded:
    """One decoded child of a source text."""

    text: str
    provenance: str
    depth: int


def decode_all(text: str, *, depth: int = DEFAULT_DEPTH) -> list[Decoded]:
    """Every decoded child of ``text``, recursively to ``depth`` levels.

    The original text is not included; the caller already has it. Order is
    breadth-first by provenance family, and duplicates are removed.
    """
    if not text or depth <= 0:
        return []
    seen: set[str] = set()
    frontier = [text]
    results: list[Decoded] = []
    for level in range(1, depth + 1):
        children: list[tuple[str, str]] = []
        for parent in frontier:
            children.extend(_decode_once(parent))
        frontier = []
        for child, provenance in children:
            if not child or child in seen:
                continue
            seen.add(child)
            results.append(Decoded(child, provenance, level))
            frontier.append(child)
        if not frontier:
            break
    return results


def _decode_once(text: str) -> list[tuple[str, str]]:
    """Every direct decode of ``text``, one level deep."""
    found: list[tuple[str, str]] = []
    found.extend(_decode_powershell(text))
    found.extend(_decode_url_tokens(text))
    for token in _B64_TOKEN.findall(text):
        decoded = _try_base64(token)
        if decoded:
            found.append((decoded, "base64"))
    return found


def _decode_url_tokens(text: str) -> list[tuple[str, str]]:
    """Percent-decode each URL token in ``text`` (not the surrounding prose).

    Decoding the whole string would produce a near-identical child that
    re-scans every other indicator in the text; restricting the pass to URL
    tokens keeps a decoded request as the only new finding.
    """
    from app.ioc.patterns import URL

    found: list[tuple[str, str]] = []
    for match in URL.finditer(text):
        if not _PERCENT.search(match.group(0)):
            continue
        decoded = _url_decode(match.group(0))
        if decoded and decoded != match.group(0):
            found.append((decoded, "url"))
    return found


def _decode_powershell(text: str) -> list[tuple[str, str]]:
    """PowerShell ``-enc`` and ``FromBase64String`` decodes."""
    found: list[tuple[str, str]] = []
    for match in _PS_ENCODED.finditer(text):
        decoded = _try_base64(match.group(1), prefer="utf-16-le")
        if decoded:
            found.append((decoded, "powershell_enc"))
    has_getstring = bool(_GET_STRING.search(text))
    for match in _FROM_BASE64.finditer(text):
        if not has_getstring:
            continue
        decoded = _try_base64(match.group(1))
        if decoded:
            found.append((decoded, "powershell_enc"))
    return found


def _url_decode(text: str) -> str | None:
    """Percent-decode, at most two rounds, or ``None`` when nothing changes."""
    once = unquote(text)
    twice = unquote(once)
    result = twice if twice != once else once
    if result == text:
        return None
    return _keep_if_printable(result)


def _try_base64(token: str, *, prefer: str | None = None) -> str | None:
    """Decode a base64 token to text, trying the encodings that fit.

    ``prefer`` is tried first (UTF-16LE for PowerShell), then UTF-8. A decode that
    is not mostly printable is rejected rather than returned half-garbled.
    """
    padded = token + "=" * (-len(token) % 4)
    try:
        raw = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None
    encodings = ["utf-16-le", "utf-8"] if prefer == "utf-16-le" else ["utf-8", "utf-16-le"]
    for encoding in encodings:
        try:
            decoded = raw.decode(encoding)
        except (UnicodeDecodeError, ValueError):
            continue
        kept = _keep_if_printable(decoded)
        if kept:
            return kept
    return None


def _keep_if_printable(text: str) -> str | None:
    """Return ``text`` when it is mostly printable and within the byte cap."""
    if not text:
        return None
    if len(text.encode("utf-8", errors="ignore")) > MAX_DECODED_BYTES:
        return None
    if _printable_ratio(text) < PRINTABLE_RATIO:
        return None
    return text.strip() or None


def _printable_ratio(text: str) -> float:
    """Share of characters that are printable or ordinary whitespace."""
    printable = sum(1 for char in text if char.isprintable() or char in "\t\r\n")
    return printable / len(text)


__all__ = ["DEFAULT_DEPTH", "MAX_DECODED_BYTES", "Decoded", "decode_all"]
