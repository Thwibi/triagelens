"""Hashing and deterministic identifier helpers.

Forensic integrity (spec 10 section 2) depends on these: originals are hashed
while streaming, alert and IOC identifiers are content-derived so re-running
detection produces the same ids.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any, BinaryIO

#: SHA-256 of the empty string; the seed of the audit hash chain.
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()

#: ``prev_hash`` of the first audit_log row (spec 10 section 2).
AUDIT_GENESIS = "0" * 64

#: Read size for streaming hashes; large enough to keep syscall overhead low.
_CHUNK = 1024 * 1024


def canonical_json(value: Any) -> str:
    """Serialise ``value`` deterministically for hashing and storage.

    Sorted keys, no insignificant whitespace and no ASCII escaping, so the
    same logical document always produces the same bytes.
    """
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_bytes(data: bytes) -> str:
    """SHA-256 of a byte string, lowercase hex."""
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    """SHA-256 of a string encoded as UTF-8."""
    return sha256_bytes(text.encode("utf-8"))


def sha256_json(value: Any) -> str:
    """SHA-256 of the canonical JSON encoding of ``value``."""
    return sha256_text(canonical_json(value))


def sha256_stream(stream: BinaryIO) -> Iterator[str]:
    """Yield the hex SHA-256 of a binary stream without buffering it whole."""
    digest = hashlib.sha256()
    while chunk := stream.read(_CHUNK):
        digest.update(chunk)
    yield digest.hexdigest()


def sha256_file(path: Path) -> str:
    """SHA-256 of a file on disk, read in bounded-size chunks."""
    with path.open("rb") as handle:
        digest = hashlib.sha256()
        while chunk := handle.read(_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def audit_chain_hash(prev_hash: str, ts: str, action: str, detail_json: str) -> str:
    """``sha256(prev_hash || ts || action || detail_json)`` (spec 10 section 2)."""
    digest = hashlib.sha256()
    digest.update(prev_hash.encode("utf-8"))
    digest.update(ts.encode("utf-8"))
    digest.update(action.encode("utf-8"))
    digest.update(detail_json.encode("utf-8"))
    return digest.hexdigest()


def content_id(*parts: str, length: int = 16) -> str:
    """Deterministic id from ``parts``.

    Used for alerts (``case|rule|group_key|window_start``, spec 04 section 6) and
    IOCs (``case|type|value_norm``, spec 02 section 4). The separator cannot
    appear in ids, values or ISO timestamps, so distinct tuples never collide.
    """
    digest = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
    return digest[:length]


def verify_sha256(path: Path, expected: str) -> bool:
    """True when ``path`` still hashes to ``expected``."""
    return sha256_file(path).lower() == expected.strip().lower()


def hash_mapping(entries: Mapping[str, str]) -> str:
    """SHA-256 over ``name=hash`` pairs sorted by name.

    This is the rule-set hash from spec 01 section 9: stable regardless of file
    system enumeration order.
    """
    digest = hashlib.sha256()
    for name in sorted(entries):
        digest.update(name.encode("utf-8"))
        digest.update(b"=")
        digest.update(entries[name].encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


__all__ = [
    "AUDIT_GENESIS",
    "EMPTY_SHA256",
    "audit_chain_hash",
    "canonical_json",
    "content_id",
    "hash_mapping",
    "sha256_bytes",
    "sha256_file",
    "sha256_json",
    "sha256_stream",
    "sha256_text",
    "verify_sha256",
]
