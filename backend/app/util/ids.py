"""Opaque, non-guessable identifiers for app-created rows.

Alert and IOC ids are content-derived (spec 00 section 8 rule 5) via
:func:`app.util.hashing.content_id`. Everything else - cases, sources, jobs,
reports - gets a random id here, because these rows are created by explicit user
action rather than derived from content.
"""

from __future__ import annotations

import secrets

#: Default id length in hex characters, matching alert and IOC ids.
DEFAULT_ID_LENGTH = 16

#: Shortest id we mint. Below 8 hex characters an id would be enumerable.
MIN_ID_LENGTH = 8


def new_id(length: int = DEFAULT_ID_LENGTH) -> str:
    """A cryptographically random hex id of ``length`` characters."""
    if length < MIN_ID_LENGTH or length % 2:
        raise ValueError(f"length must be an even number of at least {MIN_ID_LENGTH}")
    return secrets.token_hex(length // 2)


def is_id(value: str) -> bool:
    """True when ``value`` looks like an id this application minted."""
    return len(value) in {16, 32} and all(char in "0123456789abcdef" for char in value)


__all__ = ["DEFAULT_ID_LENGTH", "MIN_ID_LENGTH", "is_id", "new_id"]
