"""IOC vocabulary: types, roles, and the shapes the extractor emits (spec 05).

An IOC is stored once per case as a ``(case_id, type, value_norm)`` row; the
places it was seen are ``ioc_occurrences``. That split is why extraction produces
two things:

``IocCandidate``
    The identity of an indicator plus everything that scopes its confidence:
    the base score, whether it is private, allowlisted, or only accepted because
    of the ambiguous-TLD rule.
``IocHit``
    A candidate plus one occurrence: which event field and role it was found in,
    and whether it came from decoded content.

The extractor returns hits; the aggregator collapses them into one candidate list
and a bounded occurrence list per batch (spec 05 section 7).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from app.util.hashing import content_id


class IocType(StrEnum):
    """The fourteen indicator types (spec 05 section 1)."""

    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    FILENAME = "filename"
    FILEPATH = "filepath"
    REGISTRY = "registry"
    CVE = "cve"
    USER_AGENT = "user_agent"
    COMMAND = "command"


#: Tier 1 runs on every event during parse (spec 05 section 1).
TIER1_TYPES: frozenset[IocType] = frozenset(
    {
        IocType.IPV4,
        IocType.IPV6,
        IocType.DOMAIN,
        IocType.URL,
        IocType.EMAIL,
        IocType.MD5,
        IocType.SHA1,
        IocType.SHA256,
        IocType.CVE,
    }
)

#: Tier 2 runs only on events attached to alerts, after detection.
TIER2_TYPES: frozenset[IocType] = frozenset(
    {
        IocType.FILENAME,
        IocType.FILEPATH,
        IocType.REGISTRY,
        IocType.USER_AGENT,
        IocType.COMMAND,
    }
)

#: Network indicator types, which are classified private/public.
NETWORK_TYPES: frozenset[IocType] = frozenset({IocType.IPV4, IocType.IPV6})

#: Hash types, which share the boundary and distinctness validation.
HASH_TYPES: frozenset[IocType] = frozenset({IocType.MD5, IocType.SHA1, IocType.SHA256})


class Role(StrEnum):
    """Where an occurrence sits in an event (spec 02, ``ioc_occurrences.role``)."""

    SOURCE = "source"
    DESTINATION = "destination"
    PROCESS = "process"
    URL_REQUEST = "url_request"
    DNS_QUERY = "dns_query"
    IMAGE_HASH = "image_hash"
    MENTIONED = "mentioned"


#: Decoded-content provenance recorded on an occurrence (spec 05 section 2).
DECODED_POWERSHELL = "powershell_enc"
DECODED_BASE64 = "base64"
DECODED_URL = "url"

#: Base confidence by provenance (spec 05 section 6).
BASE_STRUCTURED = 80
BASE_DECODED = 60
BASE_FREETEXT = 50


@dataclass(frozen=True, slots=True)
class IocCandidate:
    """The identity of one indicator, with its confidence inputs.

    ``value`` is the refanged form as first seen; ``value_norm`` is the canonical
    dedup key. Two hits with equal ``type`` and ``value_norm`` are the same IOC.
    """

    type: IocType
    value: str
    value_norm: str
    base: int
    is_private: bool = False
    is_allowlisted: bool = False
    ambiguous_tld: bool = False

    def key(self) -> tuple[IocType, str]:
        """The dedup key within a case."""
        return (self.type, self.value_norm)

    def ioc_id(self, case_id: str) -> str:
        """The deterministic row id: ``sha256(case|type|value_norm)[:16]``."""
        return content_id(case_id, str(self.type), self.value_norm)


@dataclass(frozen=True, slots=True)
class IocHit:
    """One occurrence of an indicator in one event field."""

    candidate: IocCandidate
    field: str
    role: Role
    decoded_from: str | None = None


__all__ = [
    "BASE_DECODED",
    "BASE_FREETEXT",
    "BASE_STRUCTURED",
    "DECODED_BASE64",
    "DECODED_POWERSHELL",
    "DECODED_URL",
    "HASH_TYPES",
    "NETWORK_TYPES",
    "TIER1_TYPES",
    "TIER2_TYPES",
    "IocCandidate",
    "IocHit",
    "IocType",
    "Role",
]
