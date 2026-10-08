"""Field resolution pipeline (spec 04 section 4).

A Sigma rule names fields in its own vocabulary - ``CommandLine`` for Windows,
``cs-uri-stem`` for web, or an original EventData key like ``TargetUserName``
that never appears as a column. Resolving a field to SQL follows the spec's
first-hit-wins order:

1. logsource-specific map (case-insensitive), scoped by the rule's route;
2. exact normalized column name (what built-in and custom rules use);
3. ``json_extract(fields_json, '$."<F>"')`` for everything else - the mechanism
   that makes original EventData names match without a per-field mapping.

Numeric columns have text-matching support (``|contains`` and friends cast the
column to text), and the special firewall ``action`` field maps onto the
derived ``event_action`` values the parsers already write.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.ingest.events import EVENT_COLUMNS

#: Columns the resolver treats as addressable even though the events insert adds
#: them outside ``EVENT_COLUMNS``.
_EXTRA_COLUMNS = frozenset({"raw", "fields_json"})

#: Columns usable as a target once the resolver reaches step 2.
NORMALIZED_COLUMNS: frozenset[str] = frozenset(EVENT_COLUMNS) | _EXTRA_COLUMNS

#: Columns whose stored values are numeric; ``|contains``/``|startswith``/
#: ``|endswith`` on these compile to a CAST to text (spec 04 section 4).
NUMERIC_COLUMNS: frozenset[str] = frozenset(
    {
        "event_id",
        "src_port",
        "dst_port",
        "process_pid",
        "http_status",
        "bytes_out",
    }
)

#: Windows / Sysmon / Security Sigma field names -> normalized columns.
WINDOWS_FIELD_MAP: dict[str, str] = {
    "image": "process_path",
    "commandline": "process_cmdline",
    "parentimage": "parent_process_path",
    "parentcommandline": "parent_process_cmdline",
    "processid": "process_pid",
    "user": "user_name",
    "eventid": "event_id",
    "computer": "host",
    "channel": "channel",
    "provider_name": "provider",
    "targetfilename": "file_path",
    "targetobject": "registry_key",
    "details": "registry_value",
    "destinationip": "dst_ip",
    "destinationport": "dst_port",
    "sourceip": "src_ip",
    "sourceport": "src_port",
    "newprocessname": "process_path",
    "imageloaded": "file_path",
    "scriptblocktext": "message",
}

#: Web (Sigma ``webserver`` category) field names -> normalized columns.
WEB_FIELD_MAP: dict[str, str] = {
    "c-ip": "src_ip",
    "cs-method": "http_method",
    "cs-uri-stem": "url_path",
    "cs-uri-query": "url_query",
    "cs-uri": "url",
    "cs-user-agent": "user_agent",
    "sc-status": "http_status",
    "cs-username": "user_name",
    "cs-host": "json_extract(fields_json, '$.\"host_header\"')",
}

#: Firewall (Sigma ``firewall`` category) field names -> event columns.
FIREWALL_FIELD_MAP: dict[str, str] = {
    "action": "event_action",
    "username": "user_name",
}

#: Values Sigma firewall rules put in ``action`` -> the derived ``event_action``
#: values our parsers write (spec 04 section 4). Anything else compares against
#: ``event_action`` verbatim, so an unmapped value simply never matches.
FIREWALL_ACTION_MAP: dict[str, str] = {
    "deny": "firewall_deny",
    "denied": "firewall_deny",
    "drop": "firewall_deny",
    "dropped": "firewall_deny",
    "block": "firewall_deny",
    "blocked": "firewall_deny",
    "discard": "firewall_deny",
    "reject": "firewall_deny",
    "rejected": "firewall_deny",
    "allow": "firewall_allow",
    "allowed": "firewall_allow",
    "accept": "firewall_allow",
    "accepted": "firewall_allow",
    "permit": "firewall_allow",
    "permitted": "firewall_allow",
}


@dataclass(frozen=True, slots=True)
class FieldContext:
    """What the resolver knows about a rule's surroundings.

    Category-dependent maps (``ImageLoaded`` only for ``image_load``) and the
    product-scoped maps need the rule's route; the same field name can mean
    different columns in different feeds.
    """

    category: str | None = None
    channel: str | None = None
    log_type: str | None = None
    product: str | None = None
    service: str | None = None

    @classmethod
    def from_logsource(cls, logsource: Any) -> FieldContext:
        """Build the context from a pySigma ``SigmaLogSource`` (or None)."""
        if logsource is None:
            return cls()
        return cls(
            category=_string_or_none(getattr(logsource, "category", None)),
            product=_string_or_none(getattr(logsource, "product", None)),
            service=_string_or_none(getattr(logsource, "service", None)),
        )


def _string_or_none(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def _json_path(field: str) -> str:
    """``json_extract(fields_json, '$."F"')`` with the key safely escaped."""
    escaped = field.replace("\\", "\\\\").replace('"', '\\"')
    return f"json_extract(fields_json, '$.\"{escaped}\"')"


class FieldResolver:
    """Resolve a Sigma field name to a SQL expression or a column name."""

    __slots__ = ("_context", "_field_map")

    def __init__(self, context: FieldContext) -> None:
        self._context = context
        self._field_map = _select_field_map(context)

    @property
    def context(self) -> FieldContext:
        return self._context

    @property
    def uses_firewall_action(self) -> bool:
        """True when ``action`` fields carry firewall semantics here."""
        return self._field_map is FIREWALL_FIELD_MAP

    def resolve(self, field: str) -> str:
        """A SQL expression for ``field`` following the step 1-2-3 order."""
        original = field.strip()
        key = original.lower()
        if self._field_map and key in self._field_map:
            return self._field_map[key]
        if key in NORMALIZED_COLUMNS:
            return key
        # ``fields_json`` keeps original key casing (``TargetUserName``), and
        # ``json_extract`` object lookups are case-sensitive, so the rule's own
        # spelling goes into the path unchanged.
        return _json_path(original)

    def is_numeric_field(self, field: str) -> bool:
        """True when ``field`` resolves to a numeric column, not JSON."""
        return self.resolve(field) in NUMERIC_COLUMNS

    def presence_expression(self, resolved: str) -> str:
        """A NULL test for ``resolved`` used for ``field_never_present`` checks."""
        return f"{resolved} IS NOT NULL"


def _select_field_map(context: FieldContext) -> dict[str, str] | None:
    """The logsource-scoped map active for ``context``, or None."""
    category = (context.category or "").lower()
    product = (context.product or "").lower()
    service = (context.service or "").lower()

    if category == "webserver" or product in {"apache", "nginx", "iis"}:
        return WEB_FIELD_MAP
    if category == "firewall" or product in {
        "pfsense",
        "fortinet",
        "paloalto",
        "iptables",
        "firepower",
        "sonicwall",
    }:
        return FIREWALL_FIELD_MAP
    if product == "windows" or service.startswith("windows/"):
        return WINDOWS_FIELD_MAP
    return None


__all__ = [
    "FIREWALL_ACTION_MAP",
    "FIREWALL_FIELD_MAP",
    "NORMALIZED_COLUMNS",
    "NUMERIC_COLUMNS",
    "WEB_FIELD_MAP",
    "WINDOWS_FIELD_MAP",
    "FieldContext",
    "FieldResolver",
]
