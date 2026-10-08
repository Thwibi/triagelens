"""Shared Windows event mapping used by both Windows parsers (spec 03 section 2).

``windows_evtx`` (the binary EVTX reader) and ``windows_event_xml`` (the XML
export reader) see the same logical structure and must produce the same event, so
the mapping lives here once. Each parser turns one record into an ``event_dict``:

* ``windows_event_xml`` parses an ``<Event>`` element with lxml and converts it
  with :func:`event_dict_from_element`.
* ``windows_evtx`` gets the same shape directly from the native ``evtx`` library
  (``records_json``) or, when that extension is unavailable, from the vendored
  python-evtx reader rendered through the same element converter.

The dict shape follows what pyevtx-rs emits: attributes under ``#attributes``,
character data under ``#text``, repeated elements as lists, and the whole record
under an ``Event`` key. Accessors below tolerate the ``@``-prefixed attribute
spelling some emitters use, and scalar values that arrive as numbers.

The normative mapping is the table in spec 03 section 2.1. "EVERYTHING else stays
in fields_json": a value the table does not name is still evidence and is kept
under its original field name.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Any

from app.ingest.events import NormalizedEvent
from app.ingest.normalize import (
    canonical_ip,
    clean_text,
    normalize_outcome,
    parse_timestamp,
    to_int,
    to_port,
    truncate,
)
from app.ingest.parsers.base import ParseContext

#: Windows ``System.Level`` to normalized level (spec 03 section 2.1). This is the
#: ``EVENTLOG`` severity, not the syslog PRI scale, so it is applied here rather
#: than through the generic :func:`app.ingest.normalize.normalize_level`.
_WINDOWS_LEVELS: dict[int, str] = {
    0: "info",
    1: "critical",
    2: "error",
    3: "warning",
    4: "info",
    5: "debug",
}

#: Attribute keys a dict may use for element attributes, most specific first.
_ATTRIBUTE_KEYS = ("#attributes", "@attributes")

#: Value keys a dict may use for character data.
_TEXT_KEYS = ("#text", "@text")


# ---------------------------------------------------------------------------
# Event-dict construction (lxml element -> pyevtx-rs-shaped dict)
# ---------------------------------------------------------------------------


def _local_name(tag: Any) -> str:
    """Local part of a possibly namespace-qualified XML name."""
    text = tag if isinstance(tag, str) else str(tag)
    return text.rsplit("}", 1)[-1]


def _attributes(node: Any) -> dict[str, Any]:
    """Attribute mapping of an event-dict node, whatever key spelling it uses."""
    if not isinstance(node, dict):
        return {}
    for key in _ATTRIBUTE_KEYS:
        value = node.get(key)
        if isinstance(value, dict):
            return value
    return {}


def _scalar_text(value: Any) -> Any:
    """Character data of a node: ``#text`` when a dict, the value otherwise."""
    if isinstance(value, dict):
        for key in _TEXT_KEYS:
            if key in value:
                return value[key]
        return None
    return value


def element_to_value(element: Any) -> Any:
    """Convert one lxml element into the canonical event-dict value shape.

    An element with no children is its (stripped) text, or a mapping carrying
    ``#attributes`` when it also has attributes. An element with children groups
    them by tag, turning repeats into lists, exactly as the native reader does.
    """
    attributes = {_local_name(key): value for key, value in element.attrib.items()}
    text = (element.text or "").strip()
    children = list(element)
    if not children:
        if attributes:
            value: dict[str, Any] = {"#attributes": attributes}
            if text:
                value["#text"] = text
            return value
        return text
    grouped: dict[str, Any] = {}
    for child in children:
        name = _local_name(child.tag)
        child_value = element_to_value(child)
        if name in grouped:
            existing = grouped[name]
            if isinstance(existing, list):
                existing.append(child_value)
            else:
                grouped[name] = [existing, child_value]
        else:
            grouped[name] = child_value
    if attributes or text:
        result: dict[str, Any] = {}
        if attributes:
            result["#attributes"] = attributes
        result.update(grouped)
        if text:
            result["#text"] = text
        return result
    return grouped


def event_dict_from_element(element: Any) -> dict[str, Any]:
    """Wrap a parsed ``<Event>`` element in the canonical ``{"Event": ...}`` dict."""
    return {"Event": element_to_value(element)}


# ---------------------------------------------------------------------------
# Field extraction helpers
# ---------------------------------------------------------------------------


def _get(fields: dict[str, Any], name: str) -> Any:
    """Field by exact name, falling back to a case-insensitive match."""
    if name in fields:
        return fields[name]
    lowered = name.lower()
    for key, value in fields.items():
        if key.lower() == lowered:
            return value
    return None


def _as_path_value(value: Any) -> Any:
    """A column value may be a list (repeated element); the first is the value."""
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _windows_ip(value: Any) -> str | None:
    """Canonicalize an address, unwrapping an IPv4-in-IPv6 ``::ffff:`` prefix."""
    text = clean_text(_as_path_value(value))
    if text is None:
        return None
    if text.lower().startswith("::ffff:"):
        text = text[7:]
    return canonical_ip(text)


def _hex_int(value: Any) -> int | None:
    """An integer that Windows sometimes writes as hex (``0x1a4``)."""
    text = clean_text(_as_path_value(value))
    if text is None:
        return None
    if text.lower().startswith("0x"):
        try:
            return int(text, 16)
        except ValueError:
            return None
    return to_int(text)


def _join_share(fields: dict[str, Any]) -> str | None:
    """``ShareName`` + ``RelativeTargetName`` for the file-share events."""
    share = clean_text(_as_path_value(_get(fields, "ShareName")))
    relative = clean_text(_as_path_value(_get(fields, "RelativeTargetName")))
    if share is None:
        return relative
    if relative is None:
        return share
    if relative.startswith(("\\", "/")):
        return f"{share}{relative}"
    return f"{share}\\{relative}"


def _windows_level(value: Any) -> str | None:
    """Map ``System.Level`` (0-5) onto the five normalized levels."""
    scalar = _as_path_value(_scalar_text(value))
    number = to_int(scalar)
    if number is None:
        return None
    return _WINDOWS_LEVELS.get(number)


#: A column's value comes from a function of the merged field map.
ColumnSource = Callable[[dict[str, Any]], Any]


def _field(name: str) -> ColumnSource:
    return lambda fields: _as_path_value(_get(fields, name))


def _ip(name: str) -> ColumnSource:
    return lambda fields: _windows_ip(_get(fields, name))


def _hexf(name: str) -> ColumnSource:
    return lambda fields: _hex_int(_get(fields, name))


def _port(name: str) -> ColumnSource:
    return lambda fields: _as_path_value(_get(fields, name))


def _first_ip_queryresult(fields: dict[str, Any]) -> str | None:
    """Destination IP of a Sysmon DNS event: first address in ``QueryResults``.

    ``QueryResults`` is ``";"``-separated ``name;type;data`` triples (possibly
    repeated). The first address that validates wins; a plain single-IP value
    works too.
    """
    raw = _as_path_value(_get(fields, "QueryResults"))
    text = clean_text(raw)
    if text is None:
        return None
    for part in text.split(";"):
        candidate = canonical_ip(part.strip())
        if candidate is not None:
            return candidate
    return None


# ---------------------------------------------------------------------------
# The event table (spec 03 section 2.1)
# ---------------------------------------------------------------------------


class Rule:
    """One row of the mapping table."""

    __slots__ = ("action", "category", "columns", "outcome")

    def __init__(
        self,
        category: str | None,
        action: str | None,
        outcome: str | None,
        columns: dict[str, ColumnSource] | None = None,
    ) -> None:
        self.category = category
        self.action = action
        self.outcome = outcome
        self.columns = columns or {}


def _rule(
    category: str | None,
    action: str | None,
    outcome: str | None = None,
    **columns: ColumnSource,
) -> Rule:
    return Rule(category, action, outcome, dict(columns))


#: Security channel events, keyed by EventID.
_SECURITY: dict[int, Rule] = {
    4624: _rule(
        "logon",
        "logon_success",
        "success",
        user_name=_field("TargetUserName"),
        domain=_field("TargetDomainName"),
        src_ip=_ip("IpAddress"),
        src_port=_port("IpPort"),
        process_path=_field("ProcessName"),
    ),
    4625: _rule(
        "logon",
        "logon_failure",
        "failure",
        user_name=_field("TargetUserName"),
        domain=_field("TargetDomainName"),
        src_ip=_ip("IpAddress"),
        src_port=_port("IpPort"),
        process_path=_field("ProcessName"),
    ),
    4634: _rule("logon", "logoff", None, user_name=_field("TargetUserName")),
    4647: _rule("logon", "logoff", None, user_name=_field("TargetUserName")),
    4648: _rule(
        "logon",
        "logon_explicit_credentials",
        None,
        user_name=_field("SubjectUserName"),
        target_user_name=_field("TargetUserName"),
        dst_ip=_ip("IpAddress"),
    ),
    4672: _rule("logon", "special_privileges_assigned", None, user_name=_field("SubjectUserName")),
    4688: _rule(
        "process_creation",
        "process_created",
        None,
        user_name=_field("SubjectUserName"),
        process_path=_field("NewProcessName"),
        process_cmdline=_field("CommandLine"),
        parent_process_path=_field("ParentProcessName"),
        process_pid=_hexf("NewProcessId"),
    ),
    4697: _rule(
        "service_install",
        "service_installed",
        None,
        file_path=_field("ServiceFileName"),
        process_path=_field("ServiceFileName"),
        process_cmdline=_field("ServiceFileName"),
    ),
    4698: _rule(
        "scheduled_task",
        "task_created",
        None,
        user_name=_field("SubjectUserName"),
        message=_field("TaskName"),
    ),
    4702: _rule(
        "scheduled_task",
        "task_updated",
        None,
        user_name=_field("SubjectUserName"),
        message=_field("TaskName"),
    ),
    4720: _rule(
        "account_management",
        "account_created",
        None,
        user_name=_field("SubjectUserName"),
        target_user_name=_field("TargetUserName"),
    ),
    4722: _rule(
        "account_management",
        "account_enabled",
        None,
        user_name=_field("SubjectUserName"),
        target_user_name=_field("TargetUserName"),
    ),
    4724: _rule(
        "account_management",
        "password_reset",
        None,
        user_name=_field("SubjectUserName"),
        target_user_name=_field("TargetUserName"),
    ),
    4726: _rule(
        "account_management",
        "account_deleted",
        None,
        user_name=_field("SubjectUserName"),
        target_user_name=_field("TargetUserName"),
    ),
    4728: _rule(
        "account_management",
        "group_member_added",
        None,
        user_name=_field("SubjectUserName"),
        target_user_name=_field("TargetUserName"),
    ),
    4732: _rule(
        "account_management",
        "group_member_added",
        None,
        user_name=_field("SubjectUserName"),
        target_user_name=_field("TargetUserName"),
    ),
    4738: _rule(
        "account_management",
        "account_changed",
        None,
        user_name=_field("SubjectUserName"),
        target_user_name=_field("TargetUserName"),
    ),
    4768: _rule(
        "kerberos",
        "kerberos_tgt",
        None,
        user_name=_field("TargetUserName"),
        src_ip=_ip("IpAddress"),
    ),
    4769: _rule(
        "kerberos",
        "kerberos_service_ticket",
        None,
        user_name=_field("TargetUserName"),
        src_ip=_ip("IpAddress"),
    ),
    4771: _rule(
        "kerberos",
        "kerberos_preauth_failed",
        None,
        user_name=_field("TargetUserName"),
        src_ip=_ip("IpAddress"),
    ),
    4776: _rule(
        "credential_validation",
        "ntlm_validation",
        None,
        user_name=_field("TargetUserName"),
    ),
    5140: _rule(
        "file_share",
        "share_access",
        None,
        user_name=_field("SubjectUserName"),
        src_ip=_ip("IpAddress"),
        file_path=_join_share,
    ),
    5145: _rule(
        "file_share",
        "share_access",
        None,
        user_name=_field("SubjectUserName"),
        src_ip=_ip("IpAddress"),
        file_path=_join_share,
    ),
    1102: _rule("log_cleared", "audit_log_cleared", None, user_name=_field("SubjectUserName")),
}

#: System channel events.
_SYSTEM: dict[int, Rule] = {
    7045: _rule(
        "service_install",
        "service_installed",
        None,
        file_path=_field("ImagePath"),
        process_path=_field("ImagePath"),
        process_cmdline=_field("ImagePath"),
    ),
    104: _rule("log_cleared", "audit_log_cleared", None, user_name=_field("SubjectUserName")),
}

#: Sysmon events (`Microsoft-Windows-Sysmon/Operational`), keyed by EventID.
_SYSMON: dict[int, Rule] = {
    1: _rule(
        "process_creation",
        "process_created",
        None,
        process_path=_field("Image"),
        process_cmdline=_field("CommandLine"),
        parent_process_path=_field("ParentImage"),
        parent_process_cmdline=_field("ParentCommandLine"),
        user_name=_field("User"),
        process_pid=_field("ProcessId"),
    ),
    3: _rule(
        "network_connection",
        "network_connect",
        None,
        src_ip=_ip("SourceIp"),
        src_port=_port("SourcePort"),
        dst_ip=_ip("DestinationIp"),
        dst_port=_port("DestinationPort"),
        protocol=_field("Protocol"),
        process_path=_field("Image"),
        user_name=_field("User"),
    ),
    5: _rule("process_termination", "process_terminated", None, process_path=_field("Image")),
    6: _rule("driver_load", "driver_loaded", None, file_path=_field("ImageLoaded")),
    7: _rule(
        "image_load",
        "image_loaded",
        None,
        process_path=_field("Image"),
        file_path=_field("ImageLoaded"),
    ),
    8: _rule(
        "create_remote_thread",
        "remote_thread",
        None,
        process_path=_field("SourceImage"),
        file_path=_field("TargetImage"),
    ),
    10: _rule(
        "process_access",
        "process_accessed",
        None,
        process_path=_field("SourceImage"),
        file_path=_field("TargetImage"),
    ),
    11: _rule(
        "file_event",
        "file_created",
        None,
        process_path=_field("Image"),
        file_path=_field("TargetFilename"),
    ),
    12: _rule(
        "registry_add",
        "registry_create",
        None,
        process_path=_field("Image"),
        registry_key=_field("TargetObject"),
        registry_value=_field("Details"),
    ),
    13: _rule(
        "registry_set",
        "registry_set",
        None,
        process_path=_field("Image"),
        registry_key=_field("TargetObject"),
        registry_value=_field("Details"),
    ),
    14: _rule(
        "registry_rename",
        "registry_rename",
        None,
        process_path=_field("Image"),
        registry_key=_field("TargetObject"),
        registry_value=_field("Details"),
    ),
    15: _rule(
        "create_stream_hash",
        "file_stream_created",
        None,
        file_path=_field("TargetFilename"),
    ),
    17: _rule(
        "pipe_created",
        "pipe_created",
        None,
        process_path=_field("Image"),
        file_path=_field("PipeName"),
    ),
    18: _rule(
        "pipe_created",
        "pipe_connected",
        None,
        process_path=_field("Image"),
        file_path=_field("PipeName"),
    ),
    19: _rule("wmi_event", "wmi_filter", None, user_name=_field("User")),
    20: _rule("wmi_event", "wmi_consumer", None, user_name=_field("User")),
    21: _rule("wmi_event", "wmi_subscription", None, user_name=_field("User")),
    22: _rule(
        "dns_query",
        "dns_query",
        None,
        process_path=_field("Image"),
        message=_field("QueryName"),
        dst_ip=_first_ip_queryresult,
    ),
    23: _rule(
        "file_delete",
        "file_deleted",
        None,
        process_path=_field("Image"),
        file_path=_field("TargetFilename"),
    ),
    26: _rule(
        "file_delete",
        "file_deleted",
        None,
        process_path=_field("Image"),
        file_path=_field("TargetFilename"),
    ),
}

#: PowerShell operational channel (`PowerShell/Operational`).
_POWERSHELL_OP: dict[int, Rule] = {
    4104: _rule(
        "ps_script",
        "ps_script_block",
        None,
        message=lambda fields: truncate(
            str(_as_path_value(_get(fields, "ScriptBlockText")) or ""), 64 * 1024
        )[0],
        file_path=_field("Path"),
    ),
    4103: _rule("ps_module", "ps_module_log", None, message=_field("Payload")),
}

#: Classic Windows PowerShell channel.
_POWERSHELL_CLASSIC: dict[int, Rule] = {
    400: _rule("ps_classic_start", "ps_engine_state", None, message=_field("HostApplication")),
    600: _rule("ps_classic_start", "ps_engine_state", None, message=_field("HostApplication")),
}

#: Task Scheduler operational channel.
_TASK_SCHEDULER: dict[int, Rule] = {
    106: _rule("scheduled_task", None, None, message=_field("TaskName")),
    140: _rule("scheduled_task", None, None, message=_field("TaskName")),
    141: _rule("scheduled_task", None, None, message=_field("TaskName")),
}

#: WMI-Activity operational channel.
_WMI: dict[int, Rule] = {
    5861: _rule("wmi_event", "wmi_permanent_subscription", None),
}

#: Windows Defender operational channel.
_DEFENDER: dict[int, Rule] = {
    1116: _rule(
        "av_detection",
        "av_detected",
        None,
        file_path=_field("Path"),
        message=_field("Threat Name"),
    ),
    1117: _rule(
        "av_detection",
        "av_action",
        None,
        file_path=_field("Path"),
        message=_field("Threat Name"),
    ),
}

#: Terminal Services local session manager.
_TSM: dict[int, Rule] = {
    21: _rule("rdp_session", None, None, user_name=_field("User"), src_ip=_ip("Address")),
    24: _rule("rdp_session", None, None, user_name=_field("User"), src_ip=_ip("Address")),
    25: _rule("rdp_session", None, None, user_name=_field("User"), src_ip=_ip("Address")),
}


def _classify(  # noqa: PLR0911
    channel: str | None, provider: str | None, event_id: int | None
) -> Rule | None:
    """The table row for an event, or ``None`` for "anything else"."""
    chan = (channel or "").lower()
    prov = (provider or "").lower()
    if event_id is None:
        return None
    if "sysmon" in chan or "sysmon" in prov:
        return _SYSMON.get(event_id)
    if "powershell" in chan and "operational" in chan:
        return _POWERSHELL_OP.get(event_id)
    if "windows powershell" in chan:
        return _POWERSHELL_CLASSIC.get(event_id)
    if "taskscheduler" in chan:
        return _TASK_SCHEDULER.get(event_id)
    if "wmi-activity" in chan:
        return _WMI.get(event_id)
    if "windows defender" in chan:
        return _DEFENDER.get(event_id)
    if "terminalservices-localsessionmanager" in chan:
        return _TSM.get(event_id)
    if chan == "security" or "security-auditing" in prov:
        return _SECURITY.get(event_id)
    if chan == "system":
        return _SYSTEM.get(event_id)
    return None


# ---------------------------------------------------------------------------
# Field map assembly
# ---------------------------------------------------------------------------


def _iter_flattened(node: Any, prefix: str) -> Iterator[tuple[str, Any]]:
    """Yield ``(dotted_key, scalar)`` for a node, skipping ``#attributes`` levels.

    ``System.Execution`` becomes ``System.Execution.ProcessID`` and
    ``System.Execution.ThreadID``; ``System.Provider`` becomes
    ``System.Provider.Name`` and ``System.Provider.Guid``.
    """
    if isinstance(node, dict):
        for key, value in node.items():
            if key in _ATTRIBUTE_KEYS:
                if isinstance(value, dict):
                    for attribute, attribute_value in value.items():
                        yield f"{prefix}.{_local_name(attribute)}", attribute_value
            elif key in _TEXT_KEYS:
                yield prefix, value
            elif isinstance(key, str) and key.startswith("@"):
                yield f"{prefix}.{_local_name(key[1:])}", value
            else:
                yield from _iter_flattened(value, f"{prefix}.{_local_name(key)}")
    elif isinstance(node, list):
        if node:
            yield from _iter_flattened(node[0], prefix)
    else:
        yield prefix, node


def _collect_event_data(  # noqa: PLR0912
    event: dict[str, Any], fields: dict[str, Any]
) -> None:
    """Merge ``EventData`` and ``UserData`` into the field map (spec 03 section 2.1)."""
    data = event.get("EventData")
    if isinstance(data, dict):
        data_items = data.get("Data")
        if data_items is not None:
            items = data_items if isinstance(data_items, list) else [data_items]
            unnamed = 0
            for item in items:
                if isinstance(item, dict):
                    name = _attributes(item).get("Name")
                    value = _scalar_text(item)
                    if name:
                        fields.setdefault(_local_name(str(name)), value)
                    else:
                        fields.setdefault(f"Data_{unnamed}", value)
                        unnamed += 1
                else:
                    fields.setdefault(f"Data_{unnamed}", item)
                    unnamed += 1
        for key, value in data.items():
            if key != "Data" and key not in _ATTRIBUTE_KEYS:
                fields.setdefault(_local_name(key), _scalar_text(value))
    user_data = event.get("UserData")
    if isinstance(user_data, dict):
        for top_key, sub in user_data.items():
            if top_key in _ATTRIBUTE_KEYS:
                continue
            if isinstance(sub, dict):
                for key, value in sub.items():
                    if key in _ATTRIBUTE_KEYS:
                        if isinstance(value, dict):
                            for attribute, attribute_value in value.items():
                                fields.setdefault(_local_name(attribute), attribute_value)
                    elif key in _TEXT_KEYS:
                        fields.setdefault(_local_name(top_key), value)
                    else:
                        fields.setdefault(_local_name(key), _scalar_text(value))
            else:
                fields.setdefault(_local_name(top_key), sub)


def _split_sysmon_hashes(fields: dict[str, Any]) -> None:
    """Split Sysmon ``Hashes`` into ``Hash_<ALGO>`` keys (spec 03 section 2.1).

    ``Hashes`` stays verbatim; the split copies exist because the IOC engine
    reads ``Hash_SHA256``/``Hash_MD5``/``Hash_IMPHASH`` directly.
    """
    raw = clean_text(_as_path_value(_get(fields, "Hashes")))
    if raw is None:
        return
    for token in raw.split(","):
        name, _, value = token.partition("=")
        algorithm = name.strip().upper()
        digest = value.strip()
        if algorithm and digest:
            fields.setdefault(f"Hash_{algorithm}", digest)


def _synthesize_message(
    channel: str | None,
    event_id: int | None,
    action: str | None,
    values: dict[str, Any],
) -> str:
    """Build the fallback message when the row defines no natural text.

    Shape: ``"<Channel> <EventID>: <action> <key fields>"`` (spec 03 section 2.1).
    """
    head = " ".join(part for part in (channel or "", str(event_id or "")) if part)
    details = " ".join(
        f"{label}={values[key]}"
        for label, key in (
            ("user", "user_name"),
            ("src", "src_ip"),
            ("dst", "dst_ip"),
            ("process", "process_path"),
            ("file", "file_path"),
        )
        if values.get(key)
    )
    parts = [head]
    if action:
        parts.append(action)
    if details:
        parts.append(details)
    return ": ".join(part for part in parts if part).strip()


# ---------------------------------------------------------------------------
# The shared mapping function
# ---------------------------------------------------------------------------


def map_event_dict(
    event_dict: dict[str, Any],
    *,
    context: ParseContext,
    log_type: str,
    raw: str,
    record_ref: str,
) -> NormalizedEvent:
    """Turn one canonical Windows event dict into a :class:`NormalizedEvent`.

    This is the single mapping function both Windows parsers share (spec 03
    section 2.2). ``record_ref`` is the caller's identifier for the record; the
    EVTX ``EventRecordID`` overrides it when present.
    """
    event = event_dict.get("Event") if "Event" in event_dict else event_dict
    if not isinstance(event, dict):
        event = {}
    system = event.get("System")
    if not isinstance(system, dict):
        system = {}

    fields: dict[str, Any] = {}
    _collect_event_data(event, fields)
    system_fields = dict(_iter_flattened(system, "System"))
    for key, value in system_fields.items():
        fields.setdefault(key, value)
    _split_sysmon_hashes(fields)

    channel = clean_text(_scalar_text(system.get("Channel")))
    provider_node = system.get("Provider")
    provider = clean_text(_attributes(provider_node).get("Name")) if provider_node else None
    host = clean_text(_scalar_text(system.get("Computer")))
    event_id = to_int(_scalar_text(system.get("EventID")))
    level = _windows_level(system.get("Level"))
    timestamp_source = _attributes(system.get("TimeCreated")).get("SystemTime")
    timestamp = parse_timestamp(timestamp_source, fmt="iso8601")
    event_record_id = clean_text(_scalar_text(system.get("EventRecordID")))
    resolved_ref = event_record_id or record_ref

    rule = _classify(channel, provider, event_id)
    values: dict[str, Any] = {}
    if rule is not None:
        for column, source in rule.columns.items():
            values[column] = source(fields)

    category = rule.category if rule is not None else None
    if rule is not None:
        action = rule.action
    elif event_id is not None:
        action = f"event_{event_id}"
    else:
        action = None
    outcome = normalize_outcome(rule.outcome) if rule is not None else None

    message = clean_text(values.get("message"))
    if message is None:
        message = clean_text(_synthesize_message(channel, event_id, action, values))
        values.pop("message", None)

    clipped_raw, _ = truncate(raw, context.max_line_bytes)

    return NormalizedEvent(
        case_id=context.case_id,
        source_id=context.source_id,
        record_ref=resolved_ref,
        log_type=log_type,
        raw=clipped_raw,
        ts_ms=timestamp[0] if timestamp else None,
        ls_category=category,
        host=host,
        channel=channel,
        provider=provider,
        event_id=event_id,
        level=level,
        event_action=action,
        event_outcome=outcome,
        user_name=clean_text(values.get("user_name")),
        target_user_name=clean_text(values.get("target_user_name")),
        domain=clean_text(values.get("domain")),
        src_ip=canonical_ip(values.get("src_ip")) if values.get("src_ip") else None,
        src_port=to_port(values.get("src_port")),
        dst_ip=canonical_ip(values.get("dst_ip")) if values.get("dst_ip") else None,
        dst_port=to_port(values.get("dst_port")),
        protocol=clean_text(values.get("protocol")),
        process_pid=to_int(values.get("process_pid")),
        process_path=clean_text(values.get("process_path")),
        process_cmdline=clean_text(values.get("process_cmdline")),
        parent_process_path=clean_text(values.get("parent_process_path")),
        parent_process_cmdline=clean_text(values.get("parent_process_cmdline")),
        file_path=clean_text(values.get("file_path")),
        registry_key=clean_text(values.get("registry_key")),
        registry_value=clean_text(values.get("registry_value")),
        url=clean_text(values.get("url")),
        http_method=clean_text(values.get("http_method")),
        http_status=to_int(values.get("http_status")),
        user_agent=clean_text(values.get("user_agent")),
        bytes_out=to_int(values.get("bytes_out")),
        message=message,
        fields_json=fields,
    )


__all__ = [
    "Rule",
    "element_to_value",
    "event_dict_from_element",
    "map_event_dict",
]
