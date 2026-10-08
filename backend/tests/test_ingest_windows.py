"""Windows parsers: EVTX and Event XML (spec 03 section 2, spec 09 P-06/P-07/S-08).

Two things are tested here that the code cannot assert for itself: that the
shared mapping table produces the columns spec 03 section 2.1 names for every
row, and that each parser reproduces its golden fixture. The special cases spec
09 calls out - a dict-shaped ``EventID``, unnamed ``Data``, ``UserData``, a split
Sysmon ``Hashes`` field, an XXE payload and a corrupt EVTX chunk - each get their
own test, because each is a place a naive reader loses evidence silently.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from app.ingest.detect import detect
from app.ingest.parsers.base import ParseContext, load_builtin_parsers
from app.ingest.parsers.windows_common import map_event_dict
from app.ingest.parsers.windows_event_xml import WindowsEventXmlParser
from app.ingest.parsers.windows_evtx import (
    WindowsEvtxParser,
    native_backend_available,
)
from app.ingest.text import TextHead

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "evtx"
EVENT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"

SEC = "Security"
AUDIT = "Microsoft-Windows-Security-Auditing"
SYSMON_CH = "Microsoft-Windows-Sysmon/Operational"
SYSMON_PROV = "Microsoft-Windows-Sysmon"
PS_CH = "Microsoft-Windows-PowerShell/Operational"
PS_PROV = "Microsoft-Windows-PowerShell"


def event_xml(
    *,
    event_id: int,
    channel: str,
    provider: str,
    data: dict[str, str] | None = None,
    level: int = 0,
    record_id: int = 1,
    system_time: str = "2026-03-01T12:00:00.000000Z",
    user_data: str = "",
) -> str:
    """One ``<Event>`` element as XML text, for a single-record fixture."""
    data_xml = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in (data or {}).items())
    return (
        "<Event><System>"
        f'<Provider Name="{provider}"/>'
        f"<EventID>{event_id}</EventID>"
        f"<Level>{level}</Level>"
        f'<TimeCreated SystemTime="{system_time}"/>'
        f"<EventRecordID>{record_id}</EventRecordID>"
        f"<Channel>{channel}</Channel>"
        "<Computer>DC01</Computer>"
        "</System>"
        f"<EventData>{data_xml}</EventData>"
        f"{user_data}"
        "</Event>"
    )


def write_document(tmp_path: Path, body: str, name: str = "events.xml") -> Path:
    """A document wrapping ``body`` in the ``<Events>`` root."""
    path = tmp_path / name
    path.write_text(
        f'<?xml version="1.0"?><Events xmlns="{EVENT_NS}">{body}</Events>',
        encoding="utf-8",
    )
    return path


def context_for(path: Path) -> ParseContext:
    """A parse context over one fixture path."""
    return ParseContext(
        case_id="case-1",
        source_id="source-1",
        filename=path.name,
        path=path,
        max_line_bytes=1 << 20,
    )


def parse_document(path: Path) -> tuple[list[Any], list[Any]]:
    """Events and failures from the XML parser for one file."""
    events: list[Any] = []
    failures: list[Any] = []
    for item in WindowsEventXmlParser().parse(context_for(path)):
        (failures if hasattr(item, "reason") else events).append(item)
    return events, failures


def parse_evtx(path: Path, backend: str = "vendored") -> tuple[list[Any], list[Any]]:
    """Events and failures from the EVTX parser for one file."""
    events: list[Any] = []
    failures: list[Any] = []
    for item in WindowsEvtxParser(backend=backend).parse(context_for(path)):
        (failures if hasattr(item, "reason") else events).append(item)
    return events, failures


class TestRegistryAndSniff:
    """Registration and content scoring (spec 03 section 1)."""

    def test_both_parsers_register(self) -> None:
        log_types = {parser.log_type for parser in load_builtin_parsers().all()}
        assert {"windows_evtx", "windows_event_xml"} <= log_types

    def test_evtx_sniff_recognizes_magic(self) -> None:
        assert WindowsEvtxParser().sniff(TextHead(head=b"ElfFile\x00....")) == 1.0
        assert WindowsEvtxParser().sniff(TextHead(head=b"not evtx")) == 0.0

    def test_xml_sniff_recognizes_the_namespace(self) -> None:
        head = TextHead(head=f'<Events xmlns="{EVENT_NS}"><Event/></Events>'.encode())
        assert WindowsEventXmlParser().sniff(head) >= 0.9

    def test_xml_sniff_rejects_unrelated_xml(self) -> None:
        head = TextHead(head=b'<?xml version="1.0"?><config/>')
        assert WindowsEventXmlParser().sniff(head) == 0.0


class TestMappingTable:
    """Every row of the spec 03 section 2.1 table maps to the expected columns."""

    @pytest.mark.parametrize(
        ("event_id", "channel", "provider", "expected"),
        [
            (4624, SEC, AUDIT, ("logon", "logon_success", "success")),
            (4625, SEC, AUDIT, ("logon", "logon_failure", "failure")),
            (4634, SEC, AUDIT, ("logon", "logoff", None)),
            (4648, SEC, AUDIT, ("logon", "logon_explicit_credentials", None)),
            (4672, SEC, AUDIT, ("logon", "special_privileges_assigned", None)),
            (4688, SEC, AUDIT, ("process_creation", "process_created", None)),
            (4697, SEC, AUDIT, ("service_install", "service_installed", None)),
            (4698, SEC, AUDIT, ("scheduled_task", "task_created", None)),
            (4720, SEC, AUDIT, ("account_management", "account_created", None)),
            (4728, SEC, AUDIT, ("account_management", "group_member_added", None)),
            (4732, SEC, AUDIT, ("account_management", "group_member_added", None)),
            (4768, SEC, AUDIT, ("kerberos", "kerberos_tgt", None)),
            (4771, SEC, AUDIT, ("kerberos", "kerberos_preauth_failed", None)),
            (4776, SEC, AUDIT, ("credential_validation", "ntlm_validation", None)),
            (5140, SEC, AUDIT, ("file_share", "share_access", None)),
            (1102, SEC, AUDIT, ("log_cleared", "audit_log_cleared", None)),
            (1, SYSMON_CH, SYSMON_PROV, ("process_creation", "process_created", None)),
            (3, SYSMON_CH, SYSMON_PROV, ("network_connection", "network_connect", None)),
            (11, SYSMON_CH, SYSMON_PROV, ("file_event", "file_created", None)),
            (13, SYSMON_CH, SYSMON_PROV, ("registry_set", "registry_set", None)),
            (22, SYSMON_CH, SYSMON_PROV, ("dns_query", "dns_query", None)),
            (4104, PS_CH, PS_PROV, ("ps_script", "ps_script_block", None)),
        ],
    )
    def test_row(
        self,
        tmp_path: Path,
        event_id: int,
        channel: str,
        provider: str,
        expected: tuple[str, str, str | None],
    ) -> None:
        body = event_xml(event_id=event_id, channel=channel, provider=provider)
        events, failures = parse_document(write_document(tmp_path, body))
        assert not failures
        assert len(events) == 1
        event = events[0]
        assert (event.ls_category, event.event_action, event.event_outcome) == expected
        assert event.log_type == "windows_event_xml"


class TestSpecialCases:
    """The cases spec 09 P-07 names, which a naive mapping gets wrong."""

    def test_mapping_accepts_a_native_event_dict(self, tmp_path: Path) -> None:
        # The native EVTX reader hands the mapping function a dict; the shape
        # must map identically to the element path.
        event_dict = {
            "Event": {
                "System": {
                    "Provider": {"#attributes": {"Name": AUDIT}},
                    "EventID": {"#text": "4624", "#attributes": {"Qualifiers": ""}},
                    "Level": "0",
                    "TimeCreated": {"#attributes": {"SystemTime": "2026-03-01T12:00:00Z"}},
                    "EventRecordID": "42",
                    "Channel": SEC,
                    "Computer": "web01",
                },
                "EventData": {
                    "Data": [
                        {"#attributes": {"Name": "TargetUserName"}, "#text": "alice"},
                        {"#attributes": {"Name": "IpAddress"}, "#text": "::ffff:198.51.100.77"},
                    ]
                },
            }
        }
        event = map_event_dict(
            event_dict,
            context=context_for(tmp_path / "unused.xml"),
            log_type="windows_evtx",
            raw="{}",
            record_ref="x",
        )
        assert event.event_id == 4624
        assert event.record_ref == "42"
        assert event.user_name == "alice"
        assert event.src_ip == "198.51.100.77"
        assert event.channel == SEC

    def test_unnamed_data_becomes_data_n(self, tmp_path: Path) -> None:
        event_dict = {
            "Event": {
                "System": {"EventID": 1, "Channel": "X"},
                "EventData": {"Data": ["first", "second"]},
            }
        }
        event = map_event_dict(
            event_dict,
            context=context_for(tmp_path / "u.xml"),
            log_type="windows_evtx",
            raw="{}",
            record_ref="r",
        )
        assert event.fields_json["Data_0"] == "first"
        assert event.fields_json["Data_1"] == "second"

    def test_user_data_is_flattened(self, tmp_path: Path) -> None:
        body = (
            "<Event><System>"
            f'<Provider Name="{AUDIT}"/>'
            "<EventID>1102</EventID><Level>0</Level>"
            '<TimeCreated SystemTime="2026-03-01T12:00:00Z"/>'
            f"<Channel>{SEC}</Channel><Computer>DC01</Computer></System>"
            '<UserData><LogFileCleared xmlns="http://schemas.microsoft.com/win/2004/08/events">'
            "<SubjectUserName>admin</SubjectUserName>"
            "<SubjectDomainName>DC01</SubjectDomainName></LogFileCleared></UserData></Event>"
        )
        events, failures = parse_document(write_document(tmp_path, body))
        assert not failures
        event = events[0]
        assert event.ls_category == "log_cleared"
        assert event.user_name == "admin"
        assert event.fields_json["SubjectDomainName"] == "DC01"

    def test_sysmon_hashes_are_split(self, tmp_path: Path) -> None:
        body = event_xml(
            event_id=1,
            channel=SYSMON_CH,
            provider=SYSMON_PROV,
            data={"Image": "C:\\x.exe", "Hashes": "MD5=AAAA, SHA256=BBBB, IMPHASH=CCCC"},
        )
        event = parse_document(write_document(tmp_path, body))[0][0]
        assert event.fields_json["Hash_MD5"] == "AAAA"
        assert event.fields_json["Hash_SHA256"] == "BBBB"
        assert event.fields_json["Hash_IMPHASH"] == "CCCC"
        # The original field is preserved verbatim as well.
        assert event.fields_json["Hashes"] == "MD5=AAAA, SHA256=BBBB, IMPHASH=CCCC"

    def test_ipv4_in_ipv6_is_unwrapped(self, tmp_path: Path) -> None:
        body = event_xml(
            event_id=4624,
            channel=SEC,
            provider=AUDIT,
            data={"IpAddress": "::ffff:203.0.113.11", "IpPort": "52001"},
        )
        event = parse_document(write_document(tmp_path, body))[0][0]
        assert event.src_ip == "203.0.113.11"
        assert event.src_port == 52001

    def test_system_fields_are_prefixed_in_fields_json(self, tmp_path: Path) -> None:
        body = event_xml(
            event_id=4624, channel=SEC, provider=AUDIT, data={"TargetUserName": "alice"}
        )
        event = parse_document(write_document(tmp_path, body))[0][0]
        assert event.fields_json["System.EventID"] == "4624"
        assert event.fields_json["System.Channel"] == SEC

    def test_ps_script_message_carries_the_block_text(self, tmp_path: Path) -> None:
        body = event_xml(
            event_id=4104,
            channel=PS_CH,
            provider=PS_PROV,
            level=5,
            data={"ScriptBlockText": "Write-Host hello"},
        )
        event = parse_document(write_document(tmp_path, body))[0][0]
        assert event.ls_category == "ps_script"
        assert event.message == "Write-Host hello"

    @pytest.mark.parametrize(
        ("level", "expected"),
        [(0, "info"), (1, "critical"), (2, "error"), (3, "warning"), (4, "info"), (5, "debug")],
    )
    def test_windows_level_mapping(self, tmp_path: Path, level: int, expected: str) -> None:
        body = event_xml(event_id=4624, channel=SEC, provider=AUDIT, level=level, data={})
        event = parse_document(write_document(tmp_path, body, name=f"lvl{level}.xml"))[0][0]
        assert event.level == expected


class TestEventXmlParser:
    """Well-formed, malformed and hostile XML."""

    def test_authored_fixtures_match_their_goldens(self) -> None:
        for name in ("security_logons.xml", "sysmon_attack.xml", "powershell_4104.xml"):
            events, failures = parse_document(FIXTURES / name)
            golden = json.loads((FIXTURES / f"{name}.expected.json").read_text(encoding="utf-8"))
            assert [event.record_ref for event in events] == [
                event["record_ref"] for event in golden["events"]
            ]
            assert len(events) == golden["event_count"]
            assert len(failures) == len(golden["failures"])

    def test_malformed_xml_yields_a_failure_not_an_exception(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.xml"
        path.write_text(f'<?xml version="1.0"?><Events xmlns="{EVENT_NS}"><Event><System>')
        events, failures = parse_document(path)
        assert events == []
        assert len(failures) == 1
        assert "not well formed" in failures[0].reason

    def test_an_empty_events_document_yields_nothing(self, tmp_path: Path) -> None:
        path = tmp_path / "empty.xml"
        path.write_text(f'<?xml version="1.0"?><Events xmlns="{EVENT_NS}"></Events>')
        events, failures = parse_document(path)
        assert events == []
        assert failures == []

    def test_an_xxe_payload_does_not_leak_a_local_file(self, tmp_path: Path) -> None:
        secret = tmp_path / "secret.txt"
        secret.write_text("TOP-SECRET-CANARY", encoding="utf-8")
        payload = (
            '<?xml version="1.0"?>'
            f'<!DOCTYPE Events [ <!ENTITY xxe SYSTEM "file:///{secret.as_posix()}"> ]>'
            f'<Events xmlns="{EVENT_NS}">'
            "<Event><System><EventID>1</EventID><Channel>X</Channel>"
            '<TimeCreated SystemTime="2026-03-01T00:00:00Z"/></System>'
            '<EventData><Data Name="V">&xxe;</Data></EventData></Event></Events>'
        )
        path = tmp_path / "xxe.xml"
        path.write_text(payload, encoding="utf-8")
        events, _failures = parse_document(path)
        blob = "".join(event.raw + json.dumps(event.fields_json) for event in events)
        assert "TOP-SECRET-CANARY" not in blob


class TestEvtxParser:
    """The binary path, pinned to the vendored reader so it runs everywhere."""

    def test_binary_fixtures_match_their_goldens(self) -> None:
        for name in ("security_logons.evtx", "account_changes.evtx", "sysmon_attack.evtx"):
            events, _failures = parse_evtx(FIXTURES / name)
            golden = json.loads((FIXTURES / f"{name}.expected.json").read_text(encoding="utf-8"))
            assert len(events) == golden["event_count"]
            assert [event.record_ref for event in events] == [
                event["record_ref"] for event in golden["events"]
            ]

    def test_record_ref_is_the_event_record_id(self) -> None:
        events, _failures = parse_evtx(FIXTURES / "security_logons.evtx")
        assert events[0].record_ref == "319457771"

    def test_a_corrupt_chunk_is_reported_and_the_rest_survives(self, tmp_path: Path) -> None:
        data = bytearray((FIXTURES / "sysmon_attack.evtx").read_bytes())
        # Corrupt a record inside the first 64 KiB chunk. The reader must not
        # abort the whole file: the later chunks still hold their events.
        data[0x10400:0x10410] = b"\xff" * 16
        path = tmp_path / "corrupt.evtx"
        path.write_bytes(bytes(data))

        parser = WindowsEvtxParser(backend="vendored")
        context = context_for(path)
        events = 0
        failures = 0
        for item in parser.parse(context):
            if hasattr(item, "reason"):
                failures += 1
            else:
                events += 1
        assert failures >= 1
        assert events >= 100
        assert context.counters.errors == failures


class TestDetectionIntegration:
    """Detection routes both formats to the right parser."""

    def test_evtx_magic_routes_to_windows_evtx(self) -> None:
        result = detect(FIXTURES / "security_logons.evtx")
        assert result.log_type == "windows_evtx"
        assert result.source == "magic"
        assert result.parser_available is True

    def test_event_xml_routes_to_windows_event_xml(self) -> None:
        result = detect(FIXTURES / "security_logons.xml")
        assert result.log_type == "windows_event_xml"
        assert result.parser_available is True


def test_native_backend_availability_is_reported() -> None:
    """A diagnostic the status page can show; the value depends on the host."""
    assert isinstance(native_backend_available(), bool)
