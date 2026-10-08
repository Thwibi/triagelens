"""Firewall parsers: UFW/iptables, pfSense, FortiGate, PAN-OS, Cisco ASA (spec 03 5).

The five readers answer a shared question - who talked to whom, on what port, and
was it allowed - but each format carries the answer differently: bracketed kernel
tokens, a positional CSV keyed on IP version, ``key=value`` pairs, a positional
CSV keyed on a type column, and a ``%ASA-<sev>-<id>:`` frame. These tests pin the
mapping each one promises and hold detection to routing every fixture to exactly
one parser (spec 09 P-10, P-12).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.ingest.detect import detect
from app.ingest.events import EVENT_COLUMNS, NormalizedEvent
from app.ingest.parsers.base import ParseContext, ParseFailure
from app.ingest.parsers.fw_cisco_asa import FwCiscoAsaParser
from app.ingest.parsers.fw_fortinet import FwFortinetParser
from app.ingest.parsers.fw_iptables import FwIptablesParser
from app.ingest.parsers.fw_paloalto import FwPaloaltoParser
from app.ingest.parsers.fw_pfsense import FwPfsenseParser
from app.ingest.parsers.linux_syslog import LinuxSyslogParser
from app.ingest.text import TextHead

FW_DIR = Path(__file__).resolve().parent / "fixtures" / "fw"

_SCAN_SOURCE = "45.155.205.233"

_ALL_PARSERS = [
    ("ufw.log", FwIptablesParser()),
    ("pfsense_filterlog.log", FwPfsenseParser()),
    ("fortigate.log", FwFortinetParser()),
    ("paloalto_traffic.csv", FwPaloaltoParser()),
    ("asa.log", FwCiscoAsaParser()),
]


def _context(path: Path, timezone: str | None = "UTC") -> ParseContext:
    return ParseContext(
        case_id="fixture",
        source_id="fixture",
        filename=path.name,
        path=path,
        max_line_bytes=1 << 20,
        timezone=timezone,
    )


def _run(parser: object, path: Path) -> tuple[list[NormalizedEvent], list[ParseFailure]]:
    events: list[NormalizedEvent] = []
    failures: list[ParseFailure] = []
    for item in parser.parse(_context(path)):  # type: ignore[attr-defined]
        if isinstance(item, ParseFailure):
            failures.append(item)
        else:
            events.append(item)
    return events, failures


def _write(tmp_path: Path, name: str, body: str) -> Path:
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return path


def _parse_one(parser: object, tmp_path: Path, line: str, name: str = "x.log") -> NormalizedEvent:
    path = _write(tmp_path, name, line + "\n")
    events, failures = _run(parser, path)
    assert failures == []
    assert len(events) == 1
    return events[0]


def _golden(event: NormalizedEvent) -> dict:
    """The stable projection of an event stored in a golden."""
    return {
        name: getattr(event, name) for name in EVENT_COLUMNS if name not in ("source_id", "case_id")
    }


_UFW_BLOCK = (
    "Mar  1 12:00:00 fw01 kernel: [12345.100] [UFW BLOCK] IN=eth0 OUT= "
    "MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd SRC=45.155.205.233 DST=10.0.0.5 "
    "LEN=60 TTL=64 PROTO=TCP SPT=40001 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0"
)


class TestDetection:
    """Each firewall fixture routes to one parser, and syslog does not steal it."""

    @pytest.mark.parametrize(
        ("filename", "log_type"),
        [
            ("ufw.log", "fw_iptables"),
            ("pfsense_filterlog.log", "fw_pfsense"),
            ("fortigate.log", "fw_fortinet"),
            ("paloalto_traffic.csv", "fw_paloalto"),
            ("asa.log", "fw_cisco_asa"),
        ],
    )
    def test_fixtures_route_by_content(self, filename: str, log_type: str) -> None:
        result = detect(FW_DIR / filename)
        assert result.log_type == log_type
        assert result.source == "content"
        assert result.confidence >= 0.8

    def test_syslog_defers_ufw_to_the_firewall_parser(self) -> None:
        head = TextHead(head=b"x", lines=[_UFW_BLOCK], name="ufw.log")
        assert FwIptablesParser().sniff(head) == pytest.approx(0.9)
        assert LinuxSyslogParser().sniff(head) == 0.0

    def test_syslog_defers_asa_to_the_firewall_parser(self) -> None:
        line = (
            "Mar  1 12:00:00 fw01 %ASA-4-106023: Deny tcp src outside:1.2.3.4/1 "
            'dst inside:5.6.7.8/2 by access-group "acl"'
        )
        head = TextHead(head=b"x", lines=[line], name="asa.log")
        assert FwCiscoAsaParser().sniff(head) == pytest.approx(0.9)
        assert LinuxSyslogParser().sniff(head) == 0.0


class TestIptables:
    """UFW bracket verdicts, the five-tuple, and the kept kernel tokens."""

    def test_block_line(self, tmp_path: Path) -> None:
        event = _parse_one(FwIptablesParser(), tmp_path, _UFW_BLOCK, "ufw.log")
        assert event.log_type == "fw_iptables"
        assert event.ls_category == "firewall"
        assert event.event_action == "firewall_deny"
        assert event.event_outcome == "failure"
        assert event.host == "fw01"
        assert event.src_ip == "45.155.205.233"
        assert event.src_port == 40001
        assert event.dst_ip == "10.0.0.5"
        assert event.dst_port == 22
        assert event.protocol == "tcp"
        assert event.ts_iso == "2026-03-01T12:00:00.000000Z"
        assert event.fields_json["prefix"] == "[12345.100] [UFW BLOCK]"
        assert event.fields_json["IN"] == "eth0"
        assert event.fields_json["flags"] == ["SYN"]

    def test_allow_line(self, tmp_path: Path) -> None:
        line = _UFW_BLOCK.replace("[UFW BLOCK]", "[UFW ALLOW]").replace("SYN", "ACK")
        event = _parse_one(FwIptablesParser(), tmp_path, line, "ufw.log")
        assert event.event_action == "firewall_allow"
        assert event.event_outcome == "success"

    def test_ipv6_line(self, tmp_path: Path) -> None:
        line = (
            "Mar  1 12:00:00 fw01 kernel: [1.0] [UFW BLOCK] IN=eth0 OUT= SRC=2001:db8::1 "
            "DST=2001:db8::2 LEN=60 PROTO=TCP SPT=40001 DPT=22"
        )
        event = _parse_one(FwIptablesParser(), tmp_path, line, "ufw.log")
        assert event.src_ip == "2001:db8::1"
        assert event.dst_ip == "2001:db8::2"

    def test_malformed_is_a_failure_and_parsing_continues(self, tmp_path: Path) -> None:
        body = "not a firewall line\n" + _UFW_BLOCK + "\n"
        path = _write(tmp_path, "ufw.log", body)
        events, failures = _run(FwIptablesParser(), path)
        assert len(failures) == 1
        assert failures[0].record_ref == "line:1"
        assert len(events) == 1


class TestPfsense:
    """pfSense reads IPv4 and IPv6 rows with different index maps."""

    _V4 = (
        "Mar  1 12:00:00 fw01 filterlog[500]: "
        "5,,,1000000103,em0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,"
        "45.155.205.233,10.0.0.5,40001,22,0,S,1234567890,0,0"
    )
    _V6 = (
        "Mar  1 12:00:00 fw01 filterlog[500]: "
        "6,,,1000000104,em0,match,pass,in,6,0x00,0x00000,64,tcp,6,60,"
        "2001:db8::1,2001:db8::2,40001,22"
    )

    def test_ipv4_block(self, tmp_path: Path) -> None:
        event = _parse_one(FwPfsenseParser(), tmp_path, self._V4, "pfsense_filterlog.log")
        assert event.src_ip == "45.155.205.233"
        assert event.src_port == 40001
        assert event.dst_ip == "10.0.0.5"
        assert event.dst_port == 22
        assert event.protocol == "tcp"
        assert event.event_action == "firewall_deny"
        assert event.fields_json["ip_version"] == 4
        assert event.fields_json["interface"] == "em0"

    def test_ipv6_pass(self, tmp_path: Path) -> None:
        event = _parse_one(FwPfsenseParser(), tmp_path, self._V6, "pfsense_filterlog.log")
        assert event.src_ip == "2001:db8::1"
        assert event.dst_ip == "2001:db8::2"
        assert event.src_port == 40001
        assert event.dst_port == 22
        assert event.event_action == "firewall_allow"
        assert event.fields_json["ip_version"] == 6

    def test_too_few_fields_is_a_failure(self, tmp_path: Path) -> None:
        line = "Mar  1 12:00:00 fw01 filterlog[500]: 5,,,1000000103,em0,match,block"
        path = _write(tmp_path, "pfsense_filterlog.log", line + "\n")
        events, failures = _run(FwPfsenseParser(), path)
        assert events == []
        assert len(failures) == 1


class TestFortinet:
    """FortiGate key=value: quotes, proto numbers, and the two time shapes."""

    def test_deny_with_quoted_devname(self, tmp_path: Path) -> None:
        line = (
            'date=2026-03-01 time=12:00:00 devname="FW01" type=traffic subtype=forward '
            "srcip=45.155.205.233 dstip=10.0.0.5 srcport=40001 dstport=22 proto=6 "
            "action=deny policyid=1 logid=0000000013 level=notice"
        )
        event = _parse_one(FwFortinetParser(), tmp_path, line, "fortigate.log")
        assert event.host == "FW01"
        assert event.src_ip == "45.155.205.233"
        assert event.dst_port == 22
        assert event.protocol == "tcp"
        assert event.event_action == "firewall_deny"
        assert event.event_outcome == "failure"
        assert event.ts_iso == "2026-03-01T12:00:00.000000Z"
        assert event.fields_json["policyid"] == "1"

    def test_eventtime_nanoseconds_wins(self, tmp_path: Path) -> None:
        line = (
            "eventtime=1772366400000000000 type=traffic srcip=10.0.0.5 dstip=198.51.100.53 "
            "srcport=51000 dstport=443 proto=6 action=accept"
        )
        event = _parse_one(FwFortinetParser(), tmp_path, line, "fortigate.log")
        assert event.ts_iso == "2026-03-01T12:00:00.000000Z"

    def test_url_record(self, tmp_path: Path) -> None:
        line = (
            'date=2026-03-01 time=12:00:04 devname="FW01" type=utm subtype=webfilter '
            "srcip=10.0.0.5 dstip=203.0.113.66 srcport=53000 dstport=80 proto=6 action=block "
            'user="alice" url="http://malware.example/payload.exe" level=warning'
        )
        event = _parse_one(FwFortinetParser(), tmp_path, line, "fortigate.log")
        assert event.url == "http://malware.example/payload.exe"
        assert event.url_query is None
        assert event.event_action == "firewall_deny"
        assert event.user_name == "alice"
        assert event.level == "warning"

    def test_line_without_ip_is_a_failure(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "fortigate.log", "date=2026-03-01 type=traffic action=deny\n")
        events, failures = _run(FwFortinetParser(), path)
        assert events == []
        assert len(failures) == 1


_PAN_TRAFFIC = (
    "1,2026/03/01 12:00:00,0011,TRAFFIC,end,2026/03/01 12:00:00,45.155.205.233,10.0.0.5,"
    "0.0.0.0,0.0.0.0,scan-deny,-,-,web-browsing,vsys1,untrust,trust,ethernet1/1,ethernet1/2,"
    "log-forward,0,70001,1,40001,22,0,0,0x4000,tcp,deny,-"
)


class TestPaloalto:
    """PAN-OS rows are read through the versioned positional layout."""

    def test_traffic_deny(self, tmp_path: Path) -> None:
        event = _parse_one(FwPaloaltoParser(), tmp_path, _PAN_TRAFFIC, "paloalto_traffic.csv")
        assert event.log_type == "fw_paloalto"
        assert event.src_ip == "45.155.205.233"
        assert event.src_port == 40001
        assert event.dst_ip == "10.0.0.5"
        assert event.dst_port == 22
        assert event.protocol == "tcp"
        assert event.event_action == "firewall_deny"
        assert event.ts_iso == "2026-03-01T12:00:00.000000Z"
        assert event.fields_json["rule"] == "scan-deny"
        assert event.fields_json["from"] == "untrust"

    def test_threat_row_severity_and_url(self, tmp_path: Path) -> None:
        line = (
            "1,2026/03/01 12:01:00,0011,THREAT,url,2026/03/01 12:01:00,10.0.0.5,203.0.113.66,"
            "0.0.0.0,0.0.0.0,malware-block,alice,-,web-browsing,vsys1,trust,untrust,"
            "ethernet1/2,ethernet1/1,log-forward,0,70004,1,52000,80,0,0,0x4000,tcp,"
            "block-url,http://malware.example/payload.exe,86202,malware,high"
        )
        event = _parse_one(FwPaloaltoParser(), tmp_path, line, "paloalto_traffic.csv")
        assert event.event_action == "firewall_deny"
        assert event.level == "error"
        assert event.url == "http://malware.example/payload.exe"
        assert event.fields_json["threat_id"] == "86202"
        assert event.fields_json["category"] == "malware"

    def test_unmapped_type_is_stored_whole(self, tmp_path: Path) -> None:
        cells = ["1", "2026/03/01 12:02:00", "0011", "SYSTEM"] + ["x"] * 27
        event = _parse_one(FwPaloaltoParser(), tmp_path, ",".join(cells), "paloalto_traffic.csv")
        assert event.app_name == "SYSTEM"
        assert event.fields_json == {"type": "SYSTEM"}
        assert event.src_ip is None

    def test_short_row_is_a_failure(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "paloalto_traffic.csv", "1,2026/03/01,TRAFFIC,short\n")
        events, failures = _run(FwPaloaltoParser(), path)
        assert events == []
        assert len(failures) == 1


class TestCiscoAsa:
    """ASA severity/message-id mapping and the parsed message ids (spec 09 P-10)."""

    def test_106023_deny(self, tmp_path: Path) -> None:
        line = (
            "Mar  1 12:00:00 fw01 %ASA-4-106023: Deny tcp src outside:45.155.205.233/40001 "
            'dst inside:10.0.0.5/22 by access-group "acl_out"'
        )
        event = _parse_one(FwCiscoAsaParser(), tmp_path, line, "asa.log")
        assert event.event_id == 106023
        assert event.level == "warning"
        assert event.ls_category == "firewall"
        assert event.event_action == "firewall_deny"
        assert event.event_outcome == "failure"
        assert event.src_ip == "45.155.205.233"
        assert event.src_port == 40001
        assert event.dst_port == 22
        assert event.fields_json["acl"] == "acl_out"

    def test_106100_permitted(self, tmp_path: Path) -> None:
        line = (
            "Mar  1 12:00:02 fw01 %ASA-6-106100: access-list acl_in permitted tcp inside/"
            "10.0.0.5(51000) -> outside/198.51.100.53(443) hit-cnt 1 first hit [0x2, 0x0]"
        )
        event = _parse_one(FwCiscoAsaParser(), tmp_path, line, "asa.log")
        assert event.event_id == 106100
        assert event.event_action == "firewall_allow"
        assert event.event_outcome == "success"
        assert event.dst_ip == "198.51.100.53"

    def test_302013_built(self, tmp_path: Path) -> None:
        line = (
            "Mar  1 12:00:03 fw01 %ASA-6-302013: Built outbound TCP connection 12345 for "
            "inside:10.0.0.5/51000 (10.0.0.5/51000) to outside:198.51.100.53/443 "
            "(198.51.100.53/443)"
        )
        event = _parse_one(FwCiscoAsaParser(), tmp_path, line, "asa.log")
        assert event.event_action == "firewall_connection_built"
        assert event.fields_json["connection_id"] == "12345"
        assert event.fields_json["direction"] == "outbound"

    def test_302014_teardown(self, tmp_path: Path) -> None:
        line = (
            "Mar  1 12:00:04 fw01 %ASA-6-302014: Teardown TCP connection 12345 for "
            "inside:10.0.0.5/51000 (10.0.0.5/51000) to outside:198.51.100.53/443 "
            "(198.51.100.53/443) duration 0:00:05 bytes 1024"
        )
        event = _parse_one(FwCiscoAsaParser(), tmp_path, line, "asa.log")
        assert event.event_action == "firewall_connection_teardown"
        assert event.fields_json["connection_id"] == "12345"

    def test_113005_aaa_failure(self, tmp_path: Path) -> None:
        line = (
            "Mar  1 12:00:05 fw01 %ASA-5-113005: AAA user authentication Rejected : "
            "reason = AAA failure : server = 10.0.0.1 : user = admin"
        )
        event = _parse_one(FwCiscoAsaParser(), tmp_path, line, "asa.log")
        assert event.event_action == "aaa_authentication_failed"
        assert event.event_outcome == "failure"
        assert event.user_name == "admin"
        assert event.ls_category == "logon"

    def test_unrecognized_id_is_still_a_firewall_event(self, tmp_path: Path) -> None:
        line = (
            "Mar  1 12:00:06 fw01 %ASA-6-302020: Built inbound ICMP connection for faddr "
            "45.155.205.233/1 gaddr 10.0.0.5/0 laddr 10.0.0.5/0"
        )
        event = _parse_one(FwCiscoAsaParser(), tmp_path, line, "asa.log")
        assert event.event_id == 302020
        assert event.ls_category == "firewall"
        assert event.event_action is None

    def test_non_asa_line_is_a_failure(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "asa.log", "Mar  1 12:00:00 fw01 not an ASA message\n")
        events, failures = _run(FwCiscoAsaParser(), path)
        assert events == []
        assert len(failures) == 1


class TestGoldens:
    """Every committed firewall fixture parses to its recorded golden."""

    @pytest.mark.parametrize(("name", "parser"), _ALL_PARSERS)
    def test_golden(self, name: str, parser: object) -> None:
        expected = json.loads((FW_DIR / f"{name}.expected.json").read_text(encoding="utf-8"))
        events, failures = _run(parser, FW_DIR / name)
        assert {"event_count": len(events), "events": [_golden(e) for e in events]} == {
            "event_count": expected["event_count"],
            "events": expected["events"],
        }
        assert [{"record_ref": f.record_ref, "reason": f.reason} for f in failures] == expected[
            "failures"
        ]

    @pytest.mark.parametrize(("name", "parser"), _ALL_PARSERS)
    def test_events_and_failures_cover_every_nonempty_line(self, name: str, parser: object) -> None:
        path = FW_DIR / name
        nonempty = sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())
        events, failures = _run(parser, path)
        assert len(events) + len(failures) == nonempty
