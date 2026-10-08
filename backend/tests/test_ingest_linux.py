"""Linux parsers: syslog/auth, journald, and auditd (spec 03 section 3, spec 09 P-05/P-08).

The parts that cannot assert for themselves get their own tests: the three wire
framings and their continuation handling, the daemon message table, the year
rollover and DST choice for the year-less RFC 3164 clock (P-05), and the grouping,
hex decoding and ``sockaddr`` extraction for the multi-line audit records (P-08).
Each parser also reproduces its golden fixture.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.ingest.detect import detect
from app.ingest.events import EVENT_COLUMNS
from app.ingest.parsers.base import ParseContext, ParseFailure
from app.ingest.parsers.linux_auditd import LinuxAuditdParser
from app.ingest.parsers.linux_common import level_from_pri_or_info, match_message
from app.ingest.parsers.linux_journald import LinuxJournaldParser
from app.ingest.parsers.linux_syslog import LinuxAuthParser, LinuxSyslogParser
from app.ingest.text import TextHead

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "linux"


def context(
    path: Path,
    *,
    filename: str | None = None,
    assumed_year: int | None = None,
    timezone: str | None = None,
) -> ParseContext:
    """A parse context for one fixture file."""
    return ParseContext(
        case_id="case",
        source_id="source",
        filename=filename if filename is not None else path.name,
        path=path,
        max_line_bytes=1 << 20,
        assumed_year=assumed_year,
        timezone=timezone,
    )


def run(parser: object, path: Path, **kwargs: object) -> tuple[list, list]:
    """Parse ``path`` and split the stream into (events, failures)."""
    events: list = []
    failures: list = []
    for item in parser.parse(context(path, **kwargs)):  # type: ignore[attr-defined]
        if isinstance(item, ParseFailure):
            failures.append(item)
        else:
            events.append(item)
    return events, failures


def write(tmp_path: Path, name: str, text: str) -> Path:
    """Write a small fixture file under ``tmp_path``."""
    path = tmp_path / name
    path.write_text(text, encoding="utf-8", newline="\n")
    return path


class TestDetection:
    """Detection routes each Linux flavor to the right parser."""

    @pytest.mark.parametrize(
        ("filename", "log_type"),
        [
            ("auth.log", "linux_auth"),
            ("syslog_variants.log", "linux_syslog"),
            ("journal.json", "linux_journald"),
            ("audit.log", "linux_auditd"),
        ],
    )
    def test_fixtures_route_by_content(self, filename: str, log_type: str) -> None:
        result = detect(FIXTURES / filename)
        assert result.log_type == log_type
        assert result.source == "content"

    def test_filename_hint_marks_auth(self) -> None:
        head = TextHead(
            head=b"Mar  1 12:00:01 web01 app[1]: ordinary message\n",
            lines=["Mar  1 12:00:01 web01 app[1]: ordinary message"],
            name="/var/log/auth.log",
        )
        assert LinuxAuthParser().sniff(head) == pytest.approx(0.95)
        assert LinuxSyslogParser().sniff(head) == 0.0

    def test_auth_and_syslog_are_mutually_exclusive(self) -> None:
        lines = [
            f"Mar  1 12:00:0{i} web01 sshd[1]: Failed password for u from 1.2.3.4 port {i}"
            for i in range(1, 6)
        ]
        head = TextHead(head=b"x", lines=lines, name="syslog")
        assert LinuxAuthParser().sniff(head) == pytest.approx(0.95)
        assert LinuxSyslogParser().sniff(head) == 0.0


class TestFraming:
    """The three wire framings map their shared fields onto the event."""

    def test_rfc3164_uses_assumed_year(self, tmp_path: Path) -> None:
        path = write(tmp_path, "syslog", "Mar  1 12:00:01 web01 sshd[10]: hello there\n")
        events, failures = run(LinuxSyslogParser(), path, assumed_year=2025, timezone="UTC")
        assert not failures
        (event,) = events
        assert event.app_name == "sshd"
        assert event.process_pid == 10
        assert event.host == "web01"
        assert event.ts_iso == "2025-03-01T12:00:01.000000Z"
        assert event.message == "hello there"

    def test_rfc5424_fields(self, tmp_path: Path) -> None:
        path = write(
            tmp_path,
            "syslog",
            "<165>1 2026-03-02T08:00:04Z web01 nginx 2100 ID47 - request processed\n",
        )
        events, _ = run(LinuxSyslogParser(), path)
        (event,) = events
        assert event.app_name == "nginx"
        assert event.process_pid == 2100
        assert event.message == "request processed"
        assert event.ts_iso == "2026-03-02T08:00:04.000000Z"
        assert event.level == "info"

    def test_rfc3339_offset_is_applied(self, tmp_path: Path) -> None:
        path = write(tmp_path, "syslog", "2026-03-02T08:00:03.500+02:00 web01 nginx[2100]: hi\n")
        events, _ = run(LinuxSyslogParser(), path)
        (event,) = events
        assert event.ts_iso == "2026-03-02T06:00:03.500000Z"

    def test_continuation_appends_to_previous(self, tmp_path: Path) -> None:
        path = write(
            tmp_path,
            "syslog",
            "Mar  2 08:00:01 web01 app[2000]: first\n    second\n    third\n",
        )
        events, failures = run(LinuxSyslogParser(), path, assumed_year=2025)
        assert not failures
        (event,) = events
        assert event.message == "first\nsecond\nthird"
        assert event.raw == "Mar  2 08:00:01 web01 app[2000]: first\n    second\n    third"

    def test_unframed_line_is_a_failure(self, tmp_path: Path) -> None:
        path = write(tmp_path, "syslog", "this is not syslog at all\n")
        events, failures = run(LinuxSyslogParser(), path)
        assert not events
        (failure,) = failures
        assert failure.record_ref == "line:1"


class TestMessageTable:
    """The daemon message table (spec 03 section 3.1)."""

    def test_failed_password(self) -> None:
        matched = match_message("Failed password for admin from 1.2.3.4 port 4000 ssh2", "sshd")
        assert matched is not None
        assert matched.action == "ssh_failed_password"
        assert matched.category == "logon"
        assert matched.outcome == "failure"
        assert matched.columns["user_name"] == "admin"
        assert matched.columns["src_ip"] == "1.2.3.4"
        assert matched.columns["src_port"] == "4000"
        assert (
            match_message(
                "Failed password for invalid user admin from 1.2.3.4 port 1", "sshd"
            ).action
            == "ssh_failed_password"
        )

    def test_sudo_command(self) -> None:
        match = match_message(
            "  alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/sbin/useradd svc",
            "sudo",
        )
        assert match is not None
        assert match.action == "sudo_command"
        assert match.columns["user_name"] == "alice"
        assert match.columns["target_user_name"] == "root"
        assert match.columns["process_cmdline"] == "/usr/sbin/useradd svc"

    def test_sudo_pattern_is_scoped_to_sudo(self) -> None:
        line = "root : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls"
        assert match_message(line, "sshd") is None

    def test_cron_command_only_for_cron(self) -> None:
        match = match_message("(root) CMD (/usr/local/bin/backup.sh)", "CRON")
        assert match is not None
        assert match.action == "cron_command"
        assert match.columns["process_cmdline"] == "/usr/local/bin/backup.sh"
        assert match_message("(root) CMD (ls)", "app") is None

    def test_user_added(self) -> None:
        matched = match_message(
            "new user: name=svc, UID=1001, GID=1001, home=/home/svc, shell=/bin/bash", "useradd"
        )
        assert matched is not None
        assert matched.action == "user_added"
        assert matched.category == "account_management"
        assert matched.columns["target_user_name"] == "svc"


class TestPriorityLevels:
    """PRI severity maps to the normalized level (spec 03 section 3.1)."""

    @pytest.mark.parametrize(
        ("pri", "level"),
        [
            (0, "critical"),
            (2, "critical"),
            (3, "error"),
            (4, "warning"),
            (5, "info"),
            (6, "info"),
            (7, "debug"),
        ],
    )
    def test_levels(self, pri: int, level: str) -> None:
        assert level_from_pri_or_info(pri) == level

    def test_no_priority_is_info(self) -> None:
        assert level_from_pri_or_info(None) == "info"

    def test_facility_bits_are_ignored(self, tmp_path: Path) -> None:
        path = write(tmp_path, "syslog", "<13>Mar  1 12:00:01 web01 app[1]: notice\n")
        events, _ = run(LinuxSyslogParser(), path, assumed_year=2025)
        (event,) = events
        assert event.level == "info"


class TestSyslogClock:
    """The year-less RFC 3164 clock (spec 09 P-05)."""

    def test_december_rolls_into_january(self, tmp_path: Path) -> None:
        path = write(
            tmp_path,
            "syslog",
            "Dec 31 23:59:59 web01 app[1]: before\nJan  1 00:00:01 web01 app[1]: after\n",
        )
        events, _ = run(LinuxSyslogParser(), path, assumed_year=2025, timezone="UTC")
        assert [event.ts_iso for event in events] == [
            "2025-12-31T23:59:59.000000Z",
            "2026-01-01T00:00:01.000000Z",
        ]

    def test_dst_fold_resolves_deterministically(self, tmp_path: Path) -> None:
        path = write(tmp_path, "syslog", "Nov  2 01:30:00 web01 app[1]: fold\n")
        events, _ = run(LinuxSyslogParser(), path, assumed_year=2025, timezone="America/New_York")
        (event,) = events
        assert event.ts_iso == "2025-11-02T05:30:00.000000Z"

    def test_year_from_filename_when_not_assumed(self, tmp_path: Path) -> None:
        path = write(tmp_path, "syslog-2024.log", "Mar  1 12:00:01 web01 app[1]: x\n")
        events, _ = run(LinuxSyslogParser(), path, timezone="UTC")
        (event,) = events
        assert event.ts_iso == "2024-03-01T12:00:01.000000Z"


class TestAuditd:
    """Grouping, decoding and mapping of multi-line audit records (spec 09 P-08)."""

    def test_groups_by_serial_and_decodes_hex_argv(self, tmp_path: Path) -> None:
        path = write(
            tmp_path,
            "audit.log",
            'type=SYSCALL msg=audit(1740909601.000:7001): pid=901 exe="/usr/bin/cat"\n'
            'type=EXECVE msg=audit(1740909601.000:7001): argc=2 a0="cat" '
            'a1="2F6574632F706173737764"\n'
            'type=PATH msg=audit(1740909601.000:7001): item=0 name="/etc/passwd"\n',
        )
        events, failures = run(LinuxAuditdParser(), path)
        assert not failures
        (event,) = events
        assert event.record_ref == "audit:7001"
        assert event.ls_category == "process_creation"
        assert event.event_action == "process_created"
        assert event.process_cmdline == "cat /etc/passwd"
        assert event.file_path == "/etc/passwd"
        assert event.fields_json["argv"] == ["cat", "/etc/passwd"]

    def test_sockaddr_extracts_address_and_port(self, tmp_path: Path) -> None:
        path = write(
            tmp_path,
            "audit.log",
            'type=SYSCALL msg=audit(1740909602.000:7002): pid=902 exe="/usr/bin/curl"\n'
            "type=SOCKADDR msg=audit(1740909602.000:7002): saddr=0200C350C000020A\n",
        )
        events, _ = run(LinuxAuditdParser(), path)
        (event,) = events
        assert event.event_action == "socket_connect"
        assert event.ls_category is None
        assert event.dst_ip == "192.0.2.10"
        assert event.dst_port == 50000

    def test_nested_msg_fields_are_unfolded(self, tmp_path: Path) -> None:
        path = write(
            tmp_path,
            "audit.log",
            "type=USER_LOGIN msg=audit(1740909603.000:7003): pid=903 "
            'msg=\'op=login acct="admin" exe="/usr/sbin/sshd" addr=203.0.113.9 '
            "terminal=ssh res=failed'\n",
        )
        events, _ = run(LinuxAuditdParser(), path)
        (event,) = events
        assert event.user_name == "admin"
        assert event.src_ip == "203.0.113.9"
        assert event.event_outcome == "failure"
        assert event.process_path == "/usr/sbin/sshd"

    def test_unset_audit_uid_is_not_a_user(self, tmp_path: Path) -> None:
        path = write(
            tmp_path,
            "audit.log",
            'type=SYSCALL msg=audit(1740909604.000:7004): pid=904 auid=4294967295 exe="/bin/id"\n',
        )
        events, _ = run(LinuxAuditdParser(), path)
        (event,) = events
        assert event.user_name is None

    def test_missing_execve_keeps_the_syscall(self, tmp_path: Path) -> None:
        path = write(
            tmp_path,
            "audit.log",
            'type=SYSCALL msg=audit(1740909605.000:7005): pid=905 exe="/bin/ln"\n'
            'type=PATH msg=audit(1740909605.000:7005): item=0 name="/tmp/x"\n',
        )
        events, _ = run(LinuxAuditdParser(), path)
        (event,) = events
        assert event.event_action == "syscall"
        assert event.file_path == "/tmp/x"

    def test_a_bad_line_does_not_break_the_group(self, tmp_path: Path) -> None:
        path = write(
            tmp_path,
            "audit.log",
            'type=SYSCALL msg=audit(1740909606.000:7006): pid=906 exe="/bin/true"\n'
            "not an audit line at all\n"
            'type=EXECVE msg=audit(1740909606.000:7006): argc=1 a0="true"\n',
        )
        events, failures = run(LinuxAuditdParser(), path)
        assert not failures
        (event,) = events
        assert event.event_action == "process_created"
        assert len(event.fields_json["types"]) == 2


class TestJournald:
    """``journalctl -o json`` mapping (spec 03 section 3.2)."""

    def test_microsecond_time_and_columns(self, tmp_path: Path) -> None:
        path = write(
            tmp_path,
            "journal.json",
            '{"__REALTIME_TIMESTAMP":"1740909601000000","_HOSTNAME":"web01",'
            '"SYSLOG_IDENTIFIER":"sshd","_PID":"1200","PRIORITY":"4",'
            '"MESSAGE":"Failed password for admin from 185.220.101.45 port 40001 ssh2"}\n',
        )
        events, failures = run(LinuxJournaldParser(), path)
        assert not failures
        (event,) = events
        assert event.ts_iso == "2025-03-02T10:00:01.000000Z"
        assert event.host == "web01"
        assert event.app_name == "sshd"
        assert event.process_pid == 1200
        assert event.level == "warning"
        assert event.event_action == "ssh_failed_password"
        assert event.src_ip == "185.220.101.45"

    def test_message_byte_array_is_decoded(self, tmp_path: Path) -> None:
        path = write(
            tmp_path,
            "journal.json",
            '{"__REALTIME_TIMESTAMP":"1740909602000000","MESSAGE":[104,105]}',
        )
        events, _ = run(LinuxJournaldParser(), path)
        (event,) = events
        assert event.message == "hi"

    def test_exe_and_cmdline(self, tmp_path: Path) -> None:
        path = write(
            tmp_path,
            "journal.json",
            '{"__REALTIME_TIMESTAMP":"1740909603000000","_EXE":"/usr/bin/bash",'
            '"_CMDLINE":"bash -c echo hi","MESSAGE":"hi"}',
        )
        events, _ = run(LinuxJournaldParser(), path)
        (event,) = events
        assert event.process_path == "/usr/bin/bash"
        assert event.process_cmdline == "bash -c echo hi"


class TestEmptyAndFailures:
    """Degenerate input yields no events and no crash."""

    def test_empty_file(self, tmp_path: Path) -> None:
        path = write(tmp_path, "auth.log", "")
        for parser in (LinuxSyslogParser(), LinuxJournaldParser(), LinuxAuditdParser()):
            events, failures = run(parser, path)
            assert not events
            assert not failures


def _golden(event: object) -> dict:
    """The stable projection of an event stored in a golden."""
    return {
        name: getattr(event, name) for name in EVENT_COLUMNS if name not in ("source_id", "case_id")
    }


#: The parser each fixture is read with.
_GOLDEN_CASES = [
    ("auth.log", LinuxAuthParser()),
    ("syslog_variants.log", LinuxSyslogParser()),
    ("journal.json", LinuxJournaldParser()),
    ("audit.log", LinuxAuditdParser()),
]


@pytest.mark.parametrize(("filename", "parser"), _GOLDEN_CASES)
def test_fixture_golden(filename: str, parser: object) -> None:
    """Each parser reproduces its committed golden exactly."""
    expected = json.loads((FIXTURES / f"{filename}.expected.json").read_text(encoding="utf-8"))
    events, failures = run(parser, FIXTURES / filename, assumed_year=2025, timezone="UTC")
    assert {"event_count": len(events), "events": [_golden(e) for e in events]} == {
        "event_count": expected["event_count"],
        "events": expected["events"],
    }
    assert [{"record_ref": f.record_ref, "reason": f.reason} for f in failures] == expected[
        "failures"
    ]
