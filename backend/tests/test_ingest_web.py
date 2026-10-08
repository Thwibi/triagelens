"""Web parsers: Apache/nginx access and error, and IIS W3C (spec 03 section 4).

The four formats share two ideas worth pinning down: an access line that does
not frame cleanly is still an event (P-09), and every other line that cannot be
parsed becomes a ``parse_errors`` row without stopping the file. The two access
readers are also deliberately exclusive during detection, which the routing tests
hold to.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.ingest.detect import detect
from app.ingest.events import EVENT_COLUMNS, NormalizedEvent
from app.ingest.parsers.base import ParseContext, ParseFailure
from app.ingest.parsers.iis_w3c import IisW3cParser
from app.ingest.parsers.web_access import ApacheAccessParser, NginxAccessParser
from app.ingest.parsers.web_error import ApacheErrorParser, NginxErrorParser
from app.ingest.text import TextHead

WEB_DIR = Path(__file__).resolve().parent / "fixtures" / "web"


def _context(path: Path, timezone: str = "UTC") -> ParseContext:
    return ParseContext(
        case_id="case",
        source_id="source",
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


_ACCESS = (
    '203.0.113.9 - alice [01/Mar/2026:12:00:00 +0000] "GET /product.php?id=7 HTTP/1.1" '
    '200 512 "https://ref.example/" "curl/8.0"'
)


class TestAccessDetection:
    """The two access readers are mutually exclusive on the filename hint."""

    def test_apache_claims_a_plain_access_name(self) -> None:
        head = TextHead(head=b"x", lines=[_ACCESS], name="access.log")
        assert ApacheAccessParser().sniff(head) == pytest.approx(0.9)
        assert NginxAccessParser().sniff(head) == 0.0

    def test_nginx_claims_an_nginx_name(self) -> None:
        head = TextHead(head=b"x", lines=[_ACCESS], name="nginx_access.log")
        assert NginxAccessParser().sniff(head) == pytest.approx(0.9)
        assert ApacheAccessParser().sniff(head) == 0.0

    def test_no_access_lines_scores_zero(self) -> None:
        head = TextHead(head=b"x", lines=["just some text", ""], name="access.log")
        assert ApacheAccessParser().sniff(head) == 0.0


class TestAccessMapping:
    """One combined line maps every column it can (spec 03 section 4.1)."""

    def test_columns(self, tmp_path: Path) -> None:
        event = _parse_one(ApacheAccessParser(), tmp_path, _ACCESS)
        assert event.log_type == "apache_access"
        assert event.ls_category == "webserver"
        assert event.event_action == "http_request"
        assert event.event_outcome == "success"
        assert event.src_ip == "203.0.113.9"
        assert event.user_name == "alice"
        assert event.http_method == "GET"
        assert event.url == "/product.php?id=7"
        assert event.url_path == "/product.php"
        assert event.url_query == "id=7"
        assert event.http_status == 200
        assert event.bytes_out == 512
        assert event.user_agent == "curl/8.0"
        assert event.ts_iso == "2026-03-01T12:00:00.000000Z"

    def test_fields_json(self, tmp_path: Path) -> None:
        event = _parse_one(ApacheAccessParser(), tmp_path, _ACCESS)
        assert event.fields_json["referer"] == "https://ref.example/"
        assert event.fields_json["protocol"] == "HTTP/1.1"
        assert "url_decoded" not in event.fields_json

    def test_failure_status(self, tmp_path: Path) -> None:
        line = '203.0.113.9 - - [01/Mar/2026:12:00:00 +0000] "GET /x HTTP/1.1" 404 0 "-" "-"'
        event = _parse_one(ApacheAccessParser(), tmp_path, line)
        assert event.event_outcome == "failure"
        assert event.user_name is None
        assert event.bytes_out == 0
        assert event.user_agent is None

    def test_missing_size_is_none(self, tmp_path: Path) -> None:
        line = '203.0.113.9 - - [01/Mar/2026:12:00:00 +0000] "GET /x HTTP/1.1" 200 - "-" "-"'
        event = _parse_one(ApacheAccessParser(), tmp_path, line)
        assert event.bytes_out is None

    def test_percent_encoded_url_is_raw_with_decoded_copy(self, tmp_path: Path) -> None:
        line = (
            "45.155.205.233 - - [01/Mar/2026:10:00:00 +0000] "
            '"GET /product.php?id=1%27%20OR%20%271%27%3D%271 HTTP/1.1" '
            '200 1024 "-" "sqlmap/1.7"'
        )
        event = _parse_one(ApacheAccessParser(), tmp_path, line)
        assert event.url == "/product.php?id=1%27%20OR%20%271%27%3D%271"
        assert event.fields_json["url_decoded"] == "/product.php?id=1' OR '1'='1"

    def test_dash_request_is_an_event_not_an_error(self, tmp_path: Path) -> None:
        line = '203.0.113.9 - - [01/Mar/2026:12:13:00 +0000] "-" 400 0 "-" "-"'
        event = _parse_one(ApacheAccessParser(), tmp_path, line)
        assert event.http_method is None
        assert event.url is None
        assert event.http_status == 400

    def test_unframed_request_keeps_the_text(self, tmp_path: Path) -> None:
        line = '203.0.113.9 - - [01/Mar/2026:12:13:01 +0000] "not-a-request" 400 0 "-" "-"'
        event = _parse_one(ApacheAccessParser(), tmp_path, line)
        assert event.http_method is None
        assert event.url == "not-a-request"

    def test_nginx_access_uses_the_same_mapping(self, tmp_path: Path) -> None:
        event = _parse_one(NginxAccessParser(), tmp_path, _ACCESS)
        assert event.log_type == "nginx_access"
        assert event.url == "/product.php?id=7"

    def test_garbage_line_is_a_failure_and_parsing_continues(self, tmp_path: Path) -> None:
        body = "total nonsense\n" + _ACCESS + "\n"
        path = _write(tmp_path, "x.log", body)
        events, failures = _run(ApacheAccessParser(), path)
        assert len(failures) == 1
        assert failures[0].record_ref == "line:1"
        assert len(events) == 1


class TestDetection:
    """Detection routes each web fixture to the right parser with confidence."""

    @pytest.mark.parametrize(
        ("filename", "log_type", "confidence"),
        [
            ("access_combined.log", "apache_access", 0.9),
            ("nginx_access.log", "nginx_access", 0.9),
            ("nginx_error.log", "nginx_error", 0.9),
            ("apache_error.log", "apache_error", 0.9),
            ("iis.log", "iis_w3c", 0.95),
        ],
    )
    def test_fixtures_route_by_content(
        self, filename: str, log_type: str, confidence: float
    ) -> None:
        result = detect(WEB_DIR / filename)
        assert result.log_type == log_type
        assert result.source == "content"
        assert result.confidence >= 0.8
        assert result.confidence == pytest.approx(confidence)


class TestNginxError:
    """nginx error lines carry a level, a pid and sometimes a client/request."""

    _LINE = (
        '2026/03/01 12:00:00 [error] 1234#0: *1 open() "/var/www/x" failed '
        "(2: No such file or directory), client: 203.0.113.5, server: example.org, "
        'request: "GET /x HTTP/1.1", host: "example.org"'
    )

    def test_columns(self, tmp_path: Path) -> None:
        event = _parse_one(NginxErrorParser(), tmp_path, self._LINE)
        assert event.log_type == "nginx_error"
        assert event.ls_category == "webserver_error"
        assert event.level == "error"
        assert event.process_pid == 1234
        assert event.src_ip == "203.0.113.5"
        assert event.http_method == "GET"
        assert event.url == "/x"
        assert event.ts_iso == "2026-03-01T12:00:00.000000Z"

    def test_fields_json(self, tmp_path: Path) -> None:
        event = _parse_one(NginxErrorParser(), tmp_path, self._LINE)
        assert event.fields_json["thread_id"] == "0"
        assert event.fields_json["connection"] == "1"

    def test_line_without_client_or_request(self, tmp_path: Path) -> None:
        line = "2026/03/01 12:00:02 [crit] 1235#0: *3 handshake failed"
        event = _parse_one(NginxErrorParser(), tmp_path, line)
        assert event.level == "critical"
        assert event.src_ip is None
        assert event.http_method is None
        assert event.url is None

    def test_garbage_line_is_a_failure(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "x.log", "not an nginx line\n")
        events, failures = _run(NginxErrorParser(), path)
        assert events == []
        assert len(failures) == 1


class TestApacheError:
    """Apache error lines carry microsecond and non-microsecond timestamps."""

    def test_with_microseconds_and_client(self, tmp_path: Path) -> None:
        line = (
            "[Wed Oct 01 12:00:00.123456 2025] [core:error] [pid 100:tid 5] "
            "[client 203.0.113.5:55000] AH00124: Request exceeded the limit"
        )
        event = _parse_one(ApacheErrorParser(), tmp_path, line)
        assert event.log_type == "apache_error"
        assert event.level == "error"
        assert event.process_pid == 100
        assert event.src_ip == "203.0.113.5"
        assert event.src_port == 55000
        assert event.fields_json["module"] == "core"
        assert event.fields_json["error_code"] == "AH00124"
        assert event.ts_iso == "2025-10-01T12:00:00.123000Z"

    def test_line_without_microseconds(self, tmp_path: Path) -> None:
        line = "[Wed Oct 01 12:00:02 2025] [rewrite:warn] [pid 101] rewrite matched"
        event = _parse_one(ApacheErrorParser(), tmp_path, line)
        assert event.level == "warning"
        assert event.process_pid == 101
        assert event.src_ip is None
        assert event.ts_iso == "2025-10-01T12:00:02.000000Z"


class TestIis:
    """IIS is read strictly through its ``#Fields`` header."""

    _HEADER = (
        "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port "
        "cs-username c-ip cs(User-Agent) sc-status sc-substatus sc-win32-status time-taken"
    )
    _ROW = (
        "2026-03-01 12:00:01 192.0.2.20 GET /admin/login.aspx returnurl=%2Fhome 80 "
        "- 203.0.113.7 Mozilla/5.0+(Windows+NT+10.0) 302 0 0 12"
    )

    def test_columns(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "iis.log", self._HEADER + "\n" + self._ROW + "\n")
        events, failures = _run(IisW3cParser(), path)
        assert failures == []
        event = events[0]
        assert event.log_type == "iis_w3c"
        assert event.dst_ip == "192.0.2.20"
        assert event.dst_port == 80
        assert event.http_method == "GET"
        assert event.url == "/admin/login.aspx?returnurl=/home"
        assert event.url_path == "/admin/login.aspx"
        assert event.url_query == "returnurl=/home"
        assert event.src_ip == "203.0.113.7"
        assert event.user_agent == "Mozilla/5.0 (Windows NT 10.0)"
        assert event.http_status == 302
        assert event.ts_iso == "2026-03-01T12:00:01.000000Z"

    def test_failure_status(self, tmp_path: Path) -> None:
        row = (
            "2026-03-01 12:00:02 192.0.2.20 POST /api/upload - 80 CORP%5Calice "
            "203.0.113.7 curl/8.0 401 2 5 3"
        )
        path = _write(tmp_path, "iis.log", self._HEADER + "\n" + row + "\n")
        events, _ = _run(IisW3cParser(), path)
        assert events[0].event_outcome == "failure"
        assert events[0].user_name == "CORP\\alice"

    def test_data_before_header_is_a_failure(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "iis.log", self._ROW + "\n")
        events, failures = _run(IisW3cParser(), path)
        assert events == []
        assert failures[0].record_ref == "line:1"

    def test_field_count_mismatch_is_a_failure(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "iis.log", self._HEADER + "\n2026-03-01 12:00:00\n")
        events, failures = _run(IisW3cParser(), path)
        assert events == []
        assert "fields" in failures[0].reason

    def test_sniff_requires_a_header(self) -> None:
        assert IisW3cParser().sniff(TextHead(head=b"x", lines=[self._ROW], name="iis.log")) == 0.0
        assert IisW3cParser().sniff(
            TextHead(head=b"x", lines=[self._HEADER, self._ROW], name="iis.log")
        ) == pytest.approx(0.95)


class TestWebGoldens:
    """Every committed web fixture parses to its recorded golden."""

    @pytest.mark.parametrize(
        ("name", "parser"),
        [
            ("access_combined.log", ApacheAccessParser()),
            ("nginx_access.log", NginxAccessParser()),
            ("nginx_error.log", NginxErrorParser()),
            ("apache_error.log", ApacheErrorParser()),
            ("iis.log", IisW3cParser()),
        ],
    )
    def test_golden(self, name: str, parser: object) -> None:
        expected = json.loads((WEB_DIR / f"{name}.expected.json").read_text(encoding="utf-8"))
        events, failures = _run(parser, WEB_DIR / name)
        assert {"event_count": len(events), "events": [_golden(e) for e in events]} == {
            "event_count": expected["event_count"],
            "events": expected["events"],
        }
        assert [{"record_ref": f.record_ref, "reason": f.reason} for f in failures] == expected[
            "failures"
        ]


def _golden(event: NormalizedEvent) -> dict:
    """The stable projection of an event stored in a golden."""
    return {
        name: getattr(event, name) for name in EVENT_COLUMNS if name not in ("source_id", "case_id")
    }
