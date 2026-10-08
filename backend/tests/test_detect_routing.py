"""Logsource routing from ``rules/logsource_map.yaml`` (spec 04 section 3)."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.detect.routing import (
    Route,
    RoutingError,
    Unroutable,
    build_route,
    load_logsource_map,
)

BACKEND_ROOT = Path(__file__).resolve().parents[1]
MAP = BACKEND_ROOT / "rules" / "logsource_map.yaml"

MAP_YAML = """
product:
  windows: "log_type IN ('windows_evtx','windows_event_xml')"
  linux: "log_type = 'linux_auth'"
service:
  windows/security: "channel = 'Security'"
  sshd: "app_name = 'sshd'"
category:
  webserver: "ls_category = 'webserver'"
  firewall: "ls_category IN ('webserver','firewall')"
"""


@pytest.fixture
def map_path(tmp_path: Path) -> Path:
    path = tmp_path / "logsource_map.yaml"
    path.write_text(MAP_YAML, encoding="utf-8")
    return path


class TestLoad:
    def test_the_shipped_map_loads_and_has_all_sections(self) -> None:
        table = load_logsource_map(MAP)
        assert set(table) == {"product", "service", "category"}
        assert "windows" in table["product"]
        assert "windows/security" in table["service"]
        assert "webserver" in table["category"]

    def test_a_missing_file_is_a_routing_error(self, tmp_path: Path) -> None:
        with pytest.raises(RoutingError, match="cannot read logsource map"):
            load_logsource_map(tmp_path / "absent.yaml")

    def test_an_unknown_section_is_rejected(self, map_path: Path) -> None:
        map_path.write_text(
            "product: {windows: \"log_type = 'windows_evtx'\"}\nthreat: {}\n",
            encoding="utf-8",
        )
        with pytest.raises(RoutingError, match="unknown logsource map section"):
            load_logsource_map(map_path)

    def test_a_non_atom_predicate_is_rejected(self, map_path: Path) -> None:
        map_path.write_text('category:\n  webserver: "event_id < 5"\n', encoding="utf-8")
        with pytest.raises(RoutingError, match="not a routing predicate"):
            load_logsource_map(map_path)

    def test_a_non_string_statement_is_rejected(self, map_path: Path) -> None:
        map_path.write_text("category:\n  webserver: [1, 2]\n", encoding="utf-8")
        with pytest.raises(RoutingError, match="non-string"):
            load_logsource_map(map_path)

    def test_a_non_mapping_file_is_rejected(self, map_path: Path) -> None:
        map_path.write_text("- one\n- two\n", encoding="utf-8")
        with pytest.raises(RoutingError, match="must be a mapping"):
            load_logsource_map(map_path)


class TestBuildRoute:
    @pytest.fixture
    def table(self, map_path: Path) -> dict[str, dict[str, str]]:
        return load_logsource_map(map_path)

    def test_product_only(self, table: dict[str, dict[str, str]]) -> None:
        route = build_route(table, "windows", None, None)
        assert isinstance(route, Route)
        assert route.sql == "log_type IN ('windows_evtx','windows_event_xml')"
        assert route.log_types == ("windows_event_xml", "windows_evtx")

    def test_product_and_product_scoped_service(self, table: dict[str, dict[str, str]]) -> None:
        route = build_route(table, "windows", "security", None)
        assert isinstance(route, Route)
        assert route.sql == (
            "log_type IN ('windows_evtx','windows_event_xml') AND channel = 'Security'"
        )

    def test_bare_service_lookup(self, table: dict[str, dict[str, str]]) -> None:
        route = build_route(table, None, "sshd", None)
        assert isinstance(route, Route)
        assert route.sql == "app_name = 'sshd'"

    def test_category_only(self, table: dict[str, dict[str, str]]) -> None:
        route = build_route(table, None, None, "webserver")
        assert isinstance(route, Route)
        assert route.sql == "ls_category = 'webserver'"
        assert route.log_types == ()

    def test_full_stack(self, table: dict[str, dict[str, str]]) -> None:
        route = build_route(table, "windows", "security", "firewall")
        assert isinstance(route, Route)
        assert route.sql.endswith("ls_category IN ('webserver','firewall')")

    def test_the_route_only_touches_inventory_columns(
        self, table: dict[str, dict[str, str]]
    ) -> None:
        """The predicate must stay reusable against ``source_inventory`` (spec 04)."""
        import re

        route = build_route(table, "windows", "security", "firewall")
        assert isinstance(route, Route)
        columns = {m.group(1) for m in re.finditer(r"\b(\w+)\s*(?:=|IN\b)", route.sql)}
        assert columns <= {"log_type", "channel", "app_name", "ls_category"}

    def test_no_logsource_matches_everything(self, table: dict[str, dict[str, str]]) -> None:
        route = build_route(table, None, None, None)
        assert isinstance(route, Route)
        assert route.sql == ""
        assert route.unroutable is False

    def test_an_unknown_product_is_unroutable(self, table: dict[str, dict[str, str]]) -> None:
        route = build_route(table, "macos", None, None)
        assert isinstance(route, Unroutable)
        assert route.unroutable is True
        assert "macos" in route.reason

    def test_an_unknown_product_scoped_service_is_unroutable(
        self, table: dict[str, dict[str, str]]
    ) -> None:
        route = build_route(table, "windows", "dns", None)
        assert isinstance(route, Unroutable)
        assert route.unroutable is True

    def test_an_unknown_category_is_unroutable(self, table: dict[str, dict[str, str]]) -> None:
        route = build_route(table, None, None, "monitoring")
        assert isinstance(route, Unroutable)
        assert "monitoring" in route.reason


class TestShippedMapRoutes:
    """Real logsource combos rules actually carry must route, not be dropped."""

    @pytest.fixture
    def table(self) -> dict[str, dict[str, str]]:
        return load_logsource_map(MAP)

    @pytest.mark.parametrize(
        ("product", "service", "category"),
        [
            ("windows", "security", None),
            ("windows", "sysmon", "process_creation"),
            ("windows", "sysmon", "file_event"),
            ("windows", "sysmon", "network_connection"),
            ("windows", "powershell", "ps_script"),
            ("linux", "sshd", None),
            ("linux", "sudo", None),
            ("linux", "auditd", None),
            (None, None, "webserver"),
            (None, None, "firewall"),
            (None, None, "dns_query"),
        ],
    )
    def test_known_logsources_route(
        self,
        table: dict[str, dict[str, str]],
        product: str | None,
        service: str | None,
        category: str | None,
    ) -> None:
        route = build_route(table, product, service, category)
        assert isinstance(route, Route), (
            f"unroutable: {route.reason if isinstance(route, Unroutable) else ''}"
        )
        assert route.sql
        assert route.unroutable is False
