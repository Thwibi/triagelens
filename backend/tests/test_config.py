"""Configuration loading, precedence and safe-bind enforcement."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.config import (
    ConfigError,
    Settings,
    is_loopback_host,
    load_settings,
    normalize_host,
)


def write_config(path: Path, body: str) -> Path:
    """Write a config.toml body and return its path."""
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    return path


class TestDefaults:
    def test_defaults_are_usable_without_a_config_file(self, tmp_path: Path) -> None:
        settings = Settings(storage={"data_dir": str(tmp_path)})

        assert settings.server.host == "127.0.0.1"
        assert settings.server.port == 8787
        assert settings.is_loopback_bind is True
        assert settings.effective_worker_processes >= 1

    def test_evidence_paths_all_live_under_the_data_directory(self, tmp_path: Path) -> None:
        settings = Settings(storage={"data_dir": str(tmp_path)})

        for path in (
            settings.db_path,
            settings.cases_dir,
            settings.reports_dir,
            settings.logs_dir,
            settings.custom_rules_dir,
            settings.imports_dir,
        ):
            assert settings.data_dir in path.parents

    def test_code_paths_stay_inside_the_backend_package(self, tmp_path: Path) -> None:
        settings = Settings(storage={"data_dir": str(tmp_path)})

        assert settings.static_dir == settings.package_root / "app" / "static"
        assert settings.migrations_dir == settings.package_root / "migrations"
        assert settings.bundled_data_dir == settings.package_root / "data"

    def test_an_explicit_log_dir_wins(self, tmp_path: Path) -> None:
        elsewhere = tmp_path / "elsewhere"
        settings = Settings(
            storage={"data_dir": str(tmp_path / "data")},
            logging={"log_dir": str(elsewhere)},
        )

        assert settings.logs_dir == elsewhere
        assert settings.log_file == elsewhere / "triagelens.log"

    def test_an_empty_log_dir_falls_back_to_the_data_directory(self, tmp_path: Path) -> None:
        """An empty ``log_dir`` must not resolve to the current directory."""
        settings = Settings(
            storage={"data_dir": str(tmp_path / "data")},
            logging={"log_dir": ""},
        )

        assert settings.logging.log_dir is None
        assert settings.logs_dir == settings.data_dir / "logs"


class TestFileLoading:
    def test_loads_a_toml_file(self, tmp_path: Path) -> None:
        config = write_config(
            tmp_path / "config.toml",
            """
            [server]
            host = "0.0.0.0"
            port = 9999
            auth_token = "a-long-enough-token"

            [storage]
            data_dir = "./custom-data"
            """,
        )

        settings = load_settings(config_path=config, environ={})

        assert settings.server.port == 9999
        assert settings.server.auth_token == "a-long-enough-token"
        assert settings.is_loopback_bind is False

    def test_a_bare_config_path_is_resolved(self, tmp_path: Path) -> None:
        config = write_config(tmp_path / "config.toml", "[server]\nport = 1234\n")
        assert load_settings(config_path=config, environ={}).server.port == 1234

    def test_missing_explicit_file_is_an_error(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="not found"):
            load_settings(config_path=tmp_path / "absent.toml", environ={})

    def test_a_malformed_file_names_the_file(self, tmp_path: Path) -> None:
        config = write_config(tmp_path / "config.toml", "[server\nport = 1\n")
        with pytest.raises(ConfigError, match="config.toml"):
            load_settings(config_path=config, environ={})

    def test_an_unknown_section_is_rejected(self, tmp_path: Path) -> None:
        config = write_config(tmp_path / "config.toml", "[nonsense]\nvalue = 1\n")
        with pytest.raises(ConfigError, match="nonsense"):
            load_settings(config_path=config, environ={})

    def test_an_unknown_key_is_rejected(self, tmp_path: Path) -> None:
        config = write_config(tmp_path / "config.toml", "[server]\nprot = 80\n")
        with pytest.raises(ConfigError, match="prot"):
            load_settings(config_path=config, environ={})

    def test_a_wrongly_typed_key_is_rejected(self, tmp_path: Path) -> None:
        config = write_config(tmp_path / "config.toml", '[server]\nport = "eighty"\n')
        with pytest.raises(ConfigError, match="port"):
            load_settings(config_path=config, environ={})


class TestPrecedence:
    def test_environment_beats_file(self, tmp_path: Path) -> None:
        config = write_config(tmp_path / "config.toml", "[server]\nport = 1111\n")

        settings = load_settings(config_path=config, environ={"TRIAGELENS_SERVER__PORT": "2222"})

        assert settings.server.port == 2222

    def test_double_underscore_maps_to_a_nested_key(self, tmp_path: Path) -> None:
        config = write_config(tmp_path / "config.toml", "[limits]\nmax_upload_gb = 10\n")

        settings = load_settings(
            config_path=config,
            environ={"TRIAGELENS_LIMITS__MAX_UPLOAD_GB": "999"},
        )

        assert settings.limits.max_upload_gb == 999

    def test_an_unrelated_environment_variable_is_ignored(self, tmp_path: Path) -> None:
        config = write_config(tmp_path / "config.toml", "[server]\nport = 1111\n")
        assert load_settings(config_path=config, environ={"PATH": "/usr/bin"}).server.port == 1111

    def test_a_single_underscore_prefix_does_not_override(self, tmp_path: Path) -> None:
        config = write_config(tmp_path / "config.toml", "[server]\nport = 1111\n")
        settings = load_settings(config_path=config, environ={"TRIAGELENS_SERVER_PORT": "2222"})
        assert settings.server.port == 1111

    def test_an_unknown_environment_override_is_rejected(self, tmp_path: Path) -> None:
        config = write_config(tmp_path / "config.toml", "[server]\nport = 1111\n")
        with pytest.raises(ConfigError, match="made_up"):
            load_settings(config_path=config, environ={"TRIAGELENS_SERVER__MADE_UP": "x"})

    def test_a_bad_environment_value_is_rejected(self, tmp_path: Path) -> None:
        config = write_config(tmp_path / "config.toml", "[server]\nport = 1111\n")
        with pytest.raises(ConfigError, match="server.port"):
            load_settings(config_path=config, environ={"TRIAGELENS_SERVER__PORT": "not-a-port"})


class TestSafeBind:
    def test_non_loopback_without_a_token_is_refused(self, tmp_path: Path) -> None:
        config = write_config(tmp_path / "config.toml", '[server]\nhost = "0.0.0.0"\n')

        with pytest.raises(ConfigError, match="auth_token"):
            load_settings(config_path=config, environ={})

    def test_a_bare_wildcard_bind_is_refused(self, tmp_path: Path) -> None:
        config = write_config(tmp_path / "config.toml", '[server]\nhost = "*"\n')
        with pytest.raises(ConfigError, match="auth_token"):
            load_settings(config_path=config, environ={})

    def test_a_short_token_is_refused(self, tmp_path: Path) -> None:
        config = write_config(
            tmp_path / "config.toml",
            """
            [server]
            host = "0.0.0.0"
            auth_token = "tooshort"
            """,
        )
        with pytest.raises(ConfigError, match="at least"):
            load_settings(config_path=config, environ={})

    def test_a_short_token_is_refused_even_on_loopback(self, tmp_path: Path) -> None:
        config = write_config(tmp_path / "config.toml", "[server]\nport = 8787\n")
        with pytest.raises(ConfigError, match="at least"):
            load_settings(config_path=config, environ={"TRIAGELENS_SERVER__AUTH_TOKEN": "tooshort"})

    def test_a_token_at_the_minimum_length_is_accepted(self, tmp_path: Path) -> None:
        token = "a" * 16
        config = write_config(tmp_path / "config.toml", f'[server]\nauth_token = "{token}"\n')
        assert load_settings(config_path=config, environ={}).server.auth_token == token

    def test_surrounding_whitespace_is_stripped_from_the_token(self, tmp_path: Path) -> None:
        token = "a-long-enough-token"
        config = write_config(tmp_path / "config.toml", f'[server]\nauth_token = "  {token}  "\n')
        assert load_settings(config_path=config, environ={}).server.auth_token == token

    def test_a_token_supplied_by_environment_is_accepted(self, tmp_path: Path) -> None:
        config = write_config(tmp_path / "config.toml", '[server]\nhost = "192.168.1.10"\n')

        settings = load_settings(
            config_path=config,
            environ={"TRIAGELENS_SERVER__AUTH_TOKEN": "a-long-enough-token"},
        )

        assert settings.is_loopback_bind is False

    @pytest.mark.parametrize("host", ["127.0.0.1", "127.0.0.53", "::1", "localhost"])
    def test_loopback_hosts_need_no_token(self, host: str) -> None:
        assert Settings(server={"host": host}).is_loopback_bind is True

    def test_the_error_message_never_echoes_the_token(self, tmp_path: Path) -> None:
        config = write_config(
            tmp_path / "config.toml",
            """
            [server]
            host = "0.0.0.0"
            auth_token = "tooshort"
            """,
        )
        with pytest.raises(ConfigError) as excinfo:
            load_settings(config_path=config, environ={})

        assert "tooshort" not in str(excinfo.value)
        assert "auth_token" in str(excinfo.value)


class TestCsList:
    def test_a_string_becomes_a_single_item(self) -> None:
        assert Settings(server={"allowed_hosts": "example.test"}).server.allowed_hosts == [
            "example.test"
        ]

    def test_a_comma_separated_string_becomes_a_list(self) -> None:
        settings = Settings(server={"allowed_hosts": "a.test, b.test"})
        assert settings.server.allowed_hosts == ["a.test", "b.test"]

    def test_a_list_is_normalised_and_deduplicated(self) -> None:
        settings = Settings(server={"allowed_hosts": ["A.test", "b.test", "A.test"]})
        assert settings.server.allowed_hosts == ["a.test", "b.test"]

    def test_an_empty_entry_is_dropped(self) -> None:
        assert Settings(server={"allowed_hosts": ["a.test", "", "  "]}).server.allowed_hosts == [
            "a.test"
        ]

    def test_extra_hosts_join_the_loopback_allowlist(self) -> None:
        names = Settings(server={"allowed_hosts": "triage.internal"}).allowed_host_names
        assert {"localhost", "127.0.0.1", "::1", "triage.internal"} <= names


class TestHostHelpers:
    @pytest.mark.parametrize(
        ("host", "expected"),
        [
            ("127.0.0.1", True),
            ("127.9.9.9", True),
            ("::1", True),
            ("[::1]", True),
            ("localhost", True),
            ("LOCALHOST", True),
            ("0.0.0.0", False),
            ("192.168.1.1", False),
            ("example.com", False),
            ("127.0.0.1.evil.com", False),
            ("", False),
        ],
    )
    def test_is_loopback_host(self, host: str, expected: bool) -> None:
        assert is_loopback_host(host) is expected

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("Example.Test:8787", "example.test"),
            ("EXAMPLE.test", "example.test"),
            ("[::1]:8787", "::1"),
            ("[::1]", "::1"),
            ("::1", "::1"),
            ("  spaced.test  ", "spaced.test"),
            ("127.0.0.1:1", "127.0.0.1"),
            ("", ""),
        ],
    )
    def test_normalize_host(self, value: str, expected: str) -> None:
        assert normalize_host(value) == expected

    def test_csp_allows_the_websocket_origin_only_for_non_loopback_binds(self) -> None:
        loopback = Settings(server={"host": "127.0.0.1", "port": 8787})
        assert "ws://127.0.0.1:*" in loopback.csp_connect_src()
        assert "ws://127.0.0.1:8787" not in loopback.csp_connect_src()

        lan = Settings(
            server={"host": "10.0.0.5", "port": 9000, "auth_token": "a-long-enough-token"}
        )
        assert "ws://10.0.0.5:9000" in lan.csp_connect_src()


class TestBounds:
    @pytest.mark.parametrize("port", [0, -1, 65536, 99999])
    def test_an_out_of_range_port_is_rejected(self, port: int) -> None:
        with pytest.raises(ValidationError):
            Settings(server={"port": port})

    def test_a_negative_worker_count_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Settings(limits={"worker_processes": -1})

    def test_limits_must_be_positive(self) -> None:
        with pytest.raises(ValidationError):
            Settings(limits={"max_upload_gb": 0})

    def test_an_archive_depth_below_one_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Settings(limits={"max_archive_depth": 0})

    def test_worker_count_zero_means_auto(self) -> None:
        assert Settings(limits={"worker_processes": 0}).effective_worker_processes >= 1
        assert Settings(limits={"worker_processes": 3}).effective_worker_processes == 3
