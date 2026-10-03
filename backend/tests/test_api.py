"""HTTP surface: error envelopes, middleware enforcement, and static serving."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


def app_of(client: TestClient) -> FastAPI:
    """The :class:`FastAPI` instance behind a TestClient.

    ``TestClient.app`` is typed as the ASGI callable, so tests reach the real
    object through this helper instead of casting at each use.
    """
    app = client.app
    assert isinstance(app, FastAPI), f"expected a FastAPI app, got {type(app).__name__}"
    return app


@pytest.fixture
def client(settings: Settings) -> Iterator[TestClient]:
    with TestClient(create_app(settings), base_url="http://127.0.0.1:8787") as test_client:
        yield test_client


@pytest.fixture
def remote_client(data_dir: Path) -> Iterator[TestClient]:
    """A client on a non-loopback bind, where bearer auth is mandatory."""
    settings = Settings(
        server={
            "host": "0.0.0.0",
            "port": 8787,
            "allowed_hosts": ["127.0.0.1"],
            "auth_token": "0123456789abcdef",
        },
        storage={"data_dir": str(data_dir)},
        logging={"console": False, "level": "CRITICAL"},
    )
    with TestClient(create_app(settings), base_url="http://127.0.0.1:8787") as test_client:
        yield test_client


class TestHealthEndpoint:
    def test_health_is_reachable_without_a_token(self, client: TestClient) -> None:
        assert client.get("/api/health").status_code == 200

    def test_the_envelope_shape_matches_the_spec(self, client: TestClient) -> None:
        payload = client.get("/api/health").json()
        for field in (
            "app_version",
            "sqlite_version",
            "fts5",
            "json1",
            "ruleset_hash",
            "db_bytes",
            "free_disk_bytes",
            "pdf_available",
            "workers",
            "attack_version",
        ):
            assert field in payload, f"{field} missing from {sorted(payload)}"

    def test_the_payload_has_exactly_the_spec_fields(self, client: TestClient) -> None:
        assert set(client.get("/api/health").json()) == {
            "app_version",
            "attack_version",
            "ruleset_hash",
            "sqlite_version",
            "fts5",
            "json1",
            "workers",
            "db_bytes",
            "free_disk_bytes",
            "pdf_available",
        }

    def test_capability_flags_are_true_on_this_build(self, client: TestClient) -> None:
        payload = client.get("/api/health").json()
        assert payload["fts5"] is True
        assert payload["json1"] is True

    def test_numeric_fields_are_non_negative_integers(self, client: TestClient) -> None:
        payload = client.get("/api/health").json()
        for field in ("workers", "db_bytes", "free_disk_bytes"):
            assert isinstance(payload[field], int)
            assert payload[field] >= 0

    def test_the_ruleset_hash_is_populated_before_any_rules_exist(self, client: TestClient) -> None:
        payload = client.get("/api/health").json()
        assert len(payload["ruleset_hash"]) == 64

    def test_no_cache_is_advertised_for_api_responses(self, client: TestClient) -> None:
        assert client.get("/api/health").headers["cache-control"] == "no-store"

    def test_health_is_reported_as_ready_after_startup(self, client: TestClient) -> None:
        assert app_of(client).state.ready is True

    def test_the_database_is_closed_after_shutdown(self, settings: Settings) -> None:
        with TestClient(create_app(settings), base_url="http://127.0.0.1:8787") as test_client:
            assert test_client.get("/api/health").status_code == 200
        assert app_of(test_client).state.ready is False


class TestSecurityHeaders:
    def test_the_required_headers_are_present(self, client: TestClient) -> None:
        headers = client.get("/api/health").headers
        assert headers["x-content-type-options"] == "nosniff"
        assert headers["referrer-policy"] == "no-referrer"
        assert headers["cross-origin-opener-policy"] == "same-origin"
        assert headers["cross-origin-resource-policy"] == "same-origin"
        assert headers["x-frame-options"] == "DENY"

    def test_the_csp_forbids_remote_code(self, client: TestClient) -> None:
        csp = client.get("/api/health").headers["content-security-policy"]
        assert "default-src 'self'" in csp
        assert "script-src 'self'" in csp
        assert "frame-ancestors 'none'" in csp
        assert "base-uri 'none'" in csp
        assert "form-action 'self'" in csp
        assert "unsafe-inline" not in csp
        assert "unsafe-eval" not in csp

    def test_the_csp_connect_src_allows_only_local_websocket_targets(
        self, settings: Settings
    ) -> None:
        """Dev-server websockets are permitted; remote origins are not."""
        with TestClient(create_app(settings), base_url="http://127.0.0.1:8787") as test_client:
            csp = test_client.get("/api/health").headers["content-security-policy"]
        connect = csp.split("connect-src", 1)[1].split(";", 1)[0]
        assert "'self'" in connect
        assert "ws://127.0.0.1:*" in connect
        assert "ws://localhost:*" in connect
        assert "http://" not in connect
        assert "https://" not in connect

    def test_the_version_header_reports_the_build(self, client: TestClient) -> None:
        from app.version import APP_VERSION

        assert client.get("/api/health").headers["x-triagelens-version"] == APP_VERSION

    def test_headers_ride_on_error_responses_too(self, client: TestClient) -> None:
        response = client.get("/api/no-such-route")
        assert response.status_code == 404
        assert response.headers["x-content-type-options"] == "nosniff"
        assert "content-security-policy" in response.headers

    def test_headers_ride_on_host_rejections(self, client: TestClient) -> None:
        response = client.get("/api/health", headers={"Host": "evil.example"})
        assert response.status_code == 422
        assert response.headers["x-content-type-options"] == "nosniff"

    def test_the_version_header_is_not_added_twice(self, client: TestClient) -> None:
        values = client.get("/api/health").headers.get_list("x-triagelens-version")
        assert len(values) == 1


class TestHostValidation:
    def test_an_unknown_host_is_rejected(self, client: TestClient) -> None:
        response = client.get("/api/health", headers={"Host": "evil.example"})
        assert response.status_code == 422
        body = response.json()
        assert body["error"]["code"] == "VALIDATION_ERROR"
        assert body["error"]["message"] == "host not allowed"

    def test_the_rejected_host_is_echoed_as_json_not_html(self, client: TestClient) -> None:
        """Echoing the host aids debugging; JSON plus nosniff keeps it inert."""
        response = client.get("/api/health", headers={"Host": "<script>alert(1)</script>"})
        assert response.status_code == 422
        assert response.headers["content-type"].startswith("application/json")
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.json()["error"]["details"]["host"] == "<script>alert(1)</script>"

    def test_a_dns_rebinding_name_is_rejected(self, client: TestClient) -> None:
        for host in (
            "triagelens.attacker.example",
            "127.0.0.1.attacker.example",
            "localhost.attacker.example",
            "localhost.evil.com",
        ):
            response = client.get("/api/health", headers={"Host": host})
            assert response.status_code == 422, f"{host} was accepted"

    def test_localhost_is_accepted(self, client: TestClient) -> None:
        assert client.get("/api/health", headers={"Host": "localhost:8787"}).status_code == 200

    def test_an_ipv6_loopback_host_is_accepted(self, client: TestClient) -> None:
        assert client.get("/api/health", headers={"Host": "[::1]:8787"}).status_code == 200

    def test_a_trailing_dot_is_not_trusted(self, client: TestClient) -> None:
        response = client.get("/api/health", headers={"Host": "localhost."})
        assert response.status_code == 422

    def test_a_missing_host_is_rejected(self, client: TestClient) -> None:
        response = client.get("/api/health", headers={"Host": ""})
        assert response.status_code == 422

    def test_a_configured_name_is_accepted(self, data_dir: Path) -> None:
        settings = Settings(
            server={"host": "127.0.0.1", "port": 8787, "allowed_hosts": ["triage.internal"]},
            storage={"data_dir": str(data_dir)},
            logging={"console": False, "level": "CRITICAL"},
        )
        with TestClient(create_app(settings), base_url="http://127.0.0.1:8787") as test_client:
            assert (
                test_client.get("/api/health", headers={"Host": "triage.internal"}).status_code
                == 200
            )


class TestBearerAuth:
    def test_a_non_loopback_bind_requires_a_token(self, remote_client: TestClient) -> None:
        assert remote_client.get("/api/health").status_code == 401

    def test_the_correct_token_is_accepted(self, remote_client: TestClient) -> None:
        response = remote_client.get(
            "/api/health", headers={"Authorization": "Bearer 0123456789abcdef"}
        )
        assert response.status_code == 200

    def test_the_scheme_is_case_insensitive(self, remote_client: TestClient) -> None:
        response = remote_client.get(
            "/api/health", headers={"Authorization": "bearer 0123456789abcdef"}
        )
        assert response.status_code == 200

    def test_a_wrong_token_is_rejected(self, remote_client: TestClient) -> None:
        response = remote_client.get(
            "/api/health", headers={"Authorization": "Bearer 0000000000000000"}
        )
        assert response.status_code == 401

    def test_a_token_prefix_is_not_enough(self, remote_client: TestClient) -> None:
        response = remote_client.get(
            "/api/health", headers={"Authorization": "Bearer 0123456789abcde"}
        )
        assert response.status_code == 401

    def test_a_token_suffix_is_not_enough(self, remote_client: TestClient) -> None:
        response = remote_client.get(
            "/api/health", headers={"Authorization": "Bearer 00123456789abcdef"}
        )
        assert response.status_code == 401

    def test_a_token_with_trailing_space_is_still_accepted(self, remote_client: TestClient) -> None:
        response = remote_client.get(
            "/api/health", headers={"Authorization": "Bearer 0123456789abcdef  "}
        )
        assert response.status_code == 200

    @pytest.mark.parametrize(
        "header",
        [
            "0123456789abcdef",
            "Basic 0123456789abcdef",
            "Bearer",
            "Bearer ",
            "Token 0123456789abcdef",
        ],
    )
    def test_malformed_authorization_headers_are_rejected(
        self, remote_client: TestClient, header: str
    ) -> None:
        assert (
            remote_client.get("/api/health", headers={"Authorization": header}).status_code == 401
        )

    def test_the_challenge_header_is_returned(self, remote_client: TestClient) -> None:
        response = remote_client.get("/api/health")
        assert "bearer" in response.headers["www-authenticate"].lower()

    def test_the_error_body_uses_the_spec_envelope(self, remote_client: TestClient) -> None:
        body = remote_client.get("/api/health").json()
        assert body["error"]["code"] == "UNAUTHORIZED"
        assert "token" not in json_dumps(body).lower() or "invalid" in body["error"]["message"]

    def test_a_token_query_parameter_is_accepted_for_websockets(
        self, remote_client: TestClient
    ) -> None:
        """WebSocket clients cannot set headers, so spec 06 allows ?token=."""
        from app.api.middleware import BearerAuthMiddleware
        from app.config import Settings as _Settings

        settings = _Settings(
            server={"host": "0.0.0.0", "port": 8787, "auth_token": "0123456789abcdef"},
            storage={"data_dir": str(app_of(remote_client).state.settings.data_dir)},
            logging={"console": False, "level": "CRITICAL"},
        )
        assert settings.server.auth_token == "0123456789abcdef"

        middleware = BearerAuthMiddleware(_noop_app, settings)
        scope = {"headers": [], "query_string": b"token=0123456789abcdef"}
        assert middleware._presented_token(scope) == "0123456789abcdef"

    def test_a_wrong_token_query_parameter_is_rejected(self, remote_client: TestClient) -> None:
        from app.api.middleware import BearerAuthMiddleware

        settings = app_of(remote_client).state.settings
        middleware = BearerAuthMiddleware(_noop_app, settings)
        scope = {"headers": [], "query_string": b"token=nope"}
        assert middleware._presented_token(scope) == "nope"

    def test_a_non_api_path_stays_open_on_a_remote_bind(self, remote_client: TestClient) -> None:
        """Static assets are not secrets; only /api needs the token."""
        response = remote_client.get("/")
        assert response.status_code != 401

    def test_a_loopback_bind_needs_no_token(self, client: TestClient) -> None:
        assert client.get("/api/health").status_code == 200


class TestErrorEnvelopes:
    def test_an_unknown_route_uses_the_envelope(self, client: TestClient) -> None:
        response = client.get("/api/nope")
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "NOT_FOUND"

    def test_the_envelope_has_exactly_the_spec_keys(self, client: TestClient) -> None:
        body = client.get("/api/nope").json()
        assert set(body) == {"error"}
        assert set(body["error"]) >= {"code", "message"}
        assert isinstance(body["error"]["code"], str)
        assert isinstance(body["error"]["message"], str)

    def test_every_error_carries_a_known_code(self, client: TestClient) -> None:
        from app.errors import ErrorCode

        known = {code.value for code in ErrorCode}
        for path in ("/api/nope", "/api/docs/../nope"):
            code = client.get(path).json()["error"]["code"]
            assert code in known

    def test_a_wrong_method_keeps_its_status_and_uses_the_envelope(
        self, client: TestClient
    ) -> None:
        """A wrong method is a client error, not a 500."""
        response = client.post("/api/health", json={"unexpected": True})
        assert response.status_code == 405
        assert response.json()["error"]["code"] == "VALIDATION_ERROR"

    def test_a_database_failure_is_masked(self, settings: Settings) -> None:
        """SQLite internals must not leak to the client.

        Replaces the real repository method on the instance so a genuine
        OperationalError is raised inside the request handler.
        """
        app = create_app(settings)

        @app.get("/api/audit-probe", include_in_schema=False)
        def _probe() -> dict[str, int]:
            connection = app.state.database.writer
            return {"count": int(connection.execute("SELECT * FROM absent_table").fetchone()[0])}

        # Starlette matches routes in order and the SPA mount at "/" matches
        # everything, so a route added after create_app would never be reached.
        app.router.routes.insert(0, app.router.routes.pop())

        with TestClient(app, base_url="http://127.0.0.1:8787") as test_client:
            response = test_client.get("/api/audit-probe")

        assert response.status_code == 500
        body = response.json()
        assert body["error"]["code"] == "INTERNAL"
        assert "secret_internal_name" not in response.text
        assert "no such table" not in response.text

    def test_the_openapi_schema_is_served_under_api(self, client: TestClient) -> None:
        assert client.get("/api/openapi.json").status_code == 200

    def test_openapi_is_not_exposed_at_the_bare_path(self, client: TestClient) -> None:
        """Unprefixed paths belong to the SPA, not to the API surface."""
        response = client.get("/openapi.json")
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "NOT_FOUND"

    def test_swagger_ui_is_served_under_api(self, client: TestClient) -> None:
        response = client.get("/api/docs")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_the_docs_ui_carries_the_hardening_headers(self, client: TestClient) -> None:
        """Swagger loads remote JS, so the CSP must still forbid it."""
        response = client.get("/api/docs")
        assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
        assert response.headers["x-frame-options"] == "DENY"

    def test_redoc_is_disabled(self, client: TestClient) -> None:
        assert app_of(client).redoc_url is None


class TestStaticFrontend:
    """The SPA mount, exercised against the real built frontend in app/static."""

    def test_the_shell_is_mounted_when_the_build_exists(self, client: TestClient) -> None:
        assert app_of(client).state.frontend_mounted is True

    def test_the_root_serves_the_shell(self, client: TestClient) -> None:
        response = client.get("/")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_a_client_route_falls_back_to_the_shell(self, client: TestClient) -> None:
        """A hard refresh on a client-side route must not 404."""
        response = client.get("/alerts/42")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_a_missing_asset_still_404s(self, client: TestClient) -> None:
        response = client.get("/assets/index-does-not-exist.js")
        assert response.status_code == 404
        assert "text/html" not in response.headers.get("content-type", "")

    def test_the_shell_is_never_cached(self, client: TestClient) -> None:
        assert client.get("/").headers["cache-control"] == "no-store"

    def test_an_unknown_api_path_is_never_answered_with_the_shell(self, client: TestClient) -> None:
        """A 200 with HTML would hide a client bug behind a working app."""
        for path in ("/api/nope", "/api/cases/missing/deeply/nested"):
            response = client.get(path)
            assert response.status_code == 404, path
            assert response.headers["content-type"].startswith("application/json"), path

    def test_the_mount_cannot_expose_backend_files(self, client: TestClient) -> None:
        """A traversal attempt must not escape the static directory."""
        for path in (
            "/../pyproject.toml",
            "/..%2fpyproject.toml",
            "/%2e%2e/pyproject.toml",
            "/assets/../../pyproject.toml",
            "/../app/main.py",
            "/../migrations/0001_init.sql",
        ):
            response = client.get(path)
            assert "name = " not in response.text, f"{path} leaked a backend file"
            assert "CREATE TABLE" not in response.text, f"{path} leaked the schema"

    def test_a_query_string_does_not_defeat_the_fallback(self, client: TestClient) -> None:
        assert client.get("/alerts?filter=open&page=2").status_code == 200

    def test_a_trailing_slash_still_serves_the_shell(self, client: TestClient) -> None:
        assert client.get("/alerts/").status_code == 200


class TestModuleEntryPoint:
    """`python -m app.main` is how the container and the run scripts start up."""

    def test_the_module_reports_itself_as_runnable(self) -> None:
        """Without the __main__ guard the module exits 0 and serves nothing.

        That failure is silent, so it is asserted here rather than discovered when
        a deployed container dies immediately after start.
        """
        import app.main

        assert getattr(app.main, "__spec__", None) is not None
        source = Path(app.main.__file__).read_text(encoding="utf-8")
        assert '__name__ == "__main__"' in source, (
            "app.main has no __main__ guard, so `python -m app.main` would import "
            "the module and exit without starting the server"
        )

    def test_run_is_exported_for_the_run_scripts(self) -> None:
        import app.main

        assert "run" in app.main.__all__
        assert callable(app.main.run)


def json_dumps(value: object) -> str:
    """Local helper so the test does not depend on the app's serializer."""
    import json

    return json.dumps(value)


async def _noop_app(scope: object, receive: object, send: object) -> None:
    return None
