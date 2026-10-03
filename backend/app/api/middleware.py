"""ASGI middleware enforcing the HTTP hardening rules of spec 10 section 1.

Three concerns, three middlewares, added outermost-last by
:func:`app.main.create_app`:

1. :class:`SecurityHeadersMiddleware` - required headers on every response,
   including error responses produced by the two middlewares inside it.
2. :class:`HostValidationMiddleware` - rejects unexpected ``Host`` values so a
   hostile DNS name cannot point a browser at the local API (DNS rebinding).
3. :class:`BearerAuthMiddleware` - bearer token on ``/api`` paths whenever the
   server is not bound to loopback.
"""

from __future__ import annotations

import hmac
import json
import time
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any, Final

from app.config import Settings, normalize_host
from app.errors import ApiError, ErrorCode
from app.util.logging import get_logger
from app.version import APP_VERSION

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]

API_PREFIX: Final[str] = "/api"

#: The exact policy from spec 10 section 1.
_CSP_TEMPLATE: Final[str] = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src {connect_src}; "
    "frame-ancestors 'none'; "
    "base-uri 'none'; "
    "form-action 'self'"
)

#: Status meaning "no such resource"; the SPA fallback keys off exactly this code.
HTTP_NOT_FOUND: Final[int] = 404

_STATIC_HEADERS: Final[tuple[tuple[str, str], ...]] = (
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
    ("X-Frame-Options", "DENY"),
    ("X-TriageLens-Version", APP_VERSION),
)


def _raw_headers(scope: Scope) -> list[tuple[str, str]]:
    """Decoded request headers, preserving order and duplicates.

    ASGI carries header names and values as latin-1 bytes; decoding here keeps
    the rest of the module free of byte handling.
    """
    return [
        (name.decode("latin-1").lower(), value.decode("latin-1"))
        for name, value in scope["headers"]
    ]


def _header(headers: list[tuple[str, str]], name: str) -> str | None:
    """First value for ``name``, case-insensitively."""
    wanted = name.lower()
    for key, value in headers:
        if key == wanted:
            return value
    return None


def _query_value(scope: Scope, name: str) -> str | None:
    """One query parameter value from the raw query string."""
    from urllib.parse import parse_qs

    raw = scope.get("query_string", b"")
    if not raw:
        return None
    values = parse_qs(raw.decode("latin-1")).get(name)
    return values[0] if values else None


class SecurityHeadersMiddleware:
    """Attach the required headers to every HTTP response.

    ``Cache-Control: no-store`` is applied to API responses and to the SPA shell;
    hashed build assets under ``/assets`` keep normal caching.
    """

    __slots__ = ("_app", "_csp")

    def __init__(self, app: Callable[..., Awaitable[None]], settings: Settings) -> None:
        self._app = app
        self._csp = _CSP_TEMPLATE.format(connect_src=settings.csp_connect_src())

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in {"http", "websocket"}:
            await self._app(scope, receive, send)
            return

        path: str = scope.get("path", "/")
        no_store = path.startswith(API_PREFIX) or not path.startswith("/assets/")
        policy = self._csp
        headers: tuple[tuple[str, str], ...] = (
            *_STATIC_HEADERS,
            ("Content-Security-Policy", policy),
        )
        if no_store:
            headers = (*headers, ("Cache-Control", "no-store"))

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                existing = [(name, value) for name, value in message.get("headers", [])]
                names = {name.lower() for name, _ in existing}
                extra = [
                    (name.encode("latin-1"), value.encode("latin-1"))
                    for name, value in headers
                    if name.lower().encode("latin-1") not in names
                ]
                message["headers"] = existing + extra
            await send(message)

        await self._app(scope, receive, send_with_headers)


class HostValidationMiddleware:
    """Reject requests whose ``Host`` header is not a configured name.

    Without this, a page on ``evil.example`` could resolve to 127.0.0.1 and issue
    same-origin requests against the local API.

    The allowlist comes from ``server.allowed_hosts`` and is the *only* thing
    accepted. Loopback names are not special-cased here: they must be listed
    explicitly, so widening the allowlist is always a deliberate config change.
    """

    __slots__ = ("_allowed", "_app")

    def __init__(self, app: Callable[..., Awaitable[None]], settings: Settings) -> None:
        self._app = app
        self._allowed = settings.allowed_host_names

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in {"http", "websocket"}:
            await self._app(scope, receive, send)
            return

        raw = _header(_raw_headers(scope), "host")
        if raw is None:
            await self._reject(send, "missing Host header")
            return

        host = normalize_host(raw)
        if host in self._allowed:
            await self._app(scope, receive, send)
            return
        await self._reject(send, "host not allowed", host=host)

    @staticmethod
    async def _reject(send: Send, message: str, **details: Any) -> None:
        error = ApiError(ErrorCode.VALIDATION_ERROR, message, **details)
        await _write_error(send, error)


class BearerAuthMiddleware:
    """Require ``Authorization: Bearer <token>`` on API paths when not loopback.

    WebSocket clients cannot set headers, so spec 06 allows ``?token=`` there.
    Requests from loopback need no token, which is the default deployment.
    """

    __slots__ = ("_app", "_settings")

    def __init__(self, app: Callable[..., Awaitable[None]], settings: Settings) -> None:
        self._app = app
        self._settings = settings

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in {"http", "websocket"}:
            await self._app(scope, receive, send)
            return
        if self._settings.is_loopback_bind:
            await self._app(scope, receive, send)
            return

        path: str = scope.get("path", "/")
        if not path.startswith(API_PREFIX):
            await self._app(scope, receive, send)
            return

        expected = self._settings.server.auth_token
        presented = self._presented_token(scope)
        if presented is not None and hmac.compare_digest(presented, expected):
            await self._app(scope, receive, send)
            return

        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        await _write_error(
            send,
            ApiError(ErrorCode.UNAUTHORIZED, "missing or invalid bearer token"),
            extra_headers=(("WWW-Authenticate", 'Bearer realm="triagelens"'),),
        )

    @staticmethod
    def _presented_token(scope: Scope) -> str | None:
        """Token from the Authorization header, or ``?token=``."""
        authorization = _header(_raw_headers(scope), "authorization")
        if authorization is not None:
            scheme, _, value = authorization.partition(" ")
            if scheme.lower() == "bearer" and value.strip():
                return value.strip()
            return None
        return _query_value(scope, "token")


class AccessLogMiddleware:
    """One structured line per request and WebSocket, including rejected ones.

    Uvicorn's access log is disabled because it is not JSON; this replaces it
    and sits outside the security headers so a request rejected by Host
    validation or bearer auth is still recorded.
    """

    __slots__ = ("_app", "_logger")

    def __init__(self, app: Callable[..., Awaitable[None]]) -> None:
        self._app = app
        self._logger = get_logger("access")

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in {"http", "websocket"}:
            await self._app(scope, receive, send)
            return

        started = time.perf_counter()
        status: dict[str, int] = {}

        async def send_with_status(message: Message) -> None:
            if message["type"] == "http.response.start":
                status["code"] = int(message["status"])
            elif message["type"] == "websocket.accept":
                status["code"] = 101
            elif message["type"] == "websocket.close":
                status.setdefault("code", int(message.get("code", 1000)))
            await send(message)

        try:
            await self._app(scope, receive, send_with_status)
        finally:
            client = scope.get("client")
            self._logger.info(
                "request",
                extra={
                    "method": scope.get("method", scope["type"].upper()),
                    "path": scope.get("path", ""),
                    "status": status.get("code", 0),
                    "duration_ms": round((time.perf_counter() - started) * 1000, 3),
                    "client": client[0] if client else None,
                },
            )


async def _write_error(
    send: Send,
    error: ApiError,
    extra_headers: tuple[tuple[str, str], ...] = (),
) -> None:
    """Serialise an :class:`ApiError` as a spec 06 error response."""
    body = json.dumps(error.envelope(), ensure_ascii=False).encode("utf-8")
    headers: list[tuple[bytes, bytes]] = [
        (b"content-type", b"application/json; charset=utf-8"),
        (b"content-length", str(len(body)).encode("latin-1")),
    ]
    headers.extend(
        (name.encode("latin-1"), value.encode("latin-1")) for name, value in extra_headers
    )
    await send({"type": "http.response.start", "status": error.status_code, "headers": headers})
    await send({"type": "http.response.body", "body": body})


__all__ = [
    "API_PREFIX",
    "HTTP_NOT_FOUND",
    "AccessLogMiddleware",
    "BearerAuthMiddleware",
    "HostValidationMiddleware",
    "SecurityHeadersMiddleware",
]
