"""FastAPI application factory.

``create_app()`` wires the middleware stack, the routers and the static frontend
mount, and owns the startup sequence: structured logging, the SQLite capability
check (FTS5 and JSON1, spec 00 section 5) and the migration run (spec 02
section 7).

Middleware is added innermost-first because Starlette runs the most recently
added middleware outermost. The resulting order is::

    request -> AccessLog -> SecurityHeaders -> HostValidation -> BearerAuth -> routes
               (logs)       (adds headers)    (rejects bad Host) (requires token)
"""

from __future__ import annotations

import sqlite3
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import Scope

from app.api.middleware import (
    API_PREFIX,
    HTTP_NOT_FOUND,
    AccessLogMiddleware,
    BearerAuthMiddleware,
    HostValidationMiddleware,
    SecurityHeadersMiddleware,
)
from app.api.routers import ROUTERS
from app.config import Settings, load_settings
from app.db.connection import Database, SqliteCapabilityError, SqliteTooNewError
from app.db.migrations import apply_migrations
from app.db.repositories.audit import AuditRepository
from app.errors import ApiError, ErrorCode
from app.util.logging import configure_logging, get_logger
from app.version import APP_NAME, APP_VERSION

logger = get_logger("main")

#: Logged when the built frontend is missing, so the API still works in dev.
_STATIC_MISSING = (
    "frontend build not found at {path}; run 'make build' (or 'make dev' for the "
    "Vite dev server). The API is unaffected."
)


class SPAStaticFiles(StaticFiles):
    """Static files with history-API fallback.

    Any GET that does not resolve to a file returns ``index.html`` so client-side
    routes such as ``/alerts`` survive a hard refresh. Two kinds of request are
    excluded, because answering them with HTML would hide a real problem:

    * asset paths, since a missing ``.js`` file should not return an HTML page;
    * ``/api`` paths, since an unknown endpoint must return the JSON error
      envelope from spec 06 rather than a 200 with the SPA shell.
    """

    async def get_response(self, path: str, scope: Scope) -> Any:
        """Serve ``path``, falling back to ``index.html`` for navigations."""
        try:
            return await super().get_response(path, scope)
        except StarletteHTTPException as exc:
            # Starlette normalises ``path`` to OS separators, so Windows would
            # hand us ``api\\nope``. The raw scope path is always slash-delimited.
            raw = scope.get("path", path)
            if exc.status_code != HTTP_NOT_FOUND or _looks_like_asset(raw) or _is_api_path(raw):
                raise
            return await super().get_response("index.html", scope)


def _looks_like_asset(path: str) -> bool:
    """True for URLs that must 404 rather than fall back to the shell."""
    last = path.rsplit("/", 1)[-1]
    return "." in last and not last.endswith(".")


def _is_api_path(path: str) -> bool:
    """True for ``/api`` and everything under it."""
    trimmed = path.strip("/")
    return trimmed == API_PREFIX.strip("/") or trimmed.startswith(f"{API_PREFIX.strip('/')}/")


def _error_response(error: ApiError, *, status_code: int | None = None) -> JSONResponse:
    """Render an :class:`ApiError` using the spec 06 envelope."""
    return JSONResponse(status_code=status_code or error.status_code, content=error.envelope())


def _register_exception_handlers(app: FastAPI) -> None:
    """Map every error onto the spec 06 envelope."""

    @app.exception_handler(ApiError)
    async def _api_error(_: Request, exc: ApiError) -> JSONResponse:
        return _error_response(exc)

    @app.exception_handler(RequestValidationError)
    async def _validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        problems = [
            {
                "field": ".".join(str(part) for part in error["loc"][1:]) or str(error["loc"][-1]),
                "message": error["msg"],
                "type": error["type"],
            }
            for error in exc.errors()
        ]
        return _error_response(
            ApiError(ErrorCode.VALIDATION_ERROR, "request validation failed", errors=problems)
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        mapping = {
            401: ErrorCode.UNAUTHORIZED,
            403: ErrorCode.FORBIDDEN_PATH,
            404: ErrorCode.NOT_FOUND,
            405: ErrorCode.VALIDATION_ERROR,
            409: ErrorCode.CONFLICT,
            413: ErrorCode.UPLOAD_TOO_LARGE,
            422: ErrorCode.VALIDATION_ERROR,
        }
        code = mapping.get(exc.status_code, ErrorCode.INTERNAL)
        detail = exc.detail if isinstance(exc.detail, str) else "request failed"
        # A wrong method on a known path is the caller's mistake, so the status
        # stays 405; only the code needs a value, since spec 06 lists no 405 code.
        return _error_response(ApiError(code, detail), status_code=exc.status_code)

    @app.exception_handler(sqlite3.Error)
    async def _sqlite_error(_: Request, exc: sqlite3.Error) -> JSONResponse:
        logger.error("database error", extra={"detail": str(exc)}, exc_info=exc)
        return _error_response(ApiError(ErrorCode.INTERNAL, "internal database error"))

    @app.exception_handler(Exception)
    async def _unhandled(_: Request, exc: Exception) -> JSONResponse:
        logger.error("unhandled error", extra={"detail": str(exc)}, exc_info=exc)
        return _error_response(ApiError(ErrorCode.INTERNAL, "internal server error"))


def _startup(settings: Settings) -> Database:
    """Verify SQLite, open the database and bring the schema up to date."""
    database = Database(settings.db_path)
    database.capabilities.require()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    settings.cases_dir.mkdir(parents=True, exist_ok=True)
    settings.reports_dir.mkdir(parents=True, exist_ok=True)
    settings.logs_dir.mkdir(parents=True, exist_ok=True)
    settings.custom_rules_dir.mkdir(parents=True, exist_ok=True)
    applied = apply_migrations(database.writer, settings.migrations_dir)
    logger.info(
        "database ready",
        extra={
            "db_path": str(settings.db_path),
            "sqlite_version": database.capabilities.sqlite_version,
            "migrations_applied": applied,
        },
    )
    return database


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the ASGI application.

    Passing ``settings`` skips configuration discovery, which is how tests point
    the app at a temporary data directory.
    """
    resolved = settings if settings is not None else load_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        configure_logging(
            level=resolved.logging.level,
            log_file=resolved.log_file,
            file_max_bytes=resolved.logging.file_max_bytes,
            file_backup_count=resolved.logging.file_backup_count,
            console=resolved.logging.console,
            secrets=(resolved.server.auth_token,),
        )
        logger.info(
            "starting",
            extra={
                "app": APP_NAME,
                "version": APP_VERSION,
                "bind": resolved.server.bind_display,
                "data_dir": str(resolved.data_dir),
                "auth_required": not resolved.is_loopback_bind,
                "enrichment_allowed": resolved.network.allow_enrichment,
            },
        )
        try:
            database = _startup(resolved)
        except SqliteTooNewError:
            logger.error("database schema is newer than this build; refusing to start")
            raise
        except SqliteCapabilityError as exc:
            logger.error("sqlite capability check failed", extra={"detail": str(exc)})
            raise
        app.state.settings = resolved
        app.state.database = database
        app.state.audit = AuditRepository(database.writer)
        app.state.ready = True
        if not app.state.frontend_mounted:
            logger.warning(_STATIC_MISSING.format(path=resolved.static_dir))
        try:
            yield
        finally:
            app.state.ready = False
            database.close()
            logger.info("stopped", extra={"version": APP_VERSION})

    app = FastAPI(
        title=APP_NAME,
        version=APP_VERSION,
        description="Standalone, fully local log triage tool.",
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )
    app.state.settings = resolved
    app.state.ready = False

    _register_exception_handlers(app)

    for router in ROUTERS:
        app.include_router(router)

    # Innermost first: each add_middleware wraps the previous one.
    app.add_middleware(BearerAuthMiddleware, settings=resolved)
    app.add_middleware(HostValidationMiddleware, settings=resolved)
    app.add_middleware(SecurityHeadersMiddleware, settings=resolved)
    app.add_middleware(AccessLogMiddleware)

    index = resolved.static_dir / "index.html"
    frontend_mounted = index.is_file()
    if frontend_mounted:
        app.mount(
            "/", SPAStaticFiles(directory=str(resolved.static_dir), html=True), name="frontend"
        )

    app.state.frontend_mounted = frontend_mounted
    return app


def run() -> None:
    """Console entry point used by ``scripts/run.sh`` and ``scripts/run.ps1``."""
    import uvicorn

    settings = load_settings()
    uvicorn.run(
        "app.main:create_app",
        factory=True,
        host=settings.server.host,
        port=settings.server.port,
        log_config=None,
        access_log=False,
    )


if __name__ == "__main__":
    # `python -m app.main` is how the container and the run scripts start the
    # server. Without this guard the module only defines names and exits 0,
    # which looks like a silent startup failure.
    run()


__all__ = ["SPAStaticFiles", "create_app", "run"]
