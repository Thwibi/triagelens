from __future__ import annotations

from app.api.routers import cases, health, iocs, jobs, profiles, settings, sources, websocket

#: Mounted under /api by the app factory. Health carries its own prefix so the
#: docs endpoints can sit next to it without a second include.
ROUTERS = (
    cases.router,
    sources.router,
    jobs.router,
    websocket.router,
    settings.router,
    profiles.router,
    iocs.router,
)

__all__ = [
    "ROUTERS",
    "cases",
    "health",
    "iocs",
    "jobs",
    "profiles",
    "settings",
    "sources",
    "websocket",
]
