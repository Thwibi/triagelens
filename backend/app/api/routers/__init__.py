from __future__ import annotations

from app.api.routers import (
    alerts,
    audit,
    cases,
    detect,
    events,
    health,
    iocs,
    jobs,
    maintenance,
    mitre,
    profiles,
    reports,
    rules,
    settings,
    sources,
    websocket,
)

#: Mounted under /api by the app factory. Health carries its own prefix so the
#: docs endpoints can sit next to it without a second include.
ROUTERS = (
    cases.router,
    sources.router,
    jobs.router,
    detect.router,
    websocket.router,
    settings.router,
    profiles.router,
    iocs.router,
    alerts.router,
    events.router,
    audit.router,
    rules.router,
    mitre.router,
    reports.router,
    maintenance.router,
)

__all__ = [
    "ROUTERS",
    "alerts",
    "audit",
    "cases",
    "detect",
    "events",
    "health",
    "iocs",
    "jobs",
    "maintenance",
    "mitre",
    "profiles",
    "reports",
    "rules",
    "settings",
    "sources",
    "websocket",
]
