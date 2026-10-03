"""API routers."""

from __future__ import annotations

from app.api.routers import health

ROUTERS = (health.router,)

__all__ = ["ROUTERS", "health"]
