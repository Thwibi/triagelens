"""Application identity.

The version is the single source of truth for the ``X-TriageLens-Version``
response header, the ``/api/health`` payload, detection runs and reports.
"""

from __future__ import annotations

APP_NAME = "TriageLens"
APP_VERSION = "0.1.0"
ATTACK_DOMAIN = "enterprise-attack"
NAVIGATOR_VERSION = "5.1.0"
NAVIGATOR_LAYER_VERSION = "4.5"

__version__ = APP_VERSION

__all__ = [
    "APP_NAME",
    "APP_VERSION",
    "ATTACK_DOMAIN",
    "NAVIGATOR_LAYER_VERSION",
    "NAVIGATOR_VERSION",
    "__version__",
]
