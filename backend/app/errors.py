"""Stable API error codes and the error envelope from spec 06 section 1.

Every failure the API surfaces uses the shape::

    {"error": {"code": "...", "message": "...", "details": {...}}}

Codes are part of the public contract: clients branch on them, so they never
change meaning.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any


class ErrorCode(StrEnum):
    """Error codes with their fixed HTTP status (spec 06 section 1)."""

    VALIDATION_ERROR = "VALIDATION_ERROR"
    NOT_FOUND = "NOT_FOUND"
    CONFLICT = "CONFLICT"
    UNSUPPORTED_FORMAT = "UNSUPPORTED_FORMAT"
    ARCHIVE_LIMIT_EXCEEDED = "ARCHIVE_LIMIT_EXCEEDED"
    UPLOAD_TOO_LARGE = "UPLOAD_TOO_LARGE"
    RULE_COMPILE_ERROR = "RULE_COMPILE_ERROR"
    JOB_CANCELLED = "JOB_CANCELLED"
    FORBIDDEN_PATH = "FORBIDDEN_PATH"
    UNAUTHORIZED = "UNAUTHORIZED"
    PDF_UNAVAILABLE = "PDF_UNAVAILABLE"
    INSUFFICIENT_STORAGE = "INSUFFICIENT_STORAGE"
    INTERNAL = "INTERNAL"


#: Fixed HTTP status per code, from the spec 06 section 1 table.
STATUS_BY_CODE: dict[ErrorCode, int] = {
    ErrorCode.VALIDATION_ERROR: 422,
    ErrorCode.NOT_FOUND: 404,
    ErrorCode.CONFLICT: 409,
    ErrorCode.UNSUPPORTED_FORMAT: 422,
    ErrorCode.ARCHIVE_LIMIT_EXCEEDED: 413,
    ErrorCode.UPLOAD_TOO_LARGE: 413,
    ErrorCode.RULE_COMPILE_ERROR: 422,
    ErrorCode.JOB_CANCELLED: 409,
    ErrorCode.FORBIDDEN_PATH: 403,
    ErrorCode.UNAUTHORIZED: 401,
    ErrorCode.PDF_UNAVAILABLE: 422,
    ErrorCode.INSUFFICIENT_STORAGE: 507,
    ErrorCode.INTERNAL: 500,
}


class ApiError(Exception):
    """An error that is safe to render verbatim to the client.

    ``details`` must only ever contain data derived from validated input; it is
    serialised as-is so hosts, rule titles and similar are never leaked by
    accident.
    """

    __slots__ = ("code", "details", "message")

    def __init__(self, code: ErrorCode, message: str, **details: Any) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details: dict[str, Any] = details

    @property
    def status_code(self) -> int:
        """HTTP status for this error code."""
        return STATUS_BY_CODE[self.code]

    def envelope(self) -> dict[str, Any]:
        """Render the spec 06 error body."""
        return {
            "error": {
                "code": str(self.code),
                "message": self.message,
                "details": self.details,
            }
        }


def not_found(what: str, ident: str) -> ApiError:
    """Build a ``NOT_FOUND`` error naming the missing entity."""
    return ApiError(ErrorCode.NOT_FOUND, f"{what} not found", id=ident)


def validation_error(message: str, **details: Any) -> ApiError:
    """Build a ``VALIDATION_ERROR`` error."""
    return ApiError(ErrorCode.VALIDATION_ERROR, message, **details)


__all__ = [
    "STATUS_BY_CODE",
    "ApiError",
    "ErrorCode",
    "not_found",
    "validation_error",
]
