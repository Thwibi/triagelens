"""Structured JSON logging (spec 01 section 7).

Log lines are single-line JSON objects on stdout and in a rotating file under
``<data_dir>/logs/triagelens.log`` (20 MB x 5).

Two rules from spec 01 section 7 are enforced mechanically rather than by
convention:

* secrets are never written - a redacting filter removes the auth token and
  anything that looks like a credential from every record, and
* log records are size-bounded, so a hostile 1 MB log line cannot be reflected
  into the log stream.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import re
import sys
import threading
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Final

#: Log record attributes that are not user-supplied context.
_RESERVED: Final[frozenset[str]] = frozenset(
    {
        "args",
        "asctime",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "module",
        "msecs",
        "message",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "taskName",
        "thread",
        "threadName",
    }
)

#: Keys whose values are masked regardless of content.
_SECRET_KEYS: Final[frozenset[str]] = frozenset(
    {
        "api_key",
        "apikey",
        "auth",
        "authorization",
        "auth_token",
        "cookie",
        "credential",
        "password",
        "secret",
        "session",
        "token",
    }
)

#: ``key=value`` / ``key: value`` pairs whose value looks like a credential.
_CREDENTIAL_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"(?i)\b(auth[_-]?token|api[_-]?key|password|secret|bearer)\b\s*[:=]\s*\S+"
)

#: Longest rendered value kept in a record; log content is never echoed whole.
_MAX_VALUE_CHARS: Final[int] = 2048

#: Nesting depth past which a logged structure is replaced wholesale. Guards
#: against a self-referential mapping turning logging into an infinite walk.
_MAX_VALUE_DEPTH: Final[int] = 6

_configured = False
_lock = threading.Lock()
_secrets: tuple[str, ...] = ()


def _redact_text(text: str) -> str:
    """Mask registered secrets and credential-shaped substrings."""
    for secret in _secrets:
        if secret and secret in text:
            text = text.replace(secret, "***redacted***")
    return _CREDENTIAL_PATTERN.sub(lambda match: f"{match.group(1)}=***redacted***", text)


def _scrub(value: Any, depth: int = 0) -> Any:
    """Recursively redact and bound a value for safe logging."""
    if depth > _MAX_VALUE_DEPTH:
        return "***truncated***"
    if isinstance(value, str):
        text = value[:_MAX_VALUE_CHARS]
        if len(value) > _MAX_VALUE_CHARS:
            text += "...[truncated]"
        return _redact_text(text)
    if isinstance(value, bytes):
        prefix = value[:_MAX_VALUE_CHARS].decode("utf-8", "replace")
        suffix = "...[truncated]" if len(value) > _MAX_VALUE_CHARS else ""
        return f"<{len(value)} bytes>{_redact_text(prefix)}{suffix}"
    if isinstance(value, Mapping):
        scrubbed: dict[str, Any] = {}
        for key, item in value.items():
            name = str(key)
            if name.strip().lower() in _SECRET_KEYS:
                scrubbed[name] = "***redacted***"
            else:
                scrubbed[name] = _scrub(item, depth + 1)
        return scrubbed
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_scrub(item, depth + 1) for item in value]
    return value


def _exception_fields(exc_info: tuple[Any, Any, Any] | None) -> dict[str, Any] | None:
    if exc_info is None:
        return None
    exc_type, exc_value, _ = exc_info
    return {
        "type": getattr(exc_type, "__name__", str(exc_type)),
        "message": _redact_text(str(exc_value)),
    }


class JsonFormatter(logging.Formatter):
    """Render a log record as one line of JSON."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": _redact_text(str(record.getMessage())),
        }
        if record.exc_info is not None:
            exception = _exception_fields(record.exc_info)
            if exception is not None:
                payload["exception"] = exception
        if record.stack_info:
            payload["stack"] = _redact_text(record.stack_info)
        for key, value in record.__dict__.items():
            if key not in _RESERVED and not key.startswith("_"):
                payload[key] = _scrub(value)
        return json.dumps(payload, ensure_ascii=False, default=str)


class SecretRedactionFilter(logging.Filter):
    """Scrub secrets before any handler formats the record."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = _redact_text(str(record.msg))
        if record.args:
            if isinstance(record.args, Mapping):
                record.args = {key: _scrub(value) for key, value in record.args.items()}
            elif isinstance(record.args, tuple):
                record.args = tuple(_scrub(value) for value in record.args)
        for key, value in list(record.__dict__.items()):
            if key in _RESERVED or key.startswith("_"):
                continue
            if key.strip().lower() in _SECRET_KEYS:
                record.__dict__[key] = "***redacted***"
            else:
                record.__dict__[key] = _scrub(value)
        return True


def configure_logging(
    *,
    level: str = "INFO",
    log_file: Path | None = None,
    file_max_bytes: int = 20 * 1024 * 1024,
    file_backup_count: int = 5,
    console: bool = True,
    secrets: tuple[str, ...] = (),
) -> None:
    """Install the JSON handlers on the root logger. Safe to call repeatedly."""
    global _configured, _secrets  # noqa: PLW0603 - process-wide logging setup

    with _lock:
        _secrets = tuple(secret for secret in secrets if secret)
        root = logging.getLogger()
        for handler in list(root.handlers):
            root.removeHandler(handler)
            handler.close()

        root.setLevel(level)
        for existing in root.filters:
            if isinstance(existing, SecretRedactionFilter):
                root.removeFilter(existing)
        redaction = SecretRedactionFilter()
        root.addFilter(redaction)

        formatter = JsonFormatter()
        if console:
            stream = logging.StreamHandler(sys.stdout)
            stream.setFormatter(formatter)
            root.addHandler(stream)

        if log_file is not None:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            rotating: logging.Handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=file_max_bytes,
                backupCount=file_backup_count,
                encoding="utf-8",
            )
            rotating.setFormatter(formatter)
            root.addHandler(rotating)

        # uvicorn installs its own handlers; route them through ours instead.
        for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
            logger = logging.getLogger(name)
            logger.handlers = []
            logger.propagate = True
        logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
        _configured = True


def is_configured() -> bool:
    """True once :func:`configure_logging` has run."""
    return _configured


def get_logger(name: str) -> logging.Logger:
    """Return a namespaced logger; ``app`` is the root namespace."""
    return logging.getLogger(f"app.{name}" if not name.startswith("app") else name)


@contextmanager
def log_context(logger: logging.Logger, **fields: Any) -> Iterator[logging.Logger]:
    """Attach ``fields`` to every record logged inside the block.

    Implemented by stacking a filter on the logger, so the context holds across
    modules without threading a dict through every call. Existing record
    attributes win, so an explicit ``extra=`` always overrides the context.
    """
    context = _ContextFilter(fields)
    logger.addFilter(context)
    try:
        yield logger
    finally:
        logger.removeFilter(context)


class _ContextFilter(logging.Filter):
    """Merge context fields into each record."""

    def __init__(self, fields: Mapping[str, Any]) -> None:
        super().__init__()
        self._fields = fields

    def filter(self, record: logging.LogRecord) -> bool:
        for name, value in self._fields.items():
            if name not in record.__dict__:
                record.__dict__[name] = value
        return True


__all__ = [
    "JsonFormatter",
    "SecretRedactionFilter",
    "configure_logging",
    "get_logger",
    "is_configured",
    "log_context",
]
