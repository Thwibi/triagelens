"""Print a redacted diagnostic report for support (spec 10 section 5).

Everything here is safe to paste into a bug report: version numbers, the
effective configuration with secrets masked, the tail of the application log and
(optionally) the live ``/api/health`` payload. Event content is never touched -
the log holds operational lines only, and no database rows are read.

Usage::

    python scripts/diag.py
    python scripts/diag.py --health
    python scripts/diag.py --out diag.json
"""

from __future__ import annotations

import argparse
import json
import platform
import re
import sqlite3
import sys
import urllib.error
import urllib.request
from collections import deque
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"

#: Keys whose values are secrets and must never leave the machine.
_SECRET_KEY = re.compile(
    r"token|secret|password|passwd|credential|api[_-]?key", re.IGNORECASE
)

#: How many trailing log lines to include by default.
LOG_TAIL_LINES = 50


def _add_backend_to_path() -> None:
    if str(BACKEND) not in sys.path:
        sys.path.insert(0, str(BACKEND))


def _redact(value: Any) -> Any:
    """Recursively replace secret-looking values with a fixed mask.

    Applied to the configuration only: the mask is the same for every secret so
    the report never reveals even the shape of a token.
    """
    if isinstance(value, dict):
        return {
            key: "***" if _SECRET_KEY.search(key) else _redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


def _versions() -> dict[str, str]:
    """Interpreter, platform, SQLite and application versions."""
    _add_backend_to_path()
    from app.version import APP_VERSION

    return {
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "sqlite": sqlite3.sqlite_version,
        "triagelens": f"app {APP_VERSION}",
    }


def _recent_log(log_file: Path, lines: int) -> list[str]:
    """The last ``lines`` lines of the log, or a note when it is absent."""
    if not log_file.is_file():
        return [f"(no log file at {log_file})"]
    tail: deque[str] = deque(maxlen=lines)
    try:
        with log_file.open("r", encoding="utf-8", errors="replace") as handle:
            tail.extend(handle)
    except OSError as error:
        return [f"(could not read {log_file}: {error})"]
    return [line.rstrip("\n") for line in tail]


def _health(base_url: str, timeout: float) -> Any:
    """Fetch ``/api/health`` from a running server, or describe why it failed."""
    url = f"{base_url.rstrip('/')}/api/health"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, ValueError) as error:
        return {"unreachable": f"{url}: {error}"}


def main(argv: list[str] | None = None) -> int:
    """Assemble and print the report; return a process exit code."""
    parser = argparse.ArgumentParser(
        prog="diag.py", description="TriageLens diagnostics."
    )
    parser.add_argument("--config", type=Path, default=None, help="path to config.toml")
    parser.add_argument(
        "--health", action="store_true", help="also query a running /api/health"
    )
    parser.add_argument(
        "--health-timeout", type=float, default=2.0, help="health request timeout"
    )
    parser.add_argument(
        "--log-lines", type=int, default=LOG_TAIL_LINES, help="log lines to include"
    )
    parser.add_argument(
        "--out", type=Path, default=None, help="write JSON here instead of stdout"
    )
    args = parser.parse_args(argv)

    _add_backend_to_path()
    from app.config import load_settings

    settings = load_settings(args.config)

    report: dict[str, Any] = {
        "versions": _versions(),
        "config_path": str(settings.config_path)
        if settings.config_path
        else "(defaults)",
        "config": _redact(settings.model_dump(mode="json")),
        "log_file": str(settings.log_file),
        "recent_log": _recent_log(settings.log_file, args.log_lines),
    }
    if args.health:
        base_url = f"http://{settings.server.host}:{settings.server.port}"
        report["health"] = _health(base_url, args.health_timeout)

    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.out is not None:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(rendered, encoding="utf-8")
        print(f"wrote {args.out}")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
