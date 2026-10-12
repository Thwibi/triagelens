"""Cross-platform task runner for TriageLens.

``make`` is not available everywhere (notably stock Windows), so this script is
the single source of truth for the project tasks and ``Makefile`` delegates to
it. Every task works from the repository root regardless of the caller's cwd.

Usage::

    python scripts/task.py lint
    python scripts/task.py typecheck
    python scripts/task.py test
    python scripts/task.py build
    python scripts/task.py all

Exit codes are the underlying tool's own: 0 for success, non-zero on failure.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
FRONTEND = ROOT / "frontend"

#: Python version Ruff should assume for the tooling scripts.
SCRIPTS_TARGET = "py312"

#: Packages installed with the ``dev`` extra.
BACKEND_DEV_PACKAGES = (
    "httpx",
    "pytest",
    "pytest-cov",
    "coverage",
    "mypy",
    "ruff",
    "types-PyYAML",
    "types-regex",
)


def venv_python(root: Path = ROOT) -> Path:
    """The interpreter of the project virtual environment.

    Windows and POSIX name it differently, so both layouts are checked. When no
    environment exists the current interpreter is used, which keeps the script
    usable inside a container or CI image.
    """
    for candidate in (
        root / ".venv" / "Scripts" / "python.exe",
        root / ".venv" / "bin" / "python",
    ):
        if candidate.is_file():
            return candidate
    return Path(sys.executable)


def _log(message: str) -> None:
    """Progress output on stderr, so stdout stays free for tool output."""
    print(f"[task] {message}", file=sys.stderr, flush=True)


def _run(argv: Sequence[str], *, cwd: Path, env: dict[str, str] | None = None) -> int:
    """Run a command, streaming its output, and return its exit code."""
    _log(f"$ {' '.join(argv)} (in {cwd})")
    merged = {**os.environ, **(env or {})}
    completed = subprocess.run(argv, cwd=str(cwd), env=merged, check=False)
    return completed.returncode


def _python_module(module: str, *args: str) -> list[str]:
    """``<venv python> -m <module> ...`` using the project environment."""
    return [str(venv_python()), "-m", module, *args]


def _npm() -> str:
    """The npm executable, resolving Windows' ``npm.cmd`` shim."""
    found = shutil.which("npm")
    if found is None:
        raise SystemExit(
            "npm was not found on PATH. Install Node.js 20 or newer to build the frontend."
        )
    return found


def _npm_has_node() -> bool:
    """True when the npm shim resolves to a usable Node runtime."""
    try:
        completed = subprocess.run(
            [_npm(), "--version"], capture_output=True, text=True, check=False
        )
    except OSError:
        return False
    return completed.returncode == 0


# --------------------------------------------------------------------------
# Tasks
# --------------------------------------------------------------------------


def task_backend_install() -> int:
    """Create the environment and install the backend with dev extras."""
    if not venv_python().exists() or venv_python() == Path(sys.executable):
        _log("creating .venv")
        code = _run([sys.executable, "-m", "venv", str(ROOT / ".venv")], cwd=ROOT)
        if code:
            return code
    python = str(venv_python())
    _log("upgrading pip")
    code = _run([python, "-m", "pip", "install", "--upgrade", "pip"], cwd=ROOT)
    if code:
        return code
    packages = [*BACKEND_DEV_PACKAGES, "-e", str(BACKEND)]
    return _run([python, "-m", "pip", "install", *packages], cwd=ROOT)


def task_backend_lint() -> int:
    """Ruff lint plus a formatting check."""
    python = _python_module("ruff", "check", ".")
    code = _run(python, cwd=BACKEND)
    if code:
        return code
    return _run(_python_module("ruff", "format", "--check", "."), cwd=BACKEND)


def task_scripts_lint() -> int:
    """Lint and format-check the repository tooling.

    ``scripts/`` sits outside ``backend/``, so it has no pyproject of its own and
    Ruff would otherwise guess a Python version from the wrong side. Passing the
    target explicitly keeps ``tomllib`` recognised as standard library.
    """
    target = ["--target-version", SCRIPTS_TARGET]
    code = _run(
        _python_module("ruff", "check", *target, str(ROOT / "scripts")), cwd=ROOT
    )
    if code:
        return code
    return _run(
        _python_module("ruff", "format", "--check", *target, str(ROOT / "scripts")),
        cwd=ROOT,
    )


def task_backend_format() -> int:
    """Apply Ruff's formatter and safe lint fixes."""
    code = _run(_python_module("ruff", "check", "--fix", "."), cwd=BACKEND)
    if code:
        return code
    return _run(_python_module("ruff", "format", "."), cwd=BACKEND)


def task_backend_typecheck() -> int:
    """Strict mypy over the application and its tests."""
    return _run(_python_module("mypy", "-p", "app", "-p", "tests"), cwd=BACKEND)


def task_backend_test() -> int:
    """Run the backend test suite.

    ``tests/perf`` is excluded: it measures wall-clock time, which is noise under
    a shared machine and would make this gate flaky. Run it deliberately with
    ``make perf``.
    """
    return _run(_python_module("pytest", "--ignore=tests/perf"), cwd=BACKEND)


def task_perf() -> int:
    """Run the benchmarks and rewrite ``docs/perf-results.md``."""
    return _run([str(venv_python()), str(ROOT / "scripts" / "run_perf.py")], cwd=ROOT)


def task_perf_e2e() -> int:
    """Run the spec 09 section 8 end-to-end targets.

    The scale comes from ``TRIAGELENS_PERF_SCALE`` (``full`` by default, the spec
    size; ``smoke`` for a laptop), which the Makefile's ``SCALE`` variable sets.
    """
    scale = os.environ.get("TRIAGELENS_PERF_SCALE") or "full"
    return _run(
        [
            str(venv_python()),
            str(ROOT / "scripts" / "run_perf.py"),
            "--e2e",
            "--scale",
            scale,
        ],
        cwd=ROOT,
    )


def task_package() -> int:
    """Build the offline install bundle into ``dist/``."""
    return _run(
        [str(venv_python()), str(ROOT / "scripts" / "package_offline.py")], cwd=ROOT
    )


def task_backend_coverage() -> int:
    """Run the backend suite under coverage and enforce a floor."""
    return _run(
        _python_module(
            "pytest",
            "--ignore=tests/perf",
            "--cov=app",
            "--cov-report=term-missing",
            "--cov-fail-under=80",
        ),
        cwd=BACKEND,
    )


def task_frontend_install() -> int:
    """Install pinned frontend dependencies."""
    if not _npm_has_node():
        raise SystemExit(
            "npm is present but no working Node runtime was found on PATH."
        )
    return _run([_npm(), "ci"], cwd=FRONTEND)


def task_frontend_lint() -> int:
    """ESLint over the frontend sources."""
    return _run([_npm(), "run", "lint"], cwd=FRONTEND)


def task_openapi() -> int:
    """Regenerate the committed OpenAPI document and the frontend types.

    The document is written by Python (it inspects the FastAPI app) and the
    TypeScript types are derived from it by ``openapi-typescript``. Run this
    after changing any request model so the frontend sees the new shape.
    """
    code = _run(
        [str(venv_python()), str(ROOT / "scripts" / "export_openapi.py")], cwd=ROOT
    )
    if code:
        return code
    return _run([_npm(), "run", "gen:api"], cwd=FRONTEND)


def task_openapi_check() -> int:
    """Fail when the committed OpenAPI document or generated types have drifted.

    Regenerates both into place and asks git whether anything changed, so a
    stale artifact is caught before it is merged rather than after a consuming
    screen breaks.
    """
    code = task_openapi()
    if code:
        return code
    return _run(
        [
            "git",
            "diff",
            "--exit-code",
            "--",
            "frontend/src/api/openapi.json",
            "frontend/src/api/openapi.d.ts",
        ],
        cwd=ROOT,
    )


def task_frontend_typecheck() -> int:
    """TypeScript in no-emit mode."""
    return _run([_npm(), "run", "typecheck"], cwd=FRONTEND)


def task_frontend_test() -> int:
    """Frontend unit tests."""
    return _run([_npm(), "run", "test"], cwd=FRONTEND)


def task_frontend_build() -> int:
    """Production build into ``backend/app/static``."""
    return _run([_npm(), "run", "build"], cwd=FRONTEND)


def task_e2e() -> int:
    """Browser end-to-end tests (Playwright) against the built app.

    Builds the frontend into ``backend/app/static`` first because the harness
    (`e2e/serve.mjs`) serves the production bundle and the API from one origin.
    Requires a project virtualenv and ``npm run e2e:install`` once for Chromium.
    """
    code = task_frontend_build()
    if code:
        return code
    return _run([_npm(), "run", "e2e"], cwd=FRONTEND)


def task_frontend_budget() -> int:
    """Enforce the spec 07 bundle-size budget on the built frontend.

    Gzips everything under ``backend/app/static`` and fails above 1.5 MB, so it
    must run after a build (``frontend-build``/``e2e`` produce one).
    """
    return _run([_npm(), "run", "budget"], cwd=FRONTEND)


def task_dev() -> int:
    """Run the Vite dev server with the API proxied to port 8787."""
    return _run([_npm(), "run", "dev"], cwd=FRONTEND)


def task_backend_run() -> int:
    """Serve the API and the built frontend from one process."""
    return _run(_python_module("app.main"), cwd=BACKEND)


def task_lint() -> int:
    """Lint the backend, the tooling and the frontend."""
    for step in (task_backend_lint, task_scripts_lint, task_frontend_lint):
        code = step()
        if code:
            _log(f"{step.__name__} failed with exit code {code}")
            return code
    return 0


def task_typecheck() -> int:
    """Type-check both sides."""
    code = task_backend_typecheck()
    if code:
        return code
    return task_frontend_typecheck()


def task_test() -> int:
    """Test both sides."""
    code = task_backend_test()
    if code:
        return code
    return task_frontend_test()


def task_build() -> int:
    """Install, check and build everything for production."""
    for step in (
        task_backend_install,
        task_backend_lint,
        task_backend_typecheck,
        task_backend_test,
        task_frontend_install,
        task_frontend_lint,
        task_frontend_typecheck,
        task_frontend_test,
        task_frontend_build,
        task_frontend_budget,
    ):
        code = step()
        if code:
            _log(f"{step.__name__} failed with exit code {code}")
            return code
    return 0


def task_all() -> int:
    """Every quality gate: lint, typecheck, test and lockfile freshness."""
    for step in (
        task_lint,
        task_typecheck,
        task_test,
        task_lock_check,
        task_openapi_check,
    ):
        code = step()
        if code:
            _log(f"{step.__name__} failed with exit code {code}")
            return code
    return 0


def task_backend_lock() -> int:
    """Regenerate the hashed runtime lockfile from pyproject."""
    return _run([str(venv_python()), str(ROOT / "scripts" / "gen_lock.py")], cwd=ROOT)


def task_lock_check() -> int:
    """Fail if the lockfile has drifted from pyproject or PyPI."""
    return _run(
        [str(venv_python()), str(ROOT / "scripts" / "gen_lock.py"), "--check"],
        cwd=ROOT,
    )


def task_install() -> int:
    """Install backend and frontend development dependencies."""
    for step in (task_backend_install, task_frontend_install):
        code = step()
        if code:
            return code
    return 0


def task_docker_build() -> int:
    """Build the production container image."""
    if shutil.which("docker") is None:
        raise SystemExit("docker was not found on PATH.")
    return _run(
        ["docker", "build", "-f", "docker/Dockerfile", "-t", "triagelens:local", "."],
        cwd=ROOT,
    )


TASKS: dict[str, Callable[[], int]] = {
    "install": task_install,
    "backend-install": task_backend_install,
    "backend-lint": task_backend_lint,
    "scripts-lint": task_scripts_lint,
    "backend-format": task_backend_format,
    "backend-typecheck": task_backend_typecheck,
    "backend-test": task_backend_test,
    "backend-coverage": task_backend_coverage,
    "perf": task_perf,
    "perf-e2e": task_perf_e2e,
    "package": task_package,
    "backend-lock": task_backend_lock,
    "lock-check": task_lock_check,
    "backend-run": task_backend_run,
    "frontend-install": task_frontend_install,
    "frontend-lint": task_frontend_lint,
    "frontend-typecheck": task_frontend_typecheck,
    "frontend-test": task_frontend_test,
    "frontend-build": task_frontend_build,
    "frontend-budget": task_frontend_budget,
    "e2e": task_e2e,
    "openapi": task_openapi,
    "openapi-check": task_openapi_check,
    "dev": task_dev,
    "lint": task_lint,
    "typecheck": task_typecheck,
    "test": task_test,
    "build": task_build,
    "all": task_all,
    "docker-build": task_docker_build,
}


def main(argv: Sequence[str] | None = None) -> int:
    """Run one or more tasks in order."""
    parser = argparse.ArgumentParser(
        prog="task.py", description="TriageLens development tasks."
    )
    parser.add_argument("task", nargs="+", choices=sorted(TASKS), help="task(s) to run")
    args = parser.parse_args(argv)

    for name in args.task:
        code = TASKS[name]()
        if code:
            _log(f"{name} failed with exit code {code}")
            return code
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
