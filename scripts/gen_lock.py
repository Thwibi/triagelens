"""Generate ``backend/requirements.lock``: pinned runtime dependencies with hashes.

The Dockerfile installs with ``pip install --require-hashes``, so every artefact
must be pinned to an exact version and a known hash. This script reads the
runtime dependency list from ``backend/pyproject.toml``, walks the dependency
graph using the local environment for versions, then asks PyPI for the
distribution hashes of each pinned version.

Dev extras are deliberately excluded: the image ships the application, not the
tooling. The output is still environment-specific in one respect: a package
resolved conditionally on the running Python version appears if and only if it is
installed here.

Usage::

    python scripts/gen_lock.py          # write backend/requirements.lock
    python scripts/gen_lock.py --check  # fail if it is stale

Run it after changing the runtime dependencies in ``backend/pyproject.toml``, and
commit the result: the lockfile is the authority on what the container installs.
"""

from __future__ import annotations

import json
import re
import sys
import tomllib
import urllib.request
from importlib.metadata import PackageNotFoundError, distribution, requires
from pathlib import Path

from packaging.markers import UndefinedEnvironmentName
from packaging.requirements import Requirement

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
PYPROJECT = BACKEND / "pyproject.toml"
OUTPUT = BACKEND / "requirements.lock"

#: Distributions that are tooling or the project itself, never runtime deps.
EXCLUDED_ROOTS = frozenset({"pip", "setuptools", "wheel", "hatchling", "triagelens"})


def _applies_here(requirement: Requirement, extra: str) -> bool:
    """True when ``requirement`` is needed under the given extra on this interpreter.

    A dependency such as ``exceptiongroup; python_version < '3.11'`` is correctly
    absent on a newer interpreter, so it must be skipped rather than reported as
    missing. Extras are resolved by passing the extra name through, which is how
    ``uvicorn[standard]`` pulls in httptools and friends.
    """
    if requirement.marker is None:
        return True
    try:
        return requirement.marker.evaluate({"extra": extra})
    except UndefinedEnvironmentName:
        return False


def _parse(requirement: str) -> Requirement | None:
    """Parse a requirement line, or None when it is malformed."""
    try:
        return Requirement(requirement)
    except Exception:  # noqa: BLE001 - a malformed line is skipped, not fatal
        return None


def _canonical(name: str) -> str:
    """PEP 503 normalisation, so typing-extensions and typing_extensions match."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _runtime_roots() -> list[tuple[str, frozenset[str]]]:
    """Direct runtime dependencies as (name, requested extras)."""
    with PYPROJECT.open("rb") as handle:
        project = tomllib.load(handle)["project"]
    roots: list[tuple[str, frozenset[str]]] = []
    for line in project["dependencies"]:
        parsed = _parse(line)
        if parsed is None or not _applies_here(parsed, ""):
            continue
        roots.append((parsed.name, frozenset(parsed.extras)))
    return roots


def _runtime_dependencies() -> dict[str, str]:
    """Name to pinned version for the full runtime tree, extras resolved."""
    resolved: dict[str, str] = {}
    pending: list[tuple[str, frozenset[str]]] = _runtime_roots()
    while pending:
        name, extras = pending.pop()
        key = _canonical(name)
        if key.split("-", 1)[0] in EXCLUDED_ROOTS or key in resolved:
            continue
        try:
            dist = distribution(name)
        except PackageNotFoundError:
            print(
                f"{name} is required on this interpreter but is not installed; "
                "install the backend before regenerating the lockfile",
                file=sys.stderr,
            )
            return {}
        resolved[key] = dist.version
        for line in requires(dist.metadata["Name"]) or []:
            parsed = _parse(line)
            if parsed is None:
                continue
            # Evaluate once per extra this package was requested with.
            for extra in sorted(extras | {""}):
                if _applies_here(parsed, extra):
                    pending.append((parsed.name, frozenset(parsed.extras)))
    return resolved


#: The platform the lockfile targets: the container image, python:3.12-slim on
#: linux/amd64. Hashes are platform-specific, so a lockfile generated on another
#: interpreter or OS would not install in the image.
LOCK_PYTHON = (3, 12)
LOCK_PLATFORM_TAGS = ("manylinux", "x86_64")


def _compatibility(filename: str) -> tuple[int, str]:
    """Sort key preferring the least demanding wheel for a version.

    Several projects publish more than one manylinux wheel for the same
    interpreter (lxml ships glibc 2.17 and 2.28 builds). The older, lower-glibc
    wheel installs on more systems, so it is the safer pinned choice.
    """
    if "musllinux" in filename or "macosx" in filename or "win" in filename:
        return (99, filename)
    if "py3-none-any" in filename or "py2.py3-none-any" in filename:
        return (0, filename)
    match = re.search(r"manylinux[_0-9]*_(\d+)_x86_64", filename)
    if match is None:
        # any/abi3 wheels still work on any Linux with a compatible ABI.
        return (50, filename)
    return (int(match.group(1)), filename)


def _wheel_for_target(name: str, version: str) -> tuple[str, str]:
    """The single wheel matching the target platform, with its SHA-256.

    Exactly one hash per distribution. ``pip --require-hashes`` compares the
    downloaded file against the requirement's hash set, but it selects the file
    itself, so listing hashes for every platform's wheel (or for the sdist) makes
    the install fail rather than succeed on any of them.
    """
    url = f"https://pypi.org/pypi/{name}/{version}/json"
    with urllib.request.urlopen(url, timeout=30) as response:
        payload = json.load(response)
    tag = f"cp{LOCK_PYTHON[0]}{LOCK_PYTHON[1]}"
    candidates = [
        entry
        for entry in payload["urls"]
        if entry["packagetype"] == "bdist_wheel"
        and tag in entry["filename"]
        and all(part in entry["filename"] for part in LOCK_PLATFORM_TAGS)
        and "musllinux" not in entry["filename"]
        and "macosx" not in entry["filename"]
        and "win" not in entry["filename"]
    ]
    if not candidates:
        # abi3 and pure-Python wheels carry no CPython-specific tag.
        candidates = [
            entry
            for entry in payload["urls"]
            if entry["packagetype"] == "bdist_wheel"
            and "abi3" in entry["filename"]
            and "x86_64" in entry["filename"]
        ]
    if not candidates:
        # Pure-Python wheels carry no platform tag either.
        candidates = [
            entry
            for entry in payload["urls"]
            if entry["packagetype"] == "bdist_wheel" and "none-any" in entry["filename"]
        ]
    if not candidates:
        raise LookupError(f"no linux/x86_64 wheel for {name}=={version} on {tag}")
    best = min(candidates, key=lambda entry: _compatibility(entry["filename"]))
    return best["filename"], best["digests"]["sha256"]


def _render(dependencies: dict[str, str]) -> list[str]:
    """The full lockfile body for the resolved runtime tree."""
    lines = [
        "# TriageLens runtime dependencies, pinned with hashes.",
        "#",
        "# Generated by scripts/gen_lock.py from backend/pyproject.toml. Do not edit",
        "# by hand: the Dockerfile installs this file with pip --require-hashes, so a",
        "# mismatch fails the build rather than resolving to something else.",
        "#",
        "# Dev extras are excluded; this is what the application needs to run.",
        "#",
        "# Exactly one hash per distribution: the wheel for the target platform",
        "# below. pip --require-hashes picks the file itself and compares it to the",
        "# listed hash, so a multi-platform hash set makes the install fail.",
        f"# Target: CPython {LOCK_PYTHON[0]}.{LOCK_PYTHON[1]}, linux/x86_64 (the container image).",
        f"# Generated on Python {sys.version_info.major}.{sys.version_info.minor}",
        "",
    ]
    for name in sorted(dependencies):
        version = dependencies[name]
        try:
            filename, digest = _wheel_for_target(name, version)
        except LookupError as exc:
            raise RuntimeError(str(exc)) from exc
        except OSError as exc:
            raise RuntimeError(
                f"could not reach PyPI for {name}=={version}: {exc}"
            ) from exc
        lines.append(f"# {filename}")
        lines.append(f"{name}=={version} --hash=sha256:{digest}")
    return lines


def main(argv: list[str] | None = None) -> int:
    """Write the lockfile, or with --check verify the committed one is current."""
    args = sys.argv[1:] if argv is None else argv
    check = "--check" in args
    unknown = set(args) - {"--check"}
    if unknown:
        print(f"unknown argument: {min(unknown)}", file=sys.stderr)
        return 2

    dependencies = _runtime_dependencies()
    if not dependencies:
        print("could not resolve the runtime dependency tree", file=sys.stderr)
        return 1

    try:
        body = "\n".join(_render(dependencies)) + "\n"
    except RuntimeError as exc:
        print(exc, file=sys.stderr)
        return 1

    if check:
        if not OUTPUT.exists():
            print(
                f"{OUTPUT} is missing; run without --check to create it",
                file=sys.stderr,
            )
            return 1
        if OUTPUT.read_text(encoding="utf-8") != body:
            print(
                f"{OUTPUT} is out of date with backend/pyproject.toml or PyPI",
                file=sys.stderr,
            )
            return 1
        print(
            f"{OUTPUT.name} is up to date with {len(dependencies)} pinned distributions"
        )
        return 0

    OUTPUT.write_text(body, encoding="utf-8")
    print(f"wrote {OUTPUT} with {len(dependencies)} pinned distributions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
