"""Build the offline install bundle described in spec 10 section 4.2.

The bundle lets TriageLens be installed on a machine with no internet:

    dist/triagelens-<version>-offline/
        wheels/          every runtime distribution, as a wheel
        backend/         the application package, migrations, rules, ATT&CK data
        frontend/        the built SPA, already in backend/app/static
        install.sh       creates a venv and installs from wheels/, no network
        install.ps1      the same for Windows
        MANIFEST.txt     what is inside, with a SHA-256 per file

Two constraints shape this:

- Only the *runtime* dependencies are bundled. ``backend/requirements.lock``
  already excludes dev extras, so the wheelhouse is exactly what the application
  needs to run.
- The wheels are for a specific platform, because binary wheels are not portable.
  It defaults to the platform running this script and refuses to silently produce a
  bundle for another one; pass ``--platform`` to cross-build, which requires a
  matching pip download environment.

Usage::

    python scripts/package_offline.py
    python scripts/package_offline.py --platform manylinux2014_x86_64 --python 312
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
import sys
import tarfile
import tempfile
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
FRONTEND = ROOT / "frontend"
DIST = ROOT / "dist"
LOCKFILE = BACKEND / "requirements.lock"

# verify_lock is imported by path for its PyPI helpers; scripts/ is not a package.
sys.path.insert(0, str(Path(__file__).resolve().parent))

#: Copied into the bundle so an offline install does not need the source tree.
#: pyproject.toml is required: pip installs backend/ as a package, not a plain dir.
BUNDLE_BACKEND = ("app", "migrations", "rules", "data", "pyproject.toml", "README.md")


def _version() -> str:
    """The application version, taken from pyproject."""
    import tomllib

    with (BACKEND / "pyproject.toml").open("rb") as handle:
        return str(tomllib.load(handle)["project"]["version"])


def _sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            hasher.update(block)
    return hasher.hexdigest()


def _pinned_versions() -> list[tuple[str, str]]:
    """The (name, version) pairs the lockfile pins, ignoring its hashes.

    The lockfile pins Linux wheels for the container, so its hashes cannot be
    used when downloading for another platform. Versions are still authoritative:
    each is downloaded from PyPI and then checked against the digest PyPI
    publishes for the file it actually served.
    """
    pairs = []
    for line in LOCKFILE.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        requirement = line.split(" ", 1)[0]
        name, _, version = requirement.partition("==")
        if version:
            pairs.append((name, version))
    return pairs


def _verify_against_pypi(wheels: Path) -> list[str]:
    """Check each downloaded wheel against PyPI's digest. Returns failures."""
    from packaging.utils import parse_wheel_filename
    from verify_lock import file_digest, pypi_release

    failures: list[str] = []
    for wheel in sorted(wheels.glob("*.whl")):
        # Filenames cannot be split by hand: both the name and the build tag may
        # contain hyphens, and the tags sit in a fixed trailing position.
        try:
            name, version, _, _ = parse_wheel_filename(wheel.name)
        except ValueError as error:
            failures.append(f"{wheel.name}: not a valid wheel name ({error})")
            continue
        files = pypi_release(str(name), str(version))
        entry = files.get(wheel.name)
        if entry is None:
            failures.append(
                f"{wheel.name}: PyPI does not list this file for {name} {version}"
            )
            continue
        if entry["digests"]["sha256"] != file_digest(wheel):
            failures.append(f"{wheel.name}: contents do not match PyPI's digest")
    return failures


def _download_wheels(
    target: Path, pins: Sequence[tuple[str, str]], *, platform_tag: str, python_tag: str
) -> int:
    """Fetch every pinned distribution as a wheel for the target platform."""
    target.mkdir(parents=True, exist_ok=True)
    # A temporary requirements file without hashes, so pip is free to select the
    # platform's wheel while still installing exactly the pinned versions.
    with tempfile.TemporaryDirectory() as directory:
        requirement_file = Path(directory) / "pinned.txt"
        requirement_file.write_text(
            "".join(f"{name}=={version}\n" for name, version in pins), encoding="utf-8"
        )
        command = [
            sys.executable,
            "-m",
            "pip",
            "download",
            "--only-binary=:all:",
            "--no-deps",
            "--dest",
            str(target),
            "--platform",
            platform_tag,
            "--python-version",
            python_tag,
            "--requirement",
            str(requirement_file),
        ]
        completed = subprocess.run(command, cwd=str(BACKEND), check=False)
        if completed.returncode != 0:
            return 0
    return sum(1 for _ in target.glob("*.whl"))


def _copy_tree(source: Path, destination: Path, name: str) -> None:
    """Copy a directory, skipping caches and anything already ignored."""
    ignore = shutil.ignore_patterns(
        "__pycache__", "*.pyc", ".pytest_cache", ".mypy_cache"
    )
    target = destination / name
    shutil.copytree(source, target, ignore=ignore, dirs_exist_ok=True)


def _write_offline_requirements(bundle: Path, pins: Sequence[tuple[str, str]]) -> None:
    """Write the pin list the installer uses.

    It cannot be ``backend/requirements.lock``: that file records hashes for the
    Linux wheels the container uses, and this bundle ships wheels for whichever
    platform was requested. Versions are identical, so the installer pins the same
    set by name and version; integrity comes from the PyPI check performed at build
    time plus the SHA256SUMS.txt in the bundle.
    """
    lines = [
        "# Pinned by the TriageLens offline installer.",
        "# Same versions as backend/requirements.lock, without hashes, because the",
        "# bundled wheels are built for this bundle's target platform.",
    ]
    lines += [f"{name}=={version}" for name, version in sorted(pins)]
    (bundle / "requirements-offline.txt").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )


INSTALL_SH = """#!/usr/bin/env bash
# Offline installer for TriageLens.
#
# Installs the bundled wheels into a virtual environment and leaves the
# application to run from this directory, which is how the container image runs
# it: app/ must sit beside migrations/, rules/ and data/ because the application
# resolves those relative to its own location.
#
# No network access is used or required. pip is given --no-index so it cannot
# reach out even when a connection happens to be available.
#
#   ./install.sh [target-venv]

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="${1:-${HERE}/.venv}"

if [[ ! -d "${HERE}/wheels" ]]; then
    echo "wheels/ is missing; this bundle is incomplete" >&2
    exit 1
fi

echo "creating ${VENV}"
python3 -m venv "${VENV}"
PY="${VENV}/bin/python"

# --no-index keeps pip offline; --find-links points it at the bundled wheels.
"${PY}" -m pip install --no-index --find-links "${HERE}/wheels" -r "${HERE}/requirements-offline.txt"

echo
echo "installed. Next:"
echo "  cd ${HERE}/backend"
echo "  ${PY} -c 'import sqlite3; print(sqlite3.sqlite_version)'"
echo "  ${PY} -m app.main"
"""

INSTALL_PS1 = """# Offline installer for TriageLens (Windows).
#
# Installs the bundled wheels into a virtual environment and leaves the
# application to run from this directory, which is how the container image runs
# it: app/ must sit beside migrations/, rules/ and data/ because the application
# resolves those relative to its own location.
#
# No network access is used or required. pip is given --no-index so it cannot
# reach out even when a connection happens to be available.
#
#   .\\install.ps1 [target-venv]

$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$venv = if ($args.Count -ge 1) { $args[0] } else { Join-Path $here '.venv' }

if (-not (Test-Path (Join-Path $here 'wheels'))) {
    throw 'wheels/ is missing; this bundle is incomplete'
}

$wheels = Join-Path $here 'wheels'
$lock = Join-Path $here 'requirements-offline.txt'

Write-Host "creating $venv"
py -3 -m venv $venv
$python = Join-Path $venv 'Scripts\\python.exe'

& $python -m pip install --no-index --find-links $wheels -r $lock
Write-Host ''
Write-Host 'installed. Next:'
Write-Host "  cd $(Join-Path $here 'backend')"
Write-Host "  $python -m app.main"
"""


def _write_manifest(bundle: Path, generated: str) -> None:
    """Record every file with its hash, so a transfer can be verified."""
    lines = [
        "TriageLens offline bundle",
        f"Generated: {generated}",
        "",
        "Verify with: sha256sum -c SHA256SUMS.txt",
        "",
    ]
    entries: list[str] = []
    for path in sorted(bundle.rglob("*")):
        if not path.is_file() or path.name in {"MANIFEST.txt", "SHA256SUMS.txt"}:
            continue
        entries.append(f"{_sha256(path)}  {path.relative_to(bundle).as_posix()}")
    (bundle / "SHA256SUMS.txt").write_text("\n".join(entries) + "\n", encoding="utf-8")

    lines += ["## Contents", ""]
    for entry in entries:
        lines.append(f"- `{entry.split('  ', 1)[1]}`")
    (bundle / "MANIFEST.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    """Assemble the bundle and compress it."""
    parser = argparse.ArgumentParser(description="Build the offline install bundle.")
    parser.add_argument(
        "--platform",
        default=None,
        help="pip --platform tag (default: this machine, wheels for this OS only)",
    )
    parser.add_argument(
        "--python",
        default=f"{sys.version_info.major}{sys.version_info.minor}",
        help="pip --python-version, e.g. 312",
    )
    parser.add_argument("--out", type=Path, default=DIST, help="output directory")
    args = parser.parse_args(argv)

    if not LOCKFILE.is_file():
        print(f"{LOCKFILE} is missing; run: make backend-lock", file=sys.stderr)
        return 1

    static = BACKEND / "app" / "static" / "index.html"
    if not static.is_file():
        print("the frontend is not built; run: make frontend-build", file=sys.stderr)
        return 1

    version = _version()
    name = f"triagelens-{version}-offline"
    bundle = args.out / name
    if bundle.exists():
        shutil.rmtree(bundle)
    bundle.mkdir(parents=True)

    print("building", bundle)
    pins = _pinned_versions()
    for item in BUNDLE_BACKEND:
        source = BACKEND / item
        if not source.exists():
            print(f"missing {source}; skipping", file=sys.stderr)
            continue
        if source.is_dir():
            _copy_tree(source, bundle / "backend", item)
        else:
            (bundle / "backend").mkdir(exist_ok=True)
            shutil.copy2(source, bundle / "backend" / item)

    # The frontend build output is already inside backend/app/static.
    if not (bundle / "backend" / "app" / "static" / "index.html").is_file():
        print("the built frontend is missing from the bundle", file=sys.stderr)
        return 1

    print("downloading wheels")
    count = _download_wheels(
        bundle / "wheels",
        _pinned_versions(),
        platform_tag=args.platform or _native_platform_tag(),
        python_tag=args.python,
    )
    if count == 0:
        print(
            "no wheels were downloaded; the bundle would not install offline",
            file=sys.stderr,
        )
        return 1
    print(f"  {count} wheels")

    print("verifying wheels against PyPI")
    failures = _verify_against_pypi(bundle / "wheels")
    if failures:
        for failure in failures:
            print(f"  FAIL {failure}", file=sys.stderr)
        print("refusing to build a bundle with unverified wheels", file=sys.stderr)
        return 1
    print("  all verified")

    _write_offline_requirements(bundle, pins)

    install_sh = bundle / "install.sh"
    install_sh.write_text(INSTALL_SH, encoding="utf-8")
    install_sh.chmod(0o755)
    (bundle / "install.ps1").write_text(INSTALL_PS1, encoding="utf-8")

    generated = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    _write_manifest(bundle, generated)

    archive = args.out / f"{name}.tar.gz"
    if archive.exists():
        archive.unlink()
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(bundle, arcname=name)

    size_mb = archive.stat().st_size / (1024 * 1024)
    print(f"wrote {archive} ({size_mb:.1f} MiB, {count} wheels)")
    if args.platform is None:
        print(
            "note: these wheels match this machine only. Use --platform to build a "
            "bundle for a different target."
        )
    return 0


def _native_platform_tag() -> str:
    """The pip --platform tag matching the interpreter running this script."""
    import platform as platform_module

    system = platform_module.system().lower()
    machine = platform_module.machine().lower()
    if system == "windows":
        return "win_amd64" if machine in {"amd64", "x86_64"} else f"win_{machine}"
    if system == "darwin":
        return "macosx_11_0_arm64" if machine == "arm64" else "macosx_10_9_x86_64"
    # Linux wheels are manylinux-tagged rather than carrying the raw kernel arch.
    return (
        "manylinux2014_x86_64"
        if machine in {"amd64", "x86_64"}
        else f"manylinux2014_{machine}"
    )


if __name__ == "__main__":
    raise SystemExit(main())
