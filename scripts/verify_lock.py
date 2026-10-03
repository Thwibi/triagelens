"""Verify every hash in ``backend/requirements.lock`` against the real PyPI file.

``scripts/gen_lock.py --check`` proves the lockfile is current and internally
consistent. This script goes further: it downloads each pinned wheel and confirms
the bytes hash to the value recorded in the lockfile. That is the exact property
the container build depends on when pip installs with ``--require-hashes``.

Verification is platform-independent because it follows the filenames the
lockfile records rather than what the current interpreter would have installed.

Usage::

    python scripts/verify_lock.py
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCKFILE = ROOT / "backend" / "requirements.lock"

_REQUIREMENT = re.compile(
    r"^(?P<name>[A-Za-z0-9._-]+)==(?P<version>[^\s]+)\s+--hash=sha256:(?P<digest>[0-9a-f]{64})$"
)


def _entries() -> list[tuple[str, str, str, str]]:
    """(wheel filename, name, version, digest) for each requirement in the lockfile."""
    entries: list[tuple[str, str, str, str]] = []
    wheel = ""
    for line in LOCKFILE.read_text(encoding="utf-8").splitlines():
        if line.startswith("# ") and line.endswith(".whl"):
            wheel = line[2:].strip()
            continue
        if not line or line.startswith("#"):
            continue
        match = _REQUIREMENT.match(line)
        if match is None:
            print(f"unparseable lockfile line: {line}", file=sys.stderr)
            raise SystemExit(1)
        entries.append(
            (
                wheel,
                match.group("name"),
                match.group("version"),
                match.group("digest"),
            )
        )
    return entries


def file_digest(path: Path) -> str:
    """SHA-256 of a local file, read in blocks so large wheels stay off the heap."""
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            hasher.update(block)
    return hasher.hexdigest()


def remote_digest(url: str) -> str:
    """SHA-256 of a remote file, streamed rather than buffered."""
    hasher = hashlib.sha256()
    with urllib.request.urlopen(url, timeout=120) as response:
        for block in iter(lambda: response.read(1 << 20), b""):
            hasher.update(block)
    return hasher.hexdigest()


def pypi_release(name: str, version: str) -> dict[str, dict[str, str]]:
    """PyPI's file listing for a release: filename to url and digest."""
    release = json.load(
        urllib.request.urlopen(
            f"https://pypi.org/pypi/{name}/{version}/json", timeout=30
        )
    )
    return {
        entry["filename"]: entry for entry in release["urls"] if entry.get("digests")
    }


def main() -> int:
    """Check each pinned wheel; report every mismatch rather than the first.

    The file is downloaded and hashed rather than trusting PyPI's own digest, so
    this confirms the bytes actually served match what the lockfile records.
    """
    entries = _entries()
    if not entries:
        print(f"{LOCKFILE} has no requirements", file=sys.stderr)
        return 1

    failures = 0
    for wheel, name, version, expected in entries:
        files = pypi_release(name, version)
        if wheel not in files:
            print(f"FAIL {name}=={version}: PyPI has no file named {wheel}")
            failures += 1
            continue
        actual = remote_digest(files[wheel]["url"])
        if actual != expected:
            print(f"FAIL {name}=={version} ({wheel})")
            print(f"     lockfile {expected}")
            print(f"     actual   {actual}")
            failures += 1
        else:
            print(f"ok   {name}=={version}")

    if failures:
        print(
            f"\n{failures} of {len(entries)} pinned files failed verification",
            file=sys.stderr,
        )
        return 1
    print(f"\nall {len(entries)} pinned files match their recorded hashes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
