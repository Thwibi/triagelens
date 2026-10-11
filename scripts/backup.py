"""Back up one case, or the whole store, into a verifiable zip (spec 10 section 5).

A backup is a zip archive that carries three things:

- ``db/triagelens.db`` - a consistent snapshot taken with ``VACUUM INTO``. This is
  the whole database, not a filtered slice: the audit log is a single hash chain
  across every case, so a partial export could not be verified or restored
  without recomputing the chain. ``VACUUM INTO`` is used rather than a file copy
  so the snapshot is taken inside one read transaction and never captures a
  half-written WAL.
- ``cases/<case_id>/...`` - the stored originals, exactly as they sit on disk.
- ``reports/<case_id>/...`` - any generated report artefacts.
- ``manifest.json`` - the scope, the generation time and a SHA-256 and byte size
  for every file in the archive, so a restore can be checked end to end.

For a single case the file trees are limited to that case, but the database
snapshot still holds every case, for the audit-chain reason above.

Usage::

    python scripts/backup.py all  backups/
    python scripts/backup.py 1f3c...  /srv/backups/case.zip
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
import tempfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"

#: The name the database snapshot takes inside the archive.
DB_ARCNAME = "db/triagelens.db"
MANIFEST_ARCNAME = "manifest.json"


def _sha256(path: Path) -> str:
    """Stream a file through SHA-256 without loading it whole."""
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            hasher.update(block)
    return hasher.hexdigest()


def _add_backend_to_path() -> None:
    """Let a bare checkout import ``app`` without an editable install."""
    if str(BACKEND) not in sys.path:
        sys.path.insert(0, str(BACKEND))


def _load_settings(config: Path | None) -> Any:
    """Load the same settings the application runs with."""
    _add_backend_to_path()
    from app.config import load_settings

    return load_settings(config)


def _snapshot_database(db_path: Path, workdir: Path) -> Path:
    """Write a consistent copy of the database with ``VACUUM INTO``."""
    snapshot = workdir / "triagelens.db"
    connection = sqlite3.connect(str(db_path))
    try:
        connection.execute("VACUUM INTO ?", (str(snapshot),))
    finally:
        connection.close()
    return snapshot


def _case_exists(db_path: Path, case_id: str) -> bool:
    """Whether the database knows this case, so a typo does not make a stub."""
    connection = sqlite3.connect(str(db_path))
    try:
        row = connection.execute(
            "SELECT 1 FROM cases WHERE id = ?", (case_id,)
        ).fetchone()
    finally:
        connection.close()
    return row is not None


def _case_ids(cases_root: Path, reports_root: Path) -> list[str]:
    """Every case id with files on disk, from either tree, sorted and unique."""
    found: set[str] = set()
    for root in (cases_root, reports_root):
        if root.is_dir():
            found.update(path.name for path in root.iterdir() if path.is_dir())
    return sorted(found)


def _add_file(
    archive: zipfile.ZipFile, path: Path, arcname: str, entries: list[dict[str, Any]]
) -> None:
    """Add one file to the archive and record how to verify it."""
    archive.write(path, arcname)
    entries.append(
        {"path": arcname, "sha256": _sha256(path), "bytes": path.stat().st_size}
    )


def _add_tree(
    archive: zipfile.ZipFile, base: Path, prefix: str, entries: list[dict[str, Any]]
) -> None:
    """Add a directory's files under ``prefix/``, skipping the DB sidecars."""
    for path in sorted(base.rglob("*")):
        if not path.is_file() or path.suffix in {".wal", ".shm"}:
            continue
        _add_file(
            archive, path, f"{prefix}/{path.relative_to(base).as_posix()}", entries
        )


def _tree_bytes(base: Path) -> int:
    """Total size of the regular files under ``base`` (0 when it is absent)."""
    if not base.is_dir():
        return 0
    return sum(path.stat().st_size for path in base.rglob("*") if path.is_file())


def _ensure_room(settings: Any, dest: Path, needed: int) -> None:
    """Refuse a backup the destination cannot hold (spec 10 section 1).

    Exits with status 1 and a clear message rather than writing a partial zip.
    """
    _add_backend_to_path()
    from app.errors import ApiError
    from app.ingest.archive import ensure_disk_space

    probe = dest if dest.is_dir() else dest.parent
    try:
        ensure_disk_space(
            probe,
            needed_bytes=needed,
            min_free_fraction=settings.limits.min_free_disk_fraction,
        )
    except ApiError as error:
        print(
            f"not enough free disk space at {probe}: {error.message}", file=sys.stderr
        )
        raise SystemExit(1) from None


def _resolve_target(dest: Path, name: str) -> Path:
    """The zip path: an existing directory gets a generated name inside it."""
    if dest.is_dir():
        return dest / f"{name}.zip"
    return dest


def main(argv: list[str] | None = None) -> int:
    """Build the archive; return a process exit code."""
    parser = argparse.ArgumentParser(
        prog="backup.py", description="Back up TriageLens."
    )
    parser.add_argument("scope", help="a case id, or 'all' for every case")
    parser.add_argument(
        "dest", type=Path, help="output zip file, or a directory for it"
    )
    parser.add_argument("--config", type=Path, default=None, help="path to config.toml")
    args = parser.parse_args(argv)

    settings = _load_settings(args.config)
    db_path: Path = settings.db_path
    if not db_path.is_file():
        print(f"database not found: {db_path}", file=sys.stderr)
        return 1

    all_cases = args.scope == "all"
    if not all_cases and not _case_exists(db_path, args.scope):
        print(f"no such case: {args.scope}", file=sys.stderr)
        return 1

    cases_root: Path = settings.cases_dir
    reports_root: Path = settings.reports_dir
    if all_cases:
        case_ids = _case_ids(cases_root, reports_root)
    else:
        case_ids = [args.scope]

    with tempfile.TemporaryDirectory() as directory:
        snapshot = _snapshot_database(db_path, Path(directory))

        needed = snapshot.stat().st_size + sum(
            _tree_bytes(cases_root / case_id) + _tree_bytes(reports_root / case_id)
            for case_id in case_ids
        )
        _ensure_room(settings, args.dest, needed)

        name = f"triagelens-backup-{args.scope}-{datetime.now(UTC):%Y%m%dT%H%M%SZ}"
        target = _resolve_target(args.dest, name)
        target.parent.mkdir(parents=True, exist_ok=True)

        entries: list[dict[str, Any]] = []
        with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
            _add_file(archive, snapshot, DB_ARCNAME, entries)
            for case_id in case_ids:
                case_dir = cases_root / case_id
                if case_dir.is_dir():
                    _add_tree(archive, case_dir, f"cases/{case_id}", entries)
                report_dir = reports_root / case_id
                if report_dir.is_dir():
                    _add_tree(archive, report_dir, f"reports/{case_id}", entries)

            manifest = {
                "tool": "triagelens-backup",
                "generated": datetime.now(UTC).isoformat(timespec="seconds"),
                "scope": args.scope,
                "database": DB_ARCNAME,
                "files": sorted(entries, key=lambda entry: entry["path"]),
            }
            archive.writestr(
                MANIFEST_ARCNAME, json.dumps(manifest, indent=2, sort_keys=True) + "\n"
            )

    size_mb = target.stat().st_size / (1024 * 1024)
    print(f"wrote {target} ({size_mb:.1f} MiB, {len(entries)} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
