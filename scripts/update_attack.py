"""Validate and load an ATT&CK STIX 2.1 bundle (spec 04 section 7.1).

Usage::

    python scripts/update_attack.py data/attack/enterprise-attack.json
    python scripts/update_attack.py bundle.json --version 17.1.0 --db other.db

The bundle is a local file (no network at runtime); the load replaces the
MITRE tables atomically and appends an ``attack_imported`` audit entry.
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
from collections.abc import Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
sys.path.insert(0, str(BACKEND))

from app.config import Settings
from app.db.connection import connect
from app.db.migrations import apply_migrations
from app.db.repositories.audit import AuditRepository
from app.mitre.loader import load_bundle


def main(argv: Sequence[str] | None = None) -> int:
    """Load one bundle into the configured (or given) database."""
    parser = argparse.ArgumentParser(description="Load an ATT&CK STIX 2.1 bundle.")
    parser.add_argument("bundle", type=Path, help="path to the STIX bundle JSON")
    parser.add_argument(
        "--db", type=Path, default=None, help="database file (default: settings)"
    )
    parser.add_argument(
        "--version",
        default=None,
        help="attack_version to record (default: detected from the bundle)",
    )
    args = parser.parse_args(argv)

    settings = Settings()
    db_path = args.db if args.db is not None else settings.db_path
    if not db_path.is_file():
        print(f"database not found: {db_path}", file=sys.stderr)
        return 1

    connection = connect(db_path)
    try:
        apply_migrations(connection, settings.migrations_dir)
        version = load_bundle(
            connection, args.bundle, attack_version=_version_arg(args)
        )
        sha256 = _meta(connection, "sha256")
        AuditRepository(connection).append(
            "attack_imported",
            detail={
                "attack_version": version,
                "source": str(args.bundle),
                "sha256": sha256,
            },
        )
    except (OSError, ValueError) as exc:
        print(f"import failed: {exc}", file=sys.stderr)
        return 1
    finally:
        connection.close()
    print(f"ATT&CK {version} loaded into {db_path} (sha256 {sha256})")
    return 0


def _version_arg(args: argparse.Namespace) -> str | None:
    return str(args.version) if args.version else None


def _meta(connection: sqlite3.Connection, key: str) -> str:
    row = connection.execute(
        "SELECT value FROM mitre_meta WHERE key = ?", (key,)
    ).fetchone()
    return str(row["value"]) if row is not None else ""


if __name__ == "__main__":
    raise SystemExit(main())
