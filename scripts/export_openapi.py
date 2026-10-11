"""Export the backend OpenAPI document for the frontend's type generation.

The frontend turns this JSON into TypeScript request/response types with
``openapi-typescript`` (``npm run gen:api``). The document is committed so a
frontend build does not need a Python interpreter or a running server, and
``--check`` fails when the committed copy has drifted from the application.

The export is deterministic: keys are sorted and the file is written with a
trailing newline, so regenerating an unchanged API is a no-op in version
control.

Usage::

    python scripts/export_openapi.py            # write the document
    python scripts/export_openapi.py --check    # fail if it is out of date
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
TARGET = ROOT / "frontend" / "src" / "api" / "openapi.json"


def _load_schema() -> dict[str, Any]:
    """Import the application lazily and return its OpenAPI document.

    ``backend`` is added to ``sys.path`` so ``import app`` resolves without an
    editable install, which keeps this usable from a bare checkout.
    """
    if str(BACKEND) not in sys.path:
        sys.path.insert(0, str(BACKEND))
    from app.main import create_app

    return create_app().openapi()


def _render(schema: dict[str, Any]) -> str:
    """Serialize the document the same way on every machine."""
    return json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    """Write the document, or verify it when ``--check`` is passed."""
    parser = argparse.ArgumentParser(prog="export_openapi.py", description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail (exit 1) when the committed document is out of date",
    )
    args = parser.parse_args(argv)

    rendered = _render(_load_schema())

    if args.check:
        if not TARGET.is_file():
            print(f"missing {TARGET}; run: python scripts/export_openapi.py")
            return 1
        if TARGET.read_text(encoding="utf-8") != rendered:
            print(f"{TARGET} is out of date; run: python scripts/export_openapi.py")
            return 1
        print(f"{TARGET} is up to date")
        return 0

    TARGET.parent.mkdir(parents=True, exist_ok=True)
    TARGET.write_text(rendered, encoding="utf-8")
    print(f"wrote {TARGET}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
