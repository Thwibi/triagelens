#!/usr/bin/env bash
# Start TriageLens on POSIX systems.
#
# Serves the API and the built frontend from a single process on 127.0.0.1:8787.
# Pass --dev to run the Vite dev server instead, with the API proxied.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${ROOT}/.venv/bin/python"

if [[ ! -x "${PYTHON}" ]]; then
    echo "No virtual environment at ${ROOT}/.venv. Run: make install" >&2
    exit 1
fi

if [[ "${1:-}" == "--dev" ]]; then
    if [[ ! -d "${ROOT}/frontend/node_modules" ]]; then
        echo "Frontend dependencies missing. Run: make frontend-install" >&2
        exit 1
    fi
    cd "${ROOT}/frontend"
    exec npm run dev
fi

if [[ ! -f "${ROOT}/backend/app/static/index.html" ]]; then
    echo "Frontend not built. Run: make build   (or use --dev)" >&2
    exit 1
fi

cd "${ROOT}/backend"
exec "${PYTHON}" -m app.main