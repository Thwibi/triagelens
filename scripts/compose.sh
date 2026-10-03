#!/usr/bin/env bash
# Run TriageLens through docker compose.
#
#   ./scripts/compose.sh up --build     build and start on 127.0.0.1:8787
#   ./scripts/compose.sh down           stop, keep the data volume
#   ./scripts/compose.sh --profile pdf up triagelens-pdf
#   ./scripts/compose.sh logs -f        follow logs
#
# The container binds 0.0.0.0 so the published port can reach it, and the app
# refuses a non-loopback bind without an auth token. Rather than making you
# export one, this wrapper generates a token into docker/.env on first use and
# reuses it afterwards, so the token is stable across restarts. The file is
# gitignored; it is a local secret.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ROOT}/docker/.env"

if [[ ! -f "${ENV_FILE}" ]]; then
    if command -v python3 >/dev/null 2>&1; then
        token="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
    else
        echo "python3 is required to generate a token; set TRIAGELENS_TOKEN instead" >&2
        exit 1
    fi
    umask 077
    printf 'TRIAGELENS_TOKEN=%s\n' "${token}" >"${ENV_FILE}"
    echo "generated a token in docker/.env" >&2
fi

exec docker compose --env-file "${ENV_FILE}" -f "${ROOT}/docker/compose.yaml" "$@"