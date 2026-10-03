# TriageLens

Standalone, fully local security-log triage tool. Import raw logs, normalise them
into a searchable event store, run detection rules, and review alerts with their
MITRE ATT&CK context — without sending evidence anywhere.

The application is one process: a FastAPI backend that serves both the JSON API
and the built single-page frontend. Data lives in a local SQLite database.

## Status

Phase 0 (foundation) is implemented: configuration, the SQLite schema and
migration runner, the health endpoint, the HTTP hardening layer, the audit hash
chain, and a status frontend. Ingestion, detection and reporting arrive in later
phases. See [docs/STATUS.md](docs/STATUS.md) for what works today and
[docs/spec](docs/spec) for the specifications being built against.

## Requirements

- Python 3.11 or newer (3.12 recommended; the container image uses 3.12)
- Node.js 20 or newer, only to build the frontend
- SQLite with FTS5 and JSON1, which is bundled in CPython on all supported
  platforms

No network access is required at runtime, and none is used during the build.

## Quick start

```bash
make install          # create .venv and install backend + frontend deps
make build            # check everything and build the frontend
make all              # lint, typecheck and test on both sides
./scripts/run.sh      # start on http://127.0.0.1:8787
```

`make` is a thin wrapper over `python scripts/task.py`, so every task works
without it:

```bash
python scripts/task.py install
python scripts/task.py all
python scripts/task.py test
```

On Windows use `.\scripts\run.ps1`, or `.\.venv\Scripts\python.exe scripts\task.py all`.

## Common tasks

| Task | Command | What it does |
|---|---|---|
| Install | `make install` | Backend (editable, with dev extras) and pinned frontend packages |
| Lint | `make lint` | Ruff for the backend, ESLint for the frontend |
| Type-check | `make typecheck` | Strict mypy, then TypeScript in no-emit mode |
| Test | `make test` | pytest for the backend, Vitest for the frontend |
| Coverage | `make backend-coverage` | pytest with a coverage floor |
| Build | `make build` | All of the above, then the production frontend build |
| Format | `make backend-format` | Apply Ruff's formatter and safe fixes |
| Dev server | `make dev` | Vite with the API proxied to port 8787 |
| Container | `make docker-build` | Build `triagelens:local` |
| Lockfile | `make backend-lock` | Regenerate `backend/requirements.lock` |
| Verify lock | `make lock-check` | Fail if the lockfile has drifted from `pyproject.toml` |
| Benchmarks | `make perf` | Measure the storage layer and rewrite `docs/perf-results.md` |
| Offline bundle | `make package` | Build an installable bundle into `dist/` |

Run a single side when iterating: `make backend-test`, `make frontend-typecheck`,
and so on.

`make test` deliberately skips the benchmarks: they assert on wall-clock time,
which is unreliable on a shared machine and would make the gate flaky. Run
`make perf` when you want them.

## Dependencies

Runtime versions live in `backend/pyproject.toml`. The container installs from
`backend/requirements.lock`, which pins one wheel per distribution with a
SHA-256 hash for CPython 3.12 on linux/x86-64, and is installed with
`pip --require-hashes`.

After changing runtime dependencies:

```bash
make backend-lock                     # regenerate and commit the lockfile
python scripts/verify_lock.py         # re-hash every pinned file against PyPI
```

`verify_lock.py` downloads each pinned wheel and confirms the bytes match, which
is the property the container build relies on. It cannot be replaced by a local
install: the lockfile targets the container platform, not the machine you are on.

## Layout

```
backend/
  app/
    config.py          validated settings, precedence, safe-bind rules
    main.py            application factory, lifespan, middleware stack
    api/middleware.py  security headers, Host validation, bearer auth, access log
    api/routers/       HTTP endpoints (health so far)
    db/connection.py   SQLite pragmas, capability probes, transactions
    db/migrations.py   ordered, transactional migration runner
    db/repositories/   typed data access; the audit chain lives here
    models/            dataclasses mirroring database rows
    util/              hashing, ids, time, redacting structured logging
  migrations/          numbered SQL files
  tests/               pytest suite
  data/                runtime data directory (cases, sources, logs, database)
frontend/
  src/api/             typed client for the backend
  src/features/        one directory per screen
  src/lib/             pure helpers
scripts/               task runner and run scripts
docker/                Dockerfile and compose file
docs/spec/             specifications 00-11
```

## Configuration

Settings resolve in this order, later sources winning:

1. built-in defaults
2. `backend/config.toml`, then `~/.config/triagelens/config.toml`
3. environment variables prefixed `TRIAGELENS_`

Nested keys use a double underscore:

```bash
TRIAGELENS_SERVER__HOST=0.0.0.0
TRIAGELENS_SERVER__PORT=8787
TRIAGELENS_SERVER__AUTH_TOKEN=...   # required for a non-loopback bind
TRIAGELENS_LOGGING__LEVEL=DEBUG
```

A configuration error never echoes file contents, because a config file may
contain a token.

### Security posture

- **Loopback by default.** Binding to a non-loopback address without an auth
  token of at least 16 characters is refused at startup.
- **Host header validation.** Only configured hostnames are accepted, which
  blocks DNS-rebinding attacks against the local API.
- **Bearer auth.** Required on `/api` paths for non-loopback binds. WebSocket
  clients, which cannot set headers, may pass `?token=`.
- **CSP on every response,** including errors: no inline script, no remote code,
  `frame-ancestors 'none'`.
- **Audit chain.** Every audit row carries the SHA-256 of its predecessor, and
  SQLite triggers reject `UPDATE` and `DELETE`. Verification walks the chain and
  reports the first inconsistency.
- **Secrets are redacted** from logs by value and by key name.

## Testing

```bash
make test                 # everything
make backend-coverage     # backend with coverage
cd frontend && npm test   # frontend only
```

The backend suite is hermetic: each test gets a temporary data directory and the
application is built from an explicit `Settings` object, so no test depends on
your `config.toml` or environment.

## Docker

```bash
scripts/compose.sh up --build        # http://127.0.0.1:8787
scripts/compose.sh down              # stop, keep the data volume
scripts/compose.sh logs -f
scripts/compose.sh --profile pdf up triagelens-pdf
```

On Windows use `.\scripts\compose.ps1` with the same arguments.

The image runs as an unprivileged user (uid 10001), publishes on host loopback
only, and declares a healthcheck against `/api/health`. The build installs Python
dependencies with `--require-hashes` from `backend/requirements.lock`.

Two details are deliberate and worth knowing before running the image directly:

- **It binds `0.0.0.0` inside the container.** A process listening only on the
  container's own loopback cannot be reached through `-p`, because Docker forwards
  published ports to the container's IP.
- **No auth token is baked in.** The app refuses a non-loopback bind without one,
  so a bare `docker run` exits with a configuration error rather than serving the
  API unauthenticated. `scripts/compose.sh` generates a token into the gitignored
  `docker/.env` on first use, so it stays stable across restarts. To run the image
  yourself:

  ```bash
  docker run -p 127.0.0.1:8787:8787 \
    -e TRIAGELENS_SERVER__AUTH_TOKEN="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')" \
    triagelens:local
  ```

  Requests then need `Authorization: Bearer <that token>`.

The `pdf` profile only adds the WeasyPrint system libraries. WeasyPrint itself is
not a Phase 0 dependency, so that variant still reports `pdf_available: false`
until reporting lands in a later phase.

## Offline install

`make package` builds a bundle that installs with no internet access:

```
dist/triagelens-0.1.0-offline.tar.gz
```

Unpack it and run the installer for your platform:

```bash
tar xzf triagelens-0.1.0-offline.tar.gz
cd triagelens-0.1.0-offline
./install.sh                              # or .\install.ps1 on Windows
```

That creates a virtual environment, installs the bundled wheels, and leaves the
application to run from `backend/`:

```bash
cd backend && ../.venv/bin/python -m app.main
```

Details worth knowing:

- **The wheels match one platform.** Binary wheels are not portable, so the bundle
  defaults to the machine that built it and says so. Pass
  `--platform manylinux2014_x86_64` to build for Linux from another host.
- **Versions come from the lockfile.** The bundle pins the same versions as
  `backend/requirements.lock`, but without hashes, because that file records the
  Linux wheels the container uses. Every downloaded wheel is checked against the
  SHA-256 PyPI publishes before the bundle is written; the build fails rather than
  shipping an unverified file. `SHA256SUMS.txt` in the bundle covers the rest.
- **The application is not pip-installed.** `app/` resolves `migrations/`, `rules/`
  and `data/` relative to its own location, so it runs from the tree — the same
  layout the container uses.
- **ATT&CK data is not included yet.** It arrives with the detection phases; the
  bundle currently carries the seed data that exists.

## License

MIT. See [LICENSE](LICENSE).