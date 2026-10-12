# TriageLens

Standalone, fully local security-log triage tool. Import raw logs, normalise them
into a searchable event store, run detection rules, and review alerts with their
MITRE ATT&CK context — without sending evidence anywhere.

The application is one process: a FastAPI backend that serves both the JSON API
and the built single-page frontend. Data lives in a local SQLite database.

## Status

All build phases (0 through 9) are implemented. That covers the ingestion
pipeline and its parsers (Windows EVTX and event XML, Linux syslog/journald/auditd,
web access and error logs, firewall logs, generic profiles and archives), the
detection engine (builtin rules plus Sigma rules compiled to SQLite predicates),
alerts with MITRE ATT&CK context, IOC extraction, the events, timeline and
entities browsers, reports and streamed exports, and the operational scripts.

See [docs/STATUS.md](docs/STATUS.md) for what works today and the known
limitations, and [docs/DECISIONS.md](docs/DECISIONS.md) for the deliberate
deviations from the specs. The specifications being built against live in
[docs/spec](docs/spec).

## Demo

A short product teaser:

https://github.com/user-attachments/assets/c88eb143-44db-4c8c-8729-19f7326b9090

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
| E2E | `make e2e` | Build the app and run the Playwright browser scenarios, the axe-core accessibility scan and the UI first-paint perf check (needs `npx playwright install chromium` once) |
| Bundle budget | `make frontend-budget` | Enforce the spec 07 < 1.5 MB gzipped budget on the built frontend |
| Build | `make build` | All of the above, then the production frontend build |
| Format | `make backend-format` | Apply Ruff's formatter and safe fixes |
| Dev server | `make dev` | Vite with the API proxied to port 8787 |
| Container | `make docker-build` | Build `triagelens:local` |
| Lockfile | `make backend-lock` | Regenerate `backend/requirements.lock` |
| Verify lock | `make lock-check` | Fail if the lockfile has drifted from `pyproject.toml` |
| Benchmarks | `make perf` | Measure the storage layer and rewrite `docs/perf-results.md` |
| UI perf | `make perf-ui` | Measure the Alerts first-paint target with Playwright (build + Chromium) |
| End-to-end perf | `make perf-e2e SCALE=smoke\|full` | Run the spec 09 §8 targets and rewrite `docs/perf-e2e-results.md` (`smoke` by default for a laptop); runs `perf-ui` first and merges its verdict |
| Offline bundle | `make package` | Build an installable bundle into `dist/` |

Run a single side when iterating: `make backend-test`, `make frontend-typecheck`,
and so on.

`make test` deliberately skips the benchmarks: they assert on wall-clock time,
which is unreliable on a shared machine and would make the gate flaky. Run
`make perf` when you want them.

## Usage

TriageLens is a single-user, local triage workbench. A typical session runs
entirely in the browser against `http://127.0.0.1:8787`:

1. **Create a case.** A case owns its sources, events, alerts, indicators and
   reports. Cases are the unit the rail navigates.
2. **Import evidence** from the Sources screen: a single log file, a directory,
   or an archive. Uploads stream to disk, archived inputs are expanded under the
   archive limits, and each source is parsed into normalised events on a worker
   process.
3. **Detect.** Run a detection profile (`fast`, `standard` or `full`) over a
   source. Builtin and imported Sigma rules are compiled to SQLite predicates and
   executed against the event store; matches become alerts grouped into
   incidents.
4. **Review alerts** on the Alerts screen: severity, the triggering events,
   extracted indicators, and the mapped ATT&CK techniques, with coverage shown in
   the ATT&CK matrix.
5. **Pivot** through the Events, Timeline and Entities screens and the IOCs
   register, using full-text search and column filters.
6. **Report and export.** Generate a self-contained HTML, Markdown or JSON report
   (PDF when WeasyPrint is installed) and stream the current event filter as CSV
   or JSONL.

Every mutating step appends to the audit log, an append-only SHA-256 hash chain
that is verified when read.

### Backup, diagnostics and maintenance

- **Backup.** `python scripts/backup.py <case_id|all> <dest-dir>` writes a zip
  with a consistent `VACUUM INTO` database snapshot, the case file trees and a
  `manifest.json` of per-file SHA-256 digests. A single-case export still carries
  the whole database, because the audit log is one chain shared across cases.
- **Diagnostics.** `python scripts/diag.py` prints version and build info, the
  effective configuration with secret-looking values masked, and the log tail;
  add `--health` to probe a running server. It never reads event content.
- **Maintenance.** The Settings → Data pane (backed by `/api/maintenance/*`) can
  VACUUM the database, rebuild the full-text index, re-hash every stored original
  and re-verify the audit chain.

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
    api/routers/       HTTP endpoints (cases, sources, events, alerts, iocs,
                       mitre, rules, settings, reports, jobs, maintenance, ws)
    ingest/            archive handling, format detection and intake
    parsers/           one parser per log format, normalising to events
    detect/            rule engine, Sigma compilation and detection profiles
    ioc/               indicator extraction, validation, scoring and STIX export
    reports/           neutral report model, renderers and streamed exports
    jobs/              worker processes and the single writer thread
    mitre/             ATT&CK bundle import, tagging and matrix aggregation
    db/connection.py   SQLite pragmas, capability probes, transactions
    db/migrations.py   ordered, transactional migration runner
    db/repositories/   typed data access; the audit chain lives here
    models/            dataclasses mirroring database rows
    util/              hashing, ids, time, redacting structured logging
  migrations/          numbered SQL files
  rules/               builtin and vendored Sigma rules
  tests/               pytest suite (unit, API, end-to-end, perf)
  data/                runtime data directory (cases, sources, logs, database)
frontend/
  src/api/             typed client for the backend
  src/features/        one directory per screen
  src/lib/             pure helpers
scripts/               task runner, run scripts and operational tools
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
- **Offline by construction.** No component performs an outbound request; the
  optional enrichment path is disabled unless `network.allow_enrichment` is set.
- **Bounded input.** Uploads, archives (expansion ratio, total size, depth and
  member count) and per-source event counts are capped, and ingest refuses to
  start when the disk is too full rather than filling it.
- **Secure delete.** With `storage.secure_delete = true`, deleted originals are
  overwritten in place before unlinking.

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

The `pdf` profile builds a second image (served on host port 8788) with the
WeasyPrint system libraries installed. WeasyPrint itself is an optional import
that is not in the base dependency set or the lockfile, so it is absent from both
images and `/api/health` reports `pdf_available: false`; the PDF report option is
disabled and the endpoint answers `422 PDF_UNAVAILABLE`. Install WeasyPrint into
the environment yourself to enable PDF rendering.

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
- **The ATT&CK bundle is not included.** Import your own STIX export with
  `scripts/update_attack.py <enterprise-attack.json>` after install (see
  `SOURCES.md`); the coverage matrix and technique metadata populate from it. The
  detection engine still runs without it, using the fallback ATT&CK map.

## License

MIT. See [LICENSE](LICENSE).