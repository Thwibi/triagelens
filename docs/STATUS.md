# Status

What works today, and what does not. Updated at the end of each phase.

## Phase 0 — foundation (implemented)

| Area | State |
|---|---|
| Configuration | Defaults, `config.toml`, `TRIAGELENS_*` env vars, validation, safe-bind rules |
| SQLite | Pragmas from spec 01, FTS5/JSON1 capability probe, single writer, read connections, transactions |
| Migrations | Ordered discovery, statement splitting, one transaction per migration, newer-schema refusal |
| Schema | 24 tables including the FTS5 index and audit triggers; `mitre_meta` ready for an ATT&CK import |
| Audit | Append-only hash chain, verification, tombstones; `UPDATE`/`DELETE` blocked by triggers |
| HTTP | Security headers, Host validation, bearer auth for non-loopback binds, structured access log |
| Errors | Spec 06 envelope for API, HTTP, validation and unhandled failures |
| API | `GET /api/health`, `GET /api/docs`, `GET /api/openapi.json` |
| Frontend | Status page with live health polling, degraded/blocked states, auth and contract-error handling |
| Tooling | `scripts/task.py`, `Makefile`, run scripts, Dockerfile, compose file, hashed lockfile |

### Verification

| Gate | Command | Result |
|---|---|---|
| Backend lint | `make backend-lint` | clean (ruff check + format check) |
| Backend types | `make backend-typecheck` | clean (strict mypy, 45 files) |
| Backend tests | `make backend-test` | 216 passed (benchmarks excluded by design) |
| Frontend lint | `make frontend-lint` | clean |
| Frontend types | `make frontend-typecheck` | clean |
| Frontend tests | `make frontend-test` | 73 passed |
| Frontend build | `make frontend-build` | succeeds into `backend/app/static` |
| Lockfile | `make lock-check` | current: 22 pinned distributions |
| Lockfile hashes | `python scripts/verify_lock.py` | all 22 files match their recorded SHA-256 |
| Container image | `make docker-build` | builds; installs exactly the 22 pinned distributions |
| Container runtime | `docker run -p 127.0.0.1:8787:8787 -e TRIAGELENS_SERVER__AUTH_TOKEN=... triagelens:local` | healthy, serves API and SPA, 401 without a token |
| Compose | `scripts/compose.sh up -d` | healthy on 127.0.0.1:8787 |
| Benchmarks | `make perf` | 7 measurements written to `docs/perf-results.md` |
| Offline bundle | `make package` | 22 verified wheels, 8.2 MiB; installs with the network unreachable |

### Known limitations

- A migration directory may have version gaps; see `docs/DECISIONS.md`.
- A hash chain cannot detect a fully rewritten history without an external
  anchor; the immutability triggers are the primary defence.
- The frontend is not committed, so a fresh checkout needs `make build` before
  the UI is served. The API works without it and logs a warning.
- `backend/requirements.lock` pins one wheel per distribution for CPython 3.12 on
  linux/x86-64, matching the container image. `make lock-check` fails if it drifts
  from `pyproject.toml`; `python scripts/verify_lock.py` re-hashes every pinned
  file against PyPI. It cannot be verified with a plain local install, because the
  local interpreter is a different platform.
- The container binds `0.0.0.0` internally, because a process listening only on the
  container's loopback is unreachable through a published port. The app refuses a
  non-loopback bind without a token, and no token is baked into the image, so a
  bare `docker run` exits with a configuration error instead of serving the API
  unauthenticated. Use `scripts/compose.sh`, which generates one into the
  gitignored `docker/.env`.
- `--build-arg WITH_PDF=1` installs the WeasyPrint *system libraries* only, as
  spec 10 requires. WeasyPrint itself is not a Phase 0 dependency, so that variant
  still reports `pdf_available: false` and the report endpoint answers
  `422 PDF_UNAVAILABLE` until reporting lands in a later phase.
- `make perf` covers only what Phase 0 built: migrations, the audit chain, event
  insert, indexed filter, FTS query and health latency. The spec 09 ingest and
  detection targets cannot be measured until those phases exist, so
  `docs/perf-results.md` lists them as pending rather than estimating them. The
  recorded numbers come from a Windows workstation, not the spec's reference
  laptop, so they are a regression baseline and not a target verdict.
- `tests/perf` is excluded from `make test` and `make backend-coverage`. Wall-clock
  assertions fail on a loaded machine for reasons unrelated to the code, which
  would make the gate unreliable. Performance regressions surface when someone
  runs `make perf`.
- The offline bundle's wheels are platform-specific and default to the machine
  that built them; it carries no ATT&CK data, which arrives with the detection
  phases.

## Later phases

Ingestion and parsers (phase 1 onward), detection engine, IOC extraction, the
triage UI, ATT&CK import, and reporting/export. See `docs/spec/11-AGENT-BUILD-PROMPTS.md`.

## Acceptance mapping

Spec 11 section 2 requires `GET /api/health` to return the listed fields, audit
tampering to be detected, and the app to refuse to start when bound to 0.0.0.0
without a token. Each is covered:

| Requirement | Test |
|---|---|
| `/api/health` returns the spec'd fields | `tests/test_api.py::TestHealthEndpoint` |
| Security headers on every response | `tests/test_api.py::TestSecurityHeaders` |
| Host header rejection | `tests/test_api.py::TestHostValidation` |
| Bearer token required off loopback | `tests/test_api.py::TestBearerAuth` |
| Audit tampering detected | `tests/test_audit.py::TestTammerDetection` |
| Refuses 0.0.0.0 without a token | `tests/test_config.py` (safe-bind tests) |
| `make lint typecheck test` green | `scripts/task.py all` |