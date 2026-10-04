# Status

What works today, and what does not. Updated at the end of each phase.

## Phase 1 — parsing, detection and intake (implemented, partial)

Scope is the core parsing and safe-intake slice of `docs/spec/11-AGENT-BUILD-PROMPTS.md`.
The job manager, process pool, WebSocket progress, cancellation and the
cases/sources/jobs API are later phases; nothing here is reachable over HTTP yet.

| Area | State |
|---|---|
| Normalized event | `NormalizedEvent`, the `EVENT_COLUMNS` order, normalization on the way in, insert payload |
| Normalization | Text/control-character cleaning, bounded truncation, IP canonicalization, port and int coercion, severity and outcome mapping, timestamp parsing |
| Text intake | UTF-8/16/32 BOMs, BOM-less UTF-16 detection, gzip, CRLF, incremental decoding, bounded lines with an explicit truncation marker |
| Parser contract | `LogParser`, `ParseContext`, `ParseFailure`, `ParseCounters`, `Candidate`, `ParserRegistry` with built-in loading |
| Generic parser | NDJSON, top-level arrays, `events`/`records`/`Records`, `hits.hits[*]._source`, profile selection, per-record failures |
| Profiles | Strict YAML loading and validation, `@timestamp`, `[*]`, array-valued category matching, shipped ECS profile |
| Detection | Signatures, suffix fallback, bounded parser voting, operator override, binary heuristic, `needs_input` with candidates |
| Archives | ZIP and TAR expansion refusing traversal, absolute/drive/UNC paths, symlinks, encryption, links, devices, excessive depth/member count/size and expansion bombs |
| Intake | Safe filenames, SHA-256, byte-counted limits, partial-file cleanup, per-member detection, read-only evidence storage, deletion that works on Windows |
| From-path import | Path resolution, containment under configured roots, regular files only, originals untouched |

### Verification

| Gate | Command | Result |
|---|---|---|
| Backend lint | `.venv\Scripts\python.exe scripts\task.py backend-lint` | clean (ruff check + format check) |
| Backend types | `.venv\Scripts\python.exe scripts\task.py backend-typecheck` | clean (strict mypy, 66 files) |
| Backend tests | `.venv\Scripts\python.exe scripts\task.py backend-test` | 760 passed, 1 skipped (benchmarks excluded by design) |
| Backend coverage | `.venv\Scripts\python.exe scripts\task.py backend-coverage` | 82.76%, gate is 80% |
| Frontend lint | `.venv\Scripts\python.exe scripts\task.py frontend-lint` | clean |
| Frontend types | `.venv\Scripts\python.exe scripts\task.py frontend-typecheck` | clean |
| Frontend tests | `.venv\Scripts\python.exe scripts\task.py frontend-test` | 73 passed |
| Frontend build | `.venv\Scripts\python.exe scripts\task.py frontend-build` | succeeds into `backend/app/static` |
| Lockfile | `.venv\Scripts\python.exe scripts\task.py lock-check` | current: 23 pinned distributions |

`scripts/task.py all` runs the same steps. It buffers its output, so on Windows a
run that takes more than a few minutes can hit the shell timeout with nothing shown;
run the individual tasks when that happens.

### Known limitations

- Only `generic_json` is registered. EVTX, XML, CSV, Wazuh and firewall formats are
  detected and reported, but `parser_available` is false and the source parks in
  `needs_input` rather than being parsed. See `docs/DECISIONS.md`.
- The generic JSON parser reads a whole single-document JSON file into memory, capped
  at 1 GiB. NDJSON streams line by line and has no such cap.
- Archive expansion is not transactional. A member that fails validation partway
  through leaves the members already written on disk; `remove_stored` cleans them
  up, but nothing calls it automatically yet.
- `intake_path` opens the source file without a context manager of its own, relying
  on `store_stream` to consume it. It is correct but relies on reference counting.
- A CSV column holding a formatted number cannot be distinguished from a real
  float; `to_int` accepts `443.0` and rejects `443.5`.
- One encrypted-ZIP test is skipped because `pyzipper` is not installed. The
  encrypted-flag detection itself is unit-tested.
- The performance targets in spec 09 for ingest and detection are still unmeasured;
  `docs/perf-results.md` lists them as pending.

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
| Lockfile hashes | `python scripts/verify_lock.py` | all 23 pinned files match their recorded SHA-256 |
| Container image | `make docker-build` | builds; installs exactly the pinned distributions (23 as of Phase 1) |
| Container runtime | `docker run -p 127.0.0.1:8787:8787 -e TRIAGELENS_SERVER__AUTH_TOKEN=... triagelens:local` | healthy, serves API and SPA, 401 without a token |
| Compose | `scripts/compose.sh up -d` | healthy on 127.0.0.1:8787 |
| Benchmarks | `make perf` | 7 measurements written to `docs/perf-results.md` |
| Offline bundle | `.venv\Scripts\python.exe scripts\task.py package` | 23 verified wheels, 8.4 MiB; installs with the network unreachable |

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

The job manager and process pool that will drive these parsers, the
detection engine beyond format detection, IOC extraction, the triage UI, ATT&CK
import, and reporting/export. See `docs/spec/11-AGENT-BUILD-PROMPTS.md`.

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

Phase 1 acceptance, from spec 03 and spec 09. Every item below has a test:

| Requirement | Test |
|---|---|
| Text reader handles BOMs, UTF-16, gzip, CRLF and oversized lines | `tests/test_ingest_text.py` |
| A parser cannot bypass normalization | `tests/test_ingest_events.py::TestPostInitNormalization` |
| The insert payload works against the real `events` table | `tests/test_ingest_events.py::TestAgainstRealSchema` |
| Control characters stripped, invalid IPs kept only in `fields_json` | `tests/test_ingest_normalize.py::TestCleanText`, `::TestCanonicalIp` |
| A naive timestamp is refused rather than assumed | `tests/test_ingest_normalize.py::TestParseTimestamp` |
| Every record yields one event or one failure, never both | `tests/test_ingest_parsers.py::TestNdjsonParsing` (`test_invalid_json_is_a_failure_not_a_crash`, `test_non_object_line_is_a_failure`) |
| A malformed record does not lose the records around it | `tests/test_ingest_parsers.py::TestNdjsonParsing::test_good_and_bad_records_mix_without_losing_either` |
| Profile YAML is validated, not trusted | `tests/test_ingest_profiles.py` |
| Signatures beat content; an override beats both | `tests/test_ingest_detect.py::TestDetectionDecisions` |
| A recognized format with no parser is not guessed | `tests/test_ingest_detect.py::TestDetectionDecisions` |
| Archive traversal, links and bombs are refused | `tests/test_ingest_archive.py` |
| An upload over the limit leaves nothing behind | `tests/test_ingest_intake.py::TestStoreStream` |
| Every archive member is detected | `tests/test_ingest_intake.py::TestMemberDetection` |
| A from-path import outside the roots is refused | `tests/test_ingest_intake.py::TestResolveImportPath` |