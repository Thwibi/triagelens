# Architecture decisions

Each entry records a decision that is not obvious from the code, why it was
made, and what it costs. Newest first. Dates are ISO-8601.

## 2026-10-04 — Archive members are detected individually

**Decision.** `intake_stream` detects every entry of `IntakeResult.files` and keeps
the results in `IntakeResult.detections`, aligned by index. For a plain upload that
is a single-element list holding the same object as `IntakeResult.detection`.

**Why.** An archive is a container, not a log format: a ZIP of well-formed syslog
files has no format of its own, and the records that will actually be parsed are its
members. Detecting only the container reported the ZIP itself, so every member of a
valid bundle looked unrecognized and the source went to `needs_input`. `detection`
is kept as the container's own result because the source row records what was
uploaded; `detection_for(member)` and `format_candidates()` serve the per-member and
operator-facing cases, the latter collapsing duplicates so twenty identical members
are one question rather than twenty.

**Cost.** `detections` and `files` are parallel lists that a caller can desynchronise.
They are compared with `strict=True` inside `detection_for`, which turns a mismatch
into an error instead of a wrong answer.

## 2026-10-04 — A recognized format with no parser is `needs_input`

**Decision.** `DetectionResult.needs_input` is true when `log_type` is `None` **or**
`parser_available` is false.

**Why.** These are different situations with the same correct handling. An unknown
type asks the operator to choose; a recognized type with no parser in this build
cannot be fixed by choosing, but it still cannot be queued, because the parse job
would fail on a parser that does not exist. Both leave a source parked in
`needs_input` — a status spec 02 already defines for exactly this — where a person
or a later build resolves it. Reporting `needs_input` false for an unbuildable EVTX
would have sent it to a doomed job instead.

**Cost.** `needs_input` no longer means "the type is unknown", so a caller that
wants to distinguish the two must read `parser_available` or `reason` rather than
infer it. The UI prompt has to word the unbuildable case differently, since offering
a format list would be misleading.

## 2026-10-04 — UTC is resolved without the timezone database

**Decision.** `app/util/time.py:localize` treats `UTC`, `GMT`, `Z` and `UTC±00:00`
as fixed zero offsets and returns without touching `zoneinfo`. `tzdata` is also
pinned as a runtime dependency for every other zone.

**Why.** `zoneinfo` finds no database on Windows unless `tzdata` is installed, so
`ZoneInfo("UTC")` raised `ZoneInfoNotFoundError`. UTC is a constant, not a zone, and
depending on a database to express a constant made it fail on the one platform that
ships no database. The ECS profile declares `timezone: UTC`, so this broke every
naive ECS timestamp: the timestamp was dropped and the record was stored with a null
`ts_ms`, which is wrong evidence rather than a visible failure.

**Cost.** Two mechanisms for the same idea, and a caller reading `localize` has to
know the fixed-offset names are special-cased. A naive timestamp in a real IANA zone
still depends on `tzdata` being installed, which is why it is pinned rather than
left to the host.

## 2026-10-04 — The event insert binds `raw`

**Decision.** `INSERT_SQL` covers `EVENT_COLUMNS` plus `fields_json` and `raw`, and
`NormalizedEvent.values()` appends the serialized `fields_json` then `raw`.

**Why.** The `events` table declares `raw TEXT NOT NULL` with no default, so an
INSERT that omits the column fails with a constraint error and stores nothing. The
unit tests all passed against the old statement because none of them executed it.
`tests/test_ingest_events.py` now runs the real statement against the real
migration in an in-memory SQLite database, which is the only way this class of bug
shows up: a column the dataclass forgot is invisible to a mocked database.

**Cost.** The unit tests and the round-trip test now overlap slightly, and the
round-trip test depends on the migration staying loadable without FTS5.

## 2026-10-03 — The migration runner owns `schema_version`

**Decision.** `app/db/migrations.py` creates the `schema_version` table itself
(`CREATE TABLE IF NOT EXISTS`) before applying anything, and
`backend/migrations/0001_init.sql` no longer defines it.

**Why.** Previously the bookkeeping table was created by migration 1, which made
every migration assume that file was present and applied. A partial migration
directory — a legitimate state when only some files are checked out — failed with
`no such table: schema_version` instead of applying cleanly. Bookkeeping belongs
to the runner, not to the schema being versioned.

**Cost.** `schema_version` is not visible in migration 1, which can surprise
someone reading only the SQL.

## 2026-10-03 — Migration versions need not be contiguous

**Decision.** `discover_migrations` enforces unique, ascending versions but does
not require them to start at 1 or to have no gaps.

**Why.** Spec 02 section 8 says migrations are applied in order and that a newer
database is refused; it does not require a contiguous sequence. Rejecting gaps
would make a partial checkout unusable for no benefit, since ordering and
uniqueness are all the runner actually needs.

**Cost.** A genuinely missing migration is not detected as such. Applied
versions are still compared against the file set, so the app refuses to start on a
database that is newer than the build.

## 2026-10-03 — No migration checksums

**Decision.** Migrations are tracked by version and timestamp only.

**Why.** The `schema_version` schema shipped in spec 02 has no checksum column,
and adding one would require a migration before any migration could be verified —
chicken and egg. Integrity is instead provided by the audit chain and by SQLite
triggers on `audit_log`.

**Cost.** Editing an already-applied migration file is not detected. Migrations
are treated as immutable once merged.

## 2026-10-03 — The SPA never answers `/api` paths

**Decision.** `SPAStaticFiles` falls back to `index.html` only for navigation
requests: not for asset paths, and not for `/api` or anything under it.

**Why.** The history-API fallback answers unmatched paths with `200` and HTML. If
that also covered `/api`, a typo in an endpoint path would return the app shell
with a success status, hiding the bug from both the client and any monitoring.
The path is taken from the raw ASGI scope, because Starlette normalises it to OS
separators and Windows would otherwise yield `api\nope`.

**Cost.** One extra condition in the hot path, and a client-side route may not
begin with `/api`.

## 2026-10-03 — Wrong methods keep their status

**Decision.** `405` maps to the `VALIDATION_ERROR` code but keeps HTTP 405.

**Why.** Spec 06 section 2 lists the error codes and none corresponds to a wrong
HTTP method. Reporting `INTERNAL` with status 500, which is what an unmapped code
produced, misrepresents a client mistake as a server fault.

**Cost.** `VALIDATION_ERROR` covers two situations. The status disambiguates them.

## 2026-10-03 — A bare hash chain does not detect a full rewrite

**Decision.** Documented as a known limitation rather than worked around. Tests
assert both that a locally relinked chain verifies and that comparing the live
head against a recorded anchor exposes the rewrite.

**Why.** `audit_chain_hash` links rows to each other, so an attacker with write
access who recomputes every subsequent `prev_hash` and `hash` produces a chain
that verifies. Detection of that case requires an anchor held outside the chain —
a tombstone's `last_hash`, or an export — not a change to the hash function.

**Cost.** The immutability triggers are the primary defence; the chain detects
accidental corruption and partial tampering. Calling it tamper-proof would be
overclaiming.

## 2026-10-03 — ESLint 9, not 10

**Decision.** Pin ESLint 9.39.5 and `@eslint/js` 9.39.5.

**Why.** `eslint-plugin-react@7.37.5`, the current release, declares peer
dependencies only up to ESLint 9. Every other frontend tool uses its current
version. Revisit when the React plugin supports ESLint 10.

**Cost.** One major version behind on linting.

## 2026-10-03 — React 18 and TypeScript 5

**Decision.** Pin React 18.3.1 and TypeScript 5.9.3, while all other frontend
dependencies track their current releases.

**Why.** The project mandates these majors. React 19 changes ref semantics and
TypeScript 6 changes inference; both would add migration risk to a codebase with
no compatibility need behind it.

**Cost.** No access to React 19 features until that is revisited deliberately.

## 2026-10-03 — `scripts/task.py` is the source of truth

**Decision.** Every task is implemented once in Python; the `Makefile` forwards
to it.

**Why.** `make` is absent from stock Windows, which is a target platform. Two
independent implementations would drift.

**Cost.** One extra process spawn per target, and the Makefile's own output
formatting is minimal.

## 2026-10-03 — Generated frontend assets are not committed

**Decision.** `backend/app/static/` is git-ignored and produced by
`make frontend-build`.

**Why.** Hashed filenames change on every build, which would make merges
conflict constantly. The container image builds the frontend in its own stage and
copies the result in, so nothing depends on a committed bundle.

**Cost:** A checkout cannot serve the UI until `make build` has run; the API
still works and logs a warning naming the missing directory.

## 2026-10-03 — Runtime data directories are ignored individually

**Decision.** `backend/data/` is tracked; only its runtime artefacts (`*.db`,
`logs/`, `cases/`, `reports/`, `imports/`, `custom_rules/`) are ignored.

**Why.** The same tree holds bundled seed directories (`attack/`, `profiles/`)
that a fresh checkout needs in order to start offline. Ignoring the directory
would drop them.

**Cost:** The ignore list needs updating when a new runtime artefact appears.

## 2026-10-03 — Lint rules that conflict with deliberate choices are scoped, not disabled

**Decision.** `S608`, `PLC0415`, `B008`, `PT012`, `SIM117` and `FBT001` are
ignored per path with a comment explaining why, rather than globally.

**Why.** Each fires on something intentional here: f-string SQL built from module
constants, local imports that break layering cycles, FastAPI's `Depends` idiom,
and a nested `with` inside `pytest.raises` that *is* the assertion. A blanket
ignore would also hide the same mistakes elsewhere.

**Cost:** These rules no longer apply inside those paths at all.
## 2026-10-03 — Performance results are recorded, not estimated

**Decision.** `make perf` measures what Phase 0 has actually built and writes
those numbers to `docs/perf-results.md`. The spec 09 section 8 targets that
depend on parsers, detection, or the UI are listed as not yet measurable rather
than being approximated, and each is attributed to its owning phase.

**Why.** Inventing a number for an ingest or detection pipeline that does not
exist yet would produce a document that looks like evidence and is not. The
measured set — migrations, audit chain append and verify, event insert, indexed
filter, FTS query, health latency — is real, and it already catches regressions in
the storage layer that later phases depend on.

**Cost.** `docs/perf-results.md` is incomplete against spec 09 until those phases
land, so it must be re-read as a Phase 0 snapshot, not a target verdict.

## 2026-10-03 — The offline bundle installs dependencies, not the application

**Decision.** `make package` bundles wheels plus the application source tree, and
`install.sh` / `install.ps1` install only the dependencies and run
`python -m app.main` from `backend/`. The application is not pip-installed.

**Why.** `app/` resolves `migrations/`, `rules/` and `data/` relative to its own
location, so an installed wheel would look for them in `site-packages`. Running
from the tree is also what the container image does, so there is one layout to
reason about rather than two.

**Cost.** The bundle carries source rather than a binary, and the installer cannot
be a single `pip install triagelens`. Making the app a proper installable package
means moving resources inside the package, which is a later refactor.

## 2026-10-03 — Benchmarks are excluded from the test gate

**Decision.** `tests/perf` is skipped by `make test` and `make backend-coverage`,
and runs only via `make perf`.

**Why.** These tests assert on wall-clock time. Under a shared or loaded machine
they fail for reasons that have nothing to do with the code, which trains people
to ignore a red build.

**Cost.** A performance regression is not caught by CI; it surfaces when someone
runs `make perf`.
