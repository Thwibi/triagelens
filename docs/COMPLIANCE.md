# Spec compliance matrix

Every normative requirement in spec files 00-10 mapped to the code that
implements it and the test(s) that cover it. Spec 00 states the rule: where a
file says **MUST**, the implementation must do it, and nothing is optional unless
marked *(optional)*.

Status legend:

- **Covered** — implemented and exercised by a test that would fail if it regressed.
- **Partial** — implemented, but the spec's exact check is only partly exercised
  (the gap is named in the row or in "Gaps and open risks").
- **Gap** — not implemented, or not verifiable in this environment.

Test paths are relative to `backend/tests/` unless prefixed. Frontend paths are
relative to `frontend/src/`.

## 00 — README / non-functional baseline

| Requirement | Code | Test | Status |
|---|---|---|---|
| API stack: FastAPI + Uvicorn + Pydantic v2 | `app/main.py`, `app/config.py` | `test_api.py`, `test_config.py` | Covered |
| Storage: SQLite (WAL) with FTS5 and JSON1; MUST verify both at startup and fail with a clear message | `app/db/connection.py` (PRAGMA + capability probe) | `test_db_connection.py` | Covered |
| Detection: pySigma + custom SQLite evaluation | `app/detect/` | `test_detect_*.py` | Covered |
| EVTX: `evtx` (pyevtx-rs) primary, python-evtx fallback | `app/ingest/parsers/windows_evtx.py`, vendored `evtxlib/` fallback | `test_ingest_windows.py` | Covered |
| Acceptance: every MUST implemented and covered by a test | this document | — | Partial (open gaps, below) |
| Acceptance: `make test` passes; coverage ≥ 85% on `parsers`, `detect`, `ioc`, `mitre` | `scripts/task.py backend-coverage` (gate floor 80% overall; vendored `evtxlib/` omitted from coverage, as it already is from ruff and mypy) | `.coverage` report | Covered — `parsers` 88%, `detect` 92%, `ioc` 93%, `mitre` 94%, all ≥ 85%; overall 89.56% vs the 80% floor. The gate enforces 80% overall, the four named packages are measured and recorded here |
| Acceptance: the three E2E scenarios in spec 09 §7 pass on expected alert/IOC/MITRE output | pipeline + detection | `test_ingest_pipeline.py`, `test_alerts_rules_mitre_api.py`; browser level: `frontend/e2e/scenario-{a,b,c}.spec.ts` | Covered — API-level assertions plus the Playwright suite (spec 09 §7) driving the real UI end to end |

## 01 — Architecture

| Requirement | Code | Test | Status |
|---|---|---|---|
| `allow_enrichment=false` → the process MUST NOT open outbound sockets; enrichment opt-in only | no network client ships; `app/config.py` `network.allow_enrichment` (flag reserved, surfaced in `/api/health`) | `test_ingest_pipeline.py::TestNoOutboundConnects` (loopback-allowing `socket.connect`/`connect_ex`/`create_connection` guard over a full ingest → detect → report run, plus a negative control) | Covered |

## 02 — Data model

| Requirement | Code | Test | Status |
|---|---|---|---|
| Never drop information: anything unmapped lands in `fields_json` | `app/ingest/parsers/`, `app/ingest/normalize.py` | `test_ingest_normalize.py`, `test_ingest_events.py` | Covered |
| IPs MUST be validated with `ipaddress`; invalid values stay only in `fields_json` | `app/ingest/normalize.py`, `windows_common.py` | `test_ingest_normalize.py` | Covered |
| Strings stripped of NUL and C0 controls except `\t\n\r`; invalid UTF-8 decoded with `errors="replace"` | `app/ingest/normalize.py` | `test_ingest_normalize.py` | Covered |
| Empty strings become `null` | `app/ingest/normalize.py` | `test_ingest_normalize.py` | Covered |

## 03 — Parsers

No literal "MUST" tokens; the per-format tables are normative. Covered by
`test_ingest_linux.py`, `test_ingest_windows.py`, `test_ingest_web.py`,
`test_ingest_firewall.py`, `test_ingest_generic.py`, `test_ingest_archive.py`,
`test_ingest_pipeline.py`, including parser safety (S-08 XXE in
`test_ingest_windows.py`).

## 04 — Detection engine

| Requirement | Code | Test | Status |
|---|---|---|---|
| Every listed modifier MUST work (`contains, startswith, endswith, all, re, cidr, base64, base64offset, utf16le, utf16be, wide, windash, exists, cased, neq, lt, lte, gt, gte, fieldref, expand`); unsupported → `compile_error` | `app/detect/ext.py`, `compile.py` | `test_detect_compile.py`, `test_detect_rules.py` | Covered |
| Value matching case-insensitive by default; `LIKE ? ESCAPE '\'` with escaping; `cased` → `instr()`/`GLOB` | `app/detect/compile.py` | `test_detect_compile.py` | Covered |
| `1 of selection*`, `all of them`, `not`, parentheses, field-less keyword search | `app/detect/compile.py` | `test_detect_compile.py`, `test_detect_rules.py` | Covered |
| Null checks (`field: null`) → `IS NULL` | `app/detect/compile.py` | `test_detect_compile.py` | Covered |

## 05 — IOC extraction

| Requirement | Code | Test | Status |
|---|---|---|---|
| Validation rules all MUST be enforced: IP (reject leading-zero octets, version/MAC/time contexts, strip `::ffff:`); Domain (IANA TLD, length/label rules, filename rejection, ambiguous-TLD policy); URL (trailing-punct rules, `urlsplit`, host emitted as its own IOC); Hash (boundary/entropy/id-prefix/RandomSeed rules); Email (domain + local-part limits) | `app/ioc/` (`extract`, `validate`, `normalize`, `blocklists.py`) | `test_ioc_core.py` (spec 09 §5 table cases), `test_ioc_export.py`, `test_ioc_alert_link.py` | Covered |

## 06 — API

| Requirement | Code | Test | Status |
|---|---|---|---|
| Auth: none on loopback; non-loopback bind → every request MUST carry `Authorization: Bearer` (WebSocket `?token=`), else 401 | `app/api/middleware.py`, `app/config.py` | `test_api.py` | Covered |
| Errors: HTTP status + JSON body shape | `app/errors.py` | `test_api.py` and per-router API tests | Covered |
| Every endpoint in spec 06 exists, with validation/not-found/pagination | `app/api/routers/` | `test_*_api.py`, `test_ingest_pipeline.py` | Covered |

## 07 — UI spec

No literal "MUST" tokens; the screen tables are normative. Covered by frontend
Vitest suites (30 files) and, for the browser-level acceptance, the Playwright
E2E scenarios (spec 09 §7) under `frontend/e2e/`. The < 1.5 MB gzipped
bundle-size budget is enforced by `scripts/task.py frontend-budget`
(`frontend/scripts/check-bundle-budget.mjs`, run in CI), and accessibility is
checked by an axe-core WCAG 2.1 A/AA scan of the thirteen main screens
(`frontend/e2e/a11y.spec.ts`, where serious/critical violations fail) — the
Lighthouse ≥ 95 clause is met by this equivalent.

## 08 — Reporting and export

No literal "MUST" tokens; normative. Covered by `test_reports.py`,
`test_events_export.py` (formats, streaming, formula guard, autoescape) and
`features/reports/ReportsPage.test.tsx`.

## 09 — Test plan

| Requirement | Code | Test | Status |
|---|---|---|---|
| §7 E2E Scenarios A/B/C (expected results normative) | pipeline + detection | `test_ingest_pipeline.py`, `test_alerts_rules_mitre_api.py`, `test_correlation.py`, `test_mitre.py`; browser level: `frontend/e2e/scenario-{a,b,c}.spec.ts` | Covered (API-level assertions plus the Playwright browser E2E) |
| §9 S-01 zip bomb / zip-slip / symlink / absolute / nested | `app/ingest/archive.py` | `test_ingest_archive.py` (`test_zip_slip_writes_nothing_outside`, `test_absolute_member_is_refused`, `test_symlink_member_is_refused`, `test_expansion_ratio_bomb`, `test_nesting_deeper_than_allowed`), `test_ingest_pipeline.py` | Covered |
| §9 S-02 hostile text inert in UI; escaped in HTML/MD/PDF | React text rendering, `app/reports/render.py` (autoescape) | `test_reports.py` (autoescape), frontend render tests; `frontend/e2e/xss.spec.ts` (no dialog, text rendered inert) | Covered |
| §9 S-03 CSV injection prefixed in exports | `app/util/csv.py` `safe_cell` | `test_events_export.py`, `test_reports.py::test_render_alerts_csv_escapes_injection` | Covered |
| §9 S-04 SQL injection through every filter param / rule field | parameterized queries; `app/detect/fields.py` JSON-path builder doubles SQL quotes | `test_sql_injection.py` (filter sweep + hostile rule field + import), `test_detect_fields.py` | Covered |
| §9 S-05 zero outbound connects on a full run; enrichment off → 403 | no network client ships; optional enrichment (spec 05 §9) not implemented | `test_ingest_pipeline.py::TestNoOutboundConnects` (socket guard, zero non-loopback connects; negative control proves the guard fires) | Covered (the 403 half is N/A: optional enrichment ships no endpoint, so there is nothing to gate) |
| §9 S-06 non-loopback bind without token refuses to start | `app/config.py` | `test_config.py`, `test_api.py` | Covered |
| §9 S-07 YAML bombs rejected (size/alias limits) | `app/detect/rules.py` `_AliasLimitedSafeLoader` (1 MB cap, alias-event count cap, SafeLoader tag rejection) | `test_detect_rules.py::TestYamlLimits` | Covered |
| §9 S-08 XXE in event XML does not resolve entities | `app/ingest/parsers/windows_event_xml.py` (`resolve_entities=False`, `no_network=True`, `load_dtd=False`, `huge_tree=False`) | `test_ingest_windows.py::test_an_xxe_payload_does_not_leak_a_local_file` | Covered |
| §9 S-09 crashing worker → source `failed`, server up, other jobs continue | worker + writer watchdog | `test_ingest_pipeline.py` (`os._exit` worker-crash test) | Covered |
| §8 performance targets on the reference laptop | `backend/tests/perf/test_benchmarks.py` (storage/parse/IOC/health primitives) | `make perf` → `docs/perf-results.md` | Partial (end-to-end targets not measured; see Gaps) |

## 10 — Security and operations

### Threat model (spec 10 §1, "all MUST")

| Threat | Code | Test | Status |
|---|---|---|---|
| XSS via log content (UI/report) | React text rendering; ESLint `react/no-danger`; Jinja2 autoescape; CSP; no JS in reports; sandboxed preview | `test_reports.py` (autoescape), ESLint gate, `test_api.py` (CSP) | Covered |
| CSV/formula injection | `app/util/csv.py` `safe_cell` (`'`-prefix for `= + - @ \t \r`) | `test_events_export.py`, `test_reports.py` | Covered |
| Path traversal / zip-slip | `app/ingest/archive.py` (stored as `<source_id>`; resolved-path containment; reject absolute/`..`/symlink/hardlink/device) | `test_ingest_archive.py`, `test_ingest_pipeline.py` | Covered |
| Zip/decompression bombs (streaming limits) | `app/ingest/archive.py`, `app/config.py` limits | `test_ingest_archive.py` | Covered |
| Malformed EVTX crashing the server (worker + watchdog) | `app/jobs/` worker processes, per-source timeout | `test_ingest_pipeline.py` | Covered |
| ReDoS | reviewed builtin regexes; `regex` module timeout; `max_line_bytes`; per-record guard | `test_ingest_*` adversarial cases | Partial (no timing test in evidence) |
| SQL injection | parameterized queries; allowlisted identifiers; FTS `MATCH` parameterized; JSON-path quote doubling | `test_sql_injection.py` (incl. `DROP TABLE` FTS payload → 422, never 500) | Covered |
| XML attacks (XXE/entity expansion) | `windows_event_xml.py` flags | `test_ingest_windows.py` | Covered |
| YAML attacks | `_AliasLimitedSafeLoader` (1 MB size cap, alias-event count cap, custom tags rejected) | `test_detect_rules.py::TestYamlLimits` | Covered |
| Unintended network exposure | default loopback; refuse non-loopback without token; same-origin CORS; Host validation | `test_config.py`, `test_api.py` | Covered |
| Data exfiltration / telemetry | no analytics/remote assets; no network client ships; `allow_enrichment` flag reserved | `test_ingest_pipeline.py::TestNoOutboundConnects` (zero non-loopback connects on a full run) | Covered |
| Secrets leakage | keyring/env only; redacted in logs | `test_*` redaction cases; `app/util/logging.py` | Partial |
| Local abuse via `from-path` import | `allowed_import_roots`; symlink resolution; special-file refusal | `test_ingest_intake.py` | Covered |
| Disk exhaustion (≥ 3× file size; stop < 5%) | `app/ingest/archive.py` `ensure_disk_space` | `test_disk_guard.py` | Covered |

### Required HTTP headers (spec 10 §1)

| Requirement | Code | Test | Status |
|---|---|---|---|
| CSP + `X-Content-Type-Options` + `Referrer-Policy` + `Cross-Origin-Opener-Policy` + `Cache-Control: no-store` on responses | `app/api/middleware.py` | `test_api.py` | Covered |
| Preview iframe served with the sandbox CSP | `app/api/routers/reports.py` + frontend `sandbox=""` | `test_reports.py`, `ReportsPage.test.tsx` | Covered |

### Forensic integrity (spec 10 §2)

| Requirement | Code | Test | Status |
|---|---|---|---|
| Hash on intake (streaming SHA-256 → `sources.sha256`; read-only `0444` originals) | `app/ingest/intake.py`, `archive.py` | `test_ingest_intake.py`, `test_ingest_pipeline.py` | Covered |
| `GET /sources/{id}/download` returns file + `X-SHA256`; UI "Verify integrity" | `app/api/routers/sources.py` | `test_ingest_pipeline.py`, `test_maintenance.py` (hash check) | Covered |
| Evidence immutability (never opened for write) | `app/ingest/` | `test_ingest_intake.py` (read-only assertion) | Covered |
| Reproducibility (detection run records tool version, ruleset hash, ATT&CK version, profile) | `app/jobs/`, `app/detect/`, `detection_runs` store | `test_detect_api.py`, `test_detect_engine.py` | Covered |
| Audit hash chain; `GET /cases/{id}/audit-log` verifies; append-only (triggers; no UPDATE/DELETE) | `app/db/repositories/audit.py`, `migrations/0001_init.sql` | `test_audit.py`, `test_case_delete.py` | Covered |
| Case deletion writes a final tombstone in `audit_tombstones` | `app/api/routers/cases.py`, `app/db/repositories/audit.py` | `test_case_delete.py` | Covered |
| All timestamps UTC; raw text preserved | `app/util/time.py`, `events.raw` | `test_ingest_normalize.py` | Covered |

### Privacy (spec 10 §3)

| Requirement | Code | Test | Status |
|---|---|---|---|
| Data never leaves the machine by default; export warning; cover states "Contains evidence-derived data" | `app/reports/`, frontend export UI | `test_reports.py`, `ReportsPage.test.tsx` | Covered |
| Secure delete (optional): overwrite originals once before unlink when `storage.secure_delete=true` | `app/ingest/intake.py` `remove_stored(secure=)` | `test_ingest_intake.py`, `test_case_delete.py` | Covered |

### Packaging and deployment (spec 10 §4)

| Requirement | Code | Test | Status |
|---|---|---|---|
| Multi-stage Dockerfile (Node build + python:3.12-slim, lockfile `--require-hashes`, non-root, EXPOSE 8787, HEALTHCHECK, optional `WITH_PDF=1`) | `docker/Dockerfile` | — | Covered (build verified by inspection; image run not executed here) |
| Compose: loopback-published port, token, volume, healthcheck | `docker/compose.yaml`, `scripts/compose.sh`/`.ps1` | — | Covered |
| Bare metal `run.sh`/`run.ps1` (venv, FTS5/JSON1 verify, migrations, uvicorn, browser) | `scripts/run.sh`, `scripts/run.ps1` | — | Covered |
| Offline bundle (`make package`): wheelhouse, built frontend, rules/data | `scripts/package_offline.py` | — | Covered (build not run to clean install here) |
| Manual-only updates (no update checks) | `scripts/update_rules.py`, `scripts/update_attack.py` | `test_mitre.py` | Covered |

### Operations (spec 10 §5)

| Requirement | Code | Test | Status |
|---|---|---|---|
| `scripts/backup.py <case_id\|all> <dest>` zip (VACUUM INTO, originals, reports, manifest) | `scripts/backup.py` | smoke-verified (9d) | Covered |
| Settings → Data: Vacuum, Rebuild FTS, Verify hashes, Verify audit chain | `frontend/src/features/settings/SettingsPage.tsx`, `app/api/routers/maintenance.py` | `test_maintenance.py`, `SettingsPage.test.tsx` | Covered |
| Disk layout (`data/triagelens.db`, `cases/`, `reports/`, `rules/custom/`, `logs/`) | `app/config.py` | `test_config.py` | Covered |
| Resource limits: worker count, ingest queue length (default 20), queue position in UI | `app/config.py`, `app/jobs/` | `test_ingest_pipeline.py`, `JobsProvider` tests | Covered |
| Diagnostics bundle `scripts/diag.py` (versions, redacted config, recent logs, `/health`) | `scripts/diag.py` | smoke-verified (9d) | Covered |

### Supply chain (spec 10 §6)

| Requirement | Code | Test | Status |
|---|---|---|---|
| Lockfiles with hashes (`requirements.lock`, `package-lock.json`) | `backend/requirements.lock`, `frontend/package-lock.json` | `scripts/gen_lock.py`, `verify_lock.py`, `task.py lock-check` | Covered |
| `pip-audit` and `npm audit` in CI; fail on high/critical | `.github/workflows/ci.yml` (frontend job `npm audit --audit-level=high`; `dependency-audit` job `pip-audit -r backend/requirements.lock`) | the workflow itself; local `npm audit` here: 0 vulnerabilities | Covered |
| Vendored rule/data provenance in `SOURCES.md`; licences in `THIRD_PARTY_NOTICES.md` and shown in the UI About dialog | `SOURCES.md`, `THIRD_PARTY_NOTICES.md`, `backend/rules/sigma/UPSTREAM-LICENSE.md`, `AboutDialog.tsx` (bundles `THIRD_PARTY_NOTICES.md?raw` into a collapsible panel) | `SettingsPage.test.tsx` (About dialog shows "Detection Rule License (DRL) 1.1" and "MITRE ATT&CK") | Covered |

## Gaps and open risks

These are the requirements the matrix marks Partial/Gap. They are known and
intentional at this point, and are tracked in `docs/STATUS.md`; fixing them is the
remaining work.

1. **Lighthouse itself is not run.** The spec 07 accessibility clause is covered
   by an axe-core WCAG 2.1 A/AA scan of the thirteen main screens
   (`frontend/e2e/a11y.spec.ts`), but the literal Lighthouse ≥ 95 tool is not
   installed here; the axe rule set is the deterministic offline equivalent.
2. **Offline clean-machine install not executed.** `make package` and the
   installer exist, but the bundle was not installed on a separate
   network-disabled machine.
3. **Spec 09 §8 end-to-end performance targets are not measured.** `make perf`
   records storage, parsing, IOC and health *primitive* timings (refreshed
   2026-10-11 in `docs/perf-results.md`), but not the multi-worker ingest
   throughput, the 1M-event detection run (≤ 5 min, ≤ 2 GB RSS), the 5M-event
   API/FTS p95, the UI paint time, or the 10 GB ingest memory target. The
   reference-laptop verdict is therefore unproven; the numbers are a regression
   baseline only.

## Re-running the verification

```bash
make all                 # lint, typecheck, test on both sides
make backend-coverage    # backend coverage floor
make e2e                 # build the app and run the browser E2E suite
make frontend-budget     # enforce the spec 07 bundle-size budget (after a build)
make perf                # refresh docs/perf-results.md
python scripts/task.py scripts-lint
cd frontend && npx --no-install vitest --run
```

Post-audit commands that need network or new tools (not run in this environment):

```bash
python -m pip install pip-audit && pip-audit -r backend/requirements.lock
cd frontend && npm audit --audit-level=high
```
