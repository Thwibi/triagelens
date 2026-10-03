# 11 — Agent Build Prompts

Use the **Master prompt** once as the standing instruction for the coding agent, then feed the phase prompts **in order**. Do not start a phase until the previous phase's acceptance gate passes. Put this whole bundle in the repo under `docs/spec/` so the agent can read it.

---

## Master prompt (system / standing instructions)

```
You are a senior engineer building TriageLens, a standalone, fully local log triage tool, strictly from the specification bundle in docs/spec/ (files 00 to 10). Treat every MUST in the spec as a hard requirement.

Non-negotiable rules:
1. No stubs, placeholders, TODO/FIXME, pass-only functions, mock data, fake endpoints, or "implement later" comments in shipped code. Everything you write must work.
2. Do not weaken, skip, or reinterpret requirements. If something is impossible or contradictory, write the problem, the evidence, and the closest compliant alternative in DECISIONS.md, continue with that alternative, and flag it in your final report for the phase. Never silently simplify.
3. Every module ships with tests in the same change. Run the tests and the linters yourself and fix failures before reporting. Report the exact commands you ran and their results.
4. Treat all log content and uploaded files as hostile (spec 10). Parameterize SQL, escape output, bound resources.
5. The app must work fully offline. No CDN assets, no outbound network calls, no telemetry.
6. Keep parsers, detection, IOC, and MITRE code independent of FastAPI so they are importable as a library.
7. Follow the repository layout in spec 01. Use Python 3.11+, strict typing (mypy strict on app/), ruff, pytest, and pinned lockfiles.
8. Before coding a phase, read the spec files listed for that phase in full. After coding, verify each acceptance bullet explicitly and list which test proves it.
9. Commit in small logical steps with clear messages. Do not rewrite history.
10. If you need a decision the spec does not cover, choose the simplest option consistent with the spec, record it in DECISIONS.md, and proceed.

At the end of each phase output: (a) what was built, (b) test and lint commands with pass/fail summaries, (c) acceptance checklist with evidence, (d) entries added to DECISIONS.md, (e) known gaps (there should be none against the phase scope).
```

---

## Phase 0 — Scaffold, config, DB, migrations

```
Read: 00-README, 01-ARCHITECTURE, 02-DATA-MODEL, 10-SECURITY-AND-OPERATIONS (sections 1 and 4).

Build:
- Repository layout from spec 01 with backend (pyproject, app package skeleton with real modules), frontend (Vite + React + TS strict + Tailwind + ESLint with react/no-danger), docker/, scripts/, Makefile (install, dev, test, lint, typecheck, build, package, perf).
- config.py: config.toml loading + TRIAGELENS_* env overrides, validation with pydantic (refuse non-loopback bind without auth_token).
- DB layer: connection factory with the PRAGMAs in spec 01 §5, startup check for FTS5 and JSON1 with a clear error, migration runner applying migrations/0001_init.sql exactly as in spec 02 §4 (plus the audit-log immutability triggers and audit_tombstones table from spec 10 §2), repositories with typed methods for cases, sources, jobs, settings, audit_log (hash chain append + verify).
- FastAPI app factory: /api/health (spec 06), security headers middleware (spec 10 §1), Host header validation, static file mount for the built frontend, structured JSON logging.
- CI-equivalent make targets working.

Tests: migrations apply on empty DB and refuse newer schema; FTS5/JSON1 check; audit chain append/verify/tamper detection; config validation; headers present; Host validation.

Acceptance: `make lint typecheck test` green; `GET /api/health` returns the spec'd fields; tampering with an audit row is detected; app refuses to start bound to 0.0.0.0 without a token.
```

## Phase 1 — Core pipeline, detection of formats, jobs

```
Read: 01-ARCHITECTURE (sections 3 to 5), 02-DATA-MODEL (sections 1, 2, 5), 03-PARSERS (sections 1 and 7), 06-API (cases, sources, jobs, WebSocket), 10 (archives, uploads).

Build:
- NormalizedEvent dataclass and normalization helpers (control-char cleanup, empty to null, IP canonicalization, UTC conversion, level normalization).
- Parser registry + LogParser protocol + ParseContext.
- Format detection (ingest/detect.py) per spec 03 §1 with a registry-driven sniff vote.
- Safe intake: streaming upload with SHA-256, read-only storage, safe archive expansion with all limits, from-path import with allowed roots.
- Job manager: asyncio job queue, ProcessPoolExecutor workers with watchdog and memory cap, single DB writer thread with batched inserts (5,000/event batch) including FTS rows, progress events over WebSocket, cancellation with cleanup, needs_input flow and /sources/{id}/resolve.
- Source inventory computation, parse_errors storage, source counters.
- API: cases, sources, jobs, WS endpoints exactly as spec 06.
- A trivial but real parser is NOT allowed as a placeholder: use the generic NDJSON parser (spec 03 §6 with the ECS profile) so the pipeline is exercised end to end; the Windows/Linux/web/firewall parsers come in later phases.

Tests: spec 09 §6 items for cases/sources/jobs, S-01, S-06, S-09, P-01 to P-04, P-12 (for the formats available), cancellation, concurrent uploads, writer-thread batching, FTS rows consistent with events.

Acceptance: uploading an ECS NDJSON file and a zip containing three files ingests all events with correct hashes, shows progress over WebSocket, and survives a worker crash; zip bomb/zip-slip/symlink fixtures are rejected.
```

## Phase 2 — Windows parsers

```
Read: 03-PARSERS section 2 in full, 02-DATA-MODEL, 09 (P-05 to P-07, fixtures).

Build: windows_evtx and windows_event_xml parsers sharing one event-dict mapping function, with the complete mapping table in spec 03 §2.1 (every row), Sysmon hash splitting, message synthesis, ls_category assignment, per-record error handling, chunk-boundary error rows. Use the evtx (pyevtx-rs) library, with python-evtx as the documented fallback. XML parsing with the hardened lxml settings.

Also generate the Windows fixtures (script in scripts/make_fixtures.py writing both .evtx-equivalent test inputs and Event XML; if producing real .evtx binaries is impractical, include a small set of real-format .evtx files obtained or authored via a documented method, and always the XML variants) with golden expected JSON.

Tests: every table row has at least one golden test; P-07; XXE test S-08; corrupted EVTX chunk fixture; detection of both formats by magic bytes.

Acceptance: all mapping rows covered by tests; Scenario C source events parse with expected columns; throughput target measured and recorded.
```

## Phase 3 — Linux parsers

```
Read: 03-PARSERS section 3, 09 (P-05, P-08).

Build: linux_syslog/linux_auth (three framings, continuation handling, year/timezone inference, every message pattern in the table with exact regexes), linux_journald, linux_auditd (serial grouping, EXECVE reconstruction, hex decoding, SOCKADDR decoding, proctitle). Auto choice between linux_auth and linux_syslog.

Tests: golden tests for every pattern row; year rollover; hex-arg decoding; split-serial events; Scenario A source parsing exactly as in spec 09.

Acceptance: Scenario A fixtures yield the expected normalized events (event_action, user_name, src_ip, ports) and zero parse errors for valid lines.
```

## Phase 4 — Web, firewall, generic parsers

```
Read: 03-PARSERS sections 4 to 6, 09 (P-09 to P-11).

Build: apache/nginx access (+ malformed fallback), nginx/apache error, IIS W3C; iptables/UFW, pfSense filterlog, Fortinet, Palo Alto (version field maps in data/profiles/paloalto_fields.yaml), Cisco ASA (all listed message ids); generic JSON/CSV with the profile engine, all shipped profiles (ECS, Wazuh, Splunk CSV, Defender/Sentinel CSV, Zeek JSON and TSV, CloudTrail), user profile save/import, API for profile CRUD and preview (add endpoints /profiles, /profiles/preview consistent with spec 06 conventions and document them in 06).

Tests: golden tests for each parser and profile; Scenario B and the firewall part of Scenario C data; P-09 to P-11; auto-detection for every fixture.

Acceptance: all fixtures auto-detect with confidence >= 0.8 and parse with zero errors for valid lines; the mapping wizard API previews 20 rows from a sample.
```

## Phase 5 — IOC engine

```
Read: 05-IOC-EXTRACTION in full, 09 section 5.

Build: ioc package (extractors with the exact regexes, validators, ambiguous-TLD rules, refang, decoders, classification, allowlists with default_allowlist.yaml and iana_tlds.txt, confidence scoring, dedup/normalization, worker-side aggregation, tier-1 extraction wired into the ingest pipeline, tier-2 extraction API used after detection), storage into iocs/ioc_occurrences/ioc_alerts, API endpoints for IOCs, entities, export (CSV/TXT/STIX/JSON, defang), optional enrichment code path behind allow_enrichment with audit logging and keyring/env key handling.

Tests: all of spec 09 §5 (>= 150 table cases), adversarial regex timing tests, S-05, STIX validation.

Acceptance: IOC precision target met on the fixtures; no private IP emitted unflagged; exports round-trip.
```

## Phase 6 — Detection engine and rules

```
Read: 04-DETECTION-ENGINE in full, 02 (rules, alerts tables), 09 section 4.

Build: rule loader (pySigma parse, hashing, multi-document YAML, health fields), logsource routing from rules/logsource_map.yaml, the SQLite backend/compiler with every supported modifier, field-resolution pipeline, UDFs (regexp via the regex module with timeouts, cidr_match), execution with time budgets, inventory-based pruning, detection profiles, correlation engine (event_count, value_count, temporal, temporal_ordered, nesting, aliases), alert construction/grouping/deterministic ids/status carry-over, detection_runs and rule_runs recording, vendored SigmaHQ rules with SOURCES.md and licenses, the ten built-in rule files exactly as in spec 04 §10, rules API (list, CRUD for custom, validate, test, import/export, health), detect API and job.

Tests: D-01 to D-09, D-11, D-12, S-04, S-07 and the compile-health report.

Acceptance: Scenario A, B, and the correlation parts of C produce the expected alerts from raw fixtures; all built-in rules fire only on their fixtures; >= 200 SigmaHQ rules compile; results are deterministic across two runs.
```

## Phase 7 — MITRE, scoring, alerts, remaining API

```
Read: 04 sections 6 to 8, 06-API in full, 08 section 3.

Build: ATT&CK STIX loader and importer (offline), tag parser, resolver, fallbacks (data/mitre_fallbacks.yaml with at least the listed entries), matrix aggregation endpoints, technique lookup, scoring with breakdown, alert endpoints (filters, bulk, status, notes, evidence pagination), events endpoints (filters, FTS, facets, cursor pagination, count), timeline endpoint, audit-log endpoint with chain verification, settings endpoints, Navigator layer generation, and tier-2 IOC linking for alert evidence.

Tests: D-10, scoring tests, all API tests in spec 09 §6 for these endpoints (including cursor stability under concurrent inserts and FTS syntax errors), Navigator schema validation.

Acceptance: every endpoint in spec 06 exists and is covered; Scenario A/B/C API-level expectations in spec 09 §7 pass (alerts, techniques, tactics, IOCs, entities).
```

## Phase 8 — Frontend (execute as 8a to 8d, each with its own gate)

```
Read: 07-UI-SPEC in full, 06-API.

8a: app shell, theming and tokens, routing, API client with typed schemas generated from the backend OpenAPI, WebSocket client with reconnect/backoff, jobs drawer, Cases and Overview screens, Sources screen with dropzone, hashing display, needs_input flow, mapping wizard.
8b: Alerts screen (table, filters, bulk actions, keyboard shortcuts) and Alert drawer (all seven blocks), MITRE screen.
8c: IOCs, Events (FTS search, facets, drawer with raw view and safe highlighting), Timeline, Entities.
8d: Rules (list, YAML editor with validate/test, import/export, health), Reports, Settings, About/licenses, accessibility pass, empty/loading/error states everywhere.

Rules: no dangerouslySetInnerHTML anywhere; virtualization on all large tables; filters in URL; all fonts/icons bundled; no external requests (verify with a Playwright network guard).

Tests: Vitest component tests for tables/filters/drawers/shortcuts, Playwright E2E for Scenarios A to C as defined in spec 09 §7, S-02 (XSS payload rendering), Lighthouse accessibility >= 95, bundle size budget.

Acceptance: each sub-phase's screens match spec 07 item by item (produce a checklist with screenshots saved under docs/screens/); the Playwright suite passes headless.
```

## Phase 9 — Reports, packaging, hardening, final verification

```
Read: 08 (all), 10 (all), 09 (sections 8 and 9).

Build: report service (HTML via Jinja2 autoescape, Markdown, JSON, optional PDF via WeasyPrint with health flag), report endpoints and UI wiring, CSV/JSONL exports with formula-injection protection and streaming, Dockerfile and docker-compose per spec 10, run.sh/run.ps1, offline package target, backup/diag/update scripts, secure-delete option, disk-space guards, THIRD_PARTY_NOTICES.md and SOURCES.md, README.md with install/run/usage, docs/validation.md for manual dataset validation.

Run: full test suite, performance benchmarks (record results in docs/perf-results.md), security tests S-01 to S-09, E2E, pip-audit and npm audit, a clean-machine install from the offline package with networking disabled.

Final report: spec compliance matrix (every MUST in files 00 to 10 mapped to code and test), DECISIONS.md summary, performance table vs targets, open risks (should be none). Fix every gap before declaring done.
```

---

## Prompt for fixing a failed gate

```
The acceptance gate for Phase N failed. Do not change tests to make them pass and do not relax the spec. Reproduce each failure, find the root cause, fix the implementation, add a regression test where one was missing, rerun the full gate, and report the before/after results. If the spec itself is wrong or contradictory, document it in DECISIONS.md and propose the minimal spec change instead of working around it.
```

## Prompt for adding a new parser later

```
Add a new parser for <format> following spec 03 conventions: sniff() with a confidence score, streaming parse() yielding NormalizedEvent, every unmapped field preserved in fields_json, ls_category assignment, logsource_map.yaml entry if a new routing predicate is needed, golden fixtures (>= 10 valid, >= 5 malformed), auto-detection test, throughput benchmark, and documentation added to 03-PARSERS.md. No changes to unrelated modules.
```
