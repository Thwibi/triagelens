# Status

What works today, and what does not. Updated at the end of each phase.

## Phase 9 - Reporting, export, packaging and hardening (complete; open gaps recorded)

The spec 11 phase 9 build. Slices **9a (report service and endpoints)**,
**9b (streamed event CSV/JSONL export)**, **9c (Reports screen + Events
export wiring)**, **9d (backup/diagnostics scripts, disk guards, secure
delete and the Data-maintenance screens)**, **9e (README and the manual
validation guide)** and **9f (final verification)** are implemented. The
verification outcome and every requirement that could not be checked in this
environment are in `docs/COMPLIANCE.md`; the open gaps are listed below.

| Area | State |
|---|---|
| Report model | `app/reports/model.py`: one neutral dataclass tree (`ReportMeta`, `ReportSummary`, `ReportAlert`, `ReportIoc`, sources, runs, integrity) with `as_dict()` carrying `schema_version`; every format renders from this one model (spec 08 §1) |
| Options | `app/reports/options.py`: `ReportOptions` + `options_from_dict`; `alerts` absent means every status, an explicit empty list turns the alert sections off; `events_per_alert` bounded to 50; unknown format/status is a 422 |
| Gather | `app/reports/gather.py`: `gather_report` reads cases, alerts (paged, filtered by status), alert detail with evidence and per-alert IOCs, MITRE matrix + Navigator layer, timeline buckets, entities, source integrity and the audit-chain verification, on a read connection |
| Render | `app/reports/render.py`: JSON, GitHub-flavoured Markdown (widened fences, pipe-escaped cells), self-contained HTML (Jinja2 template `templates/report.html.j2`, inline CSS, inline SVG timeline + MITRE heat-grid, **autoescape on**, no JS and no external requests), PDF via WeasyPrint when installed, and the alert-overview CSV with the formula-injection guard |
| Service | `app/reports/service.py`: `generate_report` writes `reports_dir/<case_id>/<id>.<ext>`, records `reports` (path, sha256, options JSON) and appends a `report_created` audit row — all inside the writer transaction; `report_file` re-hashes the bytes against the recorded SHA-256 on download |
| Job | `app/jobs/report.py`: `ReportRunner`, registered for `JobKind.REPORT` in `main.py`, gathers + renders + writes on the single writer thread and publishes `gathering`/`rendering` stages |
| API | `app/api/routers/reports.py`: `POST /cases/{id}/reports` (202 job; PDF without WeasyPrint → `422 PDF_UNAVAILABLE`; unknown format → 422; unknown case → 404), `GET /cases/{id}/reports` (newest first + total), `GET /reports/{id}/download` (`Content-Disposition` + `X-SHA256`, re-hashed), `GET /cases/{id}/reports/alerts.csv` (bounded pages, `X-Total`, formula guard) |
| Export module | `app/reports/export.py`: `iter_events_export` walks the current filter result in keyset pages and yields text chunks, CSV with every normalized column + `fields_json` as a JSON string and JSONL with parsed `fields`; bounded by `max_rows` (1M) so no case lands in memory (spec 08 §4, spec 06 §5, spec 07 §3.7) |
| Export endpoint | `GET /cases/{id}/events/export?format=csv\|jsonl` in `app/api/routers/events.py`: the same filters as the events list, streamed; invalid FTS syntax → 422 before the body starts; unknown case → 404; unknown format → 422 |
| CSV guard | `app/util/csv.py`: one `safe_cell` (prefix `'` for `= + - @ \t \r`) shared by the report alert CSV and the event export (spec 10 §1) |
| Reports UI | `features/reports/ReportsPage.tsx`: spec 07 §3.12 options form (format with PDF gated on `health.pdf_available`, title, analyst, alert-status checkboxes, events per alert 0–50, IOC/ATT&CK/timeline/entities/raw-appendix toggles), generate → `POST /cases/{id}/reports`, a history table (created, format, truncated SHA-256 with copy, download) and an HTML preview in a `sandbox=""` (scripts-off) iframe via `GET /reports/{id}/download`; the report list refreshes when a `report` job finishes (JobsProvider → `invalidateReports`) |
| Events export UI | `features/events/EventsPage.tsx`: the CSV/JSONL buttons now stream the current filter result from `GET /cases/{id}/events/export` (via `exportEvents`, 5-minute timeout, toast) instead of serialising the loaded rows client-side |
| Disk guard | `app/ingest/archive.py`: `ensure_disk_space` refuses an ingest when the free space is under 3× the incoming bytes or below `limits.min_free_disk_fraction` (5% default), raising `INSUFFICIENT_STORAGE` (507); `app/ingest/intake.py` calls it before storing, probing the nearest existing ancestor of `data_dir` (spec 10 §1) |
| Secure delete | `app/ingest/intake.py`: `remove_stored(dir, secure=)` zeroes each file in place (then `fsync`) before unlinking when `storage.secure_delete` is set; the read-only directory is made writable first so deletion succeeds on Windows (spec 10 §3) |
| Delete audit & tombstone | `DELETE /cases/{id}` (now `204`) and `DELETE /sources/{id}` append `case_deleted`/`source_deleted` audit rows inside the writer transaction; the case delete also records `audit_tombstones` (last hash + row count) and removes `data/cases/<id>/` and `data/reports/<id>/` after the DB commit (spec 02 §4, spec 06, spec 10 §2) |
| Maintenance API | `app/api/routers/maintenance.py`: `POST /maintenance/vacuum` (VACUUM on the writer thread without a surrounding transaction, returning byte size before/after), `/maintenance/rebuild-fts` (rebuild the `events_fts` index), `/maintenance/verify-hashes` (re-hash every stored original) and `/maintenance/verify-audit` (walk the chain). Not in spec 06; see DECISIONS |
| Maintenance UI | `features/settings/SettingsPage.tsx`: the Data section gains Vacuum, Rebuild search index, Verify evidence hashes and Verify audit chain buttons, each reporting its outcome in a toast; vacuuming refreshes the health figures |
| Backup script | `scripts/backup.py <case_id\|all> <dest>`: a zip with `VACUUM INTO` database snapshot, the case(s) `cases/`+`reports/` trees and a `manifest.json` of per-file SHA-256 + byte size; refuses a case id the DB does not know and a destination without room (spec 10 §5) |
| Diagnostics script | `scripts/diag.py`: versions, the effective config with secret-looking keys masked, the log tail and an optional live `/api/health` probe; never reads event content (spec 10 §5) |
| Docs | `README.md` updated from its Phase 0 state to describe the completed application, the end-to-end usage flow and the backup/diagnostics/maintenance tools; `docs/validation.md` adds the spec 09 §2 manual procedure for validating against public datasets (EVTX-ATTACK-SAMPLES, OTRF Mordor, Hayabusa, loghub). `SOURCES.md` and `THIRD_PARTY_NOTICES.md` were already in place (9e) |
| Compliance | `docs/COMPLIANCE.md`: every normative requirement in spec 00-10 mapped to the code that implements it and the test that covers it, with a status per row and the open gaps listed explicitly (9f) |
| Tests | `tests/test_reports.py`: runner writes an escaped, self-contained HTML file whose bytes match the recorded hash; the API flow enqueues → lists → downloads JSON; PDF answers 422; validation; CSV guard; two gathers of a case are identical given a fixed timestamp. `tests/test_events_export.py`: CSV column set/guard/round-trip through `csv`, JSONL shape, filters and the row cap, validation, and multi-page streaming of `iter_events_export`. `tests/test_maintenance.py`: verify-hashes ok/tampered/missing, FTS rebuild, vacuum, audit verification. `tests/test_case_delete.py`: `204` + audit row + tombstone + directory removal, and source-delete audit. `tests/test_disk_guard.py`: the headroom and floor rules. Frontend: `ReportsPage.test.tsx` (history, form POST body, sandboxed preview, PDF disabled), `EventsPage.test.tsx` export wiring, `JobsProvider.test.tsx` report invalidation, `SettingsPage.test.tsx` maintenance actions |

### Verification

| Gate | Command | Result |
|---|---|---|
| Backend lint | `.venv\Scripts\python.exe scripts\task.py backend-lint` | clean (ruff check + format check, 196 files) |
| Backend types | `.venv\Scripts\python.exe scripts\task.py backend-typecheck` | clean (mypy, 210 source files) |
| Backend tests | `.venv\Scripts\python.exe scripts\task.py backend-test` | 1818 passed, 1 skipped |
| Backend coverage | `.venv\Scripts\python.exe scripts\task.py backend-coverage` | 89.56% overall (80% floor met); `parsers` 88%, `detect` 92%, `ioc` 93%, `mitre` 94% — all four spec 00 packages ≥ 85% (vendored `evtxlib/` omitted, as from ruff/mypy) |
| Scripts lint | `.venv\Scripts\python.exe scripts\task.py scripts-lint` | clean (ruff check + format check, 11 files) |
| Frontend lint | `npx --no-install eslint . --max-warnings 0` (in `frontend/`) | clean |
| Frontend types | `npx --no-install tsc --build --force` (in `frontend/`) | clean |
| Frontend tests | `npx --no-install vitest --run` (in `frontend/`) | 232 passed (30 files) |
| Browser E2E | `python scripts\task.py e2e` (builds the app, then Playwright) | 5 passed — Scenarios A/B/C + the S-02 XSS render check (spec 09 §7) + the axe-core a11y scan of the 13 main screens; Chromium headless |
| Bundle budget | `python scripts\task.py frontend-budget` (after a build) | 693 KB gzipped vs the 1.5 MB spec 07 budget (PASS) |
| Benchmarks | `.venv\Scripts\python.exe scripts\task.py perf` | 15 primitive benchmarks, refreshed `docs/perf-results.md` |
| Audits | `npm audit --audit-level=high` (in `frontend/`); `pip-audit -r backend/requirements.lock` | npm: 0 vulnerabilities; pip-audit: only the accepted `diskcache` advisory (diskcache 5.6.3, PYSEC-2026-2447; no fix, unreachable — see DECISIONS), otherwise clean |
| CI | `.github/workflows/ci.yml` | backend lint/typecheck/coverage, frontend lint/typecheck/test/`npm audit`/bundle budget, a `pip-audit` job, and a browser `e2e` job; not yet executed on a runner |

### Known limitations

- PDF is an optional feature: with WeasyPrint absent the endpoint answers
  `422 PDF_UNAVAILABLE` and the format is not generated (spec 08 §2). WeasyPrint is
  not installed in this environment; the Reports screen disables the PDF option and
  explains why.
- The Reports history row does not show the requested title/analyst: the stored
  `options_json` (`ReportOptions.as_dict`) carries the section toggles but not the
  cover title/analyst, and the `reports` table has no column for them (spec 06).
  They are still sent to the backend and used in the rendered cover.
- The Data-maintenance endpoints (`/api/maintenance/*`) and the
  `INSUFFICIENT_STORAGE` (507) error code are additions not in the spec 06 tables;
  they are recorded in `docs/DECISIONS.md`.
- A single-case `scripts/backup.py` still snapshots the whole database, because the
  audit log is one hash chain shared across cases and a partial export could not be
  verified; only the file trees are scoped to the case.
- `docs/perf-results.md` is refreshed (2026-10-11) but the spec 09 §8 end-to-end
  targets (multi-worker throughput, 1M-event detection, 5M-event p95, UI paint,
  10 GB ingest memory) are not measured by the harness.
- The final verification (9f) could not run everything here: the clean-machine
  offline install is unrun. The browser E2E suite (`frontend/e2e/`, five
  Playwright tests including the axe-core a11y scan) and the bundle-size budget
  were added afterwards. The remaining unrun check is itemised in
  `docs/COMPLIANCE.md` and `docs/DECISIONS.md`.
- The optional IOC enrichment (spec 05 §9) is not implemented: `allow_enrichment`
  is a reserved flag surfaced only in `/api/health`, so there is no network
  client to gate. A full ingest → detect → report run opening zero non-loopback
  sockets is asserted by `test_ingest_pipeline.py::TestNoOutboundConnects`.

## Phase 8a-8d - Frontend shell, core screens, alerts, ATT&CK, IOCs, Events, Timeline, Entities, Rules and Settings (complete)

The frontend slices from spec 11 phases 8a-8d and spec 07: the app
shell, the design-token theme, routing, a typed API client, the WebSocket client
with reconnect/backoff, the jobs drawer, the Cases, Overview and Sources screens
including the five-step custom mapping wizard, the Alerts screen with its
seven-block detail drawer, the ATT&CK coverage matrix, the IOCs, Events,
Timeline and Entities browsers, and the Rules catalogue (list, filters, YAML
validate/test editor, import/export, health) and Settings screens (general,
detection, allowlist, ATT&CK import, enrichment and data read-outs, audit
viewer, About dialog). The Reports screen is deferred to phase 9, whose report
service it needs; see the 2026-10-10 decision.

| Area | State |
|---|---|
| Design tokens | `src/index.css` maps the spec 07 §1 palette onto Tailwind 4 `@theme` variables (`--color-bg/surface/surface-2/border/text/muted/accent/sev-*`) with dark values on `:root` and a `[data-theme='light']` override; components use the utility classes (`bg-surface`, `text-muted`, `text-sev-critical`, ...); fonts (Inter, JetBrains Mono) are bundled via `@fontsource-variable`, no CDN |
| Theming | `theme/ThemeProvider.tsx`: a stored choice in `localStorage['triagelens.theme']` wins, else `prefers-color-scheme`; `applyTheme` writes `data-theme` on the document element; the shell has a toggle |
| Routing | `App.tsx`: `/` Cases, `/status` Status, `/cases/:caseId` Overview, `/cases/:caseId/sources` Sources, `/cases/:caseId/alerts` Alerts, `/cases/:caseId/mitre` ATT&CK, `/cases/:caseId/events`, `/cases/:caseId/timeline`, `/cases/:caseId/iocs`, `/cases/:caseId/entities`, `/cases/:caseId/rules` Rules, `/cases/:caseId/settings` Settings, `*` NotFound, all under `AppShell` (left rail + top bar + connection banner + toasts + jobs drawer) |
| API client | `api/` typed layer: `client.ts` (`requestJson`/`requestForm`, `ApiError`/`ContractError`, envelope parsing), `endpoints.ts` (cases, sources, ingest/resolve, jobs, detection, alerts list/detail/patch/bulk/evidence, events, timeline, entities, IOCs, MITRE case/static/navigator, profiles), `queryKeys.ts`, `queryClient.ts`, `invalidate.ts`, `hooks.ts` (TanStack Query v5). Request-body types are generated from the backend OpenAPI (`api/openapi.json` → `api/openapi.d.ts` → `api/schema.ts`, via `npm run gen:api` / `task.py openapi`); response types are hand-written because the OpenAPI document does not describe responses |
| WebSocket client | `ws/jobsSocket.ts`: server-push subscription with exponential backoff (1 s doubling to 15 s), answers a server `ping` with `pong`, drops unknown frames; drives `app/JobsProvider.tsx` (live job stages, `needs_input`, drawer open/cancel) |
| Cases | `features/cases/CasesPage.tsx`: list with per-case counts, create (name/timezone/description), rename, typed-name delete confirmation, open |
| Overview | `features/overview/OverviewPage.tsx`: KPI tiles, top-5 alerts, Recharts mini-timeline, MITRE heat strip, attacker candidates, ingest health, last detection run |
| Sources | `features/sources/SourcesPage.tsx`: multi-file/folder dropzone, per-file size/SHA-256/log type/confidence/counts, `needs_input` ranked-candidate resolve, parse-errors dialog, change type/timezone/year (save & re-parse), download, delete, profile selector + Run detection, "Auto-run after ingest" toggle (runs detection when an ingest job finishes while the screen is open) |
| Mapping wizard | `features/sources/MappingWizard.tsx` + `mappingProfile.ts`: five steps — sample, match an existing profile by `applies_when`, map fields with path autocompletion from the sample, preview 20 normalized rows and errors via `POST /profiles/preview`, save via `PUT /profiles/{name}` and re-parse. Profile YAML is emitted by a purpose-built serializer; its output was verified to load through `app.ingest.profiles.load_profile` |
| Alerts | `features/alerts/AlertsPage.tsx` + `alertFilters.ts`: URL-backed filters (level, status, host, user, min score, unmapped, `q`, tactic, technique), server-side sort on the five sortable columns, a virtualized table (`@tanstack/react-virtual`) with per-page select-all and multi-select bulk verdict, row keyboard shortcuts (j/k/Enter/x/t/f/b), pagination, and empty/loading/error states |
| Alert drawer | `features/alerts/AlertDrawer.tsx`: the seven spec 07 §3.4 blocks — header with a score-breakdown popover, ATT&CK (external links + inferred badge + unresolved tags + offline note), rule (YAML via the read-only `ui/CodeBlock.tsx` CodeMirror), evidence (stored sample + "Load all matches"), indicators (grouped, defang toggle, copy), entities, and an analyst panel (verdict select + debounced notes autosave) |
| ATT&CK | `features/mitre/MitrePage.tsx` + `mitreMatrix.ts`: tactic columns with count-scaled colour and severity borders, expandable sub-techniques, "Fired only" (case matrix) vs "Full matrix" (static reference with case counts overlaid), technique cells deep-link to the filtered alerts list, and Navigator-JSON and PNG-snapshot exports |
| IOCs | `features/iocs/IocsPage.tsx` + `iocFilters.ts`: spec 07 §3.6 tabs (All, IPs, Domains, URLs, Hashes, Emails, Files & Paths, Registry, CVEs, Other), state/sort selects, min-confidence slider, show-internal/show-allowlisted/defang toggles, confidence bar, per-page select-all and bulk export (CSV/TXT/STIX/JSON) through `exportIocs`, pagination, and URL-backed filters. Single-type tabs paginate server-side; multi-type tabs fetch at the group limit and narrow in the browser |
| IOC drawer | `features/iocs/IocDrawer.tsx`: occurrence list with event snippets, matching field and decoded-from badge, verdict select (malicious/suspicious/benign/none), allowlist toggle, tag add/remove, copy (raw and defanged), and a pivot link to the Events list filtered by the indicator |
| Events | `features/events/EventsPage.tsx` + `eventFilters.ts` + `eventColumns.ts`: FTS5 search box with an inline syntax popover, filter chips (host/log type/channel/event ID/user/src/dst/IOC/alert), a facet sidebar (top values with counts, click to filter), a virtualized table with a sticky header, persisted column picker and compact/comfortable density, newest/oldest sort, and CSV/JSONL export of the loaded rows |
| Event drawer | `features/events/EventDrawer.tsx` + `highlight.ts`: normalized-field table, related alerts, indicator chips with a defang toggle, a recursive tree of the decoded provider record with per-value copy, the raw record via the read-only `ui/CodeBlock.tsx` with a wrap toggle or a highlighted view (indicator matches drawn as text nodes, never `innerHTML`), and a "surrounding events" (±30 s, same host) list |
| Timeline | `features/timeline/TimelinePage.tsx` + `timelineBuckets.ts`: a Recharts stacked bar of events per bucket coloured by log type plus an alert-count line, a brush that sets the selected range, zoom in/out, a bucket selector (auto/1m/5m/1h/1d), and lists of alerts and notable indicators within the range |
| Entities | `features/entities/EntitiesPage.tsx`: host and user tables with event/alert counts, each name deep-linking to the Events list filtered by that host or user |
| Rules | `features/rules/RulesPage.tsx` + `ruleFilters.ts` + `ruleFormat.ts`: URL-backed filters (kind, level, status, enabled, tag, technique, health, `q`), a Catalogue/Health tab whose count cards drill into the list by bucket, a table (enabled toggle, title, level, kind, logsource, techniques, health badge), drag-and-drop or button import (`.yml`/`.yaml`/`.zip`) with a result panel, custom-rule zip export, and pagination |
| Rule drawer | `features/rules/RuleDrawer.tsx` + `ui/CodeEditor.tsx`: metadata table, an editable CodeMirror YAML editor, **Validate** (problems list), **Test on case** (match count + 20 samples), **Save/Create** (custom only), **Duplicate to custom** (rewrites the `id`), **Delete**, and an enable toggle for every kind |
| Settings | `features/settings/SettingsPage.tsx`: General (theme via `ThemeProvider`, density), Detection (profile via `PUT /settings`, read-only limits), Allowlist editor (`GET/POST/DELETE /settings/allowlist`), ATT&CK import (`POST /settings/attack/import`), Enrichment and Data read-outs (config + health figures), and a case-scoped audit-log viewer with the chain-verification result |
| About | `features/settings/AboutDialog.tsx`: live runtime diagnostics from `GET /api/health` (versions, capabilities, database and disk figures) plus a collapsible panel that reproduces `THIRD_PARTY_NOTICES.md` (bundled via `?raw`, no runtime fetch) |

### Verification

- `npx tsc --build --force` clean; `npx eslint . --max-warnings 0` clean.
- `npx vitest --run`: 222 tests across 28 files (added `rulesFilters`,
  `ruleFormat`, `RulesPage` and `SettingsPage` to the 8a-8c suites).
- The wizard's generated YAML round-trips through the backend profile loader
  (checked directly against `app.ingest.profiles.load_profile`).
- `task.py openapi-check` regenerates `frontend/src/api/{openapi.json,openapi.d.ts}`
  and fails on drift; `scripts-lint` covers `scripts/export_openapi.py`.

### Known limitations

- Only request bodies are generated from the OpenAPI document; response types
  remain hand-written because every backend response is an untyped `dict`. See the
  2026-10-10 decision.
- The global scope bar and global search (spec 07 §4) and the command palette are
  deferred; the left rail lists only the routes that exist.
- The alerts list omits a rule-source (builtin/sigma/custom) filter: the backend
  exposes no server-side filter for it, and filtering a single page client-side
  would be misleading. See the 2026-10-10 decision.
- The alert status change has no undo toast (spec 07 §4): `ToastProvider` has no
  action-button support yet. The drawer is Esc-closable and autofocuses, but has no
  full focus trap. `CodeMirror` (the rule-YAML viewer) is exercised only when the
  YAML is toggled on.
- The ATT&CK matrix tooltips show the technique id, name and count; the API's
  matrix payload carries no technique description, so the spec 07 §3.5 tooltip
  description is not shown.
- The IOCs `type` filter is single-valued server-side, so multi-type tabs (IPs,
  Hashes, Files & Paths, Other) fetch at most 1000 indicators and narrow, sort and
  slice them in the browser; beyond 1000 indicators a grouped tab undercounts, and
  its export omits the `type` filter. See the 2026-10-10 decision.
- The IOC payload carries no per-indicator host count, linked-alert count or
  ATT&CK techniques, so the spec 07 §3.6 table omits those columns.
- The Events CSV/JSONL export streams the current filter result from
  `GET /cases/{id}/events/export` (phase 9 slice 9c) up to 1M rows; the alert CSV
  export (`GET /cases/{id}/reports/alerts.csv`) is still only reachable by API.
- The Alerts and IOCs list endpoints accept no `from_ms`/`to_ms`, so the Timeline
  screens' alert and indicator lists are filtered in the browser by `last_seen_ms`
  and can only size/colour alert markers by `alert_count`, not severity.
- The Entities API returns only `{kind, name, event_count, alert_count}` (and
  always reports zero alerts), so the spec 07 §3.9 first/last-seen and top-technique
  columns are not shown.
- The Reports screen (phase 9 slice 9c) wires `POST/GET /cases/{id}/reports` and
  `GET /reports/{id}/download`; the alert-overview CSV endpoint has no UI yet.
- The About dialog shows the bundled `THIRD_PARTY_NOTICES.md` verbatim in a
  collapsible `<pre>`; the text is not rendered as formatted Markdown.
- The Rules screen has no inline CodeMirror linting: the schema-aware checks run
  through `POST /rules/validate` and the problems are listed below the editor
  rather than as editor markers (`@codemirror/lint` is not a declared dependency).
  The `POST /rules/import` result reports file names and problems, not a per-rule
  row, so the import result panel is file-scoped. Rule health covers
  `ok`/`compile_error`/`unroutable` only; never-present fields and timeouts live on
  detection runs, not the catalogue.
- Settings exposes only `detection.profile` for editing (the sole key in the
  backend's editable schema); there is no global timezone or enrichment key, so
  those spec 07 §3.13 controls are shown read-only or omitted. The Data pane's
  Vacuum, Rebuild-search-index, Verify-evidence-hashes and Verify-audit-chain
  actions were added in phase 9 slice 9d. The audit viewer is case-scoped
  (`GET /cases/{id}/audit-log`), so it asks for a case.
- Screenshots are still absent; the browser E2E suite (`frontend/e2e/`, spec 09 §7
  scenarios + the S-02 render check + an axe-core WCAG 2.1 A/AA scan of the main
  screens) and the spec 07 < 1.5 MB gzipped bundle budget (`frontend-budget` task)
  both run. The literal Lighthouse ≥ 95 tool is unmeasured; the axe-core scan is
  its deterministic equivalent.

## Phase 6 — Detection engine (implemented)

The spec 11 phase 6 build: the rule loader and compile health (spec 04 §1), the
pySigma SQLite backend and routed execution with windows, correlations (spec 04
§3–§4), detection runs with profile selection and verdict rows (spec 04 §2,
§5–§9), the rules/alerts/ATT&CK APIs (spec 06 §3), the case event browse
endpoints (spec 06 Events: list with FTS5 + keyset, count, facets, detail with
linked alerts and IOCs), and a vendored, reproducible
SigmaHQ rule sample with DRL 1.1 provenance (slice 4), and the first-run
catalogue sync that seeds a fresh database with the shipped tree (slice 5).

| Area | State |
|---|---|
| Rule loader | `detect/rules.py: load_rules` reads three dirs in one pass — `rules/builtin/` (16 shipped docs, 7 categories), `rules/sigma/` (vendored, see below) and the user custom dir `data/rules/custom/`; each rule keeps `kind` (`builtin`/`sigma`/`custom`), `rule_type`, level/status, `sha256`, `file_path` with `#N` per-document, tags and logsource; multi-document files are split; load problems (unparsable files) are reported, never dropped silently; `load_rules_from(settings)` and `load_rules_from_text` for the API paths |
| Compile health | per rule: `compile_error` (pySigma compile exceptions) and `unroutable` (no logsource-map match); `rules/health` buckets `ok`/`compile_error`/`unroutable` per kind; rules are stored and served regardless of health, so a broken rule is visible |
| Logsource map | `rules/logsource_map.yaml` routes Sigma categories → normalized columns (e.g. `process_creation` events have `process.executable` → `EventData.Image`, `command_line` → `EventData.CommandLine`); multi-field values go to `fields_json` via `json_extract`, and `cidr_rules` compile to the `cidr_match` SQLite UDF |
| Backend | `detect/backend.py: TriageBackend` (pySigma `sqliteBackend` subclass) emits deterministic SQL with bounded result reads and parameterized field/table names; rules loose on fields absent from the schema still compile |
| Detection run | `POST /cases/{id}/detect` (profile or explicit `rule_ids`) enqueues a `detect` job (202); the worker selects enabled rules by profile, scans a rolling detection window of the case's events, executes on the read replica, and writes per-rule verdict rows (`matched`/`no_match`/`error`) plus a run summary; one run may emit one alert per rule per host |
| Correlations | `SigmaCorrelationRule` `all_of` windows are supported: grouping events by correlation field and enforcing the timespan on the group's aged window; correlation rules ship in `rules/builtin/` (e.g. SSH brute-force) and load on the sigma path |
| Profiles | spec 04 §2: `fast` (builtins + stable/test at high/critical), `standard` (builtins, customs, sigma ≥ medium), `full` (everything enabled); selection is a pure function over rule metadata so `/preview`-style checks avoid the DB |
| Rules API | spec 06 §3: `GET /rules` (filters: kind, level, status, enabled, tag, technique, health, `q`), `/rules/health`, `/rules/export`, `GET /rules/{id}`, `POST /rules` (validate + upsert one), `PUT`/`PATCH`/`DELETE`, `POST /rules/validate`, `POST /rules/test` (against a pasted dispatch), `POST /rules/import` (reconciles the full catalogue: upserts every loaded rule of all three kinds, prunes stale shipped rows, reports `imported`/`synced`/`stale_removed`) |
| Catalogue sync | `detect/sync.py: sync_catalogue` loads all three sources, upserts everything (preserving `enabled`) and prunes shipped rows by id — never custom — with one `rules_imported` audit entry; runs at startup on `detection.sync_rules_on_startup` but only while the shipped rows count is zero (later boots skip the 4-5 s tree load), and powers the import refresh above |
| Alerts API | `GET /cases/{id}/alerts`, `GET/PATCH /alerts/{id}` (verdict life cycle, analyst state), `POST /alerts/bulk`, `GET /alerts/{id}/events`; each alert links its source run, rule, host and the triggering events; `tactics_json` stores ATT&CK tactic/technique tags |
| Alert IOC linking | spec 01 §8, spec 05 §3: after alerts are recorded the detect worker extracts tier-2 indicators from the evidence events (filepath/filename/registry from the structured fields; command from `process_cmdline` when the alert level ≥ medium; user agent when it matches a scanner keyword or repeats across the case) and rebuilds `ioc_alerts` so every evidence IOC — tier-1 already stored and tier-2 just stored — is linked to its alert; the re-run is idempotent (an already-seen occurrence never inflates its count), and the alert-detail `iocs` and the +5 `ioc_evidence` scoring modifier read those links |
| Events API | `GET /cases/{id}/events` (FTS5 `q` on message/process_cmdline/parent_process_cmdline/url/user_agent/file_path/raw, `from_ms`/`to_ms`, `host`, `source_id`, `log_type`, `channel`, `event_id`, `ls_category`, `user_name`, `src_ip`, `dst_ip`, `ioc_id`, `alert_id`, `level`; `sort` restricted to `ts`/`-ts`; opaque cursor on `(ts_ms, id)`, no OFFSET), `/cases/{id}/events/count` (same filters, fast count), `/cases/{id}/events/facets` (top-N values for host/log_type/channel/event_id/user_name/src_ip), `/cases/{id}/timeline` (`bucket=auto\|1m\|5m\|1h\|1d`, same filters; only non-empty epoch-aligned buckets; `alert_count` = distinct alert-linked events), `/events/{id}` (detail incl. `fields`, `raw`, linked alerts as `Alert` and IOCs); `total` is `null` on the list and `include=raw` opts the raw line in; invalid FTS syntax → 422 |
| Audit log | `GET /cases/{id}/audit-log` serves the append-only chain (spec 10 §2) newest-first: entries `{id, ts, case_id, action, detail, prev_hash, hash}` with pagination (`limit`/`offset`/`order`) and a per-request hash-chain verification `{chain_ok, rows_checked, head_hash, broken_at?, broken_reason?}` that always walks the whole chain so interleaved rows of other cases cannot hide a real edge |
| Settings API | spec 06 "Health and settings": `GET /settings` returns `{settings, overrides, allowlist}` — the effective config with the auth token masked (spec 10 §1), the stored analyst overrides overlaid on it, and the global allowlist; `PUT /settings` validates a partial update of the editable keys (`detection.profile`) and appends a `settings_changed` audit row; `GET/POST/DELETE /settings/allowlist[/{id}]` manage global entries (idempotent per `(kind, value)`, `allowlist_changed` audit, unknown id → 404); `POST /cases/{id}/detect` defaults to the stored profile override, else config |
| ATT&CK | `GET /mitre/matrix`, `/cases/{id}/mitre`, `/cases/{id}/mitre/navigator-layer` (MITRE Navigator layer v4), `GET/import /mitre/techniques…`; the import endpoint seeds tactics/techniques from a local `enterprise-attack.json` bundle via the same importer as `scripts/update_attack.py` |
| Vendored SigmaHQ rules | `scripts/update_rules.py` vendors a pinned SigmaHQ/sigma snapshot into `rules/sigma/` — 378 rules measured by compile+routing health (Windows 151, Linux 186, Web 40, network/firewall 1); a 2026-10-11 amendment added four Windows rules for the spec 09 §7 Scenario C acceptance (recorded in `rules/sigma/SOURCE.txt`); the tree is deterministic (double-load identical, digests asserted) and ships `SOURCE.txt`, `upstream-LICENSE.md` and the DRL 1.1 `LICENSE`; see `docs/DECISIONS.md` (2026-10-09) and `SOURCES.md` |
| Provenance | root `SOURCES.md` records the SigmaHQ commit `48f2d096`, tree/source SHA-256, the ATT&CK import workflow, and the IANA TLD source; `THIRD_PARTY_NOTICES.md` reproduces the DRL 1.1 and MITRE ATT&CK terms of use |
| Fixtures & scenarios | e2e detection tests drive the raw fixtures from earlier phases (Scenario A web shells, B brute-force, C scanning) through source → parse → detect and assert the expected alerts and their ATT&CK tags |

### Verification

| Gate | Command | Result |
|---|---|---|
| Backend lint | `.venv\Scripts\python.exe scripts\task.py backend-lint` | clean (ruff check + format check) |
| Backend tests | `.venv\Scripts\python.exe scripts\task.py backend-test` | 1769 passed, 1 skipped (perf benchmarks run separately); see the slice gate below |
| Backend types | `.venv\Scripts\python.exe scripts\task.py backend-typecheck` | clean (mypy, 192 source files); the earlier Application Control block lifted since Phase 5 |
| Lockfile | `.venv\Scripts\python.exe scripts\task.py lock-check` | current: pySigma 1.5.1 + `pysigma-backend-sqlite` 2.0.0 pinned via `requirements.lock` |

Slice gate (3a–3f + 4 + 5 + 6 + 7):

| Gate | Command | Result |
|---|---|---|
| Backend lint | `scripts\task.py backend-lint` | clean |
| Backend types | `scripts\task.py backend-typecheck` | clean (mypy, 192 source files) |
| Backend tests | `scripts\task.py backend-test` | 1769 passed, 1 skipped |
| Scripts lint | `scripts\task.py scripts-lint` | clean |

### Known limitations

- **Network and niche coverage is bounded by the logsource map.** 44 of 45
  `rules/network` files (cisco/zeek/dns) and most non-Windows service channels
  are unroutable with the shipped map and so excluded from the vendored sample;
  adding products there is a `logsource_map.yaml` change, not a rule change.
- The vendored sample pins SigmaHQ at `48f2d096` (2024-05-31); newer rules are
  picked up by re-running `scripts/update_rules.py` against a fresh clone.

## Phase 5 — IOC engine (implemented)

The spec 11 phase 5 build: the `app/ioc` engine (refang, decode passes, patterns
and validators, classification, allowlist, deterministic scoring,
dedup/aggregation), tier-1 extraction wired into the parse worker, and the
IOC/entity/export API of spec 06.

| Area | State |
|---|---|
| Pipeline | per text value: control-char cleanup → refang → decode (depth ≤ `[ioc] decode_depth`, default 2) → regex candidates → validate → classify → score → emit; the original text is preserved untouched (spec 05 §2) |
| Refang | `hxxp`/`hxxps`/`fxp` scheme restore, `[.]`/`(.)`/`{.}`/`[dot]`/`(dot)`/` dot `→`.`, `[:]`→`:` `[://]`→`://`, `[@]`/`(at)`/`[at]`→`@`, `\.`→`.` inside URL/domain candidates |
| Decode | PowerShell `-EncodedCommand` and `[Convert]::FromBase64String`, generic base64 with a ≥85% printable gate, URL percent-decoding (two rounds); `decoded_from` provenance (`base64`/`powershell_enc`/`url`), decoded children re-scanned, non-printable decodes discarded, decoded text capped at 256 KB |
| Validators | IPv4/IPv6 via `ipaddress` (leading-zero octets, `10.1.2.3-beta` version tags, clock/MAC-shaped IPv6 rejected, `::ffff:` unwrapped); domains against `data/iana_tlds.txt` (label ≤ 63, total ≤ 253, punycode, whole-token-is-an-IP and filename lookalikes rejected, `sid = `/`guid:`/`uuid:`/`certid = ` context blocks hex hashes); URLs via `urlsplit` with trailing punctuation stripped and the host re-validated; emails; CVEs uppercased |
| Ambiguous TLDs | `sh, py, pl, rs, zip, mov, md, so, cc, ps, pm, am, ai, io, cs, ad`: accepted from a structured field (URL host, DNS field, email domain) or in free text only with ≥ 2 labels before the TLD; the −30 score penalty applies **only** to the free-text acceptance |
| Classification | private/reserved/CGNAT/loopback/link-local/multicast flagged via `ipaddress`; RFC 5737 documentation ranges are public by design; private IOCs stored with `is_private=1`, hidden in the API unless `include_private` (behind `[ioc] extract_private_ips=true`) |
| Allowlist | `data/default_allowlist.yaml` (`domain_suffix`, `domain` kinds, `example.com`/`localhost`/`invalid` suffixes) plus case-scoped rows in the `allowlist` table; matches stored with `is_allowlisted=1`, never silently dropped; `PATCH /iocs/{id}` with `analyst_state=benign` + `allowlist: true` adds a case entry |
| Scoring | deterministic 0–100: 80 structured / 60 decoded / 50 free-text, +15 alert-linked (Phase 6), +10 when ≥ 5 distinct occurrences, +5 on ≥ 3 distinct hosts, −30 ambiguous-TLD rule, −20 private, −40 allowlisted, clamped; constants match spec 05 §6 exactly |
| Tier 1 wiring | `extract_event_hits` runs in the parse worker on every event's `ioc_fields()` (private IPs retained behind config); the writer aggregates each 5000-event batch and upserts `iocs` + `ioc_occurrences` in the same transaction as the event batch |
| Storage | `iocs` keyed `(case_id, type, value_norm)` with a content-derived `id`, `occurrences` a distinct `(event_id, field)` count, occurrence rows capped at 50 per indicator per batch, min/max `first/last_seen_ms`; re-ingest upserts with `confidence = MAX(...)` |
| API | `GET /cases/{id}/iocs` (type, `min_confidence`, `q`, `alert_id`, `host`, `state`, `include_private`, `include_allowlisted`, sort), `GET /iocs/{id}` and `/iocs/{id}/occurrences`, `PATCH /iocs/{id}` (`analyst_state`, `tags`), `POST /cases/{id}/iocs/export`, `GET /cases/{id}/entities` (hosts and users with event/alert counts) |
| Export | spec 05 §8 formats: CSV (spec columns), TXT (per line, `defang` option), STIX 2.1 bundle (`stix2` `indicator` objects; filepath/command/user-agent as `x-triagelens-observable` inside a note), JSON (full records); media types and round-trips tested |
| Benchmark | `ioc.extract`: tier-1 extraction across representative events including the decode passes, recorded in `docs/perf-results.md` as a baseline for regressions |

### Verification

| Gate | Command | Result |
|---|---|---|
| Backend lint | `.venv\Scripts\python.exe scripts\task.py backend-lint` | clean (ruff check + format check) |
| Backend tests | `.venv\Scripts\python.exe scripts\task.py backend-test` | 1347 passed, 1 skipped (the 15 performance benchmarks run separately) |
| Benchmarks | `.venv\Scripts\python.exe scripts\run_perf.py` | 15 measurements; `ioc.extract` ≈ 4,150 records/s on this host (see `docs/perf-results.md`) |
| Lockfile | `.venv\Scripts\python.exe scripts\task.py lock-check` | current: 24 pinned distributions |
| Backend types | `.venv\Scripts\python.exe scripts\task.py backend-typecheck` | blocked by this workstation's Application Control policy (same environment block as Phase 1) |

### Known limitations

- Tier-2 extraction (filename, filepath, registry, command, user-agent) is
  validated and exported by the engine, but alert-scoped extraction and
  `ioc_alerts` linkage need the detection engine and land with Phase 6.
- `ioc.extract` (≈ 4,150 records/s here) is a regression baseline, not the spec 09
  §8 pipeline target; that target measures parse + normalize + IOC tier 1 +
  persist end to end, which the ingest pipeline measures as a whole in a later
  phase.
- The enrichment path (`network.allow_enrichment`, VirusTotal/AbuseIPDB) is
  optional (spec 05 §9) and not implemented; the S-05 no-outbound-sockets half is
  now covered by `test_ingest_pipeline.py::TestNoOutboundConnects`, and the
  enrichment-endpoint 403 half is N/A while no endpoint exists.
- The ambiguous-TLD penalty is scoped to the free-text acceptance path; see
  `docs/DECISIONS.md`, 2026-10-08.

## Phase 4 — Web, firewall and generic parsers (complete)

The spec 11 phase 4 build: Apache and nginx access and error logs plus IIS W3C,
the five firewall readers (UFW/iptables, pfSense, FortiGate, PAN-OS, Cisco ASA),
and the generic JSON/CSV profile engine with its shipped profiles and API.

| Area | State |
|---|---|
| Access | `web_access.py`: one combined-log reader for Apache and nginx; a line that is not a tidy `METHOD uri` pair (a bare `"-"`, scanner junk) is still an event with the request kept verbatim and no method (P-09); the stored `url` is raw and `fields_json.url_decoded` is the percent-decoded copy |
| Access routing | Apache and nginx access are deliberately exclusive: a name mentioning `nginx` scores `nginx_access` and zeroes `apache_access`, any other name does the reverse |
| Errors | `web_error.py`: `nginx_error` (`pid#tid:`, `client:`/`request:` pulled into `src_ip`/`http_method`/`url`) and `apache_error` (`[module:level]`, `[pid N:tid M]`, `[client ip:port]`, `AH`-code in `fields_json`); both read their offset-less clock in the case timezone and leave `ts_ms` unset when the case has none |
| IIS | `iis_w3c.py`: driven by the `#Fields:` header, rows positional and `unquote_plus`-decoded; a data line before the header, or the wrong field count, is a failure |
| UFW/iptables | `fw_iptables.py`: `[UFW BLOCK]`/`ALLOW` bracket verdict plus `SRC`/`DST`/`SPT`/`DPT`/`PROTO`; every kernel token kept in `fields_json` |
| pfSense | `fw_pfsense.py`: `filterlog` CSV read through a per-IP-version index map (IPv4 and IPv6 differ); too few columns is a failure |
| FortiGate | `fw_fortinet.py`: `type=` + `srcip`/`dstip` key=value, quoted values unquoted, `eventtime` nanoseconds or `date`+`time`(+`tz`) |
| PAN-OS | `fw_paloalto.py`: positional CSV driven by `data/profiles/paloalto_fields.yaml`; only traffic/threat rows are mapped, other types stored whole; severity → level |
| Cisco ASA | `fw_cisco_asa.py`: `%ASA-<sev>-<id>:` located anywhere in the line; the P-10 id set (106023/106100/302013-302016/113005/113015/605005/611101) is parsed into columns, other 106xxx/302xxx ids still filed as firewall events |
| Firewall routing | one `log_type` per vendor, content sniff ≥ 0.8; `linux_syslog`/`linux_auth` defer to the firewall parsers when ≥ 0.6 of lines are firewall-shaped (UFW marker, `filterlog` app, `%ASA-`, or `IN=`+`SRC=`+`DST=`) so the vote stays decisive |
| Generic JSON | `generic_json.py`: NDJSON, top-level arrays, `events`/`records`/`Records`, `hits.hits[*]._source`; a mapping profile turns each record into an event, and `journalctl -o json` lines defer to `linux_journald` |
| Generic CSV | `generic_csv.py`: header row with the delimiter sniffed among `, ; \t |`, plus Zeek TSV driven by `#separator`/`#fields`; column-count mismatch and unmatched rows are per-row failures |
| Profile engine | `generic_common.py` (shared reader→profile mapping, cached shipped+user loading) and `profiles.py` (strict YAML validation, `@timestamp`, `[*]`, array-valued category matching, `default_category`); a flat CSV column whose name contains a dot (`id.orig_h`) resolves literally before dot-walking |
| Shipped profiles | `data/profiles/`: `elastic-ecs`, `wazuh-alert`, `splunk-csv`, `defender-sentinel-csv`, `zeek` (`default_category: network_connection`), `aws-cloudtrail`; user profiles live in `data/profiles/user/` and may shadow a shipped name |
| Profiles API | `app/api/routers/profiles.py`: `GET /profiles`, `GET/PUT/DELETE /profiles/{name}`, `POST /profiles/import`, `POST /profiles/preview`; built-in profiles are read-only (409 on write/delete), preview parses a scratch sample without touching the case store |
| Fixtures | Authored `access_combined.log` (205 benign + SQLi/traversal/webshell/malformed, Scenario B), `nginx_access.log`, `nginx_error.log`, `apache_error.log`, `iis.log`, `fw/{ufw.log,pfsense_filterlog.log,fortigate.log,paloalto_traffic.csv,asa.log}`, and `generic/{elastic_ecs.ndjson,wazuh_alerts.json,cloudtrail.json,zeek_conn.log,zeek_conn.json,splunk_export.csv,defender_events.csv}`, each with a sibling golden; every one auto-detects ≥ 0.8 (P-12) |
| Tests | `tests/test_ingest_web.py`, `tests/test_ingest_firewall.py`, `tests/test_ingest_generic.py`, and `tests/test_api_profiles.py`: routing, valid/malformed records, golden round-trips, detection exclusivity, profile CRUD and preview; benchmarks `web_access.parse`, `fw_paloalto.parse` and `generic_csv.parse` |

### Verification

| Gate | Command | Result |
|---|---|---|
| Backend lint | `.venv\Scripts\python.exe scripts\task.py backend-lint` | clean (ruff check + format check; 98 files) |
| Backend tests | `.venv\Scripts\python.exe scripts\task.py backend-test` | 1047 passed, 1 skipped (the 14 performance benchmarks run separately) |
| Benchmarks | `.venv\Scripts\python.exe scripts\run_perf.py` | 14 measurements; `web_access.parse` 13,699 records/s, `fw_paloalto.parse` 8,772 records/s, `generic_csv.parse` 18,519 records/s on this host |
| Fixture check | `python scripts\make_fixtures.py --check` (from `backend/`) | exits 0, goldens current |
| Lockfile | `.venv\Scripts\python.exe scripts\task.py lock-check` | current: 24 pinned distributions |
| Backend types | `.venv\Scripts\python.exe scripts\task.py backend-typecheck` | blocked by this workstation's Application Control policy (same environment block as Phase 1) |

### Known limitations

- The `access_combined.log` golden is ~225 KB, just over the 200 KB fixture
  guidance, because Scenario B requires 200+ benign requests and the golden keeps
  every column for each. The `.log` itself is ~22 KB.
- `fw_paloalto` field names are **provisional** until a vendor reference is
  supplied (see `DECISIONS.md`, 2026-10-07).
- The shipped `splunk-csv` profile reads `_time` as ISO-8601; a real Splunk export
  writes epoch seconds, so an operator imports a profile (or a variant) for it.

## Phase 3 — Linux parsers, syslog/auth, journald and auditd (implemented)

The spec 11 phase 3 build: line-oriented syslog in three framings plus the two
endpoint logs analysts reach for first. All four share the framing, timestamp and
message-table machinery in `linux_common.py`, and detection splits syslog from
auth by filename hint or daemon tags.

| Area | State |
|---|---|
| Framing | `linux_common.py`: RFC 5424, RFC 3164 and RFC 3339 tried per line (a file may interleave all three); a leading-whitespace line is a continuation appended to the record before it |
| Auth vs syslog | `linux_syslog.py`: `linux_auth` when the name says `auth.log`/`secure` or ≥60% of framed tags are authentication daemons, else `linux_syslog`; the two sniff scores are mutually exclusive |
| Message table | The spec 03 section 3.1 rows: ssh failed/accepted/invalid/disconnect, sudo, su, useradd/delete, group member, cron, crontab, systemd start/stop |
| Clock | RFC 3164 year seeded from `assumed_year`, filename, then mtime, advanced on a December→January rollover; wall-clock time localized in `context.timezone` (default `UTC`), ambiguous DST folds resolved to the earlier reading (P-05) |
| journald | `linux_journald.py`: `journalctl -o json`, every key kept in `fields_json`, columns lifted from `_HOSTNAME`/`SYSLOG_IDENTIFIER`/`_PID`/`PRIORITY`/`_EXE`/`_CMDLINE`, a byte-array `MESSAGE` decoded; `generic_json` defers journal-shaped lines to it |
| auditd | `linux_auditd.py`: lines grouped by the `msg=audit(...:serial)` id, one event per group; `EXECVE`/`PATH`/`SOCKADDR` merged, hex args decoded only when printable, packed `sockaddr` unwrapped, fields inside a quoted `msg='...'` unfolded (P-08) |
| Fixtures | Authored `auth.log`, `syslog_variants.log`, `journal.json`, `audit.log` with a sibling golden each; `scripts/make_fixtures.py --check` enforces them |

### Verification

| Gate | Command | Result |
|---|---|---|
| Backend lint | `.venv\Scripts\python.exe scripts\task.py backend-lint` | clean (ruff check + format check) |
| Backend tests | `.venv\Scripts\python.exe scripts\task.py backend-test` | 912 passed, 1 skipped (the 11 performance benchmarks run separately) |
| Benchmarks | `.venv\Scripts\python.exe scripts\run_perf.py` | 11 measurements; `linux_syslog.parse` 12,987 records/s, `linux_auditd.parse` 10,000 records/s on this host |
| Fixture check | `python scripts\make_fixtures.py --check` (from `backend/`) | exits 0, goldens current |
| Lockfile | `.venv\Scripts\python.exe scripts\task.py lock-check` | current: 24 pinned distributions |
| Backend types | `.venv\Scripts\python.exe scripts\task.py backend-typecheck` | blocked by this workstation's Application Control policy (same environment block as Phase 1) |

### Known limitations

- `case.default_timezone` is not yet threaded into `ParseContext`, so a syslog
  file read without an explicit request timezone is interpreted as UTC. See
  `docs/DECISIONS.md`.
- A `socket_connect` audit record has no `ls_category`; the spec 04 vocabulary has
  no row for a connection, so only the action names it.
- UFW-style kernel `[UFW BLOCK]` lines are framed as ordinary syslog and not yet
  delegated to a firewall parser (that parser arrives in Phase 4).
- The audit `sockaddr` decode assumes a little-endian host.

## Phase 2 — Windows parsers, EVTX and Event XML (implemented)

The spec 11 phase 2 build: two parsers over one shared mapping table. The L0
surface those parsers read (`NormalizedEvent`, `fields_json`, `record_ref`) is
populated from Windows event structure and the format detection routes each
format to the right one.

| Area | State |
|---|---|
| Shared mapping | `windows_common.py`: the spec 03 section 2.1 table for Security-Auditing, Sysmon, PowerShell (classic and Operational), TaskScheduler, WMI, Defender and TerminalServices, keyed on channel and provider |
| Event XML | `windows_event_xml.py`: a streaming `XMLPullParser`, an explicit namespace, ``EventID`` as int or `{"#text": ...}`, unnamed `Data` → `Data_0..N`, `UserData` flattened one level, per-record failures |
| EVTX | `windows_evtx.py`: the native `evtx` (pyevtx-rs) reader preferred, the vendored pure-Python `evtxlib` as the documented fallback. A corrupt chunk is one failure, not a lost file |
| Sysmon hashes | `Hashes` split into `Hash_MD5`/`Hash_SHA256`/`Hash_IMPHASH`; the verbatim field is kept |
| Levels | The Windows System.Level scale (0 info … 5 debug) applied per spec 03, distinct from the generic level mapping |
| Detection | `SUFFIX_MAP` and content signatures for both formats; a leading `<?xml ...?>` declaration is skipped before prefix matching |
| Fixtures | Real EVTX samples (copied and trimmed from the `evtx` crate's test data, MIT), authored XML fixtures, and a sibling golden per file; `scripts/make_fixtures.py --check` enforces them |

### Verification

| Gate | Command | Result |
|---|---|---|
| Backend lint | `.venv\Scripts\python.exe scripts\task.py backend-lint` | clean (ruff check + format check) |
| Backend tests | `.venv\Scripts\python.exe scripts\task.py backend-test` | 877 passed, 1 skipped (benchmarks excluded by design) |
| Benchmarks | `.venv\Scripts\python.exe scripts\run_perf.py` | 9 measurements; `windows_evtx.parse` 83 records/s (vendored), `windows_event_xml.parse` 5,435 records/s on this host |
| Fixture check | `.venv\Scripts\python.exe make_fixtures.py --check` | exits 0, goldens current |
| Lockfile | `.venv\Scripts\python.exe scripts\task.py lock-check` | current: 24 pinned distributions |
| Backend types | `.venv\Scripts\python.exe scripts\task.py backend-typecheck` | blocked by this workstation's Application Control policy (same environment block as Phase 1) |

### Known limitations

- The preferred native EVTX reader (`evtx`, pyevtx-rs) cannot load on a host
  under Application Control that blocks native extensions, which is the same
  policy that blocks mypy here. The vendored reader is the fallback and the only
  path exercised by the tests on this machine; the native path is coded and
  guarded but not executable here.
- The vendored reader parses at 83 records/s on this host, below the spec 09
  section 8 EVTX target of 8,000 records/s. The native reader is the intended way
  to meet that target; it cannot be measured here. See `docs/DECISIONS.md`.
- `Event XML` is parsed with `resolve_entities=False` and `no_network=True`, so
  an XXE payload is dropped rather than resolved; there is a test for it.
- Fixtures are copied and trimmed from a published EVTX corpus. No binXML writer
  exists in the tree, so new binary fixtures cannot be synthesized, only copied
  and trimmed; the golden files are regenerated with `--update-golden`.
- The mapping table is populated for the event IDs spec 03 names. Other event
  IDs still produce an event, but with a synthesized `event_<id>` action.

## Phase 1 — core pipeline, detection of formats, jobs (implemented)

The full spec 11 phase 1 build: the parsing and safe-intake slice plus the job
manager, process pool, WebSocket progress, cancellation, `needs_input`/resolve
and the cases/sources/jobs API exactly as spec 06.

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
| From-path import | Path resolution, containment under configured roots, regular files only, recursive directory import, originals untouched |
| Job manager | asyncio queue, `ProcessPoolExecutor` workers with watchdog and memory cap, single DB writer thread with 5,000-event batched inserts including FTS rows, pool rebuilt after a worker crash |
| Cancellation | Queued and mid-parse cancel with partial-data cleanup; a finished job (including `needs_input`) is a 409, never a silent success |
| `needs_input`/resolve | Parking undecided or unbuildable formats, operator resolve under `POST /sources/{id}/resolve`, parser-led re-parse of a parked source via `PATCH /sources/{id}` |
| WebSocket | `ping`, `job.stage`, `job.update`, `job.error`, terminal frame on the observed job; case and job scopes with no cross-case leakage |
| API | Cases, sources, jobs, upload, from-path, download, parse errors, PATCH reparse and case update, WebSocket routes mounted under `/api` |

### Verification

| Gate | Command | Result |
|---|---|---|
| Backend lint | `.venv\Scripts\python.exe scripts\task.py backend-lint` | clean (ruff check + format check) |
| Backend types | `.venv\Scripts\python.exe scripts\task.py backend-typecheck` | strict mypy config in `pyproject.toml`; the installed mypy is currently blocked from running by the workstation's Application Control policy, so this gate cannot execute here (see limitations) |
| Backend tests | `.venv\Scripts\python.exe scripts\task.py backend-test` | 822 passed, 1 skipped (benchmarks excluded by design) |
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

- Strict mypy runs from `scripts/task.py backend-typecheck` but the installed
  mypy is blocked by this workstation's Application Control (AppLocker/WDAC)
  policy (`ImportError: DLL load failed` on import). This is an environment
  block, not a code failure; type-checking enforces the strict config in
  `pyproject.toml` on machines where it can execute.
- `generic_json`, `windows_evtx` and `windows_event_xml` are registered (Phase 2).
  CSV, Wazuh and firewall formats are still detected and reported but not parsed:
  `parser_available` is false and the source parks in `needs_input` rather than
  being parsed. See `docs/DECISIONS.md`.
- The generic JSON parser reads a whole single-document JSON file into memory, capped
  at 1 GiB. NDJSON streams line by line and has no such cap.
- Archive expansion is not transactional. A member that fails validation partway
  through leaves the members already written on disk; `remove_stored` cleans them
  up, but nothing calls it automatically yet.
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

The detection engine beyond format detection (Sigma + built-in rules, MITRE
mapping and alert creation), alert-scoped tier-2 IOC extraction with `ioc_alerts`
linkage, the triage UI, ATT&CK import, and reporting/export. See
`docs/spec/11-AGENT-BUILD-PROMPTS.md`.

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

Phase 1 (spec 11) acceptance and the spec 09 section 6 / S / P items. Each has a
test:

| Requirement | Test |
|---|---|
| ECS NDJSON upload ingests every event with correct hashes and counts | `tests/test_ingest_pipeline.py::TestNdjsonIngest` |
| A ZIP of three files becomes three sources, each ingested with its own counts | `tests/test_ingest_pipeline.py::TestZipIngest` |
| Progress is shown over WebSocket in the spec 06 frame order | `tests/test_ingest_pipeline.py::TestWebSocketProgress` |
| A worker crash is survived: pool rebuilt, server healthy, later jobs work | `tests/test_ingest_pipeline.py::TestWorkerCrash` (S-09) |
| Zip-slip / symlink / expansion-bomb fixtures are rejected, nothing stored | `tests/test_ingest_pipeline.py::TestHostileArchives`, `tests/test_ingest_archive.py` (S-01) |
| Three concurrent uploads each ingest without interleaving | `tests/test_ingest_pipeline.py::TestConcurrentUploads` |
| FTS rows are written with the event batch and match the events table | `tests/test_ingest_pipeline.py::TestFtsConsistency` |
| Cancel mid-parse discards the events already stored | `tests/test_ingest_pipeline.py::TestCancellation` |
| Deleting a source cascades to its stored members | `tests/test_ingest_pipeline.py::TestZipIngest::test_deleting_the_container_removes_its_members` |
| `needs_input` parks the job and source until a parser resolves it | `tests/test_ingest_pipeline.py::TestNeedsInput` |
| PATCH re-parse replaces a source's events under a new job | `tests/test_ingest_pipeline.py::TestSourcePatchReparse` |
| From-path recursive imports directories, files only, originals untouched | `tests/test_ingest_pipeline.py::TestFromPathRecursive`, `tests/test_ingest_intake.py::TestImportCandidates` |
| Non-loopback bind without a token refuses to start | `tests/test_config.py` (safe-bind tests) (S-06) |
| Empty file → `done` with zero events; garbage → `error_count == lines` | `tests/test_ingest_parsers.py`, `tests/test_ingest_pipeline.py::TestNdjsonIngest` (P-01, P-02) |
| CRLF, BOM, UTF-16 and gzip parse identically | `tests/test_ingest_text.py` (P-03) |
| An oversized line is truncated with a marker; parse continues | `tests/test_ingest_parsers.py` (P-04) |
| Every `fixtures/*` sample detects to the right type; unknown text parks | `tests/test_ingest_detect.py` (P-12) |

Phase 2 acceptance, from spec 03 section 2 and spec 09 (P-06, P-07, S-08). Parser
behaviour is tested in `tests/test_ingest_windows.py`; the end-to-end upload path
in `tests/test_ingest_pipeline.py::TestWindowsIngest`.

| Requirement | Test |
|---|---|
| Every spec 03 section 2.1 mapping row maps to the expected category/action/outcome | `TestMappingTable::test_row` |
| A native event dict maps identically to the element path (dict-shaped `EventID`) | `TestSpecialCases::test_mapping_accepts_a_native_event_dict` |
| Unnamed `Data` becomes `Data_0..N`; `UserData` flattened one level | `TestSpecialCases::test_unnamed_data_becomes_data_n`, `::test_user_data_is_flattened` |
| Sysmon `Hashes` split into `Hash_<ALGO>` with the verbatim field kept | `TestSpecialCases::test_sysmon_hashes_are_split` |
| `::ffff:` IPv4-in-IPv6 unwrapped to the IPv4 address | `TestSpecialCases::test_ipv4_in_ipv6_is_unwrapped` |
| Windows `System.Level` scale applied | `TestSpecialCases::test_windows_level_mapping` |
| A malformed XML record is one failure, not a crash | `TestEventXmlParser::test_malformed_xml_yields_a_failure_not_an_exception` |
| An XXE payload does not read a local file | `TestEventXmlParser::test_an_xxe_payload_does_not_leak_a_local_file` (S-08) |
| Both formats match their committed goldens | `TestEventXmlParser::test_authored_fixtures_match_their_goldens`, `TestEvtxParser::test_binary_fixtures_match_their_goldens` |
| A corrupt EVTX chunk is reported and the rest survives | `TestEvtxParser::test_a_corrupt_chunk_is_reported_and_the_rest_survives` |
| Detection routes each format to its parser | `TestDetectionIntegration` |
| An EVTX upload is detected, parsed in a worker and stored under the mapped columns | `tests/test_ingest_pipeline.py::TestWindowsIngest::test_evtx_upload_is_detected_parsed_and_counted`, `::test_evtx_events_are_stored_with_the_mapped_columns` |
| An Event XML upload is detected, parsed and counted | `tests/test_ingest_pipeline.py::TestWindowsIngest::test_event_xml_upload_is_detected_parsed_and_counted` |
| A corrupt EVTX keeps its readable events end-to-end and reports the rest | `tests/test_ingest_pipeline.py::TestWindowsIngest::test_a_corrupt_evtx_keeps_its_readable_events_and_reports_the_rest` |

Phase 3 acceptance, from spec 03 section 3 and spec 09 (P-05, P-08, Scenario A).
Parser behaviour is tested in `tests/test_ingest_linux.py`; the end-to-end upload
path in `tests/test_ingest_pipeline.py::TestLinuxIngest`.

| Requirement | Test |
|---|---|
| The three framings map host, app, pid and message | `TestFraming::test_rfc3164_uses_assumed_year`, `::test_rfc5424_fields`, `::test_rfc3339_offset_is_applied` |
| A continuation line appends to the record before it | `TestFraming::test_continuation_appends_to_previous` |
| A line no framing matches is one failure, not a crash | `TestFraming::test_unframed_line_is_a_failure` |
| The spec 03 section 3.1 message rows map to action/category/outcome | `TestMessageTable` |
| A PRI maps to the normalized level; none means info | `TestPriorityLevels::test_levels`, `::test_no_priority_is_info` |
| Detection splits `linux_auth` from `linux_syslog` | `TestDetection::test_filename_hint_marks_auth`, `::test_auth_and_syslog_are_mutually_exclusive` |
| RFC 3164 crosses a December→January rollover | `TestSyslogClock::test_december_rolls_into_january` (P-05) |
| A DST fold is resolved deterministically | `TestSyslogClock::test_dst_fold_resolves_deterministically` (P-05) |
| Audit lines group by serial, one event per group | `TestAuditd::test_groups_by_serial_and_decodes_hex_argv` (P-08) |
| Hex `EXECVE` args decode only when they are text | `TestAuditd::test_groups_by_serial_and_decodes_hex_argv` (P-08) |
| A packed `sockaddr` yields address and port | `TestAuditd::test_sockaddr_extracts_address_and_port` |
| Fields inside a quoted `msg='...'` are unfolded | `TestAuditd::test_nested_msg_fields_are_unfolded` |
| An unset `auid` is not stored as a user | `TestAuditd::test_unset_audit_uid_is_not_a_user` |
| journald microseconds and a byte-array `MESSAGE` map | `TestJournald::test_microsecond_time_and_columns`, `::test_message_byte_array_is_decoded` |
| Each Linux parser reproduces its committed golden | `test_fixture_golden` |
| Detection routes each Linux fixture to its parser | `TestDetection::test_fixtures_route_by_content` |
| An auth log upload is detected, parsed in a worker and stored | `tests/test_ingest_pipeline.py::TestLinuxIngest` |

Phase 5 acceptance, from spec 05 and spec 09 section 5. Engine behaviour is
tested in `tests/test_ioc_core.py`; the export renderers in
`tests/test_ioc_export.py`; the API in `tests/test_api_iocs.py`.

| Requirement | Test |
|---|---|
| ≥ 150 labelled table-driven cases across every regex, validator, refang case, decoder, ambiguous-TLD rule and classification (I-01) | `tests/test_ioc_core.py` (259 tests: `TestRefang`, `TestDecode`, `TestPatterns`, `TestValidate*`, `TestCanonical`, `TestAllowlist`, `TestScore`, `TestAggregate`, `TestExtractCore`) |
| Refang matrix (`hxxp://evil[.]com/a`, `user[at]evil(dot)com`, `1[.]2[.]3[.]4`) (I-02) | `TestRefang` |
| Decoding: PowerShell `-enc` UTF-16LE, `FromBase64String`, double-encode depth capped, non-printable decode rejected (I-03) | `TestDecode` |
| Classification: private/CGNAT flagged, documentation ranges public, allowlist suffix matching (I-04) | `TestValidateIpv*::test_private_ranges`, `TestClassifyIp`, `TestAllowlist::test_domain_suffix_matches_subdomains` |
| Scoring table for each modifier, with clamping (I-05) | `TestScore` |
| Dedup: one row per indicator, distinct-event counts, min/max timestamps, occurrence cap 50 (I-06) | `TestAggregate::test_occurrence_counts_distinct_event_field_pairs`, `::test_occurrence_cap_bounds_rows_not_count`, `test_api_iocs.py::TestIocDetail` |
| Tiering: tier-2 types only from alert events (I-07) | deferred with the detection engine (Phase 6); the tier-2 scanners and validators are unit-tested in `TestValidatePath`/`TestValidateRegistry` |
| Exports: STIX 2.1 bundle validates, CSV round-trip, defang correctness (I-08) | `tests/test_ioc_export.py` (14 tests incl. `TestStix::test_indicator_ids_are_stable_and_bundle_is_valid`) |
| Storage and API: deduped rows, occurrences, analyst state, filters, entities (I-06/08) | `tests/test_api_iocs.py` (26 tests: list/detail/patch/export/entities) |
| Extraction throughput baseline recorded with device info (spec 09 §8) | `tests/perf/test_benchmarks.py::test_measure_ioc_extract` via `make perf` |