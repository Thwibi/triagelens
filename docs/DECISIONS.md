# Architecture decisions

Each entry records a decision that is not obvious from the code, why it was
made, and what it costs. Newest first. Dates are ISO-8601.

## 2026-10-12 — Spec 09 §8 end-to-end performance harness

**Decision.** The §8 end-to-end targets are measured by a new self-contained
harness, `backend/tests/perf/test_end_to_end.py`, run via `make perf-e2e`
(→ `docs/perf-e2e-results.md`) at a `smoke` scale by default and a `full` scale
on reference hardware. It reuses the production topology — spawn worker
processes, bounded manager queues, one shared `DBWriter`, the real
`parse_and_emit` / `DetectRunner` / `EventRepository` — rather than reimplementing
the paths, so the numbers are the code's, not a model's. The harness *records*
the numeric verdict as a `perf_target` property and only asserts run
correctness (events parsed == events written); the smoke scale is a regression
baseline, not the reference verdict.

**Why.** Spec 09 §8 names seven targets but left them unmeasured; the earlier
`make perf` covers only primitives. Measuring them exposed the real bottleneck
and forced an honest FAIL row instead of an estimate. Profiling the text path
(`cProfile`, 20k ECS records) attributes ≈ 65 % of parse time to tier-1 IOC
extraction (`app/ioc/extract.py` `scan_text` / `extract_fields`) and the rest to
generic-JSON profile mapping (`app/ingest/profiles.py` `flatten` / `applies_to`);
both are pure-Python CPU, so throughput is ≈ 1.6k events/s per worker — two
orders of magnitude under the 30k/100k targets. On this host detection, the
Events API first page, the FTS query and peak ingest RSS meet their targets.

**Cost.** Three throughput targets (text single/multi-worker, EVTX) fail on this
host and the reference-laptop verdict stays unproven; they are documented, not
waived, in `docs/COMPLIANCE.md` and shown as FAIL in `docs/perf-e2e-results.md`.
The `full` scale (1M/5M/8M rows) is too slow to run in routine CI, so it is a
manual target. The §8 UI first-paint target needs a browser, so it is measured
separately by `frontend/e2e/perf.spec.ts` (`make perf-ui`); `make perf-e2e` runs
that spec first and merges its `ui.alerts_first_paint` verdict into the same
document, and skips it (leaving the row out) when Node or Chromium is absent.

## 2026-10-11 — pip-audit: accepted risk for the diskcache advisory

**Decision.** `pip-audit -r backend/requirements.lock` reports one advisory in a
transitive dependency, `diskcache` 5.6.3 (PYSEC-2026-2447 / CVE-2025-69872, a
pickle-deserialization issue reachable only by an attacker who can already write
to the cache directory). It is accepted, and the CI `dependency-audit` job
carries an explicit `--ignore-vuln PYSEC-2026-2447`, rather than being fixed or
left to fail the build.

**Why.** There is no fix to take: 5.6.3 is the latest release and the advisory
lists no fixed version. The dependency is not ours — it arrives via
`pySigma==1.5.1` — and its only use in pySigma is the on-disk cache in
`sigma.data.mitre_attack` / `sigma.data.mitre_d3fend`, which the application
never imports (ATT&CK data is loaded through `POST /settings/attack/import`).
The vulnerable `pickle.load` path is therefore not reachable from any request.

**Cost.** A standing ignore is easy to forget. It is scoped to the single
advisory id, recorded in `docs/COMPLIANCE.md`, and must be revisited when a
fixed `diskcache` (or a pySigma release that drops it) appears.

## 2026-10-11 — Accessibility gate (axe-core) and the AA text tokens

**Decision.** The spec 07 "Lighthouse accessibility = 95" clause is realised as an
axe-core WCAG 2.1 A/AA scan of the thirteen main screens
(`frontend/e2e/a11y.spec.ts`, `@axe-core/playwright`), which fails on any serious
or critical violation. It runs inside the existing `e2e` task rather than a
separate Lighthouse harness, because axe-core is a deterministic, offline,
CI-friendly equivalent with no external browser channel. Because the spec pins a
light-theme palette whose accent and severity hexes are below the 4.5:1 AA text
ratio, six darker `*-text` tokens were added (`--accent-text`,
`--sev-{critical,high,medium,low,info}-text`) used only for text on tinted or
light surfaces; icons, dots, rings and tints keep the spec's exact hexes, so the
palette and the "icon + label + colour, never colour alone" rule are preserved.

Three fixes the scan surfaced:

1. **The Status, health and 404 screens moved off raw `slate-*` classes onto the
   theme tokens**, which is what had produced the original 26 contrast nodes.
2. **The virtualized Alerts, IOCs and Rules tables now carry real table
   semantics** — `role="table"` on the scroll region with `aria-rowcount`, sticky
   `role="rowgroup"` headers, and `role="columnheader"`/`role="cell"` children —
   satisfying spec 07 §6.
3. **Focusable scroll regions and a non-image chart wrapper**: the Events filter
   aside became `tabIndex={0}`, and the Recharts timeline wrapper changed from
   `role="img"` to `role="group"` so the Brush travellers are no longer a nested
   interactive control.

**Why.** Spec 00 requires every MUST to be covered by a test; spec 07 §6 and the
accessibility clause are normative. Leaving them would keep the requirement
Partial.

**Cost.** The scan is part of the Playwright suite, so it needs a built frontend
and a Chromium install like the scenarios. It asserts serious/critical only (not
every advisory rule), and it measures axe's rule set rather than Lighthouse's
exact score.

## 2026-10-11 — Browser E2E for Scenarios A/B/C, and the Scenario C fixture rebuild

**Decision.** The spec 09 §7 acceptance is now exercised end to end through the
real UI, not only the API. `frontend/e2e/` runs Playwright against a single
origin: `python -m app.main` (started by `e2e/serve.mjs` on an isolated temp data
dir) serves the production bundle built into `backend/app/static`. Four tests run
headless — `scenario-a.spec.ts`, `scenario-b.spec.ts`, `scenario-c.spec.ts` and
`xss.spec.ts` (the S-02 "no dialog" assertion). A new `e2e` task
(`scripts/task.py`, delegating from `make e2e`) builds the frontend and then runs
`npm run e2e`; a matching `e2e` job in `.github/workflows/ci.yml` installs
Chromium and uploads the report.

Closing Scenario C exposed three non-obvious points:

1. **The Windows fixture was rebuilt to match the spec, not the reverse.**
   `backend/scripts/make_fixtures.py::security_logons()` now emits the nineteen
   events spec 09 §7 describes (three 4624s, an eleven-account 4625 spray, the
   type-3 success, a 4688, a 4698, a 4720 and an 1102), so `windows_logon_spray.yml`
   and the four newly vendored SigmaHQ rules all fire. The golden
   (`security_logons.xml.expected.json`) was regenerated from the same generator,
   keeping it the single source of truth.
2. **`example.org` is allowlisted on purpose.** Spec 05 §5 has the engine store
   allowlisted IOCs with `is_allowlisted=1` and hide them in the UI unless "show
   allowlisted" is on; `data/default_allowlist.yaml` lists `example.org`, so
   Scenario C's `malicious-update.example.org` and its URL are extracted but
   hidden by default. The spec's E2E spec therefore asserts only the two public
   IPs in the default view, then navigates with `?allowlisted=1` to assert the
   domain and URL. The checkbox itself proved flaky in headless Chromium, so the
   URL filter is the deterministic lever.
3. **Four SigmaHQ rules were vendored to cover Scenario C's non-spray alerts**
   (audit-log cleared, suspicious scheduled task, base64 PowerShell, suspicious
   RUN key); the vendored tree moved from 374 to 378 rules, Tree SHA-256
   `a2c3f33d…`, with the amendment recorded in `rules/sigma/SOURCE.txt`.

**Why.** Spec 00 requires every MUST to be implemented *and covered by a test*,
and spec 07/09 make the three scenarios and the S-02 render check normative at
the browser level. An API-level-only pass left that requirement Partial.

**Cost.** The suite needs a built frontend and a Chromium install, so it is
heavier than the unit gates and is not folded into `make all`. The spec 07
bundle-size budget is enforced separately (see below); the Lighthouse a11y check
and the offline clean-machine install remain unrun.

**Bundle budget (same day).** A `frontend-budget` task
(`frontend/scripts/check-bundle-budget.mjs`, wired into `make build` and CI)
gzips everything under `backend/app/static` and fails above 1.5 MB. The current
build is 693 KB gzipped, so the budget is a regression guard rather than a
constraint. Lighthouse a11y ≥ 95 is the remaining spec 07 check; it needs the
`lighthouse` tool, which is not installed here.

## 2026-10-11 — Closing the 9f gaps: coverage, socket guard, licences, CI

**Decision.** The five concrete gaps the 9f entry named were closed, and three
non-obvious choices were made:

1. **`parsers` coverage.** Spec 00's 85% target is measured after omitting
   `app/ingest/parsers/evtxlib/`, the vendored third-party reader — the same
   package already excluded from `ruff` and `mypy` because it is not this
   project's code. The project-authored parser files sit at 88%, and
   `windows_evtx.py` rose from 58% to 99% by testing the native `pyevtx-rs` walker
   with a stub reader (the extension is an optional dependency, absent here). The
   four spec 00 packages (`parsers` 88%, `detect` 92%, `ioc` 93%, `mitre` 94%) are
   now all ≥ 85%; overall 89.56%.
2. **S-05 guard allows loopback.** The negative control that blocks non-loopback
   connects would also break the ingest IPC, because on Windows
   `multiprocessing.Manager` reaches its queue over loopback TCP. The guard
   therefore permits `127.0.0.1`/`::1`/`localhost` and fails on everything else,
   which still proves the offline guarantee while keeping the real workers under
   test.
3. **Licences are bundled, not fetched.** `AboutDialog.tsx` imports
   `THIRD_PARTY_NOTICES.md?raw` so the exact notice text ships in the bundle with
   no runtime request; `vite.config.ts` widens `server.fs.allow` to `['..']` so
   the dev/test file server can reach a file above the frontend root. A CI workflow
   (`.github/workflows/ci.yml`) was added for lint, typecheck, coverage, and
   `npm audit`/`pip-audit`.

**Why.** These were the acceptance-relevant gaps in the 9f matrix; leaving them
open would contradict spec 00's "85% on those four packages" and spec 09 S-05.

**Cost.** The `evtxlib` omission is a coverage-policy choice, not free coverage:
the vendored reader is exercised by the real EVTX fixtures but is not itself
measured. The socket test only guards the API/worker process it runs in (the
parse pool is a separate process, but it makes no connects). The CI workflow has
not yet run on a runner, and the Lighthouse / offline clean-machine install
remain unrun (see `docs/COMPLIANCE.md`); the browser E2E suite was added later
the same day.

## 2026-10-11 — Final verification (9f): what was run, what was not

**Decision.** The phase 9 final verification (`docs/COMPLIANCE.md`) records the
result of each gate that could run here and names every requirement that could
not be verified, rather than asserting a pass that was not executed. Ran: the
full backend gate (ruff + mypy clean; 1798 passed, 1 skipped), the full frontend
gate (tsc + ESLint clean; 232 passed), `make perf` (15 primitive benchmarks,
refreshed in `docs/perf-results.md`), `npm audit --audit-level=high` (0
vulnerabilities), and the 9d `backup.py`/`diag.py` smoke runs. The spec 00
acceptance items (every MUST tested, 85% coverage on `parsers`/`detect`/`ioc`/
`mitre`, and the three E2E scenarios passing byte-for-byte) are mapped to code
and tests in the matrix.

**Why.** The specs are normative and spec 00 requires that every MUST be
implemented *and covered by a test*; the honest form of that claim is a matrix
with the gaps visible, not a green checkmark that hides them. Several checks are
environment-bound: `pip-audit` was not installed and no CI workflow existed at the
time (both since added), the Lighthouse / bundle-budget harness is not installed,
the offline
bundle has not been installed on a separate network-disabled machine, and the
perf harness measures storage/parse/IOC/health primitives rather than the spec 09
§8 end-to-end targets.

**Cost (open risks — spec 00 says these should be none).** Five concrete gaps
were named here: (1) `app/ingest/parsers` coverage was 74%, under the spec 00
per-package 85% target; (2) no adversarial SQL-injection test (S-04); (3) no
`socket.connect` guard test for a full run (S-05); (4) `app/detect/rules.py` used
`yaml.safe_load` with neither a 1 MB document cap nor an alias-count limit
(S-07); (5) the About dialog referenced but did not render
`THIRD_PARTY_NOTICES.md`. All five were closed the same day — see "Closing the
9f gaps" above. The environment-bound items remain: no a11y/bundle
checks, no clean-machine offline install, and no spec 09 §8 end-to-end
timing/memory verdict. Each is listed under "Gaps and open risks" in
`docs/COMPLIANCE.md`. (The browser E2E half was closed later the same day — see
"Browser E2E for Scenarios A/B/C".)

## 2026-10-11 — Deleting a case or source is audited, tombstones the chain, and removes files

**Decision.** `DELETE /cases/{id}` returns `204` and, inside one writer
transaction, appends a `case_deleted` audit row, records an `audit_tombstones`
row (last hash + row count) and deletes the case (cascading to sources, events,
alerts and IOCs). Only after the commit does it remove
`data/cases/<id>/` and `data/reports/<id>/`, honouring `storage.secure_delete`
(zero-in-place before unlink). `DELETE /sources/{id}` likewise appends
`source_deleted`. File deletion is best-effort and never rolls back the DB.

**Why.** Spec 02 §4 and spec 06 require the audit entry, the cascade and the
`204`; spec 10 §2 requires a case's final chain head to be anchored so the chain
stays verifiable after its rows are gone. The pre-existing endpoints wrote no
audit row and left the case directory behind, and `write_tombstone` was defined
and tested but never called in production. Ordering the filesystem work after the
commit keeps the invariant "a row never names a file that is already gone".

**Cost.** The `case_created`/`case_updated` actions remain in
`KNOWN_ACTIONS` but are still not appended (only create/update; out of scope
here). File removal failures (a file held open) leave orphaned bytes on disk but
do not fail the request; `scripts/backup.py` and `verify-hashes` are the tools to
detect that.

## 2026-10-11 — Disk exhaustion is refused up front; maintenance is an out-of-band API

**Decision.** Ingest calls `ensure_disk_space` before storing: it refuses when
free space is under 3× the incoming bytes or below
`limits.min_free_disk_fraction` (default 5%), raising a new
`INSUFFICIENT_STORAGE` (507) code. The Settings Data pane's four operations live
under `/api/maintenance/*` (vacuum, rebuild-fts, verify-hashes, verify-audit),
which are not in the spec 06 table. `VACUUM` runs on the writer thread **without**
a surrounding transaction (`writer.run(work, transactional=False)`).

**Why.** Spec 10 §1 states the two disk rules but spec 06 defines no error code,
so one had to be added; 507 "Insufficient Storage" is the natural status.
`VACUUM` cannot execute inside a transaction (SQLite errors), so the writer
needed an explicitly non-transactional path rather than a second connection,
which would break the one-writer rule. The maintenance endpoints are grouped
apart from the request path because a large database makes them slow; they use a
5-minute timeout instead of the normal writer hand-off.

**Cost.** The frontend `ApiErrorCode` union does not yet list
`INSUFFICIENT_STORAGE` (nor several other real codes), so such an error collapses
to `INTERNAL` in the UI while the message is preserved; widening the union is
deferred. `ensure_disk_space` is a single check at ingest start, not a running
reservation, so concurrent ingests can still race past it.

## 2026-10-11 — Reports are one writer-bound job over one neutral model

**Decision.** `POST /cases/{id}/reports` enqueues a `report` job; the
`ReportRunner` gathers, renders and records the file on the single writer thread
inside one transaction, exactly like the detect runner. Every format (HTML, PDF,
Markdown, JSON, and the alert CSV) renders from the same `ReportData` tree in
`app/reports/model.py`. The HTML template turns Jinja2 **autoescape on
explicitly** rather than via `select_autoescape`, and the record's `path`/`sha256`
are re-checked on download.

**Why.** Generation must be atomic with its evidence: a `reports` row that names a
file which was never written, or a file with no row, would be a lie an analyst
could act on. Routing the whole thing through the writer gives that for free and
keeps the one-writer rule. One model keeps spec 08's cross-format guarantee "the
same data in every format" true by construction instead of by four parallel
mappers. Autoescape is explicit because `select_autoescape(["html", "xml"])`
matches on the template *name*, and the template is `report.html.j2` — it ended in
`j2`, so autoescape was silently off and a log-derived host/source value rendered
as live markup; the test seeds a `<script>` host to pin the fix.

**Cost.** A report job occupies the writer for the length of a gather + render,
so a very large case can delay other writes; the work is bounded by the alert
page size, the per-alert event cap (≤50) and the CSV page size. PDF stays
optional (missing WeasyPrint → `422 PDF_UNAVAILABLE`). The Navigator layer's
description embeds the report's `generated_at`, so it is deterministic only when
that timestamp is fixed — which is exactly the allowance spec 08 makes ("differs
only in the generation timestamp and report id").

## 2026-10-10 — Rules and Settings sit under the per-case rail; health stays catalogue-scoped

**Decision.** The Rules and Settings screens are registered as per-case routes
(`/cases/:caseId/rules`, `/cases/:caseId/settings`), matching the spec 07 §1 left
rail, even though the rules and settings endpoints are global. The Rules health
view shows only the catalogue's `ok`/`compile_error`/`unroutable` buckets.

**Why.** Spec 07 §1 lists Rules, Reports and Settings inside the per-case
navigation, and two of them genuinely need case context: Settings' audit viewer
(chain-scoped) and Rules' "Test on case". Routing them under the case keeps the
current case selected while the underlying calls stay global. For health, the
spec text also names "never-present fields" and "timeouts (from last run)", but
those are recorded per detection run (`GET /detection-runs/{id}/rules`), not in
`GET /rules/health`; the page states this rather than fabricating the columns.

**Cost.** The Rules list is not case-filtered (rules are global), so the same
catalogue shows under every case — correct, but a reader may expect otherwise.
Never-present-field and timeout diagnostics require a detection-run drill-down
that this slice does not add.

## 2026-10-10 — The Reports screen and licence bundle wait for the Phase 9 service

**Decision.** Phase 8d builds the Rules, Settings and About screens but not the
Reports screen, and the About screen shows live runtime diagnostics rather than a
third-party licence bundle.

**Why.** Spec 11 lists Reports under 8d, but the report service it needs
(`POST /cases/{id}/reports`, `GET /cases/{id}/reports`, `GET /reports/{id}/download`)
is scoped to Phase 9 and no such route exists in the backend today — confirmed by
grepping `backend/app/api/routers/` and the exported `frontend/src/api/openapi.json`
(there is no `/reports` path; the router set is rules, settings, audit, mhealth,
alerts, cases, detect, events, iocs, jobs, mitre, profiles, sources, websocket).
Likewise `THIRD_PARTY_NOTICES.md` and `SOURCES.md`, the source of the About licences,
are Phase 9 deliverables. Building either UI now would mean a screen wired to
endpoints that return 404, which the "no stubs" rule forbids. The `JobKind` union
already carries `report`, so the frontend is ready to host the screen.

**Cost.** Spec 8d is delivered minus Reports and the licences list. When Phase 9
adds the report endpoints and the notices files, add `features/reports/` (the spec 07
§3.12 options form, sandboxed preview, history table) and point About's licences
section at the generated notices. Until then About shows the real `/health` versions
and capabilities.

## 2026-10-10 — Multi-type IOC tabs fetch unfiltered and narrow in the browser

**Decision.** The IOCs screen (spec 07 §3.6) shows grouped tabs (IPs, Hashes,
Files & Paths, Other) alongside single-type tabs. A single-type tab sends its
`type` to the server; a grouped tab instead requests the indicators unfiltered by
type at a 1000-row limit and filters, sorts and slices them in the browser
(`features/iocs/iocFilters.ts`). Its bulk export therefore omits the `type` filter.

**Why.** `GET /cases/{id}/iocs` accepts a single `type` value per request, so a tab
covering several types cannot be expressed as one server query. Issuing one request
per type would break the single paginated list and the bulk-export contract;
fetching the group and narrowing locally keeps one coherent view. "All" stays fully
server-paginated.

**Cost.** A grouped tab with more than 1000 indicators undercounts and its export
covers only the fetched window. If the backend grows a repeatable `type` parameter
(or `type_in`), switch grouped tabs to server filtering and drop `isGroupedTab` /
`iocPage`.

## 2026-10-10 — Events export serialises the loaded rows, not a server stream

**Decision.** The Events screen's CSV/JSONL export (spec 07 §3.7) is built in the
browser from the rows the page has loaded, using the visible column set.

**Why.** There is no events-export endpoint; the case event list is keyset-paginated
and capped at 1000 rows per request. A client-side export of the loaded window is
the honest thing the API allows, and it keeps the exported columns identical to what
the analyst sees.

**Cost.** The spec's "streamed, max 1M rows" export is not met; a very large case
exports only the loaded page. Add a streaming export endpoint and switch this screen
to it when one exists.

## 2026-10-10 — Timeline lists filter alerts and IOCs in the browser

**Decision.** The Timeline screen (spec 07 §3.8) draws its stacked bars from the
bucketed `/timeline` payload and filters the "alerts in range" and "notable
indicators in range" lists client-side by `last_seen_ms`. Alert markers are sized
and coloured by the bucket's `alert_count` only.

**Why.** The Alerts and IOCs list endpoints accept no `from_ms`/`to_ms`, and the
timeline buckets carry no per-bucket severity, so neither the range lists nor a
severity-coloured marker can be produced from one server call. Filtering the
already-fetched lists in the browser is correct for the displayed window.

**Cost.** A range list can miss items outside the fetched page, and markers cannot
encode severity. If the list endpoints gain time bounds and the buckets gain a
severity breakdown, move both to the server and colour the markers by severity.

## 2026-10-10 — The alerts list omits a rule-source filter the backend cannot serve

**Decision.** The Alerts screen (spec 07 §3.4) exposes level, status, host, user,
minimum score, `q`, tactic, technique and unmapped filters, but not a
builtin/sigma/custom rule-source filter, even though the alert row carries
`rule_kind`.

**Why.** `GET /cases/{id}/alerts` has no server-side parameter for `rule_kind`
(only level, status, rule_id, host, user_name, min_score, q, tactic, technique and
unmapped). Filtering the 50 rows of the current page client-side would show a
partial, wrong result for any case with more than a page of alerts. Omitting the
control is honest; a filter that silently lies about the data is not.

**Cost.** Operators cannot narrow the list by rule source in the UI. If the
backend gains a `rule_kind` parameter, add it to `AlertFilters` and re-add the
control; the URL-state module (`features/alerts/alertFilters.ts`) is where the
key would live.

## 2026-10-10 — Frontend request-body types are generated from the backend OpenAPI; response types are hand-written

**Decision.** `scripts/export_openapi.py` writes the FastAPI document to
`frontend/src/api/openapi.json` (deterministic, sorted), and `npm run gen:api`
turns it into `frontend/src/api/openapi.d.ts`. `frontend/src/api/schema.ts`
re-exports those generated schemas under the app's names, and the request-body
types in `api/endpoints.ts` are aliases of them. Response shapes stay hand-written
in `api/types.ts`, and the client parses envelopes defensively
(`expectRecord`/`expectArray`, `ContractError`) rather than trusting a schema.
`openapi-check` (part of `task_all`) regenerates both artifacts and fails on drift.

**Why.** Spec 11 phase 8a asks for "typed schemas generated from the backend
OpenAPI". The backend annotates only request bodies — every response is an
untyped `dict` — so the OpenAPI document (23 component schemas, all request
bodies) cannot type responses at all; generating them would produce empty
`Record<string, unknown>`s. Generating what the document actually describes, and
keeping response types honest and hand-maintained, is the truthful reading. The
WS frames (spec 06 §4) are absent from OpenAPI and stay hand-written regardless.

**Cost.** This is a partial implementation of the phase 8a wording. If the
backend later annotates response models, `schema.ts` and `types.ts` should be
extended to consume them; until then a response-shape change must be mirrored in
`types.ts` by hand (the request half is now enforced by `openapi-check`).

## 2026-10-10 — The frontend keeps server state in TanStack Query v5, not hand-rolled hooks

**Decision.** Every screen reads server data through TanStack Query v5
(`api/hooks.ts`, `api/queryKeys.ts`, `api/queryClient.ts`). Mutations invalidate
the affected case-scoped keys through one `invalidateCaseData` helper, and the
`JobsProvider` WebSocket frames call the same invalidation so a live job update
refreshes the lists without polling. This replaces the earlier hand-rolled
`useHealth` polling pattern.

**Why.** Spec 07 §4 requires that lists update live while a job runs and that
background changes refresh the UI; a query cache with key-based invalidation is
the smallest correct way to express that and matches the stack spec 07 names.

**Cost.** Component tests must wrap a screen in a `QueryClientProvider`; the new
test helper sets `retry: false` so a failing fetch surfaces immediately instead
of retrying.

## 2026-10-10 — The mapping wizard serializes profile YAML itself

**Decision.** The custom mapping wizard builds profile YAML with a small,
purpose-built serializer in `features/sources/mappingProfile.ts`
(`buildProfileYaml`) that emits only the keys `app.ingest.profiles.load_profile`
understands, in a fixed order, quoting every scalar.

**Why.** The wizard must show the operator exactly what will be saved and dry-run
it through `POST /profiles/preview` before writing anything. Emitting the exact
YAML the loader will parse (rather than assembling a JSON body the backend then
re-serializes) keeps the preview, the saved file and the operator's mental model
identical; the emitted output was checked to load through `load_profile`.

**Cost.** The serializer is a second implementation of the profile schema and
must be kept in step with `app/ingest/profiles.py`. It deliberately supports only
the scalar/list subset the editor exposes; a hand-written profile using a feature
the wizard cannot express is edited in the (future) YAML editor instead.

## 2026-10-10 — Alert IOCs are linked in the detect transaction, and tier-2 extraction is idempotent

**Decision.** After alerts are recorded and enriched, the detect worker calls
`link_alert_iocs` (`detect/ioc_link.py`). It reads the case's `alert_events`,
reloads each evidence event as a `NormalizedEvent`, extracts tier-2 indicators
(filepath/filename/registry through the standard scanners; `command` from
`process_cmdline` only when the alert level is `medium`/`high`/`critical`;
`user_agent` only when it matches a scanner keyword or occurs at least twice
across the case), stores them through a new `IocRepository.store_alert_iocs`
that advances `occurrences` only for genuinely new `(event, field)` rows, then
rebuilds the case's `ioc_alerts` (delete the case's links, re-insert the distinct
`alert_events ⋈ ioc_occurrences` pairs) inside one `atomic()` block.

**Why.** Spec 01 §8 ("enrich + score") and spec 05 §3 place tier-2 extraction
after alerts exist, but `ioc_alerts` was previously only ever read — by the
alert-detail `iocs` list and the +5 `ioc_evidence` scoring modifier — and nothing
ever wrote it, so both were dead in production. Extracting inside the detect
transaction keeps the links consistent with the alerts they describe. Detection
runs repeat, so re-extraction must not inflate counts: the parse-stage `store`
deliberately accumulates across streaming batches, which is wrong for evidence
that is re-read whole, hence the separate idempotent `store_alert_iocs`.

**Cost.** Tier-2 indicators exist only for events an alert points at; an
indicator on a non-alerting event stays out. The scanner user-agent keyword list
is a module constant that duplicates the list in `rules/builtin/web_attacks.yml`
(spec 04 §10) and must be kept in step by hand.

## 2026-10-10 — Only settings with a live effect are writable, and allowlist adds are idempotent in code

**Decision.** `PUT /settings` accepts exactly one editable key, `detection.profile`
(one of `fast`/`standard`/`full`); the value is validated against the schema and
persisted to the `settings` table, and `POST /cases/{id}/detect` resolves its
profile as `body.profile or detection_profile(stored_overrides, config)` so a
stored override actually changes a run. Every other setting (`server`, `limits`,
`detection` knobs other than the profile) stays read-only and is rejected with
`VALIDATION_ERROR`, as are empty bodies and unknown keys. Separately,
`AllowlistRepository.add_global_entry` is idempotent per `(kind, value)`: it
`SELECT`s first and returns `(record, created)`, and the router only writes an
`allowlist_changed` audit row when `created` is true.

**Why.** Spec 06 lists a settings API and spec 11 says not to leave stubs; a
setting endpoint that accepted keys nothing reads would be a stub. Restricting the
writable set to the one knob the detect path honors keeps every accepted value
observable. The `allowlist` table has no unique index on `(scope, kind, value)`
(see spec 02 §data model), so idempotency cannot ride on `INSERT OR IGNORE` and
must be enforced by the read-then-write in the repository.

**Cost.** Adding a new editable setting means adding its schema entry, its
overlay mapping and a consumer that reads it — three edits, not one. The
allowlist read-then-write is not atomic against a concurrent duplicate insert;
the single-writer thread is what keeps it safe.

## 2026-10-09 — Event browsing uses keyset pagination and a deferred count

**Decision.** `GET /cases/{id}/events` paginates with an opaque keyset cursor on
`(ts_ms, id)` (urlsafe-base64 `"<ts_ord>:<rowid>"`), never OFFSET, and returns
`total: null`; exact totals come from `GET /cases/{id}/events/count` with the
same filters. `sort` is restricted to `ts`/`-ts` — the only orderings the keyset
is sound for — and `NULL ts_ms` events are ordered as if `0` via `COALESCE`
(with a tie-break on `id`, so a missing timestamp still pages deterministically).

**Why.** Spec 06 says events are keyset-paginated on `(ts_ms, id)` and that
`total` is omitted when a full count would be expensive; a row whose timestamp
is unset (no case timezone at ingest time) still has to land in exactly one
position. Restricting the sort keeps the where-clause's row comparison honest:
an offset- or secondary-key sort cannot be represented with one cursor tuple.

**Cost.** The first key of the browse sort is timestamp, so there is no way to
walk events by `id` alone; clients that want chronological browse must send
`sort=ts`. The cursor is not human-readable.

## 2026-10-09 — Invalid FTS syntax is a 422, and list columns are qualified for the FTS join

**Decision.** When `q` is present the events repository joins
`events_fts ON events_fts.rowid = events.id` and runs `events_fts MATCH ?`
against the query text; a malformed query surfaces as `sqlite3.OperationalError`
and is re-raised as `ValueError`, which the router maps to a 422
`VALIDATION_ERROR` whose message is the sqlite text with the `fts5: ` prefix
stripped (`invalid search query: ...`). Every column selected in an events list
query is written `events.<column>` (including `id`, which is not part of
`EVENT_COLUMNS`), and the FTS row reference comes only through the rowid join —
the query never selects from the FTS table's columns.

**Why.** The FTS external-content table and its backing table share column names
(`message`, `process_cmdline`, ..., `raw`), so a bare column list makes the
combined SELECT ambiguous and a `MATCH` error was leaking as a stored-string
rather than a clean API error. Qualifying everything and joining only on rowid
keeps the SELECT unambiguous, and converting the syntax error at the repository
boundary turns a driver exception into a normal 422 the UI can show.

**Cost.** List queries must be qualified with the table name to stay correct —
there is no shortcut that drops the prefix. The 422 message mirrors sqlite's
wording, so it reads like a parser diagnostic rather than an app message.

## 2026-10-09 — Event facets are a fixed column set under the current filters

**Decision.** `GET /cases/{id}/events/facets` computes top-N values (default 20,
max 100) for exactly five dimensions — `host`, `log_type`, `channel`, `user_name`
and `src_ip` — plus `event_id`, whose facet values are returned as integers to
match the list payload. Facets share every list filter except `limit`, and the
values counted are the raw stored strings (empty/blank values are counted once
under their verbatim value).

**Why.** Spec 06 names this exact set and a top-N limit, and the list API needs a
filterable count for each. Restricting the dimensions keeps the count query a
single indexed `GROUP BY` and makes the aggregation behaviour (blanks included)
explicit rather than guessed.

**Cost.** A new facet dimension is a schema-owning change, not a query tweak; the
field set is mirrored in `api_contract.txt` and would have to grow with the
filters. `event_id` facets are ints, so a client must not compare them to the
string form of the `event_id` filter.

## 2026-10-09 — The rule catalogue syncs from disk on first run and on every import

**Decision.** A fresh install starts with an empty `rules` table; the new
`app/detect/sync.py:sync_catalogue` loads the shipped builtin and sigma trees
plus the custom directory through the engine's own loader, upserts every loaded
rule (preserving each row's `enabled` flag) and prunes stale shipped rows by id
via `RuleRepository.delete_outside`, which never touches custom rows. It runs at
startup only when `detection.sync_rules_on_startup` is on **and** the shipped
rows count is zero, and `POST /rules/import` now uses the same path instead of
upserting only custom rules.

**Why.** Nothing ever seeded the catalogue, so a fresh install could run
detection with zero rules. Running the 4-5 s tree load on every boot is
pointless once rows exist — the shipped sets only change when the operator edits
their own files or triggers an import — so the empty-catalogue gate makes later
boots free and keeps the test suite (which opts out of the flag) fast. Routing
every sync through `load_rules` means parse, compile and health are computed
exactly as the Rules → Health view reports them, and importing a custom file no
longer leaves the rest of the catalogue stale when a vendored rule was removed.

**Cost.** The 4-5 s first boot is a visible startup pause, and there is no
dedicated manual re-sync endpoint (the spec does not define one); re-syncing by
hand means uploading a file through import or deleting the shipped rows.
`api_contract.txt` stays unchanged because the existing endpoints just gain the
`synced`/`stale_removed` response fields.

## 2026-10-09 — The SigmaHQ sample is every routable detection rule at one pinned commit, capped for Windows

**Decision.** `scripts/update_rules.py` vendors a downloaded SigmaHQ/sigma tree
(dir or zip) into `backend/rules/sigma`. The sample is every detection rule
that parses, compiles with `pysigma-backend-sqlite`, is not a correlation rule,
and routes through the shipped `logsource_map.yaml`; the Windows slice is
further spread across its first-level rule families with per-level caps
(high 90, medium 70, critical 5, low 5). Files are copied byte-for-byte and
multi-document files whole or not at all. `SOURCE.txt` records the upstream
commit, the tree and source SHA-256 digests, and the per-category counts;
`LICENSE` (DRL 1.1) sits next to the rules. Running the tool re-loads the
result and asserts the digest is unchanged, so a rerun reproduces the tree
exactly.

**Why.** Spec 09 D-12 needs a compile-health floor of 200+ SigmaHQ rules
without turning the repo into a SigmaHQ mirror. Every rule that parses,
compiles and routes is safely runnable, so taking all of Linux/Web/network and
the spread-capped Windows slice keeps the whole sample honest ("rules we can
run") while staying reviewable. Excluding unroutable rules up front keeps the
compile-health dashboard meaningful: a rule that cannot be run is a map gap,
not rule health.

**Cost.** The shipped logsource map cannot yet route most of `rules/network`
(cisco/zeek/dns — 44 of 45 files unroutable) or service/product channels
outside the selected Windows families, so the sample under-represents those
products at this commit; adding them later is a logsource-map change, not a
re-vendor. Rule content is imported wholesale from upstream, so DRL
attribution relies on the vendored `LICENSE` and `SOURCE.txt`.

**Buckets at commit `48f2d096` (2024-05-31).** 2514 rule files across
`rules/{windows,linux,web,network}`: 114 fail to parse (all `obsoletes:`,
which pySigma 1.5 rejects as an invalid Sigma type), 100 parse but are
unroutable, 0 other compile failures, 374 vendored (Windows 147 across 15
families, Linux 186, Web 40, network/firewall 1). Loading the vendored tree is
deterministic — two loads produce identical rows. (A 2026-10-11 amendment added
four Windows rules on top of this snapshot — see "Browser E2E for Scenarios
A/B/C" — so the shipped tree is now 378 rules, Tree SHA-256 `a2c3f33d…`.)

## 2026-10-08 — The ambiguous-TLD penalty follows the acceptance path, not the suffix

**Decision.** A domain whose TLD is also a common file extension keeps
`ambiguous_tld` — and the −30 score penalty — only when **free-text** acceptance
rode on the "≥ 2 labels before the TLD" rule. A domain accepted from a
structured field (URL host, DNS query, email domain) is never marked ambiguous
and keeps its 80 base. `extract.py` sets the flag as `domain.ambiguous and not
ctx.structured`; URL hosts are always unpenalized.

**Why.** Spec 05 §6 writes the penalty as "ambiguous TLD domain accepted via
≥ 2 labels rule only". `validate_domain` returns a single `ambiguous` flag for
both acceptance paths, and the extractor initially forwarded it verbatim, so a
URL like `http://evil.sh/x` lost 30 points exactly as if its host had been
guessed from prose. The spec gives structured fields a higher base **because**
they are authoritative; penalizing them for an acceptance rule they did not take
double-counts the doubt.

**Cost.** `validate_domain` still reports `ambiguous=True` for a structured
ambiguous TLD, so the distinction lives at the extractor's boundary rather than
in the validator. A value seen once in prose and once as a URL host dedups to
the URL host's 80 because aggregation keeps the higher base and its flag.

## 2026-10-07 — A dotted flat column resolves literally before dot-walking

**Decision.** `profiles.resolve` returns `record[path]` verbatim when the path has
no `[*]` and is a key of the record, before splitting it on dots.

**Why.** Dot notation means nesting (`host.name`), but a CSV column or Zeek field
is literally named with a dot (`id.orig_h`). Walking the path segment-by-segment
turned that column into `id` → `orig_h` and silently mapped every address to NULL.
Matching the literal key first keeps nesting working for JSON, where a literal
`host.name` key does not exist, while making dotted CSV names usable as written.

**Cost.** A JSON record carrying both a literal `"a.b"` key and nested
`a: {b: ...}` resolves to the literal; that shape does not occur in the shipped
formats.

## 2026-10-07 — CSV and JSON share one profile engine; CSV folds in Zeek TSV

**Decision.** `generic_common.py` owns record→event mapping, used by both
`generic_json` and the new `generic_csv`. `generic_csv` handles a plain
header-labelled table (delimiter sniffed among `, ; \t |`) and a Zeek TSV
(`#separator`/`#fields`), and reports a column-count mismatch as a per-row
failure.

**Why.** Once a record is a `dict`, the two formats are identical to map, and
duplicating that half is how the ECS and vendor mappings drift apart. Zeek writes
its columns in a header directive rather than a first row, so it needs one shared
reader, not a second parser.

**Cost.** A CSV line that is not the header and has the wrong column count becomes
a parse error rather than being guessed at, which is the spec 03 §7 rule but means
a ragged export shows failures instead of partial rows.

## 2026-10-07 — User profiles are a separate writable directory that shadows shipped ones

**Decision.** Shipped profiles live in `data/profiles`; profiles saved through the
API live in `data/profiles/user` (`TRIAGELENS_USER_PROFILES_DIR` overrides it). A
user profile may share a shipped name and wins; a name that exists only as a
shipped profile cannot be written or deleted (`409`).

**Why.** A profile is the parser for a format nobody wrote code for, so an
operator must be able to add and correct one without a rebuild. Keeping user files
in their own directory means "which profiles are bundled" stays answerable and an
upgrade cannot clobber operator data. Making built-ins read-only gives the UI a
fixed reference to compare against (spec 03 §6).

**Cost.** Shadowing a built-in needs an explicit user file rather than an edit,
and `/profiles` must merge two directories per request.

## 2026-10-07 — A profile may declare a `default_category`

**Decision.** `Profile.default_category` is used when no `category_rules` entry
matches.

**Why.** A feed like Zeek `conn.log` is entirely network connections, so writing a
rule per record type is noise. A default keeps the common case declarative while
rules still override it.

**Cost.** A feed with no rules and no default yields events with no category,
which is the honest answer.

## 2026-10-07 — Each firewall vendor gets one `log_type`; syslog defers to it

**Decision.** Detection uses a single `log_type` per vendor (`fw_iptables`,
`fw_pfsense`, `fw_fortinet`, `fw_paloalto`, `fw_cisco_asa`), each scored by a
content sniff that fires at ≥ 0.8 share. `linux_syslog`/`linux_auth` return 0.0
when ≥ 0.6 of lines are firewall-shaped (UFW marker, `filterlog` app, `%ASA-`, or
`IN=`+`SRC=`+`DST=`).

**Why.** A firewall record frames exactly like syslog, so without the deferral
both the syslog parser and the firewall parser would claim the same line and the
vote would tie. Splitting by vendor keeps the category and the parser honest: a
UFW line and a PAN-OS line are not interchangeable (spec 03 section 5, spec 09
P-10).

**Cost.** A file that mixes firewall vendors needs the operator to pick one, as
does any file whose firewall lines fall below the 0.6 share.

## 2026-10-07 — PAN-OS field names are provisional until a vendor reference is supplied

**Decision.** `data/profiles/paloalto_fields.yaml` holds the PAN-OS 10.1/11.0
positional layouts used by `fw_paloalto`, marked provisional.

**Why.** The layout is authored from the spec's column description rather than a
vendor field reference. Encoding it in one auditable YAML file - rather than magic
indices in code - means a correction is a data edit and the profile loader already
skips `kind: parser_layout` files so nothing else consumes them by accident.

**Cost.** Column names may need correcting once a real PAN-OS field reference is
available; only traffic and threat rows are mapped until then.

## 2026-10-07 — ASA parses the spec id set; other 106xxx/302xxx ids stay firewall events

**Decision.** `fw_cisco_asa` parses exactly the P-10 id set
(106023/106100/302013-302016/113005/113015/605005/611101) into columns. An
unrecognized `106xxx`/`302xxx` id still produces an event with its id, level and
text, filed as `ls_category="firewall"`. The `%ASA-` frame is located with
`search`, not `match`, because syslog framing can mistake `%ASA-6-302013` for a
tag.

**Why.** Guessing columns for ids outside the spec set would invent evidence; the
family prefix is enough to file the event correctly, and the raw text is kept
(spec 03 section 5.5).

**Cost.** An unrecognized id gets no five-tuple until its columns are added.

## 2026-10-07 — `DetectionResult.confidence` reports the accepted candidate, not the hint

**Decision.** `DetectionResult.confidence` is the best positive candidate score,
not `candidates[0].confidence`.

**Why.** When content is undecided the filename hint is listed first at 0.0 so the
operator can see it; when content *is* decisive the hint is still prepended, so
reading `candidates[0]` reported 0.0 for a confidently-detected `.csv`. The
property now reads the accepted score.

**Cost.** None; the candidate list order is unchanged for the needs_input prompt.

**Decision.** One combined-log reader backs both `apache_access` and
`nginx_access`. During detection they are mutually exclusive: a filename
containing `nginx` scores the nginx reader and zeroes the Apache one, and any
other name does the reverse.

**Why.** The access line is byte-identical on both servers, so a second pattern
would be a copy. Scoring both equally and breaking the tie alphabetically would
route the same file to `apache_access` on a coin flip; making the vote depend on
the filename keeps it decisive and matches the spec's "cosmetic" framing (spec 03
section 4.1).

**Cost.** A genuinely nginx file with no `nginx` in its name is labelled Apache.
The two produce the same columns, so the mislabel costs a label, not evidence.

## 2026-10-07 — Web error timestamps without an offset use the case timezone

**Decision.** `nginx_error` and `apache_error` read their wall-clock timestamp in
`context.timezone` and store no `ts_ms` when the case has none, rather than
defaulting to UTC.

**Why.** The web access log carries a `+0000` offset, but the error logs carry
none. Assuming UTC would silently shift every error by the server's offset and
move some evidence across a day boundary, which is the failure model the
normalizer refuses everywhere else (spec 02 section 2).

**Cost.** A case with no configured timezone gets error events with no timestamp
until `case.default_timezone` is wired into `ParseContext` (see the Phase 3
entry).

## 2026-10-07 — The Scenario B access golden may exceed the fixture size guidance

**Decision.** `web/access_combined.log` keeps the 200+ benign requests spec 09
Scenario B requires, so its golden is ~225 KB, just over the 200 KB guidance. The
`.log` itself is ~22 KB.

**Why.** Scenario B is deterministic on 200+ benign requests producing no alerts;
shrinking the fixture to please the golden size would weaken the very scenario the
fixture exists to drive. The size guidance is about committed fixtures, and 225 KB
is not a material cost.

**Cost.** A slightly larger golden than every other fixture. If the guidance
becomes a hard gate, the golden can be trimmed to a representative projection.

## 2026-10-06 — Syslog framings are matched per line, not locked per file

**Decision.** `linux_common` tries RFC 5424, RFC 3164 and RFC 3339 on every line
and takes the first that matches; it does not decide a single framing for the
whole file.

**Why.** A single collection can interleave the three (a relay writing RFC 3339
beside an appliance writing RFC 3164), and the spec 09 fixture for P-05 does
exactly that. A per-file winner would silently reclassify or drop the lines the
other framings cover.

**Cost.** A regex is attempted per line. The three patterns are anchored and
cheap, and the benchmark stays above 12,000 records/s, so the simplicity wins.

## 2026-10-06 — The year-less syslog clock defaults to UTC and resolves a DST fold earlier

**Decision.** An RFC 3164 timestamp carries no year or zone. The year is seeded
from the operator's `assumed_year`, then a year in the filename, then the file's
mtime, and advanced when the month moves backwards. The wall-clock time is
interpreted in `context.timezone`, falling back to `UTC` when none is set; an
ambiguous DST fold resolves to the earlier reading (`ambiguous="earlier"`).

**Why.** `case.default_timezone` exists in the schema but is not yet threaded
into `ParseContext`, so a parser must pick something rather than guess an
environment zone. Spec 09 P-05 requires only a deterministic choice for the fold,
and `earlier` always exists and is stable across platforms.

**Cost.** A file read without a configured timezone gets UTC, which can be an
hour or more off the host the log came from. Wiring `case.default_timezone` into
`ParseContext` is a later change.

## 2026-10-06 — `generic_json` defers journal-shaped lines to `linux_journald`

**Decision.** `generic_json.sniff` returns 0.0 when the first line carries a
journal-only key (`__REALTIME_TIMESTAMP` or `SYSLOG_IDENTIFIER`), so
`linux_journald` (0.9) wins by more than the decision margin.

**Why.** Both parsers can read the same newline-delimited JSON, but only
`linux_journald` lifts the journal keys onto the normalized columns. Without the
deferral the generic parser would claim the file and store every record as an
opaque blob.

**Cost.** A JSON file whose first line happens to carry those keys is treated as
journald; that is what the keys mean, so the ambiguity is intentional.

## 2026-10-06 — Audit `sockaddr` family is read little-endian

**Decision.** `linux_auditd` reads the `sa_family` of a packed `sockaddr` in host
(little-endian) order and the port and address in network (big-endian) order.

**Why.** That is how the kernel lays the struct out. Reading the family big-endian
turns the bytes `02 00` into 512, so no connect is ever recognized.

**Cost.** The decode assumes a little-endian host; a big-endian auditor would be
misread. Linux audit records in scope are little-endian.

## 2026-10-06 — A socket connect has no category

**Decision.** An audit `SOCKADDR` record becomes `event_action="socket_connect"`
with `ls_category` left `None`.

**Why.** The spec 04 category vocabulary has no row for a connect, and inventing
one would put a made-up classification into the evidence. The action still names
what happened.

**Cost.** Rules that key only on category miss connects; they must match the
action as well.

## 2026-10-06 — auditd process creation uses the `process_created` action

**Decision.** An auditd `EXECVE` group maps to `event_action="process_created"` and
`ls_category="process_creation"`, not the `process_executed` action named in spec
03 section 3.3.

**Why.** `process_executed` is not in the action vocabulary in force; the Windows
parsers already emit `process_created` for the same concept. Emitting a one-off
action from one parser would force every downstream rule to special-case it.

**Cost.** Spec 03 is textually inconsistent with the shipped action; this entry is
the record that the code follows the shared vocabulary on purpose.

## 2026-10-06 — The Windows EVTX reader has a native first choice and a vendored fallback

**Decision.** `windows_evtx` prefers the native `evtx` (pyevtx-rs) extension and
falls back to a vendored, pure-Python `python-evtx` tree under
`app/ingest/parsers/evtxlib/`. `native_backend_available()` reports which is in
use; the tests pin `backend="vendored"` so they run where the native wheel cannot
load.

**Why.** Spec 03 names pyevtx-rs as the reader and pure-Python as the documented
fallback. The offline bundle is pure-wheel, and hardened Windows hosts block
native extensions through Application Control — this workstation blocks the
`_native.pyd`, so a native-only parser would ship untested and unloadable.

**Cost.** Two code paths to keep correct. The vendored reader is slow (83
records/s here, below the spec target) and reproduces upstream's own limits; the
native path is guarded by `native_backend_available()` but is not exercised on
this machine.

## 2026-10-06 — Windows severity is mapped with the channel's own level table

**Decision.** `windows_common` maps `System.Level` (0→info, 1→critical,
2→error, 3→warning, 4→info, 5→debug) directly, rather than routing it through the
generic `normalize_severity`.

**Why.** The Windows levels are not the syslog severities `normalize_severity`
expects: Windows 1 is critical and 3 is warning, which is different ordering.
Reusing the generic mapping would have silently mislabelled every Windows event
that carries a level.

**Cost.** Two severity mappings exist. The generic one is unchanged and still
used by every non-Windows parser; the Windows table is applied only in the
Windows mapping function.

## 2026-10-06 — Event XML is parsed with entities and network access disabled

**Decision.** `windows_event_xml` parses with `resolve_entities=False`,
`no_network=True` and a bounded document, so a `<!DOCTYPE ... SYSTEM ...>` payload
is not resolved.

**Why.** Event XML is evidence from an untrusted host. The default XML parser
follows external entities, which turns a log file into a file-read or SSRF
primitive. A test writes an XXE payload referencing a local file and asserts the
canary never appears in the parsed event.

**Cost.** A legitimate export that (unusually) relies on external entities would
parse without them; standard Windows exports never do.

## 2026-10-06 — Binary EVTX fixtures are trimmed copies, not generated

**Decision.** The `.evtx` fixtures under `tests/fixtures/evtx/` are small,
committed copies trimmed from a published corpus, with a `PROVENANCE.md` recording
the source and a `.expected.json` golden beside each.

**Why.** There is no EVTX *writer* in the tree, so binary fixtures cannot be
synthesized the way the JSON and XML samples are. Copying a real file keeps the
reader honest against real binXML rather than a hand-built approximation.

**Cost.** Provenance must be tracked by hand, and the goldens are regenerated
with `scripts/make_fixtures.py --update-golden` rather than derived.

## 2026-10-06 — WebSocket routes are mounted explicitly

**Decision.** `app/main.py` mounts the WebSocket router's routes one at a time via
`app.add_api_websocket_route`, never by including the router wholesale.

**Why.** FastAPI's `include_router` silently drops `@router.websocket` handlers:
it only iterates the HTTP routes and copies them into the parent, so a router
that is purely WebSocket imports cleanly and serves nothing. The two progress
endpoints 404'd until each route was mounted explicitly under `/api`.

**Cost.** A WS route added to the router needs one line in `main.py`. An `__all__`
guard keeps the two lists from drifting silently, but the coupling is manual.

## 2026-10-06 — WebSocket tests run against a real uvicorn server

**Decision.** `TestWebSocketProgress` starts uvicorn in a thread (the
`LiveServer` fixture) and talks to it with `websockets.sync.client`, rather than
using Starlette's `TestClient` over WebSocket.

**Why.** Starlette's `TestClient` cannot complete a WebSocket handshake for a
route created with `add_api_websocket_route`: the connection blocks instead of
opening. The application is correct against a real server, so the test tool was
wrong. Poll-only tests would have missed the frame flushing bugs that a live
reader caught.

**Cost.** WebSocket tests need a free port and a real server thread; the polling
helpers share one `LiveServer` class across the suite.

## 2026-10-06 — A finished job cannot be cancelled

**Decision.** `DELETE /api/jobs/{id}` returns 409 `CONFLICT` for any terminal job,
and `needs_input` **is** terminal.

**Why.** `needs_input` is not paused: the parse stopped and the job is waiting on
the operator. Accepting a cancel would report progress that can never happen —
the job already stopped. Treating it as finished makes the API honest, and
cancelling it now has a correct answer (the source is parked; resolve it instead).
A null-`finished_at` stored at park time keeps the distinction visible.

**Cost.** `needs_input` no longer reads as "running but on hold"; callers that
want that must read the source's own state.

## 2026-10-06 — Resolve and re-parse start a new job, never mutate the old

**Decision.** `POST /sources/{id}/resolve` with a parser, and
`PATCH /sources/{id}` with a `log_type`/`timezone`/`assumed_year` change, both
create a **new** job that re-parses the stored file; the previous job and its
frame history stay as the terminal record of what ran before.

**Why.** A parser change invalidates the events a previous job produced. Rewriting
them in place would rewrite history; a fresh job lets the progress frame show the
new parse and lets an operator compare "before and after" without corrupting the
case. Events are replaced (not stacked) so the source's counts describe one
ingest, and the job chain is the audit trail.

**Cost.** Parsing work is repeated on a re-parse, and a source can look identical
after a resolution whose only effect was replacing its events.

## 2026-10-06 — A dead or failing source does not fail the whole job

**Decision.** `IngestRunner` ingests the parseable plans one at a time; a worker
crash or parse failure marks that **source** failed/`error_count` and the job
carries on with the rest. The job ends `done` when every parseable source
finished, `needs_input` when some sources were parked, and `failed` only when the
pipeline itself broke (e.g. the writer thread died).

**Why.** One bad member of a bundle must not discard the files around it, and one
crashed worker must not take down a case's other jobs. Spec 11 phase 1 asks that
the server survive a worker crash; per-source failure is the granularity at which
an analyst can act (re-parse or delete that source).

**Cost.** A `done` job does not, by itself, mean every source parsed; the source
rows carry the detail.

## 2026-10-06 — `alerts.changed` is deferred until alerts exist

**Decision.** The WebSocket publishes the spec 06 frames that have an observable
subject (ping, job.stage, job.update, job.error, terminal). `alerts.changed` is
not emitted in phase 1.

**Why.** Alerts are created by the detection engine, which is a later phase; there
is no row to publish and no test can observe the frame meaningfully. Emitting an
always-empty alert frame would be fabricated progress.

**Cost.** A spec-06 client written today will observe alert frames only once that
phase lands. The frame contract is unchanged.

## 2026-10-06 — A recursive from-path import is allowed, not the default

**Decision.** `POST .../sources/from-path` treats `recursive: false` as the safe
default (a directory without it is 403 `FORBIDDEN_PATH`). With `recursive: true`,
a directory is walked with `os.walk(followlinks=False)`: every regular file
imported, file symlinks accepted only when their target stays under a configured
root, symlinked directories never descended. The full expanded candidate list is
counted against the request limit before any storage happens.

**Why.** The `.ndjson`-sniffing import previously imported only whole paths, so a
directory of evidence files was unusable. Defaulting recursion off matches the
least-surprise rule for what is effectively an ingest of everything under a
directory; following symlinks out of the roots would be a containment breach.

**Cost.** Each symlinked file is resolved and re-checked on import, and an
unexpectedly large directory now waits on a clean 4xx instead of a partial one.

## 2026-10-06 — `intake_path` closes the stream it opens

**Decision.** `intake_path` wraps its `path.open("rb")` in a `try/finally` and
closes the handle after `intake_stream` returns, instead of handing the open
stream to the caller.

**Why.** An unclosed handle pins the original file on Windows, where an open
handle blocks deletion — and every import path promises to *copy*, never to hold
or move the original. The upload path closes its own file; the import path must
close its own too.

**Cost.** One `try/finally`; callers that wanted to keep the handle can no longer
take ownership of it, which the import flow never did anyway.

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

## 2026-10-09 — Timeline buckets are span-driven with epoch alignment and alert counts

**Decision.** `GET /cases/{id}/timeline` accepts `bucket=auto|1m|5m|1h|1d` and
groups events on `((COALESCE(ts_ms,0)/bucket)*bucket)` so each bucket starts on
an integer boundary (epoch-aligned). `alert_count` is the number of distinct
events in that bucket that have at least one row in `alert_events` (joined
while still applying every list filter, including `q` and IOC/alert link
filters); the response emits only buckets that contain at least one event. For
`auto`, the bucket size is the finest that fits the filtered span without
exceeding one day for very large windows, with the `<=` thresholds (<= 15m →
1m, <= 6h → 5m, <= 3d → 1h, else 1d); an empty filtered set falls back to
`1m`.

**Why.** Spec 06 requires `auto` and per-bucket splits by `log_type` and an
`alert_count`. Aligning to epoch milliseconds lets bars line up cleanly and the
SQL `GROUP BY` is trivial; counting distinct alert-linked events, rather than
counting `alert_events` rows or alerts, matches the "alert_count" wording (events
that are associated with at least one alert) and remains correct when one event
links to several alerts or vice versa.

**Cost.** Rows with no `ts_ms` sort into bucket `0`; there is no way to show them
separately (the bucket still has `t_ms = 0`). A very large span always uses at
least 1d, so granularity disappears — the thresholds are a compromise between
chart readability and data volume.

## 2026-10-09 — The audit-log endpoint walks the full chain and returns verification

**Decision.** `GET /cases/{id}/audit-log` lists a page of the requested case's
rows and, in the same response, returns a hash-chain verification of the *whole*
`audit_log` (not just the page). Verification walks from id 1 onward, recomputes
`sha256(prev_hash || ts || action || detail_json)` for each row and checks
`prev_hash` against the previous verified hash; when `case_id` is supplied to
`verify`, rows of other cases are still visited but their `hash` becomes the new
`prev_hash` (they do not count towards `rows_checked`), so interleaved rows
cannot allow the head of the requested case to be used to "bridge" a tampered
row. The API stores hashes in `prev_hash` and `hash`, returns them verbatim on
each entry, and the storage layer still aborts `UPDATE`/`DELETE` on `audit_log`
via triggers (test-guarded).

**Why.** Spec 10 requires that tampering be detectable and the per-case endpoint
report the first broken row; a global hash chain means a row in one case's
history cannot be edited without breaking the chain for later reads of that case
and for any read that reaches past the edit. Walking the whole chain on every
page call is cheap enough in practice for the small audit sets this tool will
have (the repository does a single table scan in `iter_all`), and returning the
hashes on entries lets the client re-verify the chain independently if desired.

**Cost.** A very large `audit_log` (many 10s of thousands of rows across cases)
makes every per-case audit page a full scan; if that becomes a problem the chain
will need per-case checkpoints or head-of-case records, but that's not necessary
for the spec's intent and current data volumes. `rows_checked` counts only rows
belonging to the requested case.

