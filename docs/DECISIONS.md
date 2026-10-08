# Architecture decisions

Each entry records a decision that is not obvious from the code, why it was
made, and what it costs. Newest first. Dates are ISO-8601.

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
