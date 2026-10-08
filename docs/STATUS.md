# Status

What works today, and what does not. Updated at the end of each phase.

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
- The enrichment path (`network.allow_enrichment`, VirusTotal/AbuseIPDB) is not
  implemented yet; the spec's outbound-network test (S-05) stays open.
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