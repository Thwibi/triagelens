# 01 — Architecture

## 1. Overview

```
Browser (React SPA)
   │  REST + WebSocket (127.0.0.1 only by default)
FastAPI process ──────────────────────────────────────────────┐
   │                                                          │
   ├─ API layer (routers, pydantic schemas)                   │
   ├─ Job manager (asyncio) ── ProcessPoolExecutor (parsers)  │
   │        │                         │ batches of events      │
   │        └──── single DB writer thread (SQLite, WAL) ◄──────┘
   ├─ Detection engine (pySigma → SQL, correlation in Python)
   ├─ MITRE service (offline STIX → tables)
   ├─ IOC engine
   └─ Report/export service
Data dir:  data/triagelens.db, data/cases/<case_id>/sources/<source_id>/original, data/reports/
```

One Python process serves the API and the built frontend (static files). CPU-bound parsing runs in worker processes so a malformed file can crash a worker, not the server.

## 2. Repository layout

```
triagelens/
├─ backend/
│  ├─ pyproject.toml
│  ├─ app/
│  │  ├─ main.py                 # FastAPI app factory, static mount, startup checks
│  │  ├─ config.py               # config.toml + env overrides (TRIAGELENS_*)
│  │  ├─ db/                     # connection mgmt, migrations runner, repositories
│  │  ├─ models/                 # pydantic schemas + dataclasses (NormalizedEvent, ...)
│  │  ├─ ingest/                 # intake, archive expansion, format detection, pipeline
│  │  ├─ parsers/                # one module per parser + registry
│  │  ├─ detect/                 # sigma loader, backend, router, correlation, scoring
│  │  ├─ mitre/                  # STIX loader, tag mapper, fallbacks
│  │  ├─ ioc/                    # extractors, refang, decoders, scoring, allowlists
│  │  ├─ reports/                # jinja templates, navigator, stix, csv
│  │  ├─ api/                    # routers: cases, sources, jobs, events, alerts, iocs, rules, mitre, reports, settings
│  │  ├─ jobs/                   # job manager, progress bus
│  │  └─ util/                   # time, hashing, safe archive, logging
│  ├─ migrations/                # 0001_init.sql, 0002_*.sql ...
│  ├─ rules/
│  │  ├─ sigma/                  # vendored SigmaHQ rules (windows, linux, web, network) + LICENSE
│  │  ├─ builtin/                # TriageLens built-in rules (YAML, see 04)
│  │  └─ logsource_map.yaml      # logsource → event predicates
│  ├─ data/
│  │  ├─ attack/enterprise-attack.json     # offline STIX bundle
│  │  ├─ iana_tlds.txt
│  │  ├─ default_allowlist.yaml
│  │  ├─ mitre_fallbacks.yaml
│  │  └─ profiles/               # generic JSON/CSV mapping profiles
│  ├─ scripts/                   # update_attack.py, update_rules.py, make_fixtures.py
│  └─ tests/
├─ frontend/                     # Vite + React + TS
├─ docker/                       # Dockerfile, docker-compose.yml
├─ scripts/                      # run.sh, run.ps1
├─ DECISIONS.md
└─ Makefile                      # install, dev, test, lint, build, package
```

## 3. Ingestion pipeline

Stages (each stage updates `jobs.progress` and emits WebSocket events):

1. **Intake** — stream upload to `original`, compute SHA-256 while writing, `chmod 0444`. Archives (`.zip`, `.tar`, `.tar.gz`, `.gz`, `.7z` optional) are expanded safely (see 10): each member becomes its own source.
2. **Detect format** — `detect(path) -> DetectionResult(log_type, confidence, alternatives)`; user override allowed. Confidence < 0.6 → job pauses in `needs_input` and the UI asks the user to pick the type (and timezone/year when relevant).
3. **Parse** — worker process iterates `parser.parse(path, ctx)` yielding `NormalizedEvent`. Malformed records never abort the parse: they increment `error_count` and are written to `parse_errors` (source_id, record_ref, reason, raw excerpt ≤ 2 KB).
4. **IOC extraction (tier 1)** — in the worker, on every event (network IOCs + hashes). Output travels with the event batch.
5. **Persist** — batches of 5,000 events; one writer thread; one transaction per batch; FTS rows inserted in the same transaction.
6. **Inventory** — after parse, compute distinct `(log_type, channel, app_name, ls_category)` for the source; stored in `source_inventory`. Used to prune rules (04).
7. **Detect** — see 04. Runs automatically after parse unless disabled in settings; can be re-run per case.
8. **Enrich + score** — MITRE resolution, alert scoring, alert-scoped IOC extraction (tier 2).
9. **Finalize** — update counts, status `done`, audit log entry.

Cancellation: `DELETE /api/jobs/{id}` sets a cancel flag checked per batch; partial data for the cancelled source is removed.

## 4. Core interfaces

```python
@dataclass(slots=True)
class ParseContext:
    source_id: str
    case_id: str
    timezone: str            # IANA tz for timestamps lacking tz
    assumed_year: int | None # for syslog-style stamps
    host_hint: str | None
    limits: Limits           # max_line_bytes, max_events
    on_error: Callable[[str, str, str], None]  # record_ref, reason, raw_excerpt

class LogParser(Protocol):
    name: ClassVar[str]
    log_type: ClassVar[str]
    def sniff(self, head: bytes, filename: str) -> float: ...   # 0.0–1.0
    def parse(self, path: Path, ctx: ParseContext) -> Iterator[NormalizedEvent]: ...
```

Parsers register through `parsers/registry.py` (explicit list, no import side effects). `NormalizedEvent` is defined in 02.

## 5. Concurrency and database access

- SQLite opened with `journal_mode=WAL`, `synchronous=NORMAL`, `foreign_keys=ON`, `busy_timeout=10000`, `temp_store=MEMORY`, `mmap_size=2GB` (configurable).
- Exactly one writer connection (thread). API handlers use short-lived read connections. Long reads (detection) use their own connection.
- Rule evaluation registers Python UDFs on its connection: `regexp(pattern, value)` (via `regex` with 100 ms per-call timeout, cached compiled patterns), `cidr_match(ip, cidr)`, `b64_contains(...)` if needed by modifiers.
- Per-rule time budget enforced with `conn.set_progress_handler`; exceeding it marks the rule run `timeout` and records it in `rule_runs`.

## 6. Configuration (`config.toml`, overridable by `TRIAGELENS_<SECTION>__<KEY>` env vars)

```toml
[server]
host = "127.0.0.1"
port = 8787
auth_token = ""            # required (non-empty) if host != 127.0.0.1

[storage]
data_dir = "./data"

[limits]
max_upload_gb = 10
max_line_bytes = 1048576
max_events_per_source = 50000000
max_archive_expansion_ratio = 100
max_archive_total_gb = 50
worker_processes = 0       # 0 = cpu_count - 1

[detection]
profile = "standard"       # fast | standard | full
auto_run_after_ingest = true
sync_rules_on_startup = true   # seed the shipped rule tree on first run only
max_sample_events_per_alert = 500
rule_timeout_seconds = 120
alert_group_window_minutes = 60

[ioc]
extract_private_ips = true
decode_depth = 2

[network]
allow_enrichment = false   # opt-in; when false the process MUST NOT open outbound sockets

[ui]
default_theme = "dark"
```

## 7. Logging and observability

- Structured JSON logs to stdout and `data/logs/triagelens.log` (rotating, 20 MB × 5).
- Never log raw event content above DEBUG; never log auth tokens.
- `/api/health` returns versions (app, ATT&CK, rule-set hash), SQLite version, FTS5/JSON1 availability, worker status, DB size, free disk.

## 8. Error handling

- API errors use the envelope in 06 (`{"error": {"code", "message", "details"}}`).
- Each failure class has a stable code (e.g., `UNSUPPORTED_FORMAT`, `ARCHIVE_LIMIT_EXCEEDED`, `RULE_COMPILE_ERROR`, `JOB_CANCELLED`).
- A failing rule never fails a detection run; it is recorded with `compile_error` or `rule_runs.status='error'`.

## 9. Versioning and reproducibility

Each detection run stores: tool version, rule-set hash (SHA-256 over sorted rule file hashes of enabled rules), ATT&CK version, profile, timestamp (`detection_runs` table). Reports embed these.
