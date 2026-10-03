# 10 — Security, Forensic Integrity, and Operations

## 1. Threat model

Logs are **hostile input**: attackers control log content (user agents, usernames, URLs, command lines, hostnames). Uploaded files and archives may be malicious. The tool runs on an analyst workstation that may hold sensitive evidence.

| Threat | Mitigation (all MUST) |
|---|---|
| XSS via log content in the UI/report | React text rendering only; ESLint `react/no-danger` as error; Jinja2 autoescape; CSP (below); reports have no JS; preview iframe sandboxed |
| CSV/formula injection in exports | Prefix `'` for cells starting with `= + - @ \t \r` |
| Path traversal / zip-slip | Never use the client filename on disk (files stored as `<source_id>`); archive members extracted via a safe extractor that resolves and verifies the final path is inside the target; reject absolute paths, `..`, symlinks, hardlinks, device files |
| Zip/decompression bombs | Limits: total expanded size (`max_archive_total_gb`), per-member ratio (`max_archive_expansion_ratio`), nesting depth ≤ 3, member count ≤ 10,000; enforce while streaming, not after |
| Malformed binary input (EVTX) crashing the server | Parsing in worker processes with a watchdog (per-source timeout, memory cap via `resource.setrlimit` on POSIX); crash → source `failed`, server unaffected |
| ReDoS | Built-in regexes reviewed and tested against adversarial inputs; user rule `re` uses the `regex` module with a per-call timeout; `max_line_bytes` caps input; per-record parsing time guard |
| SQL injection | Parameterized queries everywhere; dynamic identifiers (columns, JSON keys) only from allowlists or quoted via a validated JSON-path builder; FTS `MATCH` strings passed as parameters |
| XML attacks (XXE, entity expansion) | `lxml` parser with `resolve_entities=False`, `no_network=True`, `load_dtd=False`, `huge_tree=False` |
| YAML attacks | `yaml.safe_load` only; limits on document size (1 MB), alias count; reject custom tags |
| Unintended network exposure | Default bind `127.0.0.1`; refuse to start on non-loopback without `auth_token`; CORS same-origin only; no wildcard CORS; Host header validation (allow `localhost`, `127.0.0.1`, configured names) to prevent DNS rebinding |
| Data exfiltration / telemetry | No analytics, no update checks, no remote fonts/scripts; outbound sockets disabled unless `allow_enrichment=true`; enrichment logs every request in the audit log |
| Secrets leakage | API keys only via OS keyring or env var; never stored in DB, logs, reports; redacted in debug output |
| Local privilege/abuse via `from-path` import | Only paths under `allowed_import_roots`; resolve symlinks before checking; refuse special files |
| Disk exhaustion | Check free disk before ingest (need ≥ 3× file size); stop with a clear error when < 5% free |

### Required HTTP headers (all responses)

```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self' ws://127.0.0.1:* ws://localhost:*; frame-ancestors 'none'; base-uri 'none'; form-action 'self'
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Cross-Origin-Opener-Policy: same-origin
Cache-Control: no-store   (API responses)
```
(`connect-src` extended with the configured host:port for non-loopback deployments. The report preview iframe is served with `Content-Security-Policy: sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:`.)

## 2. Forensic integrity

1. **Hash on intake**: SHA-256 computed while streaming the upload; stored in `sources.sha256`; originals stored read-only (`0444`) under `data/cases/<case>/sources/<id>/original`. `GET /sources/{id}/download` returns the file and `X-SHA256`; the UI has a "Verify integrity" action recomputing the hash and comparing.
2. **Immutability of evidence**: the original file is never opened for write; parsing reads it directly.
3. **Reproducibility**: each detection run records tool version, ruleset hash, ATT&CK version, profile; reports embed these.
4. **Audit log with hash chain**: every state-changing action appends a row where `hash = sha256(prev_hash || ts || action || detail_json)`. `GET /cases/{id}/audit-log` verifies the chain and reports the first broken row. The audit table is append-only at the application level (no UPDATE/DELETE statements exist for it; test asserts this by grepping the code and by a DB trigger `BEFORE UPDATE/DELETE ... RAISE(ABORT)`; case deletion is the only deleter and writes a final tombstone entry in a separate `audit_tombstones` table with the last hash).
5. **Time**: all timestamps UTC; original raw text preserved so analysts can verify any normalization.

## 3. Privacy

- Data never leaves the machine by default. Report files may contain sensitive data; the UI warns on export and the report cover states "Contains evidence-derived data".
- "Secure delete" (optional): case deletion overwrites original files once before unlinking when `storage.secure_delete=true` (best effort; documented as not guaranteed on SSD/CoW file systems).

## 4. Packaging and deployment

### 4.1 Docker

`docker/Dockerfile` multi-stage: (1) `node:lts` builds the frontend; (2) `python:3.12-slim` installs wheels from a lockfile (`pip install --require-hashes`), copies built frontend into `app/static`, creates a non-root user, `EXPOSE 8787`, `HEALTHCHECK` on `/api/health`. WeasyPrint system libs installed in an optional build arg `WITH_PDF=1`.

`docker-compose.yml`:
```yaml
services:
  triagelens:
    build: { context: .., dockerfile: docker/Dockerfile }
    ports: ["127.0.0.1:8787:8787"]
    volumes: ["./data:/app/data"]
    environment:
      TRIAGELENS_SERVER__HOST: "0.0.0.0"          # inside the container only
      TRIAGELENS_SERVER__AUTH_TOKEN: "${TRIAGELENS_TOKEN:?set a token}"
    read_only: true
    tmpfs: ["/tmp"]
    cap_drop: ["ALL"]
    security_opt: ["no-new-privileges:true"]
```
The published port is bound to loopback on the host.

### 4.2 Bare metal

`scripts/run.sh` / `scripts/run.ps1`: create venv, `pip install` from the wheelhouse or lockfile, verify SQLite FTS5/JSON1, run migrations, start Uvicorn with the built frontend, open the browser. An offline install bundle (`make package`) contains the wheelhouse, built frontend, ATT&CK data and rules so the tool installs with no internet.

### 4.3 Updates

Rules and ATT&CK data are updated **manually** (import from file); the app never checks for updates. `scripts/update_rules.py` and `scripts/update_attack.py` document the upstream locations and validate/convert before import.

## 5. Operations

- **Backups**: `scripts/backup.py <case_id|all> <dest>` produces a zip (DB export via `VACUUM INTO`, originals, reports, manifest with hashes).
- **Maintenance**: Settings → Data has Vacuum, Rebuild FTS, Verify all hashes, Verify audit chain.
- **Disk layout**: `data/triagelens.db` (+ WAL), `data/cases/`, `data/reports/`, `data/rules/custom/`, `data/logs/`.
- **Resource limits**: configurable worker count; ingest queue length limit (default 20 pending files); UI shows queue position.
- **Diagnostics bundle**: `scripts/diag.py` collects versions, config (secrets redacted), recent logs (no event content), `/health` output.

## 6. Dependency and supply-chain hygiene

- Lockfiles with hashes (`uv.lock`/`requirements.txt --hash`, `package-lock.json`).
- `pip-audit` and `npm audit` in CI; fail on high/critical.
- Vendored rule sets and ATT&CK data record source URL, commit/version, and SHA-256 in `SOURCES.md`; licenses (SigmaHQ DRL 1.1, MITRE ATT&CK terms of use) reproduced in `THIRD_PARTY_NOTICES.md` and shown in the UI About dialog.
