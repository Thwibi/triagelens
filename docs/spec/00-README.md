# TriageLens — Specification Bundle (working name)

A **standalone, fully local** log triage tool. It ingests raw logs (Windows EVTX, Linux, web, firewall, generic JSON/CSV), normalizes them, runs detections (Sigma + built-in rules), maps every alert to **MITRE ATT&CK**, extracts **IOCs**, and presents everything in a web UI with exportable reports.

This bundle is written to be handed to an AI coding agent. Every file is normative: where it says "MUST", the implementation must do it. Nothing here is optional unless marked **(optional)**.

---

## 1. Goals

1. Drop in one or many log files → within minutes get: alerts (rule that fired), ATT&CK tactic/technique, affected host/user, timeline, IOCs, evidence events.
2. Work **offline**. No telemetry, no cloud calls. Enrichment (VirusTotal, AbuseIPDB) is opt-in, off by default, clearly labelled.
3. Support all of: Windows EVTX (+ exported Event XML), Linux syslog/auth.log/journald/auditd, Apache/Nginx/IIS web logs, firewall logs (iptables/UFW, pfSense, Fortinet, Palo Alto, Cisco ASA), generic JSON/CSV with mapping profiles.
4. Use **Sigma** as the detection language so the community rule corpus works and each rule carries its own ATT&CK tags.
5. Be forensically sound: originals are hashed (SHA-256) and never modified; every result is reproducible from (source hashes + rule-set hash + ATT&CK version + tool version).
6. Handle at least several million events on a laptop with a responsive UI.

## 2. Non-goals

- Not a SIEM (no agents, no live collection, no multi-user RBAC, no clustering).
- Not an EDR / malware sandbox. IOC extraction is static (no detonation).
- No automatic remediation or blocking.

## 3. Users

SOC L1/L2 analysts, DFIR responders, and students who need a fast local answer to "what happened in these logs and what should I look at first?"

## 4. Capability summary

| Capability | Where specified |
|---|---|
| Architecture, process model, config | 01-ARCHITECTURE.md |
| Normalized schema, SQLite DDL | 02-DATA-MODEL.md |
| Format detection and every parser | 03-PARSERS.md |
| Sigma engine, field maps, correlation, built-in rules, MITRE mapping, scoring | 04-DETECTION-ENGINE.md |
| IOC extraction, refanging, decoding, scoring, export | 05-IOC-EXTRACTION.md |
| REST + WebSocket API | 06-API.md |
| Screens, components, design tokens | 07-UI-SPEC.md |
| Reports, ATT&CK Navigator layer, STIX | 08-REPORTING-EXPORT.md |
| Tests, fixtures, acceptance criteria | 09-TEST-PLAN.md |
| Threat model, hardening, chain of custody, packaging | 10-SECURITY-AND-OPERATIONS.md |
| Phased prompts for the coding agent | 11-AGENT-BUILD-PROMPTS.md |

## 5. Tech stack

| Layer | Choice |
|---|---|
| Language | Python 3.11+ (3.12 fine) |
| API | FastAPI + Uvicorn, Pydantic v2 |
| Storage | SQLite (WAL) with FTS5 and JSON1. MUST verify both at startup and fail with a clear message if missing |
| Detection | pySigma (rule parsing, pipelines, correlation rules) + custom SQLite evaluation (see 04) |
| EVTX | `evtx` (pyevtx-rs) for speed; `python-evtx` as fallback |
| Regex for user rules | `regex` module (supports timeouts, ReDoS protection) |
| Templates | Jinja2 (autoescape ON) |
| PDF | WeasyPrint **(optional)**; HTML and Markdown reports always available |
| Frontend | React 18, TypeScript 5, Vite, TanStack Table v8, TanStack Query v5, Recharts, CodeMirror 6 (YAML editor), Tailwind CSS |
| Packaging | Docker Compose + bare-metal scripts (`run.sh`, `run.ps1`) |

Use current stable versions of everything; pin exact versions in lockfiles.

## 6. Build order

1. Scaffold, DB, config, migrations (P0)
2. Core pipeline, format detection, job system (P1)
3. Windows parsers (P2) → Linux parsers (P3) → web/firewall/generic parsers (P4)
4. IOC engine (P5)
5. Detection engine + rules pack (P6)
6. MITRE, alerts, scoring, full API (P7)
7. Frontend (P8)
8. Reporting, packaging, hardening, E2E (P9)

Details and acceptance gates per phase are in 11-AGENT-BUILD-PROMPTS.md.

## 7. Definition of done

- Every MUST in this bundle is implemented and covered by a test.
- `make test` passes (unit + integration + E2E); coverage ≥ 85% on backend packages `parsers`, `detect`, `ioc`, `mitre`.
- The three E2E scenarios in 09-TEST-PLAN.md pass byte-for-byte on expected alert/IOC/MITRE output.
- App runs with the network disabled and makes zero outbound connections (verified by test).
- No `TODO`, `FIXME`, `pass`-only functions, mock data, or placeholder UI in shipped code.

## 8. Global rules for the implementing agent

1. No stubs, no placeholders, no weakened requirements. If something cannot be done as written, record it in `DECISIONS.md` with the reason and the closest compliant alternative, and flag it; never silently simplify.
2. Treat all log content as hostile input (see 10).
3. Every module ships with tests in the same change.
4. Keep parsers, detection, and IOC code free of web-framework imports so they are reusable as a library and testable in isolation.
5. Deterministic output: same inputs → same alerts, same IDs where possible (use content-derived IDs for alerts and IOCs).
6. All timestamps stored as UTC epoch milliseconds plus ISO-8601 string.

## 9. Glossary

- **Source**: one ingested file (or one file extracted from an archive).
- **Case**: a container of sources, events, alerts, IOCs. One investigation.
- **Normalized event**: the common-schema row all parsers emit.
- **Logsource**: Sigma's (product, service, category) triple; routed to event predicates (04).
- **Base rule / correlation rule**: a Sigma detection rule / a Sigma correlation rule built on base rules.
