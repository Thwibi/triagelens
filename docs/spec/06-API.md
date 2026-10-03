# 06 — API

Base path `/api`. JSON in/out (UTF-8). All timestamps are ISO-8601 UTC strings in responses plus `*_ms` epoch fields where noted. IDs are strings.

## 1. Conventions

- **Auth**: none on `127.0.0.1`. If `server.host` is not loopback, every request MUST carry `Authorization: Bearer <server.auth_token>` (WebSocket: `?token=`). Missing/invalid → 401.
- **Errors**: HTTP status + body
  ```json
  {"error": {"code": "UNSUPPORTED_FORMAT", "message": "Could not determine log type", "details": {"candidates": [{"log_type": "linux_syslog", "score": 0.41}]}}}
  ```
  Codes: `VALIDATION_ERROR`(422) `NOT_FOUND`(404) `CONFLICT`(409) `UNSUPPORTED_FORMAT`(422) `ARCHIVE_LIMIT_EXCEEDED`(413) `UPLOAD_TOO_LARGE`(413) `RULE_COMPILE_ERROR`(422) `JOB_CANCELLED`(409) `FORBIDDEN_PATH`(403) `UNAUTHORIZED`(401) `INTERNAL`(500).
- **Pagination**: list endpoints take `limit` (default 100, max 1000) and either `cursor` (events, opaque) or `offset`. Responses: `{"items": [...], "next_cursor": "..."|null, "total": N|null}`. `total` is omitted (`null`) for events when it would require a full count; provide `GET .../events/count` for counts with the same filters.
- **Sorting**: `sort=field` or `-field`.
- **Versioning**: header `X-TriageLens-Version` on all responses.

## 2. Schemas (Pydantic models, abbreviated)

```
Case      {id, name, description, default_timezone, created_at, updated_at, counts:{sources,events,alerts,iocs}}
Source    {id, case_id, filename, parent_source_id, size_bytes, sha256, log_type, detect_confidence, timezone, assumed_year,
           status, event_count, error_count, first_event_ms, last_event_ms, error_detail, ingested_at}
Event     {id, source_id, record_ref, ts_ms, ts_iso, log_type, ls_category, host, channel, provider, app_name, event_id, level,
           event_action, event_outcome, user_name, target_user_name, domain, src_ip, src_port, dst_ip, dst_port, protocol,
           process_pid, process_path, process_cmdline, parent_process_path, parent_process_cmdline, file_path, registry_key,
           registry_value, url, url_path, url_query, http_method, http_status, user_agent, bytes_out, message,
           fields: object, raw: string}                      # `raw`/`fields` only on detail or ?include=raw
Alert     {id, case_id, rule_id, rule_title, rule_kind, rule_type, level, score, status, analyst_notes,
           tactics:[{shortname,name}], techniques:[{id,name,tactics:[...],source:"tag"|"fallback"}],
           groups_software:[{id,name,kind}], unresolved_tags:[str], host, user_name, first_seen_ms, last_seen_ms,
           match_count, false_positives:[str], references:[str]}
AlertDetail = Alert + {score_breakdown:[{label,delta}], events:[Event(no raw)], iocs:[IOC], rule:{id,title,description,yaml}}
IOC       {id, type, value, value_norm, confidence, occurrences, first_seen_ms, last_seen_ms, is_private, is_allowlisted,
           analyst_state, tags:[str], alert_ids:[str], hosts:[str], techniques:[str]}
Rule      {id, title, kind, rule_type, level, status, enabled, tags:[str], logsource:object, compile_error, unroutable,
           file_path, updated_at}
Job       {id, case_id, kind, source_id, status, stage, progress, message, error, created_at, started_at, finished_at}
```

## 3. Endpoints

### Health and settings
| Method | Path | Notes |
|---|---|---|
| GET | `/health` | `{app_version, attack_version, ruleset_hash, sqlite_version, fts5, json1, workers, db_bytes, free_disk_bytes}` |
| GET | `/settings` | all settings incl. detection profile, limits (read-only), allowlist |
| PUT | `/settings` | partial update; validates keys; audit-logged |
| GET/POST/DELETE | `/settings/allowlist[/{id}]` | global allowlist CRUD |
| POST | `/settings/attack/import` | multipart ATT&CK STIX bundle; replaces MITRE tables atomically; returns new `attack_version` |

### Cases
| Method | Path | Notes |
|---|---|---|
| POST | `/cases` | `{name, description?, default_timezone?}` |
| GET | `/cases` | list with counts |
| GET | `/cases/{id}` | |
| PATCH | `/cases/{id}` | rename, description, timezone |
| DELETE | `/cases/{id}` | cascades; audit entry; returns 204 |

### Sources and ingestion
| Method | Path | Notes |
|---|---|---|
| POST | `/cases/{id}/sources` | `multipart/form-data`: `files[]` (one or many), optional `log_type`, `timezone`, `assumed_year`. Streams to disk. Returns `{jobs:[Job], sources:[Source]}` (202) |
| POST | `/cases/{id}/sources/from-path` | `{paths:[str], recursive:bool}`; allowed only under `storage.allowed_import_roots` (default: user home + `data/imports`); else `FORBIDDEN_PATH`. Files are copied, not moved |
| GET | `/cases/{id}/sources` | |
| GET | `/sources/{id}` | includes `parse_errors_sample` (first 50) |
| GET | `/sources/{id}/parse-errors` | paginated |
| PATCH | `/sources/{id}` | `{log_type?, timezone?, assumed_year?}`; if changed → re-parse job (events replaced) |
| POST | `/sources/{id}/resolve` | for `needs_input`: `{log_type, timezone?, assumed_year?, profile_id?}` resumes ingest |
| DELETE | `/sources/{id}` | |
| GET | `/sources/{id}/download` | the original file (integrity check header `X-SHA256`) |

### Jobs
| Method | Path | Notes |
|---|---|---|
| GET | `/jobs/{id}` | |
| GET | `/cases/{id}/jobs` | |
| DELETE | `/jobs/{id}` | cancel |
| WS | `/ws/jobs/{id}` and `/ws/cases/{id}` | server-push messages (§4) |

### Events
| Method | Path | Notes |
|---|---|---|
| GET | `/cases/{id}/events` | filters: `q` (FTS5 query syntax; invalid syntax → 422 with the sqlite message simplified), `from_ms`, `to_ms`, `host`, `source_id`, `log_type`, `channel`, `event_id`, `ls_category`, `user_name`, `src_ip`, `dst_ip`, `ioc_id`, `alert_id`, `level`, `sort`, `cursor`, `limit`, `include=raw` |
| GET | `/cases/{id}/events/count` | same filters |
| GET | `/events/{id}` | full detail incl. `fields`, `raw`, `alerts:[Alert]`, `iocs:[IOC]` |
| GET | `/cases/{id}/events/facets` | top-N values (default 20) for host, log_type, channel, event_id, user_name, src_ip under the current filters |
| GET | `/cases/{id}/timeline` | `bucket=auto|1m|5m|1h|1d`, same filters → `{bucket_ms, buckets:[{t_ms, count, by_log_type:{...}, alert_count}]}` |

### Alerts
| Method | Path | Notes |
|---|---|---|
| GET | `/cases/{id}/alerts` | filters: `level`, `status`, `rule_id`, `tactic`, `technique`, `host`, `user_name`, `min_score`, `q` (rule title), `unmapped=true`, `sort` (default `-score`) |
| GET | `/alerts/{id}` | `AlertDetail` |
| PATCH | `/alerts/{id}` | `{status?, analyst_notes?}`; audit-logged |
| POST | `/alerts/bulk` | `{ids:[...], status}` |
| GET | `/alerts/{id}/events` | paginated evidence beyond the stored sample (re-queries the rule for that cluster window) |

### Detection
| Method | Path | Notes |
|---|---|---|
| POST | `/cases/{id}/detect` | `{profile?: fast|standard|full, rule_ids?: [str]}` → Job |
| GET | `/cases/{id}/detection-runs` | list with `ruleset_hash`, `attack_version`, counts |
| GET | `/detection-runs/{id}/rules` | per-rule status, match counts, durations, errors |

### MITRE
| Method | Path | Notes |
|---|---|---|
| GET | `/mitre/matrix` | static ATT&CK matrix: tactics in order, techniques with sub-techniques |
| GET | `/cases/{id}/mitre` | `{attack_version, tactics:[{shortname,name,techniques:[{id,name,alert_count,max_level,alert_ids,subtechniques:[...]}]}], unmapped_alert_count}` |
| GET | `/mitre/techniques/{attack_id}` | name, description, tactics, platforms, url |
| GET | `/cases/{id}/mitre/navigator-layer` | ATT&CK Navigator layer JSON (08) |

### IOCs
| Method | Path | Notes |
|---|---|---|
| GET | `/cases/{id}/iocs` | filters: `type`, `min_confidence`, `q`, `alert_id`, `host`, `state`, `include_private=false`, `include_allowlisted=false`, `sort` |
| GET | `/iocs/{id}` | with occurrences (paginated sub-resource `/iocs/{id}/occurrences`) |
| PATCH | `/iocs/{id}` | `{analyst_state?, tags?}`; `analyst_state=benign` also offers `allowlist=true` to add a case allowlist entry |
| POST | `/cases/{id}/iocs/export` | `{format: csv|txt|stix|json, ids?:[...], filters?:{...}, defang?:bool}` → file download |
| GET | `/cases/{id}/entities` | hosts and users with event/alert counts |

### Rules
| Method | Path | Notes |
|---|---|---|
| GET | `/rules` | filters: `kind`, `level`, `status`, `enabled`, `tag`, `technique`, `health` (`ok|compile_error|unroutable`), `q`, pagination |
| GET | `/rules/{id}` | with YAML |
| POST | `/rules` | `{yaml}` create custom rule(s) (multi-doc allowed); validates first |
| PUT | `/rules/{id}` | custom only |
| PATCH | `/rules/{id}` | `{enabled}` allowed for every kind |
| DELETE | `/rules/{id}` | custom only |
| POST | `/rules/validate` | `{yaml}` → `{valid, rules:[{id,title,type,errors:[...],warnings:[...]}]}` |
| POST | `/rules/test` | `{yaml, case_id, limit?:20}` → `{match_count, samples:[Event], duration_ms, warnings}` |
| POST | `/rules/import` | multipart zip/yml; returns Job; result lists per-rule outcome |
| GET | `/rules/export` | zip of selected/all custom rules |
| GET | `/rules/health` | counts and lists by problem class |

### Reports
| Method | Path | Notes |
|---|---|---|
| POST | `/cases/{id}/reports` | `{format: html|pdf|md|json, title?, analyst?, include:{alerts:[status...], iocs:bool, mitre:bool, timeline:bool, events_per_alert:int, entities:bool, appendix_raw:bool}}` → Job |
| GET | `/cases/{id}/reports` | |
| GET | `/reports/{id}/download` | file with `Content-Disposition`, `X-SHA256` |
| GET | `/cases/{id}/audit-log` | paginated; includes hash chain verification result `{chain_ok: bool, broken_at?: id}` |

## 4. WebSocket messages

Server → client JSON frames:

```json
{"type":"job.update","job":{...Job...}}
{"type":"job.stage","job_id":"...","stage":"parsing","progress":0.42,"events":1250000,"errors":3,"rate_eps":41200}
{"type":"source.update","source":{...Source...}}
{"type":"alerts.changed","case_id":"...","new_alerts":12}
{"type":"needs_input","job_id":"...","source_id":"...","candidates":[{"log_type":"...","score":0.52}]}
{"type":"error","code":"...","message":"..."}
```
Heartbeat `{"type":"ping"}` every 20 s; client replies `pong` or reconnects with backoff (1 s → 15 s). On reconnect the UI refetches job state via REST.

## 5. Performance requirements for the API

- `GET .../events` first page < 300 ms on a 5M-event case with indexed filters; FTS queries < 1 s typical.
- Keyset (cursor) pagination on `(ts_ms, id)`; no `OFFSET` on events.
- Large exports stream (no full in-memory build).
