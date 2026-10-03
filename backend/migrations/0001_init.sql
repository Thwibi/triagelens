-- TriageLens initial schema (spec 02 section 4), plus the audit-log
-- immutability triggers and audit_tombstones table required by spec 10
-- section 2. Applied by app.db.migrations inside a single transaction.
--
-- The migration-bookkeeping table (schema_version) is owned and created by the
-- runner itself, so it is deliberately absent here.

PRAGMA foreign_keys = ON;

CREATE TABLE settings (key TEXT PRIMARY KEY, value_json TEXT NOT NULL);

CREATE TABLE cases (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  default_timezone TEXT NOT NULL DEFAULT 'UTC',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE sources (
  id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  filename TEXT NOT NULL,                 -- original name, display only
  parent_source_id TEXT REFERENCES sources(id) ON DELETE CASCADE,  -- archive parent
  stored_path TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  sha256 TEXT NOT NULL,
  log_type TEXT,
  detect_confidence REAL,
  timezone TEXT,
  assumed_year INTEGER,
  status TEXT NOT NULL CHECK (status IN
    ('queued','needs_input','parsing','detecting','done','failed','cancelled')),
  event_count INTEGER NOT NULL DEFAULT 0,
  error_count INTEGER NOT NULL DEFAULT 0,
  first_event_ms INTEGER,
  last_event_ms INTEGER,
  error_detail TEXT,
  ingested_at TEXT NOT NULL
);
CREATE INDEX idx_sources_case ON sources(case_id);

CREATE TABLE parse_errors (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source_id TEXT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  record_ref TEXT NOT NULL,
  reason TEXT NOT NULL,
  raw_excerpt TEXT
);

CREATE TABLE source_inventory (
  source_id TEXT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  log_type TEXT NOT NULL,
  channel TEXT NOT NULL DEFAULT '',
  app_name TEXT NOT NULL DEFAULT '',
  ls_category TEXT NOT NULL DEFAULT '',
  event_count INTEGER NOT NULL,
  PRIMARY KEY (source_id, log_type, channel, app_name, ls_category)
);

CREATE TABLE events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id TEXT NOT NULL,
  source_id TEXT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  record_ref TEXT NOT NULL,
  ts_ms INTEGER,
  ts_iso TEXT,
  log_type TEXT NOT NULL,
  ls_category TEXT,
  host TEXT, channel TEXT, provider TEXT, app_name TEXT,
  event_id INTEGER, level TEXT, event_action TEXT, event_outcome TEXT,
  user_name TEXT, target_user_name TEXT, domain TEXT,
  src_ip TEXT, src_port INTEGER, dst_ip TEXT, dst_port INTEGER, protocol TEXT,
  process_pid INTEGER, process_path TEXT, process_cmdline TEXT,
  parent_process_path TEXT, parent_process_cmdline TEXT,
  file_path TEXT, registry_key TEXT, registry_value TEXT,
  url TEXT, url_path TEXT, url_query TEXT,
  http_method TEXT, http_status INTEGER, user_agent TEXT, bytes_out INTEGER,
  message TEXT,
  fields_json TEXT NOT NULL DEFAULT '{}',
  raw TEXT NOT NULL
);
CREATE INDEX idx_ev_case_ts   ON events(case_id, ts_ms);
CREATE INDEX idx_ev_source    ON events(source_id);
CREATE INDEX idx_ev_host      ON events(case_id, host);
CREATE INDEX idx_ev_eid       ON events(case_id, channel, event_id);
CREATE INDEX idx_ev_cat       ON events(case_id, ls_category);
CREATE INDEX idx_ev_app       ON events(case_id, app_name);
CREATE INDEX idx_ev_srcip     ON events(case_id, src_ip);
CREATE INDEX idx_ev_dstip     ON events(case_id, dst_ip);
CREATE INDEX idx_ev_user      ON events(case_id, user_name);

CREATE VIRTUAL TABLE events_fts USING fts5(
  message, process_cmdline, parent_process_cmdline, url, user_agent, file_path, raw,
  content='events', content_rowid='id',
  tokenize='unicode61 remove_diacritics 2'
);
-- FTS rows are inserted explicitly with the event batch (same transaction).
-- On source deletion run: INSERT INTO events_fts(events_fts, rowid, ...) VALUES('delete', ...) per row,
-- or 'rebuild' when more than 100k rows are removed.

CREATE TABLE rules (
  id TEXT PRIMARY KEY,                     -- Sigma id (UUID) or generated for rules lacking one
  title TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('sigma','builtin','custom')),
  rule_type TEXT NOT NULL CHECK (rule_type IN ('detection','correlation')),
  level TEXT NOT NULL,
  status TEXT,
  enabled INTEGER NOT NULL DEFAULT 1,
  yaml TEXT NOT NULL,
  tags_json TEXT NOT NULL DEFAULT '[]',
  logsource_json TEXT NOT NULL DEFAULT '{}',
  file_path TEXT,
  sha256 TEXT NOT NULL,
  compile_error TEXT,                      -- null when healthy
  unroutable INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL
);

CREATE TABLE detection_runs (
  id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  profile TEXT NOT NULL,
  tool_version TEXT NOT NULL,
  ruleset_hash TEXT NOT NULL,
  attack_version TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  status TEXT NOT NULL CHECK (status IN ('running','done','failed','cancelled'))
);

CREATE TABLE rule_runs (
  run_id TEXT NOT NULL REFERENCES detection_runs(id) ON DELETE CASCADE,
  rule_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('ok','skipped_no_data','timeout','error')),
  match_count INTEGER NOT NULL DEFAULT 0,
  duration_ms INTEGER NOT NULL DEFAULT 0,
  error TEXT,
  PRIMARY KEY (run_id, rule_id)
);

CREATE TABLE alerts (
  id TEXT PRIMARY KEY,                     -- sha256(case|rule|group_key|window_start)[:16]
  case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  run_id TEXT NOT NULL REFERENCES detection_runs(id) ON DELETE CASCADE,
  rule_id TEXT NOT NULL,
  rule_title TEXT NOT NULL,
  rule_kind TEXT NOT NULL,
  rule_type TEXT NOT NULL,
  level TEXT NOT NULL,
  score INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'new'
    CHECK (status IN ('new','triaged','true_positive','false_positive','benign')),
  analyst_notes TEXT,
  tactics_json TEXT NOT NULL DEFAULT '[]',     -- [{"shortname","name"}]
  techniques_json TEXT NOT NULL DEFAULT '[]',  -- [{"id","name","tactics":[...]}]
  groups_software_json TEXT NOT NULL DEFAULT '[]',
  host TEXT, user_name TEXT,
  group_key TEXT NOT NULL,
  first_seen_ms INTEGER, last_seen_ms INTEGER,
  match_count INTEGER NOT NULL,
  false_positives_json TEXT NOT NULL DEFAULT '[]',
  references_json TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL
);
CREATE INDEX idx_alerts_case ON alerts(case_id, score DESC);

CREATE TABLE alert_events (
  alert_id TEXT NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
  event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
  PRIMARY KEY (alert_id, event_id)
);

CREATE TABLE iocs (
  id TEXT PRIMARY KEY,                     -- sha256(case|type|value_norm)[:16]
  case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  type TEXT NOT NULL CHECK (type IN
    ('ipv4','ipv6','domain','url','email','md5','sha1','sha256',
     'filename','filepath','registry','cve','user_agent','command')),
  value TEXT NOT NULL,                     -- as first seen (refanged form)
  value_norm TEXT NOT NULL,                -- lowercased/canonical
  first_seen_ms INTEGER, last_seen_ms INTEGER,
  occurrences INTEGER NOT NULL DEFAULT 0,
  confidence INTEGER NOT NULL,
  is_private INTEGER NOT NULL DEFAULT 0,
  is_allowlisted INTEGER NOT NULL DEFAULT 0,
  analyst_state TEXT NOT NULL DEFAULT 'none'
    CHECK (analyst_state IN ('none','malicious','suspicious','benign')),
  tags_json TEXT NOT NULL DEFAULT '[]',
  UNIQUE (case_id, type, value_norm)
);

CREATE TABLE ioc_occurrences (
  ioc_id TEXT NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
  event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
  field TEXT NOT NULL,                     -- column or fields_json key where found
  role TEXT NOT NULL,                      -- source|destination|process|url_request|dns_query|image_hash|mentioned
  decoded_from TEXT,                       -- e.g. 'powershell_enc', 'base64', 'url'
  PRIMARY KEY (ioc_id, event_id, field)
);

CREATE TABLE ioc_alerts (
  ioc_id TEXT NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
  alert_id TEXT NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
  PRIMARY KEY (ioc_id, alert_id)
);

CREATE TABLE allowlist (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scope TEXT NOT NULL CHECK (scope IN ('global','case')),
  case_id TEXT REFERENCES cases(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('domain','domain_suffix','ip','cidr','hash','regex')),
  value TEXT NOT NULL,
  note TEXT
);

CREATE TABLE mitre_tactics (
  shortname TEXT PRIMARY KEY, attack_id TEXT NOT NULL, name TEXT NOT NULL, order_idx INTEGER NOT NULL
);

CREATE TABLE mitre_techniques (
  attack_id TEXT PRIMARY KEY,              -- T1059 or T1059.001
  stix_id TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  is_subtechnique INTEGER NOT NULL,
  parent_id TEXT,
  tactics_json TEXT NOT NULL,              -- ["execution", ...]
  platforms_json TEXT NOT NULL DEFAULT '[]',
  url TEXT,
  deprecated INTEGER NOT NULL DEFAULT 0,
  revoked INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE mitre_groups_software (
  attack_id TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK (kind IN ('group','software')),
  name TEXT NOT NULL, url TEXT
);

CREATE TABLE mitre_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);  -- attack_version, loaded_at, sha256

CREATE TABLE jobs (
  id TEXT PRIMARY KEY,
  case_id TEXT REFERENCES cases(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('ingest','detect','report','rules_import')),
  source_id TEXT,
  status TEXT NOT NULL CHECK (status IN
    ('queued','running','needs_input','done','failed','cancelled')),
  stage TEXT, progress REAL NOT NULL DEFAULT 0,
  message TEXT, error TEXT,
  created_at TEXT NOT NULL, started_at TEXT, finished_at TEXT
);

CREATE TABLE reports (
  id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  format TEXT NOT NULL CHECK (format IN ('html','pdf','md','json')),
  options_json TEXT NOT NULL,
  path TEXT NOT NULL, sha256 TEXT NOT NULL, created_at TEXT NOT NULL
);

CREATE TABLE audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  case_id TEXT,
  action TEXT NOT NULL,        -- case_created, source_ingested, detection_run, alert_status, ioc_state, report_created, rules_imported, settings_changed, source_deleted
  detail_json TEXT NOT NULL,
  prev_hash TEXT NOT NULL,     -- hash of previous row ('0'*64 for first)
  hash TEXT NOT NULL           -- sha256(prev_hash || ts || action || detail_json)
);

-- Audit log immutability (spec 10 section 2): the table is append-only at the
-- storage layer as well as at the application layer. Case deletion is the only
-- permitted removal and it records a final row in audit_tombstones instead.
CREATE TRIGGER audit_log_block_update BEFORE UPDATE ON audit_log
BEGIN
  SELECT RAISE(ABORT, 'audit_log is append-only: UPDATE is not permitted');
END;

CREATE TRIGGER audit_log_block_delete BEFORE DELETE ON audit_log
BEGIN
  SELECT RAISE(ABORT, 'audit_log is append-only: DELETE is not permitted');
END;

-- Case deletion records the final chain head here so the append-only audit log
-- can keep referring to it after the case rows are gone (spec 10 section 2).
CREATE TABLE audit_tombstones (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id TEXT NOT NULL,
  deleted_at TEXT NOT NULL,
  last_hash TEXT NOT NULL,
  row_count INTEGER NOT NULL
);
CREATE INDEX idx_audit_tombstones_case ON audit_tombstones(case_id);
CREATE INDEX idx_audit_log_case ON audit_log(case_id, id);
CREATE INDEX idx_audit_log_action ON audit_log(action);
CREATE INDEX idx_parse_errors_source ON parse_errors(source_id, id);
CREATE INDEX idx_events_record_ref ON events(source_id, record_ref);