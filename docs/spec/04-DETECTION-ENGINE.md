# 04 — Detection Engine, MITRE Mapping, Scoring

## 1. Rule sources

| Kind | Location | Notes |
|---|---|---|
| `sigma` | `backend/rules/sigma/**` | Vendored SigmaHQ rules (windows, linux, web, network/firewall, cloud optional). Keep upstream LICENSE (DRL 1.1) and a `SOURCE.txt` with commit hash. Updated offline via `scripts/update_rules.py <zip-or-dir>` or UI import |
| `builtin` | `backend/rules/builtin/*.yml` | Shipped by TriageLens (§7). Same YAML format |
| `custom` | `data/rules/custom/*.yml` | User-authored in the UI editor; stored as files + `rules` rows |

All rules are standard Sigma YAML (detection rules and Sigma correlation rules). Loaded with `yaml.safe_load` only. On load each rule is parsed by pySigma, hashed (SHA-256 of file bytes), compiled, and stored in `rules` with `compile_error` set on failure (a failing rule is listed under Rules → Health and never blocks the others).

## 2. Evaluation strategy (SQL-compiled Sigma)

For each enabled rule, in order of: correlation base rules first, then the rest:

1. **Route** the rule's `logsource` to an SQL predicate on `events` (§3).
2. **Prune**: skip the rule (`rule_runs.status='skipped_no_data'`) if no source in the case has an inventory row matching the routing predicate.
3. **Compile** the Sigma `detection` to an SQL `WHERE` fragment with a TriageLens pySigma backend (`SQLiteBackend` subclass of `TextQueryBackend`). Start from `pysigma-backend-sqlite` if it satisfies the requirements below; otherwise implement the backend directly. Requirements:
   - Field resolution through the pipeline in §4.
   - Value matching case-insensitive by default; `contains/startswith/endswith` → `LIKE ? ESCAPE '\'` with `%`/`_`/`\` escaped; `cased` → `instr()`/`GLOB`-based case-sensitive check.
   - Supported modifiers (all MUST work): `contains, startswith, endswith, all, re (with i m s flags), cidr, base64, base64offset, utf16le, utf16be, wide, windash, exists, cased, neq, lt, lte, gt, gte, fieldref, expand`. Unsupported modifiers → rule gets `compile_error="unsupported modifier: X"`.
   - `1 of selection*`, `all of them`, `not`, parentheses, keyword (field-less) searches (matched against `message`, `process_cmdline`, `url`, `raw` via FTS or `LIKE` on `raw`).
   - Null checks (`field: null`) → `IS NULL`.
   - Numeric fields compared numerically.
4. **Execute** on the case DB (read connection with UDFs `regexp`, `cidr_match`): `SELECT id, ts_ms, host, user_name, ... FROM events WHERE case_id=:c AND (<route>) AND (<compiled>) ORDER BY ts_ms`. Time budget `rule_timeout_seconds` via progress handler.
5. **Aggregate** matches into alerts (§6). Store up to `max_sample_events_per_alert` event IDs; `match_count` holds the real total.
6. **Correlation rules** (§5) run after their base rules.
7. Record a `rule_runs` row for every rule.

Detection profiles (settings):

| Profile | Rules executed |
|---|---|
| `fast` | `level in (high, critical)` and `status in (stable, test)` + all builtin |
| `standard` (default) | `level >= medium` + all builtin + all custom |
| `full` | everything enabled, including `experimental` and `low/informational` |

## 3. Logsource routing (`rules/logsource_map.yaml`)

The map turns a Sigma `logsource` (`product`, `service`, `category`) into predicates on `log_type`, `channel`, `app_name`, `ls_category`. A rule's predicate is the AND of the matching entries for each key present; multiple entries for the same key are OR'ed. Missing keys are unconstrained.

```yaml
product:
  windows:   "log_type IN ('windows_evtx','windows_event_xml')"
  linux:     "log_type IN ('linux_syslog','linux_auth','linux_journald','linux_auditd')"
  apache:    "log_type IN ('apache_access','apache_error')"
  nginx:     "log_type IN ('nginx_access','nginx_error')"
  iis:       "log_type = 'iis_w3c'"
service:
  # product-scoped services (key is "<product>/<service>")
  windows/security:        "channel = 'Security'"
  windows/system:          "channel = 'System'"
  windows/application:     "channel = 'Application'"
  windows/sysmon:          "channel = 'Microsoft-Windows-Sysmon/Operational'"
  windows/powershell:      "channel = 'Microsoft-Windows-PowerShell/Operational'"
  windows/powershell-classic: "channel = 'Windows PowerShell'"
  windows/taskscheduler:   "channel = 'Microsoft-Windows-TaskScheduler/Operational'"
  windows/wmi:             "channel = 'Microsoft-Windows-WMI-Activity/Operational'"
  windows/windefend:       "channel = 'Microsoft-Windows-Windows Defender/Operational'"
  windows/dns-server:      "channel = 'DNS Server'"
  windows/bits-client:     "channel = 'Microsoft-Windows-Bits-Client/Operational'"
  windows/terminalservices-localsessionmanager: "channel = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'"
  windows/firewall-as:     "channel = 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'"
  windows/ntlm:            "channel = 'Microsoft-Windows-NTLM/Operational'"
  windows/codeintegrity-operational: "channel = 'Microsoft-Windows-CodeIntegrity/Operational'"
  linux/auth:              "log_type = 'linux_auth' OR app_name IN ('sshd','sudo','su','login','useradd','usermod','userdel','groupadd','passwd')"
  linux/sshd:              "app_name = 'sshd'"
  linux/sudo:              "app_name = 'sudo'"
  linux/syslog:            "log_type IN ('linux_syslog','linux_auth')"
  linux/cron:              "app_name IN ('CRON','cron','crond')"
  linux/auditd:            "log_type = 'linux_auditd'"
  linux/journald:          "log_type = 'linux_journald'"
  linux/kernel:            "app_name = 'kernel'"
category:
  # Direct: parser assigns ls_category with the same name
  process_creation:     "ls_category = 'process_creation'"
  network_connection:   "ls_category = 'network_connection'"
  file_event:           "ls_category = 'file_event'"
  file_delete:          "ls_category = 'file_delete'"
  image_load:           "ls_category = 'image_load'"
  driver_load:          "ls_category = 'driver_load'"
  process_access:       "ls_category = 'process_access'"
  process_termination:  "ls_category = 'process_termination'"
  create_remote_thread: "ls_category = 'create_remote_thread'"
  create_stream_hash:   "ls_category = 'create_stream_hash'"
  pipe_created:         "ls_category = 'pipe_created'"
  dns_query:            "ls_category = 'dns_query'"
  wmi_event:            "ls_category = 'wmi_event'"
  registry_add:         "ls_category = 'registry_add'"
  registry_set:         "ls_category = 'registry_set'"
  registry_event:       "ls_category IN ('registry_add','registry_set','registry_rename')"
  registry_delete:      "ls_category = 'registry_delete'"
  ps_script:            "ls_category = 'ps_script'"
  ps_module:            "ls_category = 'ps_module'"
  ps_classic_start:     "ls_category = 'ps_classic_start'"
  webserver:            "ls_category = 'webserver'"
  firewall:             "ls_category = 'firewall'"
  proxy:                "ls_category = 'webserver'"   # best-effort for proxy-style Sigma web rules
```

Rules whose logsource cannot be routed (unknown product/service/category) get `unroutable=1`, are skipped, and appear in Rules → Health with the reason. Never silently match against all events.

## 4. Field resolution pipeline

Order (first hit wins) for a field name `F` in a rule:

1. Logsource-specific maps (case-insensitive on `F`):
   - **Windows / Sysmon / Security** (Sigma original names): `Image→process_path`, `CommandLine→process_cmdline`, `ParentImage→parent_process_path`, `ParentCommandLine→parent_process_cmdline`, `ProcessId→process_pid`, `User→user_name`, `EventID→event_id`, `Computer→host`, `Channel→channel`, `Provider_Name→provider`, `TargetFilename→file_path`, `TargetObject→registry_key`, `Details→registry_value`, `DestinationIp→dst_ip`, `DestinationPort→dst_port`, `SourceIp→src_ip`, `SourcePort→src_port`, `NewProcessName→process_path` (only for Security 4688 rows), `ImageLoaded→file_path` (category `image_load`/`driver_load`), `ScriptBlockText→message` (category `ps_script`).
   - **Web (Sigma `webserver`)**: `c-ip→src_ip`, `cs-method→http_method`, `cs-uri-stem→url_path`, `cs-uri-query→url_query`, `cs-uri→url`, `cs-user-agent→user_agent`, `sc-status→http_status`, `cs-username→user_name`, `cs-host`→`fields_json.host_header`.
   - **Firewall (generic Sigma network)**: `src_ip, dst_ip, src_port, dst_port, action` (`action` → `event_action`-derived: `firewall_deny→'denied'`, `firewall_allow→'allowed'` handled through a computed expression), `username→user_name`.
2. Exact normalized column name (this is what TriageLens built-in and custom rules use, e.g. `src_ip`, `event_action`).
3. Fallback: `json_extract(fields_json, '$."<F>"')`. This is what makes original Windows EventData names (`IpAddress`, `TargetUserName`, `LogonType`, `Hashes`, `GrantedAccess`, `CallTrace`, ...) work without per-field mapping.
4. If `F` is absent from every event of the routed set during pruning (checked via `json_each`/inventory sampling), the rule still runs (field simply never matches) but records a warning in `rule_runs.error` of the form `field_never_present: <F>`.

`contains/startswith/endswith` on numeric columns cast to text.

## 5. Correlation rules

Support Sigma correlation rules (`correlation:` blocks) of types `event_count`, `value_count`, `temporal`, `temporal_ordered`. Implemented in Python after base rules, using base-rule matches (kept in a temp table `tmp_matches(rule_id, event_id, ts_ms, g0..g3, vfield)` populated with the group-by values and the `condition.field` value for value_count).

Algorithm per correlation rule:

1. Resolve `rules:` references by id or name (recursively for nested correlations, max depth 3).
2. Group matches by `group-by` field tuple (with `aliases` honored when base rules name the field differently).
3. Sliding window of `timespan` over time-sorted matches:
   - `event_count`: count within window; fire when the condition (`gte/gt/lte/lt/eq`) holds. Coalesce overlapping firings per group into one alert (`first_seen` = start of first window, `last_seen` = end of last).
   - `value_count`: number of distinct values of `condition.field` in the window.
   - `temporal`: all referenced rules occur in the window for the same group.
   - `temporal_ordered`: same, in the listed order.
4. Base rules referenced with `generate: false` (default for correlation-referenced rules) produce **no** alerts of their own; if `generate: true` they also alert.
5. Alert evidence = the contributing events (capped by `max_sample_events_per_alert`).

## 6. Alert construction

For each (non-correlation) rule with matches:

- **group_key** = `host|user_name` of the match; one alert per `(rule_id, group_key)` per time cluster: matches separated by more than `alert_group_window_minutes` start a new alert.
- `alert.id = sha256(case_id|rule_id|group_key|cluster_start_ms)[:16]` → deterministic across re-runs.
- `first_seen_ms`, `last_seen_ms`, `match_count`, sample event ids, `false_positives_json` (from rule `falsepositives`), `references_json` (from rule `references`).
- `status` carry-over: on re-run, if an alert with the same id exists, keep `status` and `analyst_notes`.

Re-running detection replaces alerts from the previous run except those whose status is not `new` (analyst-touched alerts are kept and re-linked to the new run when the same id re-appears; otherwise marked stale with `analyst_notes` preserved and an `alerts.status` unchanged).

## 7. MITRE ATT&CK mapping

### 7.1 Data

- `data/attack/enterprise-attack.json` is the STIX 2.1 bundle from `mitre-attack/attack-stix-data`. `scripts/update_attack.py <file>` validates and loads it; the app also offers "Import ATT&CK bundle" (file) in Settings. No network at runtime.
- Load into `mitre_tactics`, `mitre_techniques`, `mitre_groups_software`, `mitre_meta(attack_version, loaded_at, sha256)`.
- Techniques: STIX `attack-pattern` objects; `attack_id` from `external_references[source_name=="mitre-attack"].external_id`; tactics from `kill_chain_phases` (`kill_chain_name=="mitre-attack"`); sub-technique parent from `x_mitre_is_subtechnique` + `subtechnique-of` relationships. Skip `revoked` and `x_mitre_deprecated` (kept in table flagged, hidden in UI).
- Tactic order: reconnaissance, resource-development, initial-access, execution, persistence, privilege-escalation, defense-evasion, credential-access, discovery, lateral-movement, collection, command-and-control, exfiltration, impact.

### 7.2 Tag parsing (Sigma tags → ATT&CK)

| Tag form | Meaning |
|---|---|
| `attack.t1059`, `attack.t1059.001` | technique / sub-technique (uppercase to `T1059.001`) |
| `attack.execution`, `attack.defense-evasion` (underscores normalized to hyphens) | tactic |
| `attack.g0032` / `attack.s0002` | group / software (shown as context chips) |

Resolution:
1. Tags that reference an unknown ID → keep the raw tag under `unresolved_tags` in the alert detail; never invent a name.
2. Tactics shown for an alert = explicit tactic tags; if none, the union of tactics from the resolved techniques.
3. In the matrix a technique appears under the tactic(s) the rule declared; if the rule declared none, under all tactics of the technique.
4. Sub-technique present → also credit the parent technique in rollups (marked "via sub-technique").

### 7.3 Fallbacks (`data/mitre_fallbacks.yaml`)

For detections without ATT&CK tags (builtin/custom rules lacking them), a fallback map by `event_action`/`event_id` is consulted so the alert is never blank when a sensible mapping exists. Entries ship for at least:

```yaml
- when: { channel: Security, event_id: 1102 }        # audit log cleared
  techniques: [T1070.001]
- when: { channel: System,   event_id: 104 }
  techniques: [T1070.001]
- when: { channel: Security, event_id: 4720 }        # account created
  techniques: [T1136.001]
- when: { channel: Security, event_id: 4698 }        # scheduled task created
  techniques: [T1053.005]
- when: { channel: System,   event_id: 7045 }        # service installed
  techniques: [T1543.003]
- when: { event_action: ssh_failed_password }
  techniques: [T1110.001]
- when: { event_action: user_added }
  techniques: [T1136.001]
- when: { event_action: crontab_modified }
  techniques: [T1053.003]
```
Fallback-derived mappings are labelled `source: fallback` in the alert (UI shows "inferred"). Alerts with no mapping show "Unmapped" and are listed in a dedicated filter.

## 8. Severity and scoring

`score = base(level) + modifiers`, clamped to 0–100:

| level | base |
|---|---|
| critical | 90 |
| high | 70 |
| medium | 50 |
| low | 30 |
| informational | 10 |

Modifiers (deterministic):
- +10 if another alert (any rule) on the same `host` overlaps within ±15 minutes (cluster).
- +5 if the alert's evidence contains a non-private, non-allowlisted IP/domain IOC with confidence ≥ 70.
- +5 if `match_count ≥ 10`, +5 more if `≥ 100`.
- −10 if the rule `status` is `experimental` or `unsupported`.
- −10 when the analyst marks a *sibling* alert (same rule + host) `false_positive` (applied at re-run).

Score and each modifier are stored (`alerts.score`; breakdown in `detail` endpoint) so the UI can show "why this score".

## 9. Rule management (UI/API behaviors)

- Enable/disable per rule, per rule-set, or per tag; stored in `rules.enabled`.
- Custom rule editor validates by running pySigma parse + backend compile (`POST /api/rules/validate`) and a **dry-run** against a chosen case (`POST /api/rules/test`) returning match count, up to 20 sample events, and execution time.
- Import (folder/zip/file) is offline, validates every rule, shows a per-rule result table, and writes an audit entry.
- Rule health view: compile errors, unroutable rules, rules with `field_never_present`, rules that timed out.

## 10. Built-in rules (ship exactly these; IDs are fixed)

All use normalized field names. `generate: false` on bases that only feed correlations.

```yaml
# rules/builtin/linux_ssh_bruteforce.yml
title: SSH Failed Password (base)
id: 7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e01
status: stable
description: Base rule feeding SSH brute-force correlation.
logsource: { product: linux, service: sshd }
detection:
  selection:
    event_action:
      - ssh_failed_password
      - ssh_invalid_user
  condition: selection
level: informational
tags: [attack.credential-access, attack.t1110.001]
---
title: SSH Brute Force From Single Source
id: 7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e02
status: stable
description: Ten or more failed SSH authentications from one source within five minutes.
correlation:
  type: event_count
  rules: [7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e01]
  group-by: [src_ip]
  timespan: 5m
  condition: { gte: 10 }
level: high
falsepositives: [Misconfigured automation, password-manager retries]
tags: [attack.credential-access, attack.t1110.001]
---
title: SSH Successful Login After Failures From Same Source
id: 7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e03
status: stable
description: A successful SSH login from a source that failed authentication within the previous ten minutes.
correlation:
  type: temporal_ordered
  rules:
    - 7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e01
    - 7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e04
  group-by: [src_ip]
  timespan: 10m
level: critical
tags: [attack.initial-access, attack.t1078, attack.credential-access, attack.t1110]
---
title: SSH Accepted Login (base)
id: 7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e04
status: stable
logsource: { product: linux, service: sshd }
detection:
  selection: { event_action: ssh_accepted_login }
  condition: selection
level: informational
tags: [attack.initial-access, attack.t1078]
```

```yaml
# rules/builtin/windows_logon_spray.yml
title: Windows Failed Logon (base)
id: 7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e10
status: stable
logsource: { product: windows, service: security }
detection:
  selection: { EventID: 4625 }
  condition: selection
level: informational
tags: [attack.credential-access, attack.t1110]
---
title: Password Spraying - Many Accounts From One Source
id: 7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e11
status: stable
description: Failed logons for 10 or more distinct accounts from one source address within 10 minutes.
correlation:
  type: value_count
  rules: [7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e10]
  group-by: [IpAddress]
  timespan: 10m
  condition: { gte: 10, field: TargetUserName }
level: high
falsepositives: [Shared NAT gateways, misconfigured service accounts]
tags: [attack.credential-access, attack.t1110.003]
---
title: Windows Brute Force - Many Failures Against One Account
id: 7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e12
status: stable
correlation:
  type: event_count
  rules: [7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e10]
  group-by: [TargetUserName]
  timespan: 5m
  condition: { gte: 15 }
level: medium
tags: [attack.credential-access, attack.t1110.001]
```

```yaml
# rules/builtin/web_attacks.yml
title: Web SQL Injection Patterns
id: 7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e20
status: stable
description: Common SQL injection payloads in the request target.
logsource: { category: webserver }
detection:
  selection:
    cs-uri-query|contains:
      - "' or "
      - "%27%20or%20"
      - "union select"
      - "union%20select"
      - "union+select"
      - "information_schema"
      - "sleep("
      - "benchmark("
      - "extractvalue("
      - "' --"
      - "%27--"
  condition: selection
level: high
falsepositives: [Security scanners run by the owner, search endpoints with SQL-like text]
tags: [attack.initial-access, attack.t1190]
---
title: Web Path Traversal Attempt
id: 7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e21
status: stable
logsource: { category: webserver }
detection:
  selection:
    cs-uri-stem|contains:
      - "../"
      - "..%2f"
      - "%2e%2e/"
      - "%2e%2e%2f"
      - "..\\"
      - "/etc/passwd"
      - "/windows/win.ini"
  condition: selection
level: high
tags: [attack.initial-access, attack.t1190]
---
title: Known Scanner or Attack Tool User-Agent
id: 7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e22
status: stable
logsource: { category: webserver }
detection:
  selection:
    cs-user-agent|contains:
      - sqlmap
      - nikto
      - nmap scripting engine
      - masscan
      - gobuster
      - dirbuster
      - wpscan
      - nuclei
      - acunetix
      - nessus
      - zgrab
      - feroxbuster
  condition: selection
level: medium
tags: [attack.reconnaissance, attack.t1595.002]
---
title: Web Shell-Like Request (script upload paths)
id: 7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e23
status: test
logsource: { category: webserver }
detection:
  selection:
    cs-method: POST
    cs-uri-stem|endswith: [".php", ".jsp", ".aspx", ".asp"]
    cs-uri-stem|contains: ["/uploads/", "/upload/", "/files/", "/images/", "/tmp/"]
    sc-status: [200, 201]
  condition: selection
level: medium
tags: [attack.persistence, attack.t1505.003]
```

```yaml
# rules/builtin/firewall.yml
title: Firewall Deny (base)
id: 7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e30
status: stable
logsource: { category: firewall }
detection:
  selection: { event_action: firewall_deny }
  condition: selection
level: informational
tags: [attack.discovery, attack.t1046]
---
title: Port Scan - Many Destination Ports Denied From One Source
id: 7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e31
status: stable
description: One source hit 20 or more distinct destination ports and was denied within one minute.
correlation:
  type: value_count
  rules: [7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e30]
  group-by: [src_ip]
  timespan: 1m
  condition: { gte: 20, field: dst_port }
level: medium
falsepositives: [Vulnerability scanners owned by the organization]
tags: [attack.reconnaissance, attack.t1595.001, attack.discovery, attack.t1046]
---
title: Host Sweep - One Port Denied Across Many Destinations
id: 7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e32
status: stable
correlation:
  type: value_count
  rules: [7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e30]
  group-by: [src_ip, dst_port]
  timespan: 1m
  condition: { gte: 20, field: dst_ip }
level: medium
tags: [attack.reconnaissance, attack.t1595.001]
```

```yaml
# rules/builtin/linux_persistence.yml
title: Local User Account Created (Linux)
id: 7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e40
status: stable
logsource: { product: linux, service: auth }
detection:
  selection: { event_action: user_added }
  condition: selection
level: medium
falsepositives: [Legitimate administration]
tags: [attack.persistence, attack.t1136.001]
---
title: Sudo Command Run As Root By Unexpected Shell Spawn
id: 7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e41
status: test
logsource: { product: linux, service: auth }
detection:
  selection:
    event_action: sudo_command
    target_user_name: root
    process_cmdline|contains:
      - "/bin/bash"
      - "/bin/sh"
      - "su -"
      - "chmod u+s"
      - "chmod 4755"
      - "visudo"
  condition: selection
level: medium
tags: [attack.privilege-escalation, attack.t1548.003]
```

Multi-document YAML files are split into separate rules on load (each document is one rule; the file hash is stored once and the doc index is part of the rule's `file_path#N`).

## 11. Acceptance

- All ten built-in rule groups above compile and fire on their fixture data (09 scenarios).
- A sample of ≥ 200 SigmaHQ Windows/Linux/web rules compile without error (compile failures are categorized and listed in `DECISIONS.md` with counts).
- Rule results are identical across runs (deterministic IDs and ordering).
