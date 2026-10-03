# 03 — Format Detection and Parsers

## 1. Format detection

`ingest/detect.py`:

1. Read the first 64 KB (and the first 200 lines for text).
2. Hard signatures: EVTX magic `ElfFile\x00` → `windows_evtx` (confidence 1.0); `<Events>`/`<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">` → `windows_event_xml` (0.95).
3. Otherwise every parser's `sniff(head, filename)` returns 0.0–1.0 by matching ≥ 80% of sampled non-empty lines against its primary regex (and filename hints such as `auth.log`, `secure`, `access.log`, `filterlog`, `.evtx`).
4. Highest score wins if ≥ 0.6 and the runner-up is ≥ 0.15 lower; otherwise status `needs_input` with the ranked candidates returned to the UI.
5. A user override always wins and is recorded in `sources.log_type`.

Archives are expanded first (see 10), and detection runs on each member.

Text reading rules (all text parsers): open in binary, decode UTF-8 with `errors="replace"` (BOM stripped; UTF-16 auto-detected by BOM); split on `\n`, strip trailing `\r`; lines longer than `max_line_bytes` are truncated with a marker and counted as a warning; gzip members (`.gz`) are transparently streamed.

---

## 2. Windows

### 2.1 `windows_evtx` (EVTX binary)

Use `evtx.PyEvtxParser(path).records_json()`. Each record yields `event_record_id`, `timestamp`, `data` (JSON string). Handle the JSON quirks:

- `Event.System.EventID` may be an int or `{"#text": 4624, "@Qualifiers": ...}`; take `#text` if dict.
- `Provider` is `{"#attributes": {"Name": ..., "Guid": ...}}`.
- `TimeCreated.#attributes.SystemTime` is ISO-8601 UTC.
- `Event.EventData` is a dict of named `Data` values; when `Data` elements are unnamed it is `{"Data": [..]}` → store as `Data_0, Data_1, ...`.
- `Event.UserData` (e.g. 1102, 104) → flatten one level.
- `Event.RenderingInfo` is ignored; message strings are not available from the file (no provider DLLs), so `message` is synthesized from the event table below.
- Corrupt records: caught per record, counted in `error_count`, parsing continues (the library may stop at a chunk boundary; log that as a `parse_errors` row).

Common mapping: `host`=Computer, `channel`=Channel, `provider`=Provider.Name, `event_id`=EventID, `level` from System.Level (1 critical, 2 error, 3 warning, 4 info, 5 debug; 0 → info), `ts_*` from SystemTime, `record_ref`=EventRecordID, `log_type`=`windows_evtx`. `fields_json` = all EventData/UserData fields (original names) plus `System.*` fields prefixed `System.` (e.g. `System.Execution.ProcessID`). `raw` = compact JSON of the record.

Event-specific mapping (columns set in addition to the common ones; EVERYTHING else stays in `fields_json`):

| Channel / EventID | `ls_category` | `event_action` / `outcome` | Column mapping |
|---|---|---|---|
| Security 4624 | `logon` | `logon_success` / success | `user_name`=TargetUserName, `domain`=TargetDomainName, `src_ip`=IpAddress, `src_port`=IpPort, `process_path`=ProcessName |
| Security 4625 | `logon` | `logon_failure` / failure | same as 4624 |
| Security 4634/4647 | `logon` | `logoff` | `user_name`=TargetUserName |
| Security 4648 | `logon` | `logon_explicit_credentials` | `user_name`=SubjectUserName, `target_user_name`=TargetUserName, `dst_ip`=IpAddress |
| Security 4672 | `logon` | `special_privileges_assigned` | `user_name`=SubjectUserName |
| Security 4688 | `process_creation` | `process_created` | `user_name`=SubjectUserName, `process_path`=NewProcessName, `process_cmdline`=CommandLine, `parent_process_path`=ParentProcessName, `process_pid`=hex NewProcessId→int |
| Security 4697 / System 7045 | `service_install` | `service_installed` | `file_path`/`process_path`=ServiceFileName or ImagePath, `process_cmdline`=same |
| Security 4698/4702 | `scheduled_task` | `task_created` / `task_updated` | `user_name`=SubjectUserName; `message`=TaskName |
| Security 4720/4722/4724/4726/4728/4732/4738 | `account_management` | `account_created`, `account_enabled`, `password_reset`, `account_deleted`, `group_member_added`, ... | `user_name`=SubjectUserName, `target_user_name`=TargetUserName |
| Security 4768/4769/4771 | `kerberos` | `kerberos_tgt` / `kerberos_service_ticket` / `kerberos_preauth_failed` | `user_name`=TargetUserName, `src_ip`=IpAddress (strip `::ffff:`) |
| Security 4776 | `credential_validation` | `ntlm_validation` | `user_name`=TargetUserName |
| Security 5140/5145 | `file_share` | `share_access` | `user_name`=SubjectUserName, `src_ip`=IpAddress, `file_path`=ShareName+RelativeTargetName |
| Security 1102 / System 104 | `log_cleared` | `audit_log_cleared` | `user_name`=SubjectUserName |
| Sysmon 1 | `process_creation` | `process_created` | `process_path`=Image, `process_cmdline`=CommandLine, `parent_process_path`=ParentImage, `parent_process_cmdline`=ParentCommandLine, `user_name`=User, `process_pid`=ProcessId |
| Sysmon 3 | `network_connection` | `network_connect` | `src_ip`=SourceIp, `src_port`=SourcePort, `dst_ip`=DestinationIp, `dst_port`=DestinationPort, `protocol`=lower(Protocol), `process_path`=Image, `user_name`=User |
| Sysmon 5 | `process_termination` | `process_terminated` | `process_path`=Image |
| Sysmon 6 | `driver_load` | `driver_loaded` | `file_path`=ImageLoaded |
| Sysmon 7 | `image_load` | `image_loaded` | `process_path`=Image, `file_path`=ImageLoaded |
| Sysmon 8 | `create_remote_thread` | `remote_thread` | `process_path`=SourceImage, `file_path`=TargetImage |
| Sysmon 10 | `process_access` | `process_accessed` | `process_path`=SourceImage, `file_path`=TargetImage |
| Sysmon 11 | `file_event` | `file_created` | `process_path`=Image, `file_path`=TargetFilename |
| Sysmon 12/13/14 | `registry_add` (12 create), `registry_set` (13), `registry_rename` (14) | `registry_*` | `process_path`=Image, `registry_key`=TargetObject, `registry_value`=Details |
| Sysmon 15 | `create_stream_hash` | `file_stream_created` | `file_path`=TargetFilename |
| Sysmon 17/18 | `pipe_created` | `pipe_created` / `pipe_connected` | `process_path`=Image; `file_path`=PipeName |
| Sysmon 19/20/21 | `wmi_event` | `wmi_*` | `user_name`=User |
| Sysmon 22 | `dns_query` | `dns_query` | `process_path`=Image; `message`=QueryName; `dst_ip`=first IP in QueryResults |
| Sysmon 23/26 | `file_delete` | `file_deleted` | `process_path`=Image, `file_path`=TargetFilename |
| PowerShell/Operational 4104 | `ps_script` | `ps_script_block` | `message`=ScriptBlockText (truncate to 64 KB in column; full text in `fields_json`), `file_path`=Path |
| PowerShell/Operational 4103 | `ps_module` | `ps_module_log` | `message`=Payload |
| Windows PowerShell 400/600 | `ps_classic_start` | `ps_engine_state` | `message`=HostApplication |
| TaskScheduler/Operational 106/140/141 | `scheduled_task` | | `message`=TaskName |
| WMI-Activity/Operational 5861 | `wmi_event` | `wmi_permanent_subscription` | |
| Windows Defender/Operational 1116/1117 | `av_detection` | `av_detected` / `av_action` | `file_path`=Path, `message`=Threat Name |
| TerminalServices-LocalSessionManager 21/24/25 | `rdp_session` | | `user_name`=User, `src_ip`=Address |
| anything else | `null` | `event_<id>` | common columns only |

`message` synthesized: `"<Channel> <EventID>: <action> <key fields>"` for events without natural text.

Hashes (Sysmon): keep `Hashes` verbatim in `fields_json` and additionally split into `fields_json.Hash_SHA256`, `Hash_MD5`, `Hash_IMPHASH` (IOC engine reads these).

### 2.2 `windows_event_xml`

Event XML exports (`wevtutil qe /f:xml`, Event Viewer "Save as XML"): stream with `lxml.etree.iterparse` (disable DTD/entities: `resolve_entities=False, no_network=True, huge_tree=False`), one `<Event>` per record, then apply the same mapping as 2.1 using a shared `event_dict` structure so both parsers reuse one mapping function.

---

## 3. Linux

### 3.1 `linux_syslog` and `linux_auth` (shared syslog framing)

Framing regexes (try in order, remember the winner per file):

```
RFC3164: ^(?:<(?P<pri>\d{1,3})>)?(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s(?P<host>\S+)\s(?P<tag>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s(?P<msg>.*)$
RFC3339 (rsyslog): ^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\s(?P<host>\S+)\s(?P<tag>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s(?P<msg>.*)$
RFC5424: ^<(?P<pri>\d{1,3})>(?P<ver>\d)\s(?P<ts>\S+)\s(?P<host>\S+)\s(?P<app>\S+)\s(?P<pid>\S+)\s(?P<msgid>\S+)\s(?P<sd>-|(?:\[.*?\])+)\s?(?P<msg>.*)$
```

Mapping: `host`, `app_name`=tag/app, `provider`=tag, `process_pid`=pid, `message`=msg, `level` from PRI severity (`pri & 7`: 0–2 critical, 3 error, 4 warning, 5–6 info, 7 debug; no PRI → info). Lines that do not match any framing and do not start with whitespace are errors; lines starting with whitespace are appended to the previous event's message (continuation) and `raw`.

`log_type` = `linux_auth` if the filename matches `auth.log*`/`secure*` or ≥ 60% of lines have tag in {sshd, sudo, su, login, passwd, useradd, usermod, userdel, groupadd, cron, polkitd, pam*, systemd-logind}; else `linux_syslog`.

Message parsers (applied by `app_name`; first match wins; unmatched messages keep only common columns). `ls_category` is `null` unless stated.

| Pattern (regex on `msg`) | `event_action` / outcome | Columns |
|---|---|---|
| `Failed (?P<method>\S+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)` | `ssh_failed_password` (method name appended to `fields_json.auth_method`) / failure | `user_name`, `src_ip`, `src_port` |
| `Accepted (?P<method>password\|publickey\|keyboard-interactive/pam\|hostbased\|gssapi\S*) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)` | `ssh_accepted_login` / success | same |
| `Invalid user (?P<user>\S*) from (?P<ip>\S+)(?: port (?P<port>\d+))?` | `ssh_invalid_user` / failure | same |
| `Connection closed by (?:authenticating user (?P<user>\S+) )?(?P<ip>\S+) port (?P<port>\d+)` | `ssh_connection_closed` | same |
| `Disconnected from (?:authenticating \|invalid )?user (?P<user>\S+) (?P<ip>\S+) port (?P<port>\d+)` | `ssh_disconnected` | same |
| `Did not receive identification string from (?P<ip>\S+)` | `ssh_no_identification` | `src_ip` |
| `^\s*(?P<user>\S+)\s*:\s*(?:TTY=(?P<tty>\S+)\s*;\s*)?PWD=(?P<pwd>.*?)\s*;\s*USER=(?P<target>\S+)\s*;\s*COMMAND=(?P<cmd>.*)$` (app sudo) | `sudo_command` ; `ls_category=process_creation` | `user_name`, `target_user_name`, `process_cmdline`=cmd, `file_path`=pwd |
| `(?P<user>\S+) : (?P<n>\d+) incorrect password attempts?` | `sudo_auth_failure` / failure | `user_name` |
| `pam_unix\(su(?:-l)?:session\): session opened for user (?P<target>\S+)(?: \(uid=\d+\))? by (?:\(uid=\d+\)\|(?P<user>\S+)\(uid=\d+\))` | `su_session_opened` / success | `user_name`, `target_user_name` |
| `FAILED SU \(to (?P<target>\S+)\) (?P<user>\S+) on` | `su_failed` / failure | |
| `new user: name=(?P<name>[^,]+), UID=(?P<uid>\d+), GID=(?P<gid>\d+), home=(?P<home>[^,]+), shell=(?P<shell>\S+)` | `user_added` ; `ls_category=account_management` | `target_user_name`=name |
| `delete user '(?P<name>[^']+)'` | `user_deleted` | `target_user_name` |
| `add '(?P<name>[^']+)' to (?:shadow )?group '(?P<grp>[^']+)'` | `group_member_added` | `target_user_name` |
| `\((?P<user>[^)]+)\) CMD \((?P<cmd>.*)\)` (app CRON) | `cron_command` ; `ls_category=process_creation` | `user_name`, `process_cmdline` |
| `\((?P<user>[^)]+)\) (?:REPLACE\|BEGIN EDIT\|END EDIT\|DELETE) \(` (cron) | `crontab_modified` | `user_name` |
| `Started (?P<unit>.+)\.$` / `Stopped (?P<unit>.+)\.$` (systemd) | `service_started` / `service_stopped` | `message` |
| kernel `\[(?P<tag>UFW (?:BLOCK\|ALLOW\|AUDIT)[^\]]*)\]` | delegated to the iptables parser logic | see 4.1 |

Add `ls_category` `logon` for all `ssh_*`, `sudo_auth_failure`, `su_*` actions.

### 3.2 `linux_journald`

`journalctl -o json` (one JSON object per line). Map `__REALTIME_TIMESTAMP` (µs since epoch) → ts, `_HOSTNAME` → host, `SYSLOG_IDENTIFIER` → app_name/provider, `_PID` → process_pid, `MESSAGE` → message (if MESSAGE is an array of ints, decode as bytes), `PRIORITY` → level, `_EXE` → process_path, `_CMDLINE` → process_cmdline, `_UID` → fields_json. Then feed `MESSAGE` through the same message parsers as 3.1 keyed on `SYSLOG_IDENTIFIER`. All journal fields go to `fields_json`.

### 3.3 `linux_auditd`

Line format: `type=<TYPE> msg=audit(<epoch>.<ms>:<serial>): <key=value ...>`. Group consecutive lines by `serial` (flush on serial change or EOF) into one logical event.

- `SYSCALL` → `process_path`=`exe`, `process_pid`=`pid`, `user_name`=`auid` resolved via `AUID`/`UID` text if present (`auid=1000 uid=0 ... AUID="bob" UID="root"` in enriched logs), `fields_json` gets `syscall`, `success`, `exit`, `ppid`, `comm`, `key`.
- `EXECVE` → rebuild `process_cmdline` from `a0..aN` (values may be hex-encoded when they contain special chars: if a value matches `^[0-9A-F]+$` and even length and decodes to printable text, decode; `a<N>_len`/`argc` honored), `ls_category=process_creation`, `event_action=process_executed`.
- `PATH` (`name=`, `nametype=`) → `file_path`.
- `USER_AUTH`, `USER_LOGIN`, `USER_START`, `USER_END`, `USER_ACCT`, `CRED_ACQ` → `ls_category=logon`; `res=success|failed` → outcome; `acct=`, `addr=` → `user_name`, `src_ip`; `hostname=?` → ignore.
- `ADD_USER`, `DEL_USER`, `ADD_GROUP`, `USER_MGMT` → `account_management`.
- `SOCKADDR` (`saddr=` hex) → decode family 2 (AF_INET: port = bytes 2–3, ip = bytes 4–7) / 10 (AF_INET6) → `dst_ip`, `dst_port`, with `event_action=socket_connect` when the syscall is `connect`.
- `proctitle=` hex-decoded (NUL → space) → `fields_json.proctitle`; used as `process_cmdline` fallback.
- One normalized event per logical event: the SYSCALL/EXECVE merge produces a single `process_created` event (`record_ref`=`audit:<serial>`); `raw` holds all grouped lines.

---

## 4. Web

### 4.1 `apache_access` / `nginx_access`

Combined format regex (Apache/Nginx default):

```
^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<uri>\S+)(?: (?P<proto>HTTP/[\d.]+))?" (?P<status>\d{3}) (?P<bytes>\d+|-)(?: "(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?
```

- Timestamp: `%d/%b/%Y:%H:%M:%S %z`.
- Fallback regex for malformed request lines (`"-"`, binary junk, `\x16\x03...`): `^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "(?P<req>[^"]*)" (?P<status>\d{3}) (?P<bytes>\d+|-)(?: "(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?` → `url`=req, `http_method` null, event still created.
- Mapping: `src_ip`=ip (validated), `user_name`=user (`-` → null), `http_method`, `url`=uri (percent-decoding is NOT applied to the stored value; `fields_json.url_decoded` holds the decoded form for IOC/detection use), `url_path`/`url_query` split on first `?`, `http_status`, `bytes_out`, `user_agent`=ua (`-` → null), `ls_category=webserver`, `event_action=http_request`, `event_outcome` = success for status < 400, failure otherwise. `fields_json` includes `referer`, `protocol`, `cs-uri-stem`-style aliases are NOT stored (the Sigma field map handles that, see 04).
- Custom `LogFormat`/`log_format`: the generic CSV/JSON profile mechanism (§6) allows regex-named-group profiles for web logs; the UI exposes "custom web format" under source options.
- `nginx_access` vs `apache_access` is cosmetic (hints: `nginx` in filename, or `$request_time` extras); both share the parser and differ only in `log_type`.

### 4.2 `nginx_error` / `apache_error`

```
nginx: ^(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(?P<level>\w+)\] (?P<pid>\d+)#(?P<tid>\d+): (?:\*(?P<cid>\d+) )?(?P<msg>.*)$
apache 2.4: ^\[(?P<ts>[^\]]+)\] \[(?:(?P<module>[^:\]]+):)?(?P<level>\w+)\] \[pid (?P<pid>\d+)(?::tid \d+)?\](?: \[client (?P<ip>[^\]:]+)(?::(?P<port>\d+))?\])? (?P<msg>.*)$
```
`ls_category=webserver_error`; extract `client: <ip>` from nginx messages into `src_ip`, `request: "<METHOD> <uri> ..."` into `http_method`/`url`.

### 4.3 `iis_w3c`

Header-driven: lines starting `#Fields:` define column order (space-separated); `#Date:`/`#Software:`/`#Version:` ignored; `+` in values is a space. Mapping: `date`+`time` → UTC (IIS W3C is UTC by default), `c-ip`→`src_ip`, `s-ip`→`dst_ip`, `s-port`→`dst_port`, `cs-method`→`http_method`, `cs-uri-stem`→`url_path`, `cs-uri-query`→`url_query` (`-` → null), `url`=stem+`?`+query, `cs-username`→`user_name`, `cs(User-Agent)`→`user_agent`, `sc-status`→`http_status`, `sc-bytes`→`bytes_out`; all fields to `fields_json` by original names. `ls_category=webserver`.

---

## 5. Firewall

### 5.1 `fw_iptables` (iptables/UFW kernel log lines, also via syslog framing)

Detect lines containing `IN=` and `SRC=` and `DST=`. Parse the `KEY=VALUE` tokens (`IN`, `OUT`, `MAC`, `SRC`, `DST`, `LEN`, `TTL`, `ID`, `PROTO`, `SPT`, `DPT`, `FLAGS` as bare words `SYN`, `ACK`, ...). Action from the bracket/prefix: contains `BLOCK`, `DROP`, `REJECT`, `DENY` → `deny`; `ALLOW`, `ACCEPT` → `allow`; otherwise `unknown`. Mapping: `src_ip`=SRC, `dst_ip`=DST, `src_port`=SPT, `dst_port`=DPT, `protocol`=lower(PROTO), `event_action`=`firewall_deny|firewall_allow`, `event_outcome`=failure|success, `ls_category=firewall`, `fields_json` keeps all tokens + `prefix`.

### 5.2 `fw_pfsense` (`filterlog`)

After `filterlog[pid]: ` the payload is CSV. Common prefix: `0 rule, 1 subrule, 2 anchor, 3 tracker, 4 interface, 5 reason, 6 action, 7 direction, 8 ip_version`. For `ip_version=4`: `9 tos, 10 ecn, 11 ttl, 12 id, 13 offset, 14 flags, 15 proto_id, 16 proto_name, 17 length, 18 src, 19 dst`, then (tcp/udp) `20 sport, 21 dport, 22 datalen`, tcp adds `23 flags`, `24 seq`, ... For `ip_version=6`: `9 class, 10 flow_label, 11 hop_limit, 12 proto_name, 13 proto_id, 14 length, 15 src, 16 dst`, then `17 sport, 18 dport`. Action `block|pass|reject` → deny/allow/deny. `fields_json` stores `interface`, `direction`, `rule`, `tracker`, `reason`.

### 5.3 `fw_fortinet`

Key=value with optional double quotes (`key="value with spaces"`). Required keys for detection: `type=` and (`srcip=` or `dstip=`). Mapping: `date`+`time`(+`tz` when present) → ts (use `eventtime` nanoseconds when present), `devname`→`host`, `srcip`/`dstip`/`srcport`/`dstport`, `proto` (6/17/1 → tcp/udp/icmp), `action` (`deny|block|blocked|dropped|drop|ip-conn` → deny; everything else → allow; raw value kept in `fields_json.action`), `user`/`srcuser`→`user_name`, `url`→`url`, `service`, `app`, `policyid`, `logid`, `subtype`, `level`. `ls_category=firewall`.

### 5.4 `fw_paloalto`

CSV (syslog-framed or raw). Detect by field 3 ∈ {`TRAFFIC`, `THREAT`, `SYSTEM`, `CONFIG`, `URL`, `GLOBALPROTECT`} and ≥ 30 columns. Positional map lives in `data/profiles/paloalto_fields.yaml` (version-specific; ship the PAN-OS 10/11 layouts and verify against the vendor log-field reference). Required TRAFFIC fields: generated time, source address, destination address, rule, source user, application, source zone, destination zone, session id, source port, destination port, IP protocol, action. Action `allow` → allow; `deny|drop|reset-client|reset-server|reset-both|block-url` → deny. `THREAT` logs add `fields_json.threat_id`, `severity`, `category`; map `severity` high/critical → `level=error`.

### 5.5 `fw_cisco_asa`

Frame: `%ASA-<sev>-<msgid>: <text>` (optionally syslog-prefixed). Implement at least:

```
106023: Deny (?P<proto>\w+) src (?P<sif>\S+):(?P<sip>[\d.]+)/(?P<sport>\d+) dst (?P<dif>\S+):(?P<dip>[\d.]+)/(?P<dport>\d+) by access-group "(?P<acl>[^"]+)"
106100: access-list (?P<acl>\S+) (?P<act>permitted|denied) (?P<proto>\w+) (?P<sif>\S+)/(?P<sip>[\d.]+)\((?P<sport>\d+)\) -> (?P<dif>\S+)/(?P<dip>[\d.]+)\((?P<dport>\d+)\)
302013/302015 (Built): Built (?P<dir>inbound|outbound) (?P<proto>TCP|UDP) connection (?P<cid>\d+) for (?P<sif>\S+):(?P<sip>[\d.]+)/(?P<sport>\d+) \([^)]*\) to (?P<dif>\S+):(?P<dip>[\d.]+)/(?P<dport>\d+)
302014/302016 (Teardown): Teardown (?P<proto>TCP|UDP) connection (?P<cid>\d+) for (?P<sif>\S+):(?P<sip>[\d.]+)/(?P<sport>\d+) \([^)]*\) to (?P<dif>\S+):(?P<dip>[\d.]+)/(?P<dport>\d+)
113005/113015 (AAA failure): AAA user authentication Rejected .* user = (?P<user>\S+)
605005/611101 (login/VPN): ... user = (?P<user>\S+)
```
Unmatched ASA messages keep `event_id`=msgid, `level` from severity, `message`. `ls_category=firewall` for 106xxx/302xxx.

---

## 6. Generic JSON and CSV (mapping profiles)

`generic_json` (NDJSON or a single JSON array/object with an `events`/`records`/`Records`/`hits.hits[*]._source` list) and `generic_csv` (header row; delimiter sniffed among `, ; \t |`).

Mapping profiles are YAML files in `data/profiles/` and user-importable:

```yaml
name: elastic-ecs
applies_when: { any_key: ["@timestamp", "ecs.version"] }
timestamp: { path: "@timestamp", format: iso8601 }          # or epoch_s | epoch_ms | strptime: "%Y-%m-%d %H:%M:%S"
timezone: UTC
fields:
  host:                 "host.name"
  user_name:            "user.name"
  src_ip:               "source.ip"
  src_port:             "source.port"
  dst_ip:               "destination.ip"
  dst_port:             "destination.port"
  process_path:         "process.executable"
  process_cmdline:      "process.command_line"
  parent_process_path:  "process.parent.executable"
  file_path:            "file.path"
  url:                  "url.original"
  http_method:          "http.request.method"
  http_status:          "http.response.status_code"
  user_agent:           "user_agent.original"
  message:              "message"
  event_id:             "event.code"
  event_action:         "event.action"
  event_outcome:        "event.outcome"
category_rules:         # first match wins
  - { when: { "event.category": "process" }, ls_category: process_creation }
  - { when: { "event.category": "network" }, ls_category: network_connection }
```

Ship profiles for: Elastic ECS, Wazuh alert JSON, Splunk CSV export (`_time,host,source,sourcetype,_raw`), Microsoft Defender/Sentinel CSV exports, Zeek `conn.log`/`dns.log`/`http.log` (JSON and TSV with `#fields`), AWS CloudTrail (`Records[]`: `eventTime`, `eventName`, `userIdentity.arn`, `sourceIPAddress`, `userAgent`, `errorCode`).

UI "Custom mapping" lets the user pick a sample record, map JSON paths/CSV columns to normalized fields via dropdowns, preview 20 normalized rows, and save as a profile. Paths use dot notation with `[*]` for arrays (first element) and are validated server-side.

Unmapped JSON keys are flattened with dot-notation into `fields_json`. `raw` = original JSON text / CSV line.

---

## 7. Parser acceptance rules (apply to every parser)

1. Streaming: memory use independent of file size (no full-file reads except JSON-array inputs, which use `ijson`).
2. Every record yields exactly one event or one `parse_errors` row.
3. Fixture-driven tests with expected normalized JSON for ≥ 10 representative lines/records per parser plus ≥ 5 malformed ones (see 09).
4. Throughput targets are in 09 §8.
