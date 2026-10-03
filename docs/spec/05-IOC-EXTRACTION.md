# 05 — IOC Extraction

## 1. IOC types

`ipv4, ipv6, domain, url, email, md5, sha1, sha256, filename, filepath, registry, cve, user_agent, command`.

Two tiers keep noise down:

| Tier | Types | Runs on |
|---|---|---|
| **1 — global** | ipv4, ipv6, domain, url, email, md5, sha1, sha256, cve | every event, during parse |
| **2 — alert-scoped** | filename, filepath, registry, user_agent, command | only events attached to alerts (after detection) |

Usernames and hostnames are **entities**, not IOCs: they are shown in alert detail and in an "Entities" panel (hosts, users, with counts), and exported with the report.

## 2. Pipeline per text value

```
value → control-char cleanup → refang → decode pass (depth ≤ decode_depth) → regex candidates → validate → classify (private/allowlisted) → score → emit
```

The decode pass runs on the original text and each decoded child; every IOC records `decoded_from` when it came from a decoded child.

### 2.1 Refanging (applied on a copy; the original text is preserved as evidence)

Replace case-insensitively: `hxxp`→`http`, `hxxps`→`https`, `fxp`→`ftp`, `[.]` `(.)` `{.}` `[dot]` `(dot)` ` dot ` (only between label-like tokens)→`.`, `[:]`→`:`, `[://]`→`://`, `[@]` `(at)` `[at]`→`@`, `\.`→`.` (only inside URL/domain candidates).

### 2.2 Decoding

1. **PowerShell**: find `-(?:e|ec|en|enc|enco|encod|encode|encoded|encodedcommand)\s+([A-Za-z0-9+/=]{16,})` (case-insensitive) → base64 → UTF-16LE → text. Also `[Convert]::FromBase64String\(['"]([^'"]+)['"]\)` followed by `GetString` (try UTF-8, then UTF-16LE).
2. **Generic base64**: tokens of ≥ 40 chars matching `[A-Za-z0-9+/]{40,}={0,2}` that decode to text with ≥ 85% printable characters (UTF-8 or UTF-16LE).
3. **URL percent-decoding**: for `url`, `url_query`, `message` of web events and for command lines containing `%XX` sequences (max two rounds).
4. **Hex** (`0x`/`\x`-style strings ≥ 16 bytes decoding to printable text) — **(optional)**.
5. Never recurse beyond `decode_depth` (default 2); cap decoded text at 256 KB; discard decodes that are not mostly printable.

Decoded PowerShell command text is also stored in `events.fields_json.decoded_cmdline` for display (alert-scoped events only).

## 3. Candidate regexes and validation

```
IPv4  (?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])
IPv6  (?<![:\w])(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}(?![:\w])
URL   \b(?:https?|ftps?|sftp|tftp|ldaps?|smb)://[^\s<>"'`\\^{}|]+
EMAIL \b[A-Za-z0-9._%+\-]{1,64}@(?:[A-Za-z0-9\-]+\.)+[A-Za-z]{2,24}\b
DOMAIN (?<![\w@.\-/])(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24}|xn--[a-z0-9\-]{2,59})(?![\w\-])   (case-insensitive)
MD5   \b[a-fA-F0-9]{32}\b
SHA1  \b[a-fA-F0-9]{40}\b
SHA256 \b[a-fA-F0-9]{64}\b
CVE   \bCVE-\d{4}-\d{4,7}\b            (case-insensitive; stored uppercase)
WINPATH \b[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*
UNCPATH \\\\[A-Za-z0-9._$\-]+\\[^\s"<>|]+
NIXPATH (?<![\w:/.])/(?:tmp|var/tmp|dev/shm|home|root|etc|usr/local|opt|var/www)(?:/[^\s"'<>|;&]+)+
REGKEY \b(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_[A-Z_]+)\\[^\r\n"']+
```

Validation rules (all MUST be enforced):

- **IP**: parse with `ipaddress.ip_address`; reject leading-zero octets (`01.2.3.4`); reject when immediately preceded by `v`, `version `, `ver `, or part of a dotted version context (`\d+\.\d+\.\d+\.\d+` followed by a letter like `-beta`); IPv6 candidates that match `\d{2}:\d{2}:\d{2}` (times) or a MAC pattern `([0-9a-f]{2}:){5}[0-9a-f]{2}` are rejected; strip `::ffff:` mapped prefix → IPv4.
- **Domain**: TLD must be in `data/iana_tlds.txt` (lowercase, punycode `xn--` accepted); labels ≤ 63, total ≤ 253; no label starting/ending with `-`; reject if the whole token is an IP; reject if token equals a known filename pattern (`*.exe|dll|sys|log|tmp|dat|txt|ini|cfg|json|xml|yml|yaml`). **Ambiguous TLDs** (`sh, py, pl, rs, zip, mov, md, so, cc, ps, pm, am, ai, io, cs, ad`) are accepted from structured fields (URL host, DNS query, `Host` header, email domain) or when ≥ 2 labels precede the TLD; otherwise dropped from free text.
- **URL**: strip trailing `.,;:)]}'"` characters unless balanced; must parse with `urllib.parse.urlsplit`; host extracted and validated as IP or domain; the host is also emitted as its own IOC (role `url_request`) with the same evidence.
- **Hash**: boundaries ensure not part of a longer hex run; reject all-same-character values and values with ≤ 3 distinct characters; reject when the preceding 12 characters match `(?i)(?:sid|guid|uuid|id)[=: ]`; MD5-length candidates in `RandomSeed`/`SessionId` fields are skipped (field name blocklist in `ioc/blocklists.py`).
- **Email**: domain part validated like a domain; local part ≤ 64.
- **Paths** (tier 2): keep only when (a) the directory is suspicious (`\Temp\`, `\AppData\`, `\ProgramData\`, `\Users\Public\`, `\Downloads\`, `\Windows\Temp\`, `\$Recycle.Bin\`, `/tmp/`, `/var/tmp/`, `/dev/shm/`, `/var/www/`) or (b) the extension is executable/script (`exe, dll, sys, scr, bat, cmd, ps1, psm1, vbs, vbe, js, jse, hta, lnk, jar, msi, iso, img, one, docm, xlsm, py, sh, elf`). Emit both `filepath` and `filename` (basename).
- **Registry** (tier 2): keep only persistence/defense-evasion-relevant hives: contains any of `\Run`, `\RunOnce`, `\Services\`, `\Winlogon`, `\Image File Execution Options`, `\Policies\`, `\Windows Defender`, `\Schedule\TaskCache`, `\Environment`, `\Explorer\`, `\Classes\CLSID`, `\Lsa`.
- **Command** (tier 2): the `process_cmdline` of alert events, truncated to 2,000 chars, only for alerts with `level >= medium`.
- **User agent** (tier 2): from `user_agent` on alert events; kept when it matches the scanner list from 04 §10 or occurs ≤ 2 times in the case.

## 4. Structured-field extraction (higher confidence)

Prior to regex over free text, read typed fields directly:

| Source field | IOC type | Role |
|---|---|---|
| `src_ip` | ipv4/ipv6 | `source` |
| `dst_ip` | ipv4/ipv6 | `destination` |
| `url` (host + full URL) | url, domain/ip | `url_request` |
| Sysmon 22 `QueryName` (message), `QueryResults` IPs | domain, ip | `dns_query` |
| Sysmon 3 `DestinationHostname` | domain | `destination` |
| `fields_json.Hash_SHA256/MD5/SHA1` (Sysmon `Hashes`, `Hash`, `FileHash`, `Hashes` key=value lists) | hashes | `image_hash` |
| Defender 1116 `Threat Name` | (tag on file IOCs) | |
| email-bearing fields (`Sender`, `Recipient`, `mail`) | email | `mentioned` |

All other text fields (`message`, `process_cmdline`, `parent_process_cmdline`, `file_path`, `registry_*`, `url_query`, `fields_json` string values) go through the regex path with role `mentioned` (or `process` for command lines).

## 5. Classification and allowlisting

Every IPv4/IPv6 is classified with `ipaddress`:

- `is_private=1` when `is_private` (RFC1918/ULA), loopback, link-local, multicast, unspecified, or reserved (`0.0.0.0/8`, `100.64.0.0/10` CGNAT, `240.0.0.0/4`, `255.255.255.255`).
- **Documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) are treated as public** so demos and fixtures work. (Real logs will not normally contain them.)
- Private IOCs are stored (flag set), shown under "Internal" in the UI, and excluded from exports and scoring by default.

Allowlist (`data/default_allowlist.yaml`, editable in Settings; entries stored in `allowlist`):

```yaml
domain_suffix: [schemas.microsoft.com, schemas.xmlsoap.org, www.w3.org, purl.org, ns.adobe.com,
                localhost, local, example.com, example.org, example.net, test, invalid]
domain: [windowsupdate.microsoft.com, ctldl.windowsupdate.com, crl.microsoft.com]
```
Matching IOCs are stored with `is_allowlisted=1` (never silently dropped; hidden in the UI unless "show allowlisted" is on). Users can add case-scoped allowlist entries from the IOC table ("mark benign"), which also set `analyst_state='benign'`.

## 6. Confidence score (0–100, deterministic)

```
base = 80  structured network/hash field
       60  decoded content
       50  free-text regex
+15  occurs in an event attached to an alert
+10  occurs ≥ 5 times
+5   occurs on ≥ 3 distinct hosts (or ≥ 3 distinct sources)
-30  ambiguous TLD domain accepted via ≥ 2 labels rule only
-20  private/reserved IP
-40  allowlisted
clamp to [0, 100]
```
Occurrence counts are the number of distinct events (`ioc_occurrences`). `first_seen_ms/last_seen_ms` are min/max event timestamps.

## 7. Dedup and storage

- Key: `(case_id, type, value_norm)`. `value_norm`: IPs → canonical `ipaddress` string; domains → lowercase punycode (idna) with trailing dot stripped; URLs → scheme/host lowercased, default ports removed, fragment removed, path/query preserved; hashes → lowercase; emails → lowercase; paths/registry → as-is (case preserved) but dedup case-insensitively on Windows-style values.
- `ioc_occurrences` stores up to 50 occurrences per IOC per source (counter keeps the true total in `iocs.occurrences`).
- IOCs found in alert events are linked in `ioc_alerts`.
- Worker processes pre-aggregate IOCs per batch (dict) and send aggregated rows to the writer thread to avoid millions of inserts.

## 8. Export

| Format | Details |
|---|---|
| CSV | columns: `type,value,confidence,occurrences,first_seen,last_seen,hosts,alerts,mitre_techniques,analyst_state,tags` |
| TXT | one value per line, optional `defang=true` |
| STIX 2.1 | bundle of `indicator` objects, `pattern_type: stix`, `valid_from` = first_seen, `labels` = `["malicious-activity"]` when `analyst_state='malicious'` else `["anomalous-activity"]`; patterns: `[ipv4-addr:value = '…']`, `[ipv6-addr:value = '…']`, `[domain-name:value = '…']`, `[url:value = '…']`, `[email-addr:value = '…']`, `[file:hashes.'SHA-256' = '…']` (`MD5`, `SHA-1` likewise), `[windows-registry-key:key = '…']`, `[file:name = '…']`. Filepath/command/user-agent IOCs are exported only as `x-triagelens-observable` custom properties inside a note |
| JSON | full IOC records with occurrences and linked alerts |

Defanging for display/export: `.`→`[.]` in domains/IPs, `http`→`hxxp` in URLs, `@`→`[@]` in emails.

## 9. Optional enrichment (off by default)

When `network.allow_enrichment=true` the UI shows an "Enrich" action for selected IOCs (VirusTotal v3, AbuseIPDB) using user-supplied API keys stored in the OS keyring or an env var (never in the DB or logs). Each outbound request is audit-logged; only the IOC value is sent. With the flag off, the code path is not reachable and a test asserts no sockets are opened.

## 10. Acceptance

- ≥ 150 labelled unit tests covering each regex, validator, refang case, decoder, ambiguous-TLD rule, and classification (see 09).
- Precision check on the bundled sample set: ≥ 95% of emitted tier-1 IOCs are true indicators in labelled fixtures; zero private IPs emitted unflagged.
- Extraction throughput target in 09 §8; no catastrophic backtracking (all regexes tested against 1 MB adversarial strings with a 1 s cap).
