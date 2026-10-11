# Sources

TriageLens ships a bounded set of third-party data. Each entry records the
upstream source, the pinned revision/version where one exists, and a SHA-256
so the shipped bytes can be reproduced and audited.

## SigmaHQ detection rules — `backend/rules/sigma/`

- **Upstream:** https://github.com/SigmaHQ/sigma
- **Pinned commit:** `48f2d096991a9ae89fd2710804901d1cd88d9746` (2024-05-31)
- **Tree SHA-256:** `a2c3f33d76a44dbddd5fb537e3c73e07c4e128c8d9624db54dfbb7484cdf891f`
- **Source SHA-256:** `c68b809a8621406ad82469954624b6468064cf595a575b1bb2fdba2ab0b2c88a`
- **License:** Detection Rule License (DRL) 1.1 — see `backend/rules/sigma/LICENSE` and `THIRD_PARTY_NOTICES.md`
- **Tooling:** `scripts/update_rules.py` (dir or zip source, dry-run, digest + SOURCE.txt regeneration)
- **Selection:** every detection rule that parses, compiles with the SQLite backend and routes
  through `backend/rules/logsource_map.yaml`; the Windows slice is capped per rule family and
  severity (see `docs/DECISIONS.md`, "SigmaHQ sample" entry). The `SOURCE.txt` next to the rules
  records the exact revision and selection counts. A 2026-10-11 amendment added
  four Windows rules (audit-log cleared, suspicious scheduled task, base64
  PowerShell, suspicious RUN key) for the spec 09 §7 Scenario C acceptance; it is
  noted in `SOURCE.txt` itself.

## MITRE ATT&CK — `backend/data/attack/` (not committed)

- **Upstream:** https://github.com/mitre-attack/attack-stix-data (or an equivalent `enterprise-attack.json` export)
- **License:** MITRE ATT&CK content is used under the MITRE ATT&CK terms of use — see `THIRD_PARTY_NOTICES.md`
- **Tooling:** the ATT&CK bundle is imported into the local database by `scripts/update_attack.py`
  (e.g. `python scripts/update_attack.py data/attack/enterprise-attack.json`); the bundle itself is
  not vendored, and any imported SHA-256 is recorded in the audit trail rather than this file.

## IANA top-level domains — `backend/data/iana_tlds.txt`

- **Upstream:** https://data.iana.org/TLD/tlds-alpha-by-domain.txt (public domain data)
- **License:** the IANA TLD list is public domain; see `THIRD_PARTY_NOTICES.md`
- **Use:** candidate extraction and URL/IOC normalization.