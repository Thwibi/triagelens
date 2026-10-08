# Windows EVTX fixture provenance

The binary `.evtx` fixtures here are real EVTX files used to exercise the
`windows_evtx` parser against genuine binXML, which a hand-authored file cannot
reproduce without a binXML writer. They are small, committed, and only ever
changed through `scripts/make_fixtures.py`.

## Source

- Upstream: <https://github.com/omerbenamram/evtx> (`samples/` directory).
- License: MIT. The sample logs are redistributed under that license with
  attribution; see the upstream `LICENSE`. This repository's own license is
  unaffected.
- Retried from the upstream `samples/` tree; the files are byte-identical to the
  upstream originals except where noted under "Transformations".

## Files

| Fixture | Upstream sample | Size | Transform |
| --- | --- | --- | --- |
| `security_logons.evtx` | `Security_short_selected.evtx` | 68 KiB | none |
| `account_changes.evtx` | `new-user-security.evtx` | 68 KiB | none |
| `sysmon_attack.evtx` | `sysmon.evtx` | 196 KiB | trimmed to the first 3 chunks |

The 200 KiB fixture ceiling in spec 09 is why `sysmon.evtx` is trimmed. The
trim keeps the first three 64 KiB chunks, rewrites the file header's
`oldest_chunk` (0), `current_chunk_number` (2), `next_record_number` and
`chunk_count` (3), and recomputes the header checksum at offset `0x7C` with
`zlib.crc32(header[:0x78])`. The result is a valid EVTX file that the vendored
reader parses without error; see `make_fixtures.py` and the Phase 2 notes.

## Contents

- `security_logons.evtx` — 7 records: 5152, 4611, 4776, 4625, 5152, 5157, 4673;
  channel `Security`, provider `Microsoft-Windows-Security-Auditing`, computer
  `temporal`.
- `account_changes.evtx` — 4 records: 4728, 4720, 4732, 4732; computer
  `IE8Win7`.
- `sysmon_attack.evtx` — 120 records, Sysmon channel, including event IDs 1, 10,
  11, 13, 15, 16; computer `DESKTOP-2KGM189`.

## The XML fixtures

`security_logons.xml`, `sysmon_attack.xml` and `powershell_4104.xml` are
authored by `scripts/make_fixtures.py` from literals in that file. They carry the
richer Scenario C content the binary samples do not (a password spray, an
encoded PowerShell downloader, a Run-key persistence event, a scheduled task, an
audit-log clear), so the mapping table and the special cases in spec 09 P-07 are
covered without shipping large `wevtutil` exports.