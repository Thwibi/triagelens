# Manual dataset validation

The committed test fixtures (`backend/tests/fixtures/`) are synthetic, small and
generated reproducibly, which makes them fast and deterministic but also confined
to the shapes their authors imagined. Spec 09 section 2 therefore calls for a
second, **manual** pass against real public datasets that are too large and too
varied to commit.

This document is the procedure for that pass. It is run by a human on a machine
that can reach the public sources once; TriageLens itself never accesses the
network.

## Scope

The manual pass validates the parts the synthetic fixtures exercise least:

- the Windows EVTX and event-XML parsers across many producers and channels,
- the Linux syslog / journald / auditd parsers against real oddities,
- the web-access and generic CSV/JSON parsers under volume,
- Sigma rule coverage (which techniques real rules actually match),
- end-to-end behaviour at a size where performance, memory and pagination matter.

It is a validation of the pipeline, not of a fixed expected output: there is no
golden file for a third-party dataset, so the checks below are qualitative
("parsing reports no unexpected errors", "alerts map to plausible techniques")
rather than exact counts.

## Prerequisites

Build and start the application, then open the UI:

```bash
make install
make build
./scripts/run.sh            # http://127.0.0.1:8787  (.\scripts\run.ps1 on Windows)
```

Optional but recommended:

- Import an ATT&CK bundle so technique names, tactics and descriptions resolve
  instead of falling back to the bundled map:
  `python scripts/update_attack.py <enterprise-attack.json>` (see `SOURCES.md`).
- Watch `docs/perf-results.md` and `python scripts/diag.py` for resource figures
  on the machine under test.

## General procedure

For every dataset below:

1. **Create a case** named for the dataset.
2. **Import** the files from the Sources screen (a directory import for a whole
   sample tree, or an archive where the source ships a zip). Let the jobs drawer
   reach `done`.
3. **Check parsing.** The source row shows parsed and error counts. A handful of
   `parse_errors` rows on genuinely malformed lines is expected; a large error
   count on a well-formed dataset is a defect. Drill into the Events screen and
   confirm the normalised columns (timestamp, host, user, process, source IP) are
   populated, and that `fields_json` carries the format-specific keys.
4. **Run detection** with the `standard` profile over each source.
5. **Review** the Alerts screen (severity, evidence, extracted IOCs), the ATT&CK
   matrix (which techniques are covered), and the IOCs register.
6. **Report and export** — generate an HTML report and export the event filter as
   CSV, then spot-check that escaping and the CSV formula guard behaved.
7. **Verify the chain** from Settings → Data → Verify audit chain, and record the
   run in the table at the end of this document.

## Public datasets

| Dataset | Where | Formats exercised |
|---|---|---|
| EVTX-ATTACK-SAMPLES | https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES | Windows EVTX (Sysmon, Security, PowerShell) |
| OTRF Security-Datasets (Mordor) | https://github.com/OTRF/Security-Datasets | EVTX and pre-recorded JSON |
| Hayabusa sample EVTX | https://github.com/Yamato-Security/hayabusa-sample-evtx | Windows EVTX with known detections |
| loghub | https://github.com/logpai/loghub | Linux auth, OpenSSH, Apache, Hadoop text logs |

### EVTX-ATTACK-SAMPLES (sbousseaden)

A large collection of single-technique EVTX files, one directory per ATT&CK
technique.

- **Import** a representative subset (for example the Sysmon and Security
  subdirectories) rather than the whole tree, to keep a run bounded.
- **Check** that every `.evtx` file parses with the native reader and that the
  XML exports in the same repo produce the same events through the event-XML
  parser.
- **Expect** alerts for the executables and command lines the rules target —
  for example encoded PowerShell, `certutil` downloads, scheduled-task creation
  and credential-access tooling — with techniques such as `T1059.001`,
  `T1053.005` and `T1003` appearing in the matrix. Technique coverage, not an
  exact alert count, is the signal.
- **Watch** the ATT&CK matrix populate across multiple tactics; a technique that
  only ever maps to the fallback id suggests the bundle is missing.

### OTRF Security-Datasets (Mordor)

Recorded adversary emulation with both EVTX and JSON exports.

- **Prefer the EVTX** export for the Windows scenarios so the native path is
  exercised; use the JSON export to exercise the structured-JSON ingestion.
- **Check** that the JSON records normalise timestamp, host, user and process
  fields, and that copied-and-pasted multi-line JSON does not split records.
- **Expect** the emulated techniques of each scenario to appear as alerts, and
  the host/user entities on the Entities screen to match the scenario.

### Hayabusa sample EVTX

A small, well-labelled Windows EVTX set with a published list of expected
detections.

- **Import** the sample EVTX files.
- **Compare** against the published labels: the detection rules that hayabusa
  matches should mostly overlap with TriageLens' Sigma rule set. Differences are
  expected (different rule revisions) but a whole family of misses points at a
  routing or field-mapping gap in `rules/logsource_map.yaml`.
- **Use** this set as the primary **rule-coverage** check.

### loghub

Large real-world text logs (Linux, OpenSSH, Apache, Hadoop and others).

- **Import** one log class at a time to isolate parser behaviour; the OpenSSH and
  Linux sets validate `linux/auth.log` handling, the Apache set validates the web
  access parser, and the Hadoop set exercises the generic text profile.
- **Check** throughput and memory in `docs/perf-results.md` terms — this is the
  set most likely to expose a streaming or pagination problem.
- **Expect** parse-error counts near zero on the well-structured logs and a
  graceful, bounded error count on the known-garbage ones (a source ends `done`
  with warnings, never `failed`, for malformed lines alone).

## Acceptance

A dataset run passes when, for each source:

- parsing completes with no unexpected errors and populated normalised columns,
- detection produces plausible, technique-tagged alerts (none for a benign set),
- the alert evidence links back to the originating events and indicators,
- the generated report and CSV/JSONL exports are well-formed and escaped,
- the audit chain still verifies after the run.

Record every run so regressions are visible across releases:

| Date | Dataset | Sources | Events | Alerts | Notes |
|---|---|---|---|---|---|
| | | | | | |
