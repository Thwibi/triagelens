# 07 — UI Specification

SPA served by the backend. React 18 + TypeScript, Vite, TanStack Router (or React Router), TanStack Query for server state, TanStack Table v8 with virtualization (`@tanstack/react-virtual`) for large tables, Recharts, CodeMirror 6 for YAML/raw views, Tailwind CSS. **No CDN assets**: fonts (Inter, JetBrains Mono), icons (Lucide), and all scripts are bundled so the UI works offline.

## 1. Design tokens

CSS variables on `:root` (dark default) and `[data-theme="light"]`. The user toggle persists in `localStorage` and defaults to `prefers-color-scheme`/`config.ui.default_theme`.

| Token | Dark | Light |
|---|---|---|
| `--bg` | `#0E1116` | `#F6F8FA` |
| `--surface` | `#151A21` | `#FFFFFF` |
| `--surface-2` | `#1C232C` | `#EEF1F5` |
| `--border` | `#2A333F` | `#D5DBE3` |
| `--text` | `#E6EDF3` | `#1B2430` |
| `--muted` | `#8B98A5` | `#5B6776` |
| `--accent` | `#2DD4BF` | `#0F9D8F` |
| `--sev-critical` | `#F43F5E` | `#DC2646` |
| `--sev-high` | `#F97316` | `#D9600A` |
| `--sev-medium` | `#EAB308` | `#B98A00` |
| `--sev-low` | `#38BDF8` | `#1D8FD0` |
| `--sev-info` | `#94A3B8` | `#64748B` |

Typography: Inter for UI (14 px base), JetBrains Mono for data (IPs, hashes, commands, raw logs, IDs; 13 px). 4-pt spacing grid; 6 px radius; 1 px borders; no heavy shadows. Severity is always conveyed by **icon + label + colour** (never colour alone). WCAG AA contrast for text in both themes. Visible focus ring (2 px accent outline) on all interactive elements.

## 2. Layout

- **Left rail** (collapsible): Cases switcher, then per-case nav: Overview, Alerts, MITRE, IOCs, Events, Timeline, Entities, Sources, Rules, Reports, Settings.
- **Top bar**: case name, **scope bar** (time range picker with brush sync, host multi-select, source multi-select, log-type multi-select; shown on Alerts/IOCs/Events/Timeline/MITRE/Entities), global search (`/`), theme toggle, running-jobs indicator (opens jobs drawer).
- **Right drawer** (resizable 420–900 px) for details (event, alert, IOC) so list context is kept.
- Responsive: ≥ 1280 px full layout; 768–1279 rail collapsed to icons; < 768 px read-only mobile layout with stacked cards (upload disabled below 768 px).

## 3. Screens

### 3.1 Cases (home)
Cards/table: name, last updated, sources/events/alerts/IOCs counts, highest alert level. Actions: New case (name, description, default timezone), rename, delete (typed-name confirmation). Empty state: large "Create your first case" with drag-and-drop hint.

### 3.2 Overview
- KPI tiles: events, sources, alerts by level (clickable), distinct IOCs (external), hosts.
- "Top 5 alerts by score" with technique chips.
- Mini timeline (events + alert markers), mini MITRE heat strip (14 tactics, colour = max level).
- Top attacker candidates: external IPs ranked by (confidence × alert links).
- Ingest health: parse error rate per source with link to Sources.
- Last detection run info: profile, rules run/skipped/errored, ATT&CK version, ruleset hash (copy button).

### 3.3 Sources (upload and ingest)
- **Dropzone** accepts files, multiple files, folders (webkitdirectory), archives. Shows per-file: name, size, SHA-256 (after upload), detected type + confidence, timezone and year controls (shown for syslog-style types), status chip, progress bar with events/s, errors count.
- `needs_input` rows show an inline "Which log type is this?" selector with ranked candidates and a "Custom mapping…" option (opens the mapping wizard, §3.11).
- Row actions: re-detect, change type/timezone (triggers re-parse with confirmation), view parse errors (modal table), download original, delete.
- Footer: "Run detection" (profile selector) and "Auto-run after ingest" toggle.

### 3.4 Alerts
Table (virtualized): severity badge, score (with tiny bar), rule title, ATT&CK technique chips (`T1110.001 Brute Force: Password Guessing`), tactic chips, host, user, first/last seen, count, status. Left filter panel: level, status, tactic, technique, rule source (sigma/builtin/custom), host, user, "unmapped only". Sorting by any column. Multi-select with bulk status change. Keyboard: `j/k` move, `Enter` open, `t` true positive, `f` false positive, `b` benign, `x` select.

**Alert drawer**:
1. Header: title, severity, score + "why this score" popover (breakdown).
2. ATT&CK block: tactic → technique chips linking to MITRE page + external ATT&CK URL (opens in a new tab with `rel=noopener`; an "offline" note appears if no network), "inferred" badge for fallback mappings, group/software chips, unresolved tags list.
3. Rule block: description, level, status, falsepositives, references (rendered as plain text links, not auto-opened), "View rule YAML" (read-only CodeMirror), "Open in rule editor".
4. Evidence: paginated events (sample first, "Load all matches" streams the rest), each row expandable inline; IOC highlights.
5. IOCs found in evidence (grouped by type) with copy/defang toggles.
6. Entities: hosts and users involved with counts.
7. Analyst panel: status select, notes (autosave with debounce, 5 s "Saved" indicator).

### 3.5 MITRE
ATT&CK Enterprise matrix: 14 tactic columns in canonical order; each column lists techniques (parents), expandable to sub-techniques. Cell shows technique ID + name + alert count; colour intensity by alert count, border by max severity. Modes: "Fired only" (default, hides empty cells) / "Full matrix". Click a technique → alerts list filtered to it (drawer). Tooltip: description first 200 chars. Export buttons: Navigator layer JSON, PNG snapshot of the matrix. Shows ATT&CK version badge.

### 3.6 IOCs
Tabs by type (All, IPs, Domains, URLs, Hashes, Emails, Files & Paths, Registry, CVEs, Other). Table: value (mono, copy), type, confidence bar, occurrences, first/last seen, hosts count, linked alerts count, ATT&CK techniques, state chip (none/malicious/suspicious/benign). Toggles: show internal, show allowlisted, defang values, min confidence slider. Row drawer: occurrences list with source event snippets and the matching field, decoded-from badge, linked alerts, actions (mark malicious/suspicious/benign, add tag, add to allowlist, copy, pivot to Events filtered by this IOC). Bulk: select → Export (CSV/TXT/STIX/JSON; defang toggle). Optional "Enrich" button only when enrichment is enabled in Settings.

### 3.7 Events
Search bar (FTS5 syntax with an inline help popover: `AND`, `OR`, `NOT`, `"phrase"`, `prefix*`, column filters like `process_cmdline:powershell`), filter chips for host/log type/channel/event ID/user/IP. Virtualized table with sticky header, column picker (persisted), compact/comfortable density, default columns: time, host, log type, event ID/action, user, src→dst, summary (`message` or process/cmdline). Facet sidebar with top values and counts; click to add filter. Row click → Event drawer: normalized fields table, original fields (tree view with copy), raw (CodeMirror read-only, wrap toggle), related alerts, IOCs (highlighted inside raw via computed text ranges; rendering uses text nodes only — never `innerHTML`), "Show surrounding events" (±N seconds same host) button. Export current result set to CSV/JSONL (streamed, max 1M rows).

### 3.8 Timeline
Stacked bar chart (events per bucket coloured by log type) with alert markers (severity-coloured) on top; brush to set the global time range; zoom in/out buttons; bucket selector (auto/1m/5m/1h/1d). Under the chart, list of alerts and notable IOCs in the selected range.

### 3.9 Entities
Hosts and Users tables: counts of events/alerts, first/last seen, top techniques; click → filters other views.

### 3.10 Rules
- List with filters (kind, level, status, enabled, tag/technique, health) and search. Columns: enabled toggle, title, level, kind, logsource, techniques, health badge.
- Detail/editor: CodeMirror YAML with schema-aware linting from `/rules/validate`; buttons **Validate**, **Test on case** (shows count, 20 samples, duration), **Save** (custom only), **Duplicate to custom** (for sigma/builtin), **Delete**.
- Import (drag zip/yml) with per-rule result table; Export custom rules.
- Health tab: compile errors, unroutable, never-present fields, timeouts (from last run).
- Bulk enable/disable by tag/level.

### 3.11 Custom mapping wizard (generic JSON/CSV)
Steps: (1) choose sample file/record, (2) auto-suggest profile match (by `applies_when`), (3) map fields via dropdowns with path autocompletion from the sample, set timestamp format/timezone and category rules, (4) preview 20 normalized rows and errors, (5) save profile, re-parse.

### 3.12 Reports
Options form: format, title, analyst name, include alert statuses, events per alert (0–50), include IOCs/MITRE/timeline/entities, include raw appendix. Preview HTML in an iframe with `sandbox` (no scripts). History table with SHA-256 and download.

### 3.13 Settings
General (timezone, theme, density), Detection (profile, auto-run, limits read-only), Allowlist editor, ATT&CK data (version, import bundle), Enrichment (opt-in, key entry), Data (data dir, disk usage, DB size, vacuum button), Audit log viewer with chain verification result.

## 4. States and behaviors (applies to every screen)

- **Loading**: skeletons (not spinners) for tables/cards; chart placeholders.
- **Empty**: purposeful text and a primary action (e.g., Alerts empty before detection → "Run detection"; after detection with zero alerts → "No detections matched. N rules ran, M skipped" with link to the run summary).
- **Error**: inline panel with code, message, "Retry"; global toast for background failures; offline/disconnected banner for WebSocket loss.
- **Large data**: all tables virtualized and server-paginated; never render > 500 DOM rows.
- **Destructive actions**: confirm dialog with typed name for case deletion; undo toast (10 s) for alert status changes.
- **Persistence**: filters in URL query params (shareable deep links), table column prefs in `localStorage`.
- **Copy**: every IOC/hash/IP/command has a copy button with toast; Shift+copy copies the defanged form.
- **Security in UI**: all log-derived strings rendered as text; no `dangerouslySetInnerHTML` anywhere (lint rule enforced); external links `rel="noopener noreferrer"`; strict CSP (see 10).

## 5. Keyboard shortcuts

`/` focus search · `g o/a/m/i/e/t/s/r` go to Overview/Alerts/MITRE/IOCs/Events/Timeline/Sources/Rules · `j/k` next/prev row · `Enter` open drawer · `Esc` close drawer/dialog · `t/f/b` mark alert true-positive/false-positive/benign · `x` select row · `?` shortcut cheat sheet · `[` / `]` collapse rail / widen drawer.

## 6. Accessibility

Semantic landmarks, table roles with `aria-rowcount`/`aria-rowindex` for virtualized tables, focus trap in drawers/dialogs, `aria-live="polite"` for job progress and toasts, full keyboard operability, reduced-motion support (`prefers-reduced-motion` disables chart/drawer animation).

## 7. Frontend quality gates

TypeScript `strict`, ESLint (with `no-danger`), Vitest + Testing Library component tests for tables/filters/drawers, Playwright E2E for the three scenarios in 09, bundle size budget < 1.5 MB gzipped, Lighthouse accessibility ≥ 95 on main screens.
