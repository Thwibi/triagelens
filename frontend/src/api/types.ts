/**
 * Typed wire types for the API surface.
 *
 * Every type mirrors the backend payload exactly; the compiler rejects any drift
 * at the call site instead of failing silently at runtime.
 */

/** `GET /api/health` response body. Every field is required by spec 08. */
export interface HealthReport {
  readonly app_version: string
  readonly attack_version: string
  readonly ruleset_hash: string
  readonly sqlite_version: string
  readonly fts5: boolean
  readonly json1: boolean
  readonly workers: number
  readonly db_bytes: number
  readonly free_disk_bytes: number
  readonly pdf_available: boolean
}

/** Stable error code from the spec 06 envelope. */
export type ApiErrorCode =
  | 'VALIDATION_ERROR'
  | 'UNAUTHORIZED'
  | 'NOT_FOUND'
  | 'CONFLICT'
  | 'INTERNAL'
  | 'UPLOAD_TOO_LARGE'
  | 'FORBIDDEN_PATH'
  | 'ARCHIVE_REJECTED'
  | 'PARSE_ERROR'
  | 'CAPABILITY_MISSING'
  | 'JOB_NOT_FOUND'

/** Every known code, for runtime validation of server responses. */
export const API_ERROR_CODES: readonly ApiErrorCode[] = [
  'VALIDATION_ERROR',
  'UNAUTHORIZED',
  'NOT_FOUND',
  'CONFLICT',
  'INTERNAL',
  'UPLOAD_TOO_LARGE',
  'FORBIDDEN_PATH',
  'ARCHIVE_REJECTED',
  'PARSE_ERROR',
  'CAPABILITY_MISSING',
  'JOB_NOT_FOUND',
] as const satisfies readonly ApiErrorCode[]

/** True when `value` is one of the spec 06 error codes. */
export function isApiErrorCode(value: string): value is ApiErrorCode {
  return (API_ERROR_CODES as readonly string[]).includes(value)
}

/** Machine-readable error envelope returned by every non-2xx API response. */
export interface ApiErrorEnvelope {
  readonly error: {
    readonly code: ApiErrorCode
    readonly message: string
    readonly details?: Readonly<Record<string, unknown>>
  }
}

/** One health field rendered as a labelled row. */
export interface HealthField {
  readonly label: string
  readonly value: string
  readonly state: HealthState
}

/** Visual state for a health field: OK, degraded, or a blocking problem. */
export type HealthState = 'ok' | 'degraded' | 'error'

/** Which health fields are required to be present for the app to be usable. */
export const REQUIRED_HEALTH_FIELDS: readonly (keyof HealthReport)[] = [
  'app_version',
  'attack_version',
  'ruleset_hash',
  'sqlite_version',
  'fts5',
  'json1',
  'workers',
  'db_bytes',
  'free_disk_bytes',
  'pdf_available',
] as const satisfies readonly (keyof HealthReport)[]

// ---------------------------------------------------------------------------
// Domain enums (mirror the backend CHECK constraints and Python enums)
// ---------------------------------------------------------------------------

/** `alerts.level` / rule level, loudest to quietest. */
export type AlertLevel = 'critical' | 'high' | 'medium' | 'low' | 'informational'

/** Ordered loudest-first, for sorting and severity roll-ups. */
export const ALERT_LEVELS: readonly AlertLevel[] = [
  'critical',
  'high',
  'medium',
  'low',
  'informational',
] as const satisfies readonly AlertLevel[]

/** `alerts.status` (spec 04 section 6). */
export type AlertStatus = 'new' | 'triaged' | 'true_positive' | 'false_positive' | 'benign'

/** Every alert status, in the backend's canonical order (spec 04 section 6). */
export const ALERT_STATUSES: readonly AlertStatus[] = [
  'new',
  'triaged',
  'true_positive',
  'false_positive',
  'benign',
] as const satisfies readonly AlertStatus[]

/** A source row's lifecycle, mirroring `sources.status`. */
export type SourceStatus =
  | 'queued'
  | 'needs_input'
  | 'parsing'
  | 'detecting'
  | 'done'
  | 'failed'
  | 'cancelled'

/** A job row's lifecycle, mirroring `jobs.status`. */
export type JobStatus = 'queued' | 'running' | 'needs_input' | 'done' | 'failed' | 'cancelled'

/** A job's work kind, mirroring `jobs.kind`. */
export type JobKind = 'ingest' | 'detect' | 'report' | 'rules_import'

/** An analyst's disposition of an IOC. */
export type AnalystState = 'none' | 'malicious' | 'suspicious' | 'benign'

// ---------------------------------------------------------------------------
// Query envelope
// ---------------------------------------------------------------------------

/** The paginated list envelope used across the API (spec 06 section 1). */
export interface ListEnvelope<T> {
  readonly items: readonly T[]
  readonly total?: number | null
  readonly limit?: number
  readonly offset?: number
  readonly next_cursor?: string | null
}

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

/** Roll-up counts a case carries. */
export interface CaseCounts {
  readonly sources: number
  readonly events: number
  readonly alerts: number
  readonly iocs: number
}

/** One case (`GET /api/cases`). */
export interface Case {
  readonly id: string
  readonly name: string
  readonly description: string | null
  readonly default_timezone: string
  readonly created_at: string
  readonly updated_at: string
  readonly counts: CaseCounts
}

// ---------------------------------------------------------------------------
// Sources
// ---------------------------------------------------------------------------

/** One ingested file (`GET /api/cases/{id}/sources`). */
export interface Source {
  readonly id: string
  readonly case_id: string
  readonly filename: string
  readonly parent_source_id: string | null
  readonly log_type: string | null
  readonly detect_confidence: number | null
  readonly timezone: string | null
  readonly assumed_year: number | null
  readonly status: SourceStatus
  readonly event_count: number
  readonly error_count: number
  readonly first_event_ms: number | null
  readonly last_event_ms: number | null
  readonly error_detail: string | null
  readonly size_bytes: number
  readonly sha256: string
}

/** One malformed record (`GET /api/sources/{id}/parse-errors`). */
export interface ParseError {
  readonly record_ref: string
  readonly reason: string
  readonly raw_excerpt: string | null
}

/** A ranked log-type guess returned for a `needs_input` source. */
export interface LogTypeCandidate {
  readonly log_type: string
  readonly score: number
}

// ---------------------------------------------------------------------------
// Jobs
// ---------------------------------------------------------------------------

/** One background job (`GET /api/jobs/{id}`). */
export interface Job {
  readonly id: string
  readonly case_id: string | null
  readonly kind: JobKind
  readonly source_id: string | null
  readonly status: JobStatus
  readonly stage: string | null
  readonly progress: number
  readonly message: string | null
  readonly error: string | null
  readonly created_at: string
  readonly started_at: string | null
  readonly finished_at: string | null
}

// ---------------------------------------------------------------------------
// Alerts
// ---------------------------------------------------------------------------

/** One ATT&CK tactic as the alert payload renders it. */
export interface AlertTactic {
  readonly shortname: string
  readonly name: string
}

/** One ATT&CK technique attached to an alert. */
export interface AlertTechnique {
  readonly id: string
  readonly name: string
  readonly tactics: readonly string[]
  readonly source: 'tag' | 'fallback'
}

/** One ATT&CK group or software the rule references. */
export interface GroupSoftware {
  readonly id: string
  readonly name: string
  readonly kind: string
}

/** An alert list row (`GET /api/cases/{id}/alerts`). */
export interface Alert {
  readonly id: string
  readonly case_id: string
  readonly rule_id: string
  readonly rule_title: string
  readonly rule_kind: string
  readonly rule_type: string
  readonly level: AlertLevel
  readonly score: number
  readonly status: AlertStatus
  readonly analyst_notes: string | null
  readonly tactics: readonly AlertTactic[]
  readonly techniques: readonly AlertTechnique[]
  readonly groups_software: readonly GroupSoftware[]
  readonly unresolved_tags: readonly string[]
  readonly host: string | null
  readonly user_name: string | null
  readonly first_seen_ms: number | null
  readonly last_seen_ms: number | null
  readonly match_count: number
  readonly false_positives: readonly string[]
  readonly references: readonly string[]
}

/** One line of the alert's score arithmetic (`AlertDetail.score_breakdown`). */
export interface ScoreBreakdownEntry {
  readonly label: string
  readonly delta: number
}

/** A single normalized event as the alert detail and evidence list show it. */
export interface AlertEventBrief {
  readonly id: number
  readonly source_id: string
  readonly record_ref: string
  readonly ts_ms: number | null
  readonly ts_iso: string | null
  readonly log_type: string | null
  readonly ls_category: string | null
  readonly host: string | null
  readonly channel: string | null
  readonly app_name: string | null
  readonly event_id: string | null
  readonly level: string | null
  readonly event_action: string | null
  readonly user_name: string | null
  readonly src_ip: string | null
  readonly dst_ip: string | null
  readonly message: string | null
}

/** An indicator linked to an alert (`AlertDetail.iocs`). */
export interface AlertIoc {
  readonly id: string
  readonly type: string
  readonly value: string
  readonly value_norm: string
  readonly confidence: number
}

/** The detected rule behind an alert, with its YAML (`AlertDetail.rule`). */
export interface AlertRuleDetail {
  readonly id: string
  readonly title: string
  readonly description: string | null
  readonly yaml: string
}

/** `GET /api/alerts/{id}`: the list row plus breakdown, evidence and rule. */
export interface AlertDetail extends Alert {
  readonly score_breakdown: readonly ScoreBreakdownEntry[]
  readonly events: readonly AlertEventBrief[]
  readonly iocs: readonly AlertIoc[]
  readonly rule?: AlertRuleDetail
}

// ---------------------------------------------------------------------------
// Timeline
// ---------------------------------------------------------------------------

/** One timeline bucket (`GET /api/cases/{id}/timeline`). */
export interface TimelineBucket {
  readonly t_ms: number
  readonly count: number
  readonly by_log_type: Readonly<Record<string, number>>
  readonly alert_count: number
}

/** Bucketed event volume under the current filters. */
export interface Timeline {
  readonly bucket_ms: number
  readonly buckets: readonly TimelineBucket[]
}

// ---------------------------------------------------------------------------
// MITRE
// ---------------------------------------------------------------------------

/** One technique cell in the case matrix. */
export interface MitreTechniqueCell {
  readonly id: string
  readonly name: string
  readonly alert_count: number
  readonly max_level: AlertLevel | null
  readonly alert_ids: readonly string[]
  readonly subtechniques: readonly MitreTechniqueCell[]
}

/** One tactic column in the case matrix. */
export interface MitreTactic {
  readonly shortname: string
  readonly name: string
  readonly techniques: readonly MitreTechniqueCell[]
}

/** `GET /api/cases/{id}/mitre`. */
export interface CaseMitreMatrix {
  readonly attack_version: string
  readonly tactics: readonly MitreTactic[]
  readonly unmapped_alert_count: number
}

/** One technique in the static reference matrix (no alert counts). */
export interface MitreStaticTechnique {
  readonly id: string
  readonly name: string
  readonly subtechniques: readonly MitreStaticTechnique[]
}

/** One tactic column in the static reference matrix. */
export interface MitreStaticTactic {
  readonly shortname: string
  readonly name: string
  readonly techniques: readonly MitreStaticTechnique[]
}

/** `GET /api/mitre/matrix`: the full ATT&CK matrix, independent of any case. */
export interface MitreStaticMatrix {
  readonly attack_version: string
  readonly tactics: readonly MitreStaticTactic[]
}

// ---------------------------------------------------------------------------
// IOCs and entities
// ---------------------------------------------------------------------------

/** One indicator (`GET /api/cases/{id}/iocs`). */
export interface Ioc {
  readonly id: string
  readonly case_id: string
  readonly type: string
  readonly value: string
  readonly value_norm: string
  readonly first_seen_ms: number | null
  readonly last_seen_ms: number | null
  readonly occurrences: number
  readonly confidence: number
  readonly is_private: boolean
  readonly is_allowlisted: boolean
  readonly analyst_state: AnalystState
  readonly tags: readonly string[]
}

/** Where one indicator was seen, newest event first (`IocDetail`). */
export interface IocOccurrence {
  readonly event_id: number
  readonly field: string
  readonly role: string
  readonly decoded_from: string | null
  readonly ts_ms: number | null
  readonly host: string | null
  readonly log_type: string | null
  readonly source_id: string
  readonly message: string | null
}

/** `GET /api/iocs/{id}`: the indicator plus a bounded occurrence preview. */
export interface IocDetail extends Ioc {
  readonly occurrences_preview: readonly IocOccurrence[]
}

/** One host or user with counts (`GET /api/cases/{id}/entities`). */
export interface Entity {
  readonly kind: string
  readonly name: string
  readonly event_count: number
  readonly alert_count: number
}

// ---------------------------------------------------------------------------
// Detection runs
// ---------------------------------------------------------------------------

/** One detection run (`GET /api/cases/{id}/detection-runs`). */
export interface DetectionRun {
  readonly id: string
  readonly case_id: string
  readonly profile: string
  readonly tool_version: string
  readonly ruleset_hash: string
  readonly attack_version: string
  readonly started_at: string | null
  readonly finished_at: string | null
  readonly status: string
  readonly counts: {
    readonly rules: number
    readonly alerts: number
  }
}

/** A detection profile level (spec 04 section 2). */
export type DetectionProfile = 'fast' | 'standard' | 'full'

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

/**
 * One normalized event row (`GET /api/cases/{id}/events`, spec 06).
 *
 * `fields` is the untouched provider record as a JSON object; `raw` is present
 * only on the detail payload (`include=raw`). Both are log-derived and must be
 * rendered as text, never as markup.
 */
export interface EventRecord {
  readonly id: number
  readonly case_id: string
  readonly source_id: string
  readonly record_ref: string
  readonly ts_ms: number | null
  readonly ts_iso: string | null
  readonly log_type: string | null
  readonly ls_category: string | null
  readonly host: string | null
  readonly channel: string | null
  readonly provider: string | null
  readonly app_name: string | null
  readonly event_id: number | null
  readonly level: string | null
  readonly event_action: string | null
  readonly event_outcome: string | null
  readonly user_name: string | null
  readonly target_user_name: string | null
  readonly domain: string | null
  readonly src_ip: string | null
  readonly src_port: number | null
  readonly dst_ip: string | null
  readonly dst_port: number | null
  readonly protocol: string | null
  readonly process_pid: number | null
  readonly process_path: string | null
  readonly process_cmdline: string | null
  readonly parent_process_path: string | null
  readonly parent_process_cmdline: string | null
  readonly file_path: string | null
  readonly registry_key: string | null
  readonly registry_value: string | null
  readonly url: string | null
  readonly url_path: string | null
  readonly url_query: string | null
  readonly http_method: string | null
  readonly http_status: number | null
  readonly user_agent: string | null
  readonly bytes_out: number | null
  readonly message: string | null
  readonly fields: Readonly<Record<string, unknown>>
  readonly raw?: string | null
}

/** An indicator that occurred in one event (`EventDetail.iocs`). */
export interface EventIocBrief {
  readonly id: string
  readonly type: string
  readonly value: string
  readonly value_norm: string
  readonly confidence: number
}

/** `GET /api/events/{id}`: the full record plus linked alerts and IOCs. */
export interface EventDetail extends EventRecord {
  readonly raw: string | null
  readonly alerts: readonly Alert[]
  readonly iocs: readonly EventIocBrief[]
}

/** One facet bucket: a distinct value and how many events carry it. */
export interface FacetValue {
  readonly value: string | number
  readonly count: number
}

/** `GET /api/cases/{id}/events/facets`: top values per facet column. */
export interface EventFacets {
  readonly facets: Readonly<Record<string, readonly FacetValue[]>>
}

// ---------------------------------------------------------------------------
// Events (count only, used by Overview KPI tiles)
// ---------------------------------------------------------------------------

/** `GET /api/cases/{id}/events/count`. */
export interface EventCount {
  readonly count: number
}

// ---------------------------------------------------------------------------
// WebSocket frames (spec 06 section 4)
// ---------------------------------------------------------------------------

/** A job progress frame. */
export interface WsJobStage {
  readonly type: 'job.stage'
  readonly job_id: string
  readonly stage: string
  readonly progress: number
  readonly events: number
  readonly errors: number
  readonly rate_eps: number
}

/** A whole-job update frame. */
export interface WsJobUpdate {
  readonly type: 'job.update'
  readonly job: Job
}

/** A source row changed. */
export interface WsSourceUpdate {
  readonly type: 'source.update'
  readonly source: Source
}

/** The case's alert set changed; the UI should refetch. */
export interface WsAlertsChanged {
  readonly type: 'alerts.changed'
  readonly case_id: string
  readonly new_alerts: number
}

/** A source needs an operator's log-type decision. */
export interface WsNeedsInput {
  readonly type: 'needs_input'
  readonly job_id: string
  readonly source_id: string
  readonly candidates: readonly LogTypeCandidate[]
}

/** A server-side error frame. */
export interface WsError {
  readonly type: 'error'
  readonly code: string
  readonly message: string
}

/** A heartbeat. */
export interface WsPing {
  readonly type: 'ping'
}

// ---------------------------------------------------------------------------
// Mapping profiles (spec 06 section 3, spec 07 section 3.11)
// ---------------------------------------------------------------------------

/** The `applies_when` block that makes a profile plausible for a record. */
export interface ProfileAppliesWhen {
  readonly any_key: readonly string[]
}

/** A `category_rules` entry: field equality tests, first match wins. */
export interface ProfileCategoryRule {
  readonly when: Readonly<Record<string, unknown>>
  readonly ls_category: string
}

/** One mapping profile as `GET /api/profiles` returns it (no raw YAML). */
export interface MappingProfile {
  readonly name: string
  readonly builtin: boolean
  readonly timestamp: { readonly path: string; readonly format: string }
  readonly timezone: string | null
  readonly default_category: string | null
  readonly applies_when: ProfileAppliesWhen
  readonly fields: Readonly<Record<string, string>>
  readonly category_rules: readonly ProfileCategoryRule[]
}

/** One mapping profile plus its YAML source (`GET /api/profiles/{name}`). */
export interface MappingProfileDetail extends MappingProfile {
  readonly yaml: string
}

/** One normalized row from a preview (`POST /api/profiles/preview`). */
export interface PreviewRow {
  readonly ts_ms?: number | null
  readonly ts_iso?: string | null
  readonly host?: string | null
  readonly user_name?: string | null
  readonly level?: string | null
  readonly event_action?: string | null
  readonly src_ip?: string | null
  readonly dst_ip?: string | null
  readonly url?: string | null
  readonly message?: string | null
  readonly fields?: Readonly<Record<string, unknown>>
}

/** One rejected record from a preview. */
export interface PreviewError {
  readonly record_ref: string
  readonly reason: string
}

/** The dry-run result of parsing a sample through a profile. */
export interface ProfilePreview {
  readonly log_type: string
  readonly rows: readonly PreviewRow[]
  readonly errors: readonly PreviewError[]
  readonly row_count: number
  readonly error_count: number
}

/** Every frame the server may push. */
export type ServerFrame =
  | WsJobStage
  | WsJobUpdate
  | WsSourceUpdate
  | WsAlertsChanged
  | WsNeedsInput
  | WsError
  | WsPing

// ---------------------------------------------------------------------------
// Rule catalogue (spec 06 "Rules", spec 07 section 3.10)
// ---------------------------------------------------------------------------

/** One rule row (`GET /api/rules`). */
export interface Rule {
  readonly id: string
  readonly title: string
  readonly kind: string
  readonly rule_type: string
  readonly level: string
  readonly status: string
  readonly enabled: boolean
  readonly tags: readonly string[]
  readonly logsource: Readonly<Record<string, unknown>>
  readonly file_path: string
  readonly sha256: string
  readonly compile_error: string | null
  readonly unroutable: boolean
  readonly healthy: boolean
  readonly updated_at: string
}

/** One rule plus its YAML (`GET /api/rules/{id}`). */
export interface RuleDetail extends Rule {
  readonly yaml: string
}

/** A rule load problem (`POST /api/rules/validate`). */
export interface RuleProblem {
  readonly where: string
  readonly error: string
}

/** `GET /api/rules/health`: bucket counts keyed by health class. */
export interface RuleHealthCounts {
  readonly total: number
  readonly ok?: number
  readonly compile_error?: number
  readonly unroutable?: number
  readonly [bucket: string]: number | undefined
}

/** `POST /api/rules/validate` result. */
export interface RuleValidateResult {
  readonly valid: boolean
  readonly rules: readonly Rule[]
  readonly problems: readonly RuleProblem[]
}

/** `POST /api/rules/test` result (samples are raw-free event briefs). */
export interface RuleTestResult {
  readonly rule: Rule
  readonly executed: boolean
  readonly total_matches: number
  readonly items: readonly AlertEventBrief[]
}

/** `POST /api/rules/import` result. */
export interface RuleImportResult {
  readonly job: Job
  readonly imported: number
  readonly synced: number
  readonly stale_removed: number
  readonly files: readonly string[]
  readonly problems: readonly RuleProblem[]
}

// ---------------------------------------------------------------------------
// Settings, allowlist and audit (spec 06 "Health and settings")
// ---------------------------------------------------------------------------

/** One global allowlist entry. */
export interface AllowlistEntry {
  readonly id: number
  readonly scope: string
  readonly case_id: string | null
  readonly kind: string
  readonly value: string
  readonly note: string | null
}

/** `GET`/`PUT /api/settings`: effective config, overrides and the allowlist. */
export interface SettingsPayload {
  readonly settings: Readonly<Record<string, unknown>>
  readonly overrides: Readonly<Record<string, unknown>>
  readonly allowlist: readonly AllowlistEntry[]
}

/** One audit-chain row (`GET /api/cases/{id}/audit-log`). */
export interface AuditEntry {
  readonly id: number
  readonly ts: string
  readonly case_id: string
  readonly action: string
  readonly detail: unknown
  readonly prev_hash: string | null
  readonly hash: string
}

/** The audit page plus its chain-verification result. */
export interface AuditLog {
  readonly items: readonly AuditEntry[]
  readonly total: number
  readonly limit: number
  readonly offset: number
  readonly chain_ok: boolean
  readonly rows_checked: number
  readonly broken_at?: number
  readonly broken_reason?: string
}

/** `POST /api/settings/attack/import` result. */
export interface AttackImportResult {
  readonly attack_version: string
  readonly techniques: number
}

// ---------------------------------------------------------------------------
// Reports (spec 06 "Reports", spec 07 section 3.12, spec 08)
// ---------------------------------------------------------------------------

/** The four report formats the backend can render (spec 08 section 1). */
export type ReportFormat = 'html' | 'pdf' | 'md' | 'json'

/** The options object stored alongside a generated report. */
export interface ReportOptions {
  readonly format: ReportFormat
  readonly statuses: readonly string[]
  readonly events_per_alert: number
  readonly iocs: boolean
  readonly mitre: boolean
  readonly timeline: boolean
  readonly entities: boolean
  readonly appendix_raw: boolean
}

/** One generated report row (`GET /api/cases/{id}/reports`). */
export interface Report {
  readonly id: string
  readonly case_id: string
  readonly format: ReportFormat
  readonly sha256: string
  readonly created_at: string
  readonly options: ReportOptions
}

/** The section toggles of a report request (spec 08 section 1). */
export interface ReportIncludeBody {
  readonly alerts?: readonly string[] | undefined
  readonly iocs?: boolean | undefined
  readonly mitre?: boolean | undefined
  readonly timeline?: boolean | undefined
  readonly entities?: boolean | undefined
  readonly appendix_raw?: boolean | undefined
  readonly events_per_alert?: number | undefined
}

/** Body of `POST /api/cases/{id}/reports`. */
export interface ReportRequestBody {
  readonly format: ReportFormat
  readonly title?: string | undefined
  readonly analyst?: string | undefined
  readonly include?: ReportIncludeBody | undefined
}

// ---------------------------------------------------------------------------
// Maintenance (spec 10 section 5, spec 07 section 3.13)
// ---------------------------------------------------------------------------

/** Result of `POST /api/maintenance/vacuum`. */
export interface VacuumResult {
  readonly ok: boolean
  readonly db_bytes_before: number
  readonly db_bytes_after: number
}

/** Result of `POST /api/maintenance/rebuild-fts`. */
export interface RebuildFtsResult {
  readonly ok: boolean
  readonly indexed: number
}

/** One source whose stored file failed verification. */
export interface HashMismatch {
  readonly source_id: string
  readonly case_id: string
  readonly path: string
}

/** Result of `POST /api/maintenance/verify-hashes` (spec 10 section 2). */
export interface VerifyHashesResult {
  readonly ok: boolean
  readonly checked: number
  readonly mismatched: readonly HashMismatch[]
  readonly missing: readonly HashMismatch[]
}

/** Result of `POST /api/maintenance/verify-audit`. */
export interface VerifyAuditResult {
  readonly chain_ok: boolean
  readonly rows_checked: number
  readonly broken_at?: number | undefined
  readonly broken_reason?: string | undefined
}