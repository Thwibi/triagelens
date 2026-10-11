import {
  expectArray,
  expectRecord,
  getForFile,
  getJson,
  postForFile,
  requestForm,
  requestJson,
} from './client'
import type { DownloadedFile, JsonRequestOptions, RequestOptions } from './client'
import type {
  DetectBody as DetectBodySchema,
  AlertBulkBody,
  AlertPatchBody,
  AllowlistBody as AllowlistBodySchema,
  PatchCaseBody as PatchCaseBodySchema,
  PatchSourceBody as PatchSourceBodySchema,
  PreviewProfileBody as PreviewProfileBodySchema,
  ResolveSourceBody as ResolveSourceBodySchema,
  RuleEnabledBody as RuleEnabledBodySchema,
  RuleTestBody as RuleTestBodySchema,
  RuleYamlBody as RuleYamlBodySchema,
  SaveProfileBody,
  SettingsUpdateBody as SettingsUpdateBodySchema,
} from './schema'
import type {
  Alert,
  AlertDetail,
  AlertEventBrief,
  AlertLevel,
  AlertStatus,
  AllowlistEntry,
  AnalystState,
  AttackImportResult,
  AuditLog,
  Case,
  CaseMitreMatrix,
  DetectionRun,
  Entity,
  EventDetail,
  EventFacets,
  EventRecord,
  Ioc,
  IocDetail,
  IocOccurrence,
  Job,
  ListEnvelope,
  LogTypeCandidate,
  MappingProfile,
  MappingProfileDetail,
  MitreStaticMatrix,
  ParseError,
  ProfilePreview,
  Report,
  ReportRequestBody,
  RebuildFtsResult,
  Rule,
  RuleDetail,
  RuleHealthCounts,
  RuleImportResult,
  RuleProblem,
  RuleTestResult,
  RuleValidateResult,
  SettingsPayload,
  Source,
  Timeline,
  VacuumResult,
  VerifyAuditResult,
  VerifyHashesResult,
} from './types'
/** Query values the endpoints accept: primitives, arrays, or nothing. */
export type QueryValue = string | number | boolean | null | undefined | readonly string[]

/**
 * Build a query string from a filter object.
 *
 * `undefined`/`null` are dropped (rather than sent as the string "undefined"),
 * and array values become repeated keys, which is what the backend's list
 * parsers expect.
 */
export function buildQuery(params: Readonly<Record<string, QueryValue>>): string {
  const search = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null) {
      continue
    }
    if (Array.isArray(value)) {
      for (const item of value) {
        search.append(key, String(item))
      }
    } else {
      search.append(key, String(value))
    }
  }
  const encoded = search.toString()
  return encoded.length === 0 ? '' : `?${encoded}`
}

/** Confirms a list envelope has an `items` array and returns it typed. */
function readItems<T>(body: unknown, what: string): ListEnvelope<T> {
  const record = expectRecord(body, what)
  const items = expectArray(record['items'], what) as readonly T[]
  return { ...record, items }
}

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

export async function listCases(options: RequestOptions = {}): Promise<ListEnvelope<Case>> {
  return readItems<Case>(await getJson('/api/cases', options), 'cases')
}

export async function getCase(caseId: string, options: RequestOptions = {}): Promise<Case> {
  return (await getJson(`/api/cases/${encodeURIComponent(caseId)}`, options)) as Case
}

export interface CreateCaseBody {
  readonly name: string
  readonly description?: string
  readonly default_timezone?: string
}

export async function createCase(body: CreateCaseBody, options: RequestOptions = {}): Promise<Case> {
  return (await requestJson('/api/cases', { ...options, json: body })) as Case
}

export type PatchCaseBody = PatchCaseBodySchema

export async function patchCase(
  caseId: string,
  body: PatchCaseBody,
  options: RequestOptions = {},
): Promise<Case> {
  return (await requestJson(`/api/cases/${encodeURIComponent(caseId)}`, {
    ...options,
    method: 'PATCH',
    json: body,
  })) as Case
}

export async function deleteCase(caseId: string, options: RequestOptions = {}): Promise<void> {
  await requestJson(`/api/cases/${encodeURIComponent(caseId)}`, { ...options, method: 'DELETE' })
}

// ---------------------------------------------------------------------------
// Sources
// ---------------------------------------------------------------------------

export async function listSources(
  caseId: string,
  options: RequestOptions = {},
): Promise<ListEnvelope<Source>> {
  return readItems<Source>(
    await getJson(`/api/cases/${encodeURIComponent(caseId)}/sources`, options),
    'sources',
  )
}

export async function getSource(sourceId: string, options: RequestOptions = {}): Promise<Source> {
  return (await getJson(`/api/sources/${encodeURIComponent(sourceId)}`, options)) as Source
}

export interface UploadOptions extends RequestOptions {
  readonly logType?: string
  readonly timezone?: string
  readonly assumedYear?: number
}

/** POST the dropped files to a case and return the created jobs and sources. */
export async function uploadSources(
  caseId: string,
  files: readonly File[],
  options: UploadOptions = {},
): Promise<{ readonly jobs: readonly Job[]; readonly sources: readonly Source[] }> {
  const form = new FormData()
  for (const file of files) {
    form.append('files', file, file.name)
  }
  if (options.logType !== undefined) {
    form.append('log_type', options.logType)
  }
  if (options.timezone !== undefined) {
    form.append('timezone', options.timezone)
  }
  if (options.assumedYear !== undefined) {
    form.append('assumed_year', String(options.assumedYear))
  }
  const body = expectRecord(
    await requestForm(`/api/cases/${encodeURIComponent(caseId)}/sources`, form, options),
    'upload',
  )
  return {
    jobs: expectArray(body['jobs'], 'upload') as readonly Job[],
    sources: expectArray(body['sources'], 'upload') as readonly Source[],
  }
}

export type ResolveSourceBody = ResolveSourceBodySchema

export async function resolveSource(
  sourceId: string,
  body: ResolveSourceBody,
  options: RequestOptions = {},
): Promise<{ readonly job: Job; readonly source: Source }> {
  const record = expectRecord(
    await requestJson(`/api/sources/${encodeURIComponent(sourceId)}/resolve`, { ...options, json: body }),
    'resolve',
  )
  return { job: record['job'] as Job, source: record['source'] as Source }
}

export type PatchSourceBody = PatchSourceBodySchema

export async function patchSource(
  sourceId: string,
  body: PatchSourceBody,
  options: RequestOptions = {},
): Promise<{ readonly job?: Job; readonly source: Source }> {
  const record = expectRecord(
    await requestJson(`/api/sources/${encodeURIComponent(sourceId)}`, {
      ...options,
      method: 'PATCH',
      json: body,
    }),
    'source',
  )
  if ('job' in record) {
    return { job: record['job'] as Job, source: record['source'] as Source }
  }
  return { source: record as unknown as Source }
}

export async function deleteSource(sourceId: string, options: RequestOptions = {}): Promise<void> {
  await requestJson(`/api/sources/${encodeURIComponent(sourceId)}`, { ...options, method: 'DELETE' })
}

export async function listParseErrors(
  sourceId: string,
  page = 1,
  options: RequestOptions = {},
): Promise<ListEnvelope<ParseError>> {
  return readItems<ParseError>(
    await getJson(`/api/sources/${encodeURIComponent(sourceId)}/parse-errors${buildQuery({ page })}`, options),
    'parse errors',
  )
}

/** The URL an anchor can point at to download the stored original. */
export function sourceDownloadUrl(sourceId: string): string {
  return `/api/sources/${encodeURIComponent(sourceId)}/download`
}

// ---------------------------------------------------------------------------
// Jobs
// ---------------------------------------------------------------------------

export async function listCaseJobs(
  caseId: string,
  options: RequestOptions = {},
): Promise<ListEnvelope<Job>> {
  return readItems<Job>(await getJson(`/api/cases/${encodeURIComponent(caseId)}/jobs`, options), 'jobs')
}

export async function getJob(jobId: string, options: RequestOptions = {}): Promise<Job> {
  return (await getJson(`/api/jobs/${encodeURIComponent(jobId)}`, options)) as Job
}

export async function cancelJob(jobId: string, options: RequestOptions = {}): Promise<void> {
  await requestJson(`/api/jobs/${encodeURIComponent(jobId)}`, { ...options, method: 'DELETE' })
}

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

export type DetectBody = DetectBodySchema

export async function runDetection(
  caseId: string,
  body: DetectBody = {},
  options: RequestOptions = {},
): Promise<Job> {
  return (await requestJson(`/api/cases/${encodeURIComponent(caseId)}/detect`, {
    ...options,
    json: body,
  })) as Job
}

export async function listDetectionRuns(
  caseId: string,
  options: RequestOptions = {},
): Promise<ListEnvelope<DetectionRun>> {
  return readItems<DetectionRun>(
    await getJson(`/api/cases/${encodeURIComponent(caseId)}/detection-runs`, options),
    'detection runs',
  )
}

// ---------------------------------------------------------------------------
// Alerts (list is used by Overview's "top alerts")
// ---------------------------------------------------------------------------

export interface AlertFilters {
  readonly level?: AlertLevel | undefined
  readonly status?: AlertStatus | undefined
  readonly rule_id?: string | undefined
  readonly host?: string | undefined
  readonly user_name?: string | undefined
  readonly min_score?: number | undefined
  readonly q?: string | undefined
  readonly tactic?: string | undefined
  readonly technique?: string | undefined
  readonly unmapped?: boolean | undefined
  readonly sort?: string | undefined
  readonly limit?: number | undefined
  readonly offset?: number | undefined
}

export async function listAlerts(
  caseId: string,
  filters: AlertFilters = {},
  options: RequestOptions = {},
): Promise<ListEnvelope<Alert>> {
  return readItems<Alert>(
    await getJson(`/api/cases/${encodeURIComponent(caseId)}/alerts${buildQuery({ ...filters })}`, options),
    'alerts',
  )
}

/** One alert with its score breakdown, evidence, linked IOCs and rule. */
export async function getAlert(alertId: string, options: RequestOptions = {}): Promise<AlertDetail> {
  return (await getJson(`/api/alerts/${encodeURIComponent(alertId)}`, options)) as AlertDetail
}

/** Set an analyst verdict and/or notes on one alert. */
export async function patchAlert(
  alertId: string,
  body: AlertPatchBody,
  options: RequestOptions = {},
): Promise<Alert> {
  const record = expectRecord(
    await requestJson(`/api/alerts/${encodeURIComponent(alertId)}`, {
      ...options,
      method: 'PATCH',
      json: body,
    }),
    'alert',
  )
  return record['item'] as Alert
}

/** Set the same verdict on many alerts (spec 06). */
export async function bulkUpdateAlerts(
  body: AlertBulkBody,
  options: RequestOptions = {},
): Promise<{ readonly items: readonly Alert[]; readonly updated: number }> {
  const record = expectRecord(
    await requestJson('/api/alerts/bulk', { ...options, method: 'POST', json: body }),
    'alerts',
  )
  return {
    items: expectArray(record['items'], 'alerts') as readonly Alert[],
    updated: Number(record['updated'] ?? 0),
  }
}

/** Evidence events beyond the stored sample (spec 06). */
export async function listAlertEvidence(
  alertId: string,
  page = 1,
  limit = 100,
  options: RequestOptions = {},
): Promise<ListEnvelope<AlertEventBrief>> {
  const offset = Math.max(0, (page - 1) * limit)
  return readItems<AlertEventBrief>(
    await getJson(
      `/api/alerts/${encodeURIComponent(alertId)}/events${buildQuery({ limit, offset })}`,
      options,
    ),
    'alert evidence',
  )
}

// ---------------------------------------------------------------------------
// Events / timeline / entities / IOCs / MITRE (Overview inputs)
// ---------------------------------------------------------------------------

/** Every documented event filter (spec 06 "Events"). */
export interface EventFilters {
  readonly q?: string | undefined
  readonly from_ms?: number | undefined
  readonly to_ms?: number | undefined
  readonly host?: string | undefined
  readonly source_id?: string | undefined
  readonly log_type?: string | undefined
  readonly channel?: string | undefined
  readonly event_id?: number | undefined
  readonly ls_category?: string | undefined
  readonly user_name?: string | undefined
  readonly src_ip?: string | undefined
  readonly dst_ip?: string | undefined
  readonly ioc_id?: string | undefined
  readonly alert_id?: string | undefined
  readonly level?: string | undefined
  readonly include?: 'raw' | undefined
  readonly sort?: 'ts' | '-ts' | undefined
  readonly limit?: number | undefined
  readonly cursor?: string | undefined
}

export async function listEvents(
  caseId: string,
  filters: EventFilters = {},
  options: RequestOptions = {},
): Promise<ListEnvelope<EventRecord>> {
  return readItems<EventRecord>(
    await getJson(`/api/cases/${encodeURIComponent(caseId)}/events${buildQuery({ ...filters })}`, options),
    'events',
  )
}

export async function countEvents(
  caseId: string,
  filters: EventFilters = {},
  options: RequestOptions = {},
): Promise<number> {
  const record = expectRecord(
    await getJson(`/api/cases/${encodeURIComponent(caseId)}/events/count${buildQuery({ ...filters })}`, options),
    'event count',
  )
  return Number(record['count'] ?? 0)
}

export async function listEventFacets(
  caseId: string,
  filters: EventFilters = {},
  options: RequestOptions = {},
): Promise<EventFacets> {
  return (await getJson(
    `/api/cases/${encodeURIComponent(caseId)}/events/facets${buildQuery({ ...filters })}`,
    options,
  )) as EventFacets
}

export async function getEvent(eventId: number, options: RequestOptions = {}): Promise<EventDetail> {
  return (await getJson(`/api/events/${eventId}`, options)) as EventDetail
}

/** The two event export formats the backend streams (spec 07 section 3.7). */
export type EventExportFormat = 'csv' | 'jsonl'

/**
 * Stream the current event filter result set as a downloadable file.
 *
 * The backend caps the export at one million rows regardless of the requested
 * `limit`, so the request may run far longer than the default JSON timeout;
 * callers pass a generous `timeoutMs`.
 */
export async function exportEvents(
  caseId: string,
  format: EventExportFormat,
  filters: EventFilters = {},
  options: RequestOptions = {},
): Promise<DownloadedFile> {
  return getForFile(
    `/api/cases/${encodeURIComponent(caseId)}/events/export${buildQuery({
      format,
      q: filters.q,
      from_ms: filters.from_ms,
      to_ms: filters.to_ms,
      host: filters.host,
      source_id: filters.source_id,
      log_type: filters.log_type,
      channel: filters.channel,
      event_id: filters.event_id,
      ls_category: filters.ls_category,
      user_name: filters.user_name,
      src_ip: filters.src_ip,
      dst_ip: filters.dst_ip,
      ioc_id: filters.ioc_id,
      alert_id: filters.alert_id,
      level: filters.level,
      sort: filters.sort,
    })}`,
    options,
  )
}

/** Named timeline bucket sizes accepted by `/timeline` (spec 06). */
export type TimelineBucketSize = 'auto' | '1m' | '5m' | '1h' | '1d'

export async function getTimeline(
  caseId: string,
  bucket: TimelineBucketSize = 'auto',
  options: RequestOptions = {},
): Promise<Timeline> {
  return (await getJson(
    `/api/cases/${encodeURIComponent(caseId)}/timeline${buildQuery({ bucket })}`,
    options,
  )) as Timeline
}

/** The timeline under the event filters (used by the Timeline screen). */
export async function getFilteredTimeline(
  caseId: string,
  filters: EventFilters = {},
  bucket: TimelineBucketSize = 'auto',
  options: RequestOptions = {},
): Promise<Timeline> {
  return (await getJson(
    `/api/cases/${encodeURIComponent(caseId)}/timeline${buildQuery({ ...filters, bucket })}`,
    options,
  )) as Timeline
}

export async function listEntities(
  caseId: string,
  options: RequestOptions = {},
): Promise<readonly Entity[]> {
  return expectArray(
    await getJson(`/api/cases/${encodeURIComponent(caseId)}/entities`, options),
    'entities',
  ) as readonly Entity[]
}

export interface IocFilters {
  readonly type?: string | undefined
  readonly min_confidence?: number | undefined
  readonly q?: string | undefined
  readonly host?: string | undefined
  readonly state?: AnalystState | undefined
  readonly include_private?: boolean | undefined
  readonly include_allowlisted?: boolean | undefined
  readonly limit?: number | undefined
  readonly offset?: number | undefined
  readonly sort?: string | undefined
  readonly order?: 'asc' | 'desc' | undefined
}

export async function listIocs(
  caseId: string,
  filters: IocFilters = {},
  options: RequestOptions = {},
): Promise<ListEnvelope<Ioc>> {
  return readItems<Ioc>(
    await getJson(`/api/cases/${encodeURIComponent(caseId)}/iocs${buildQuery({ ...filters })}`, options),
    'iocs',
  )
}

/** One indicator with its occurrence preview (`GET /api/iocs/{id}`). */
export async function getIoc(iocId: string, options: RequestOptions = {}): Promise<IocDetail> {
  return (await getJson(`/api/iocs/${encodeURIComponent(iocId)}`, options)) as IocDetail
}

/** Every place one indicator was seen, newest first (spec 06). */
export async function listIocOccurrences(
  iocId: string,
  limit = 500,
  options: RequestOptions = {},
): Promise<ListEnvelope<IocOccurrence>> {
  return readItems<IocOccurrence>(
    await getJson(`/api/iocs/${encodeURIComponent(iocId)}/occurrences${buildQuery({ limit })}`, options),
    'ioc occurrences',
  )
}

/** `PATCH /api/iocs/{id}` body (spec 06). */
export interface IocPatchBody {
  readonly analyst_state?: AnalystState
  readonly tags?: readonly string[]
  readonly allowlist?: boolean
}

export async function patchIoc(
  iocId: string,
  body: IocPatchBody,
  options: RequestOptions = {},
): Promise<Ioc> {
  return (await requestJson(`/api/iocs/${encodeURIComponent(iocId)}`, {
    ...options,
    method: 'PATCH',
    json: body,
  })) as Ioc
}

/** The four IOC export formats the backend can render (spec 05 section 8). */
export type IocExportFormat = 'csv' | 'txt' | 'stix' | 'json'

export interface IocExportBody {
  readonly format: IocExportFormat
  readonly ids?: readonly string[] | undefined
  readonly filters?: Readonly<Record<string, unknown>> | undefined
  readonly defang?: boolean | undefined
}

export async function exportIocs(
  caseId: string,
  body: IocExportBody,
  options: RequestOptions = {},
): Promise<DownloadedFile> {
  return postForFile(
    `/api/cases/${encodeURIComponent(caseId)}/iocs/export`,
    { ...body, ids: body.ids !== undefined ? [...body.ids] : undefined },
    options,
  )
}

export async function getCaseMitre(
  caseId: string,
  options: RequestOptions = {},
): Promise<CaseMitreMatrix> {
  return (await getJson(
    `/api/cases/${encodeURIComponent(caseId)}/mitre`,
    options,
  )) as CaseMitreMatrix
}

/** The full ATT&CK matrix, independent of any case (spec 06). */
export async function getMitreStatic(options: RequestOptions = {}): Promise<MitreStaticMatrix> {
  return (await getJson('/api/mitre/matrix', options)) as MitreStaticMatrix
}

/** The ATT&CK Navigator layer for one case (spec 08 section 3). */
export async function getMitreNavigatorLayer(
  caseId: string,
  options: RequestOptions = {},
): Promise<Readonly<Record<string, unknown>>> {
  return expectRecord(
    await getJson(`/api/cases/${encodeURIComponent(caseId)}/mitre/navigator-layer`, options),
    'navigator layer',
  )
}

export interface NeedsInputState {
  readonly jobId: string
  readonly sourceId: string
  readonly candidates: readonly LogTypeCandidate[]
}

// ---------------------------------------------------------------------------
// Mapping profiles (spec 06 section 3, spec 07 section 3.11)
// ---------------------------------------------------------------------------

export async function listProfiles(options: RequestOptions = {}): Promise<ListEnvelope<MappingProfile>> {
  return readItems<MappingProfile>(await getJson('/api/profiles', options), 'profiles')
}

export async function getProfile(name: string, options: RequestOptions = {}): Promise<MappingProfileDetail> {
  return (await getJson(`/api/profiles/${encodeURIComponent(name)}`, options)) as MappingProfileDetail
}

export async function saveProfile(
  name: string,
  yaml: string,
  options: RequestOptions = {},
): Promise<MappingProfile> {
  const body: SaveProfileBody = { yaml }
  return (await requestJson(`/api/profiles/${encodeURIComponent(name)}`, {
    ...options,
    method: 'PUT',
    json: body,
  })) as MappingProfile
}

export async function deleteProfile(name: string, options: RequestOptions = {}): Promise<void> {
  await requestJson(`/api/profiles/${encodeURIComponent(name)}`, { ...options, method: 'DELETE' })
}

export type PreviewProfileBody = PreviewProfileBodySchema

export async function previewProfile(
  body: PreviewProfileBody,
  options: RequestOptions = {},
): Promise<ProfilePreview> {
  return (await requestJson('/api/profiles/preview', { ...options, json: body })) as ProfilePreview
}

// ---------------------------------------------------------------------------
// Rules (spec 06 "Rules", spec 07 section 3.10)
// ---------------------------------------------------------------------------

export interface RuleFilters {
  readonly kind?: string | undefined
  readonly level?: string | undefined
  readonly status?: string | undefined
  readonly enabled?: boolean | undefined
  readonly tag?: string | undefined
  readonly technique?: string | undefined
  readonly health?: string | undefined
  readonly q?: string | undefined
  readonly limit?: number | undefined
  readonly offset?: number | undefined
}

export async function listRules(
  filters: RuleFilters = {},
  options: RequestOptions = {},
): Promise<ListEnvelope<Rule>> {
  return readItems<Rule>(await getJson(`/api/rules${buildQuery({ ...filters })}`, options), 'rules')
}

export async function getRule(ruleId: string, options: RequestOptions = {}): Promise<RuleDetail> {
  return (await getJson(`/api/rules/${encodeURIComponent(ruleId)}`, options)) as RuleDetail
}

export async function rulesHealth(options: RequestOptions = {}): Promise<RuleHealthCounts> {
  const record = expectRecord(await getJson('/api/rules/health', options), 'rules health')
  const total = typeof record['total'] === 'number' ? record['total'] : 0
  const counts: Record<string, number> = {}
  for (const [key, value] of Object.entries(record)) {
    if (key !== 'total' && typeof value === 'number') {
      counts[key] = value
    }
  }
  return { total, ...counts }
}

export type RuleYamlBody = RuleYamlBodySchema
export type RuleEnabledBody = RuleEnabledBodySchema
export type RuleTestBody = RuleTestBodySchema

export async function validateRule(
  yaml: string,
  options: RequestOptions = {},
): Promise<RuleValidateResult> {
  return (await requestJson('/api/rules/validate', {
    ...options,
    json: { yaml } satisfies RuleYamlBody,
  })) as RuleValidateResult
}

export async function testRule(
  body: RuleTestBody,
  options: RequestOptions = {},
): Promise<RuleTestResult> {
  return (await requestJson('/api/rules/test', { ...options, json: body })) as RuleTestResult
}

export async function createRule(yaml: string, options: RequestOptions = {}): Promise<readonly Rule[]> {
  const record = expectRecord(
    await requestJson('/api/rules', { ...options, json: { yaml } satisfies RuleYamlBody }),
    'create rule',
  )
  return expectArray(record['items'], 'create rule') as readonly Rule[]
}

export async function replaceRule(
  ruleId: string,
  yaml: string,
  options: RequestOptions = {},
): Promise<Rule> {
  const record = expectRecord(
    await requestJson(`/api/rules/${encodeURIComponent(ruleId)}`, {
      ...options,
      method: 'PUT',
      json: { yaml } satisfies RuleYamlBody,
    }),
    'replace rule',
  )
  return record['item'] as Rule
}

export async function setRuleEnabled(
  ruleId: string,
  enabled: boolean,
  options: RequestOptions = {},
): Promise<Rule> {
  const record = expectRecord(
    await requestJson(`/api/rules/${encodeURIComponent(ruleId)}`, {
      ...options,
      method: 'PATCH',
      json: { enabled } satisfies RuleEnabledBody,
    }),
    'toggle rule',
  )
  return record['item'] as Rule
}

export async function deleteRule(ruleId: string, options: RequestOptions = {}): Promise<void> {
  await requestJson(`/api/rules/${encodeURIComponent(ruleId)}`, { ...options, method: 'DELETE' })
}

/** Upload one or more `.yml`/`.zip` rule files; the backend writes them and
 * refreshes the catalogue synchronously (spec 06). */
export async function importRules(
  files: readonly File[],
  options: RequestOptions = {},
): Promise<RuleImportResult> {
  const form = new FormData()
  for (const file of files) {
    form.append('files', file, file.name)
  }
  const record = expectRecord(await requestForm('/api/rules/import', form, options), 'rules import')
  return {
    job: record['job'] as Job,
    imported: record['imported'] as number,
    synced: record['synced'] as number,
    stale_removed: record['stale_removed'] as number,
    files: (record['files'] ?? []) as readonly string[],
    problems: (record['problems'] ?? []) as readonly RuleProblem[],
  }
}

/** Download every catalogue rule's YAML as a zip (spec 06). */
export async function exportRules(options: RequestOptions = {}): Promise<DownloadedFile> {
  return getForFile('/api/rules/export', options)
}

// ---------------------------------------------------------------------------
// Reports (spec 06 "Reports", spec 07 section 3.12, spec 08)
// ---------------------------------------------------------------------------

/** Enqueue a report job; the returned job drives the progress UI. */export async function createReport(
  caseId: string,
  body: ReportRequestBody,
  options: RequestOptions = {},
): Promise<Job> {
  return (await requestJson(`/api/cases/${encodeURIComponent(caseId)}/reports`, {
    ...options,
    json: body,
  })) as Job
}

export async function listReports(
  caseId: string,
  limit = 50,
  offset = 0,
  options: RequestOptions = {},
): Promise<ListEnvelope<Report>> {
  return readItems<Report>(
    await getJson(
      `/api/cases/${encodeURIComponent(caseId)}/reports${buildQuery({ limit, offset })}`,
      options,
    ),
    'reports',
  )
}

/** Download one generated report; the file carries its `X-SHA256` header. */
export async function downloadReport(
  reportId: string,
  options: RequestOptions = {},
): Promise<DownloadedFile> {
  return getForFile(`/api/reports/${encodeURIComponent(reportId)}/download`, options)
}

// ---------------------------------------------------------------------------
// Maintenance (spec 10 section 5, spec 07 section 3.13)
// ---------------------------------------------------------------------------

/** Compact the database and report the size before and after. */
export async function vacuumDatabase(options: RequestOptions = {}): Promise<VacuumResult> {
  return (await requestJson('/api/maintenance/vacuum', { ...options, method: 'POST' })) as VacuumResult
}

/** Rebuild the full-text search index from the events table. */
export async function rebuildFts(options: RequestOptions = {}): Promise<RebuildFtsResult> {
  return (await requestJson('/api/maintenance/rebuild-fts', {
    ...options,
    method: 'POST',
  })) as RebuildFtsResult
}

/** Re-hash every stored original and compare with its intake-time digest. */
export async function verifyHashes(options: RequestOptions = {}): Promise<VerifyHashesResult> {
  return (await requestJson('/api/maintenance/verify-hashes', {
    ...options,
    method: 'POST',
  })) as VerifyHashesResult
}

/** Walk the audit hash chain and report the first broken row. */
export async function verifyAuditChain(options: RequestOptions = {}): Promise<VerifyAuditResult> {
  return (await requestJson('/api/maintenance/verify-audit', {
    ...options,
    method: 'POST',
  })) as VerifyAuditResult
}

// ---------------------------------------------------------------------------
// Settings, allowlist and audit (spec 06 "Health and settings")
// ---------------------------------------------------------------------------

export async function getSettings(options: RequestOptions = {}): Promise<SettingsPayload> {
  return (await getJson('/api/settings', options)) as SettingsPayload
}

export type SettingsUpdateBody = SettingsUpdateBodySchema

export async function updateSettings(
  values: Readonly<Record<string, unknown>>,
  options: RequestOptions = {},
): Promise<SettingsPayload> {
  return (await requestJson('/api/settings', {
    ...options,
    method: 'PUT',
    json: { values } satisfies SettingsUpdateBody,
  })) as SettingsPayload
}

export async function listAllowlist(options: RequestOptions = {}): Promise<ListEnvelope<AllowlistEntry>> {
  return readItems<AllowlistEntry>(await getJson('/api/settings/allowlist', options), 'allowlist')
}

export type AllowlistBody = AllowlistBodySchema

export async function createAllowlistEntry(
  body: AllowlistBody,
  options: RequestOptions = {},
): Promise<AllowlistEntry> {
  return (await requestJson('/api/settings/allowlist', { ...options, json: body })) as AllowlistEntry
}

export async function deleteAllowlistEntry(entryId: number, options: RequestOptions = {}): Promise<void> {
  await requestJson(`/api/settings/allowlist/${String(entryId)}`, { ...options, method: 'DELETE' })
}

/** Replace the ATT&CK catalogue from an uploaded STIX 2.1 bundle (spec 06). */
export async function importAttackBundle(
  bundle: File,
  options: RequestOptions = {},
): Promise<AttackImportResult> {
  const form = new FormData()
  form.append('bundle', bundle, bundle.name)
  return (await requestForm('/api/settings/attack/import', form, options)) as AttackImportResult
}

export interface AuditLogQuery {
  readonly limit?: number | undefined
  readonly offset?: number | undefined
  readonly order?: 'asc' | 'desc' | undefined
}

export async function getCaseAuditLog(
  caseId: string,
  query: AuditLogQuery = {},
  options: RequestOptions = {},
): Promise<AuditLog> {
  return (await getJson(
    `/api/cases/${encodeURIComponent(caseId)}/audit-log${buildQuery({ ...query })}`,
    options,
  )) as AuditLog
}

export type { JsonRequestOptions }
