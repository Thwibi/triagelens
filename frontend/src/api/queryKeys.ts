/**
 * Query-key factory.
 *
 * Centralised so a mutation can invalidate exactly the caches it dirties without
 * guessing at string shapes, and so tests can assert on stable keys. Every
 * function carries an explicit return type because the project compiles with
 * `isolatedDeclarations`.
 */

export interface QueryKeys {
  health(): readonly unknown[]
  cases(): readonly unknown[]
  case(caseId: string): readonly unknown[]
  sources(caseId: string): readonly unknown[]
  jobs(caseId: string): readonly unknown[]
  job(jobId: string): readonly unknown[]
  detectionRuns(caseId: string): readonly unknown[]
  alerts(caseId: string): readonly unknown[]
  alertList(caseId: string, filters: unknown): readonly unknown[]
  alert(alertId: string): readonly unknown[]
  alertEvidence(alertId: string, page: number): readonly unknown[]
  timeline(caseId: string): readonly unknown[]
  timelineFiltered(caseId: string, filters: unknown, bucket: string): readonly unknown[]
  mitre(caseId: string): readonly unknown[]
  mitreStatic(): readonly unknown[]
  iocList(caseId: string, filters: unknown): readonly unknown[]
  ioc(iocId: string): readonly unknown[]
  iocOccurrences(iocId: string): readonly unknown[]
  entities(caseId: string): readonly unknown[]
  eventCount(caseId: string): readonly unknown[]
  eventCountFiltered(caseId: string, filters: unknown): readonly unknown[]
  eventList(caseId: string, filters: unknown): readonly unknown[]
  eventDetail(eventId: number): readonly unknown[]
  eventFacets(caseId: string, filters: unknown): readonly unknown[]
  rules(filters: unknown): readonly unknown[]
  rule(ruleId: string): readonly unknown[]
  rulesHealth(): readonly unknown[]
  reports(caseId: string): readonly unknown[]
  settings(): readonly unknown[]
  allowlist(): readonly unknown[]
  auditLog(caseId: string, query: unknown): readonly unknown[]
}

export const queryKeys: QueryKeys = {
  health: () => ['health'],
  cases: () => ['cases'],
  case: (caseId) => ['case', caseId],
  sources: (caseId) => ['case', caseId, 'sources'],
  jobs: (caseId) => ['case', caseId, 'jobs'],
  job: (jobId) => ['job', jobId],
  detectionRuns: (caseId) => ['case', caseId, 'detection-runs'],
  alerts: (caseId) => ['case', caseId, 'alerts'],
  alertList: (caseId, filters) => ['case', caseId, 'alerts', filters],
  alert: (alertId) => ['alert', alertId],
  alertEvidence: (alertId, page) => ['alert', alertId, 'evidence', page],
  timeline: (caseId) => ['case', caseId, 'timeline'],
  timelineFiltered: (caseId, filters, bucket) => ['case', caseId, 'timeline', bucket, filters],
  mitre: (caseId) => ['case', caseId, 'mitre'],
  mitreStatic: () => ['mitre', 'matrix'],
  iocList: (caseId, filters) => ['case', caseId, 'iocs', filters],
  ioc: (iocId) => ['ioc', iocId],
  iocOccurrences: (iocId) => ['ioc', iocId, 'occurrences'],
  entities: (caseId) => ['case', caseId, 'entities'],
  eventCount: (caseId) => ['case', caseId, 'events', 'count'],
  eventCountFiltered: (caseId, filters) => ['case', caseId, 'events', 'count', filters],
  eventList: (caseId, filters) => ['case', caseId, 'events', filters],
  eventDetail: (eventId) => ['event', eventId],
  eventFacets: (caseId, filters) => ['case', caseId, 'events', 'facets', filters],
  rules: (filters) => ['rules', filters],
  rule: (ruleId) => ['rule', ruleId],
  rulesHealth: () => ['rules', 'health'],
  reports: (caseId) => ['case', caseId, 'reports'],
  settings: () => ['settings'],
  allowlist: () => ['settings', 'allowlist'],
  auditLog: (caseId, query) => ['case', caseId, 'audit-log', query],
}
