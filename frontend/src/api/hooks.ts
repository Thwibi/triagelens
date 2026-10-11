import { useQuery } from '@tanstack/react-query'
import type { UseQueryResult } from '@tanstack/react-query'

import { fetchHealth } from './client'
import {
  countEvents,
  getAlert,
  getCase,
  getCaseAuditLog,
  getCaseMitre,
  getEvent,
  getFilteredTimeline,
  getIoc,
  getMitreStatic,
  getRule,
  getSettings,
  getTimeline,
  listAlertEvidence,
  listAlerts,
  listAllowlist,
  listCases,
  listCaseJobs,
  listDetectionRuns,
  listEntities,
  listEventFacets,
  listEvents,
  listIocOccurrences,
  listIocs,
  listReports,
  listRules,
  listSources,
  rulesHealth,
} from './endpoints'
import type {
  AlertFilters,
  AuditLogQuery,
  EventFilters,
  IocFilters,
  RuleFilters,
  TimelineBucketSize,
} from './endpoints'
import { queryKeys } from './queryKeys'
import type {
  Alert,
  AlertDetail,
  AlertEventBrief,
  AllowlistEntry,
  AuditLog,
  Case,
  CaseMitreMatrix,
  DetectionRun,
  Entity,
  EventDetail,
  EventFacets,
  EventRecord,
  HealthReport,
  Ioc,
  IocDetail,
  IocOccurrence,
  Job,
  ListEnvelope,
  MitreStaticMatrix,
  Report,
  Rule,
  RuleDetail,
  RuleHealthCounts,
  SettingsPayload,
  Source,
  Timeline,
} from './types'

/** Shared query-hook layer: one place that knows each endpoint's key and shape. */

/**
 * Narrows a required identifier for a query function.
 *
 * Queries that need an id set `enabled: id !== null`, so the function only ever
 * runs with a real value; this makes that guarantee explicit instead of an
 * unchecked assertion.
 */
function requireId(id: string | null): string {
  if (id === null) {
    throw new Error('A required identifier is missing for this query.')
  }
  return id
}

export function useHealthQuery(): UseQueryResult<HealthReport> {
  return useQuery({ queryKey: queryKeys.health(), queryFn: ({ signal }) => fetchHealth({ signal }) })
}

export function useCasesQuery(): UseQueryResult<ListEnvelope<Case>> {
  return useQuery({ queryKey: queryKeys.cases(), queryFn: ({ signal }) => listCases({ signal }) })
}

export function useCaseQuery(caseId: string | null): UseQueryResult<Case> {
  return useQuery({
    queryKey: queryKeys.case(caseId ?? ''),
    queryFn: ({ signal }) => getCase(requireId(caseId), { signal }),
    enabled: caseId !== null,
  })
}

export function useSourcesQuery(caseId: string | null): UseQueryResult<ListEnvelope<Source>> {
  return useQuery({
    queryKey: queryKeys.sources(caseId ?? ''),
    queryFn: ({ signal }) => listSources(requireId(caseId), { signal }),
    enabled: caseId !== null,
  })
}

export function useCaseJobsQuery(caseId: string | null): UseQueryResult<ListEnvelope<Job>> {
  return useQuery({
    queryKey: queryKeys.jobs(caseId ?? ''),
    queryFn: ({ signal }) => listCaseJobs(requireId(caseId), { signal }),
    enabled: caseId !== null,
  })
}

export function useDetectionRunsQuery(caseId: string | null): UseQueryResult<ListEnvelope<DetectionRun>> {
  return useQuery({
    queryKey: queryKeys.detectionRuns(caseId ?? ''),
    queryFn: ({ signal }) => listDetectionRuns(requireId(caseId), { signal }),
    enabled: caseId !== null,
  })
}

export function useTopAlertsQuery(caseId: string | null, limit = 5): UseQueryResult<ListEnvelope<Alert>> {
  const filters: AlertFilters = { sort: '-score', limit }
  return useQuery({
    queryKey: queryKeys.alertList(caseId ?? '', filters),
    queryFn: ({ signal }) => listAlerts(requireId(caseId), filters, { signal }),
    enabled: caseId !== null,
  })
}

export function useAlertsQuery(
  caseId: string | null,
  filters: AlertFilters,
): UseQueryResult<ListEnvelope<Alert>> {
  return useQuery({
    queryKey: queryKeys.alertList(caseId ?? '', filters),
    queryFn: ({ signal }) => listAlerts(requireId(caseId), filters, { signal }),
    enabled: caseId !== null,
  })
}

export function useAlertQuery(alertId: string | null): UseQueryResult<AlertDetail> {
  return useQuery({
    queryKey: queryKeys.alert(alertId ?? ''),
    queryFn: ({ signal }) => getAlert(requireId(alertId), { signal }),
    enabled: alertId !== null,
  })
}

export function useAlertEvidenceQuery(
  alertId: string | null,
  page: number,
  limit = 100,
): UseQueryResult<ListEnvelope<AlertEventBrief>> {
  return useQuery({
    queryKey: queryKeys.alertEvidence(alertId ?? '', page),
    queryFn: ({ signal }) => listAlertEvidence(requireId(alertId), page, limit, { signal }),
    enabled: alertId !== null && page > 0,
  })
}

export function useTimelineQuery(caseId: string | null): UseQueryResult<Timeline> {
  return useQuery({
    queryKey: queryKeys.timeline(caseId ?? ''),
    queryFn: ({ signal }) => getTimeline(requireId(caseId), 'auto', { signal }),
    enabled: caseId !== null,
  })
}

export function useCaseMitreQuery(caseId: string | null): UseQueryResult<CaseMitreMatrix> {
  return useQuery({
    queryKey: queryKeys.mitre(caseId ?? ''),
    queryFn: ({ signal }) => getCaseMitre(requireId(caseId), { signal }),
    enabled: caseId !== null,
  })
}

/** The static reference matrix; fetched only when the caller asks for it. */
export function useMitreStaticQuery(enabled: boolean): UseQueryResult<MitreStaticMatrix> {
  return useQuery({
    queryKey: queryKeys.mitreStatic(),
    queryFn: ({ signal }) => getMitreStatic({ signal }),
    enabled,
  })
}

export function useEntitiesQuery(caseId: string | null): UseQueryResult<readonly Entity[]> {
  return useQuery({
    queryKey: queryKeys.entities(caseId ?? ''),
    queryFn: ({ signal }) => listEntities(requireId(caseId), { signal }),
    enabled: caseId !== null,
  })
}

export function useEventCountQuery(caseId: string | null): UseQueryResult<number> {
  return useQuery({
    queryKey: queryKeys.eventCount(caseId ?? ''),
    queryFn: ({ signal }) => countEvents(requireId(caseId), {}, { signal }),
    enabled: caseId !== null,
  })
}

export function useIocsQuery(
  caseId: string | null,
  filters: IocFilters = { include_private: false, include_allowlisted: false },
): UseQueryResult<ListEnvelope<Ioc>> {
  return useQuery({
    queryKey: queryKeys.iocList(caseId ?? '', filters),
    queryFn: ({ signal }) => listIocs(requireId(caseId), filters, { signal }),
    enabled: caseId !== null,
  })
}

export function useIocQuery(iocId: string | null): UseQueryResult<IocDetail> {
  return useQuery({
    queryKey: queryKeys.ioc(iocId ?? ''),
    queryFn: ({ signal }) => getIoc(requireId(iocId), { signal }),
    enabled: iocId !== null,
  })
}

export function useIocOccurrencesQuery(
  iocId: string | null,
  limit = 500,
): UseQueryResult<ListEnvelope<IocOccurrence>> {
  return useQuery({
    queryKey: queryKeys.iocOccurrences(iocId ?? ''),
    queryFn: ({ signal }) => listIocOccurrences(requireId(iocId), limit, { signal }),
    enabled: iocId !== null,
  })
}

export function useEventsQuery(
  caseId: string | null,
  filters: EventFilters,
): UseQueryResult<ListEnvelope<EventRecord>> {
  return useQuery({
    queryKey: queryKeys.eventList(caseId ?? '', filters),
    queryFn: ({ signal }) => listEvents(requireId(caseId), filters, { signal }),
    enabled: caseId !== null,
  })
}

export function useEventFacetsQuery(
  caseId: string | null,
  filters: EventFilters,
): UseQueryResult<EventFacets> {
  return useQuery({
    queryKey: queryKeys.eventFacets(caseId ?? '', filters),
    queryFn: ({ signal }) => listEventFacets(requireId(caseId), filters, { signal }),
    enabled: caseId !== null,
  })
}

export function useEventCountFilteredQuery(
  caseId: string | null,
  filters: EventFilters,
): UseQueryResult<number> {
  return useQuery({
    queryKey: queryKeys.eventCountFiltered(caseId ?? '', filters),
    queryFn: ({ signal }) => countEvents(requireId(caseId), filters, { signal }),
    enabled: caseId !== null,
  })
}

export function useEventQuery(eventId: number | null): UseQueryResult<EventDetail> {
  return useQuery({
    queryKey: queryKeys.eventDetail(eventId ?? 0),
    queryFn: ({ signal }) => {
      if (eventId === null) {
        throw new Error('An event id is required for this query.')
      }
      return getEvent(eventId, { signal })
    },
    enabled: eventId !== null,
  })
}

export function useFilteredTimelineQuery(
  caseId: string | null,
  filters: EventFilters,
  bucket: TimelineBucketSize,
): UseQueryResult<Timeline> {
  return useQuery({
    queryKey: queryKeys.timelineFiltered(caseId ?? '', filters, bucket),
    queryFn: ({ signal }) => getFilteredTimeline(requireId(caseId), filters, bucket, { signal }),
    enabled: caseId !== null,
  })
}

export function useRulesQuery(filters: RuleFilters): UseQueryResult<ListEnvelope<Rule>> {
  return useQuery({
    queryKey: queryKeys.rules(filters),
    queryFn: ({ signal }) => listRules(filters, { signal }),
  })
}

export function useRuleQuery(ruleId: string | null): UseQueryResult<RuleDetail> {
  return useQuery({
    queryKey: queryKeys.rule(ruleId ?? ''),
    queryFn: ({ signal }) => getRule(requireId(ruleId), { signal }),
    enabled: ruleId !== null,
  })
}

export function useRulesHealthQuery(): UseQueryResult<RuleHealthCounts> {
  return useQuery({
    queryKey: queryKeys.rulesHealth(),
    queryFn: ({ signal }) => rulesHealth({ signal }),
  })
}

export function useReportsQuery(caseId: string | null): UseQueryResult<ListEnvelope<Report>> {
  return useQuery({
    queryKey: queryKeys.reports(caseId ?? ''),
    queryFn: ({ signal }) => listReports(requireId(caseId), 50, 0, { signal }),
    enabled: caseId !== null,
  })
}

export function useSettingsQuery(): UseQueryResult<SettingsPayload> {
  return useQuery({
    queryKey: queryKeys.settings(),
    queryFn: ({ signal }) => getSettings({ signal }),
  })
}

export function useAllowlistQuery(): UseQueryResult<ListEnvelope<AllowlistEntry>> {
  return useQuery({
    queryKey: queryKeys.allowlist(),
    queryFn: ({ signal }) => listAllowlist({ signal }),
  })
}

export function useAuditLogQuery(
  caseId: string | null,
  query: AuditLogQuery,
): UseQueryResult<AuditLog> {
  return useQuery({
    queryKey: queryKeys.auditLog(caseId ?? '', query),
    queryFn: ({ signal }) => getCaseAuditLog(requireId(caseId), query, { signal }),
    enabled: caseId !== null,
  })
}
