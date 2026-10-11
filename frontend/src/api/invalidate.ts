import type { QueryClient } from '@tanstack/react-query'

import { queryKeys } from './queryKeys'

/** Refresh every case-scoped cache after a change that could affect any of them. */
export function invalidateCaseData(queryClient: QueryClient, caseId: string): void {
  for (const key of [
    queryKeys.case(caseId),
    queryKeys.sources(caseId),
    queryKeys.jobs(caseId),
    queryKeys.detectionRuns(caseId),
    queryKeys.alerts(caseId),
    queryKeys.timeline(caseId),
    queryKeys.mitre(caseId),
    queryKeys.entities(caseId),
    queryKeys.eventCount(caseId),
    ['case', caseId, 'events'],
    ['case', caseId, 'iocs'],
    queryKeys.cases(),
  ]) {
    void queryClient.invalidateQueries({ queryKey: key })
  }
}

/**
 * Refresh the alert caches a verdict change dirties.
 *
 * The list is keyed by case and the detail by alert id, so both are invalidated
 * by their own prefix; the case counts refresh too because the Alert tile reads
 * them from `GET /cases`.
 */
export function invalidateAlerts(queryClient: QueryClient, caseId: string): void {
  for (const key of [queryKeys.alerts(caseId), queryKeys.case(caseId), queryKeys.cases()]) {
    void queryClient.invalidateQueries({ queryKey: key })
  }
}

/** Refresh one alert's detail after its verdict or notes change. */
export function invalidateAlertDetail(queryClient: QueryClient, alertId: string): void {
  void queryClient.invalidateQueries({ queryKey: queryKeys.alert(alertId) })
}

/**
 * Refresh the IOC caches an indicator verdict change dirties.
 *
 * The list is keyed by case (and filter object), so it is invalidated by its
 * `['case', id, 'iocs']` prefix; the detail and occurrence caches are keyed by
 * the indicator id. The case counts refresh because the IOC tile reads them.
 */
export function invalidateIocs(queryClient: QueryClient, caseId: string, iocId: string): void {
  for (const key of [
    ['case', caseId, 'iocs'],
    queryKeys.ioc(iocId),
    queryKeys.iocOccurrences(iocId),
    queryKeys.case(caseId),
    queryKeys.cases(),
  ]) {
    void queryClient.invalidateQueries({ queryKey: key })
  }
}

/**
 * Refresh the rule catalogue caches after a create/replace/delete/toggle/import.
 *
 * The list is keyed by filter object, so it is invalidated by its `['rules']`
 * prefix; health counts and each rule detail are invalidated too.
 */
export function invalidateRules(queryClient: QueryClient, ruleId?: string): void {
  for (const key of [queryKeys.rules({}), ['rules'], queryKeys.rulesHealth()]) {
    void queryClient.invalidateQueries({ queryKey: key })
  }
  if (ruleId !== undefined) {
    void queryClient.invalidateQueries({ queryKey: queryKeys.rule(ruleId) })
  }
}

/** Refresh the settings payload and the global allowlist after a change. */
export function invalidateSettings(queryClient: QueryClient): void {
  for (const key of [queryKeys.settings(), queryKeys.allowlist()]) {
    void queryClient.invalidateQueries({ queryKey: key })
  }
}

/** Refresh a case's report history after a report job finishes. */
export function invalidateReports(queryClient: QueryClient, caseId: string): void {
  void queryClient.invalidateQueries({ queryKey: queryKeys.reports(caseId) })
}
