/**
 * Alert list filters and their URL round-trip (spec 07 sections 3.4 and 4).
 *
 * Filters live in the query string so a filtered view is a shareable deep link.
 * The parsing and serialising are pure functions here so they can be tested
 * without a router, and so `AlertsPage` stays a thin view.
 */
import type { AlertFilters } from '../../api/endpoints'
import type { AlertLevel, AlertStatus } from '../../api/types'

/** Rows requested per page; the table is server-paginated. */
export const ALERT_PAGE_SIZE = 50

/** The filter state as it appears in the URL (empty string means "unset"). */
export interface AlertFilterState {
  readonly level: AlertLevel | ''
  readonly status: AlertStatus | ''
  readonly q: string
  readonly host: string
  readonly user_name: string
  readonly min_score: number | null
  readonly tactic: string
  readonly technique: string
  readonly unmapped: boolean
  readonly sort: string
  readonly page: number
  readonly alert: string | null
}

export const DEFAULT_ALERT_FILTERS: AlertFilterState = {
  level: '',
  status: '',
  q: '',
  host: '',
  user_name: '',
  min_score: null,
  tactic: '',
  technique: '',
  unmapped: false,
  sort: '-score',
  page: 1,
  alert: null,
}

const LEVELS: readonly string[] = ['critical', 'high', 'medium', 'low', 'informational']
const STATUSES: readonly string[] = ['new', 'triaged', 'true_positive', 'false_positive', 'benign']

/** Columns whose click sorts server-side (mirrors the backend `_SORTS` set). */
export const ALERT_SORTABLE: Readonly<Record<string, string>> = {
  score: 'score',
  rule_title: 'rule_title',
  match_count: 'match_count',
  first_seen: 'first_seen',
  last_seen: 'last_seen',
}

function firstValue(params: URLSearchParams, key: string): string | null {
  const value = params.get(key)
  return value === null || value.length === 0 ? null : value
}

/** Read the filter state out of a query string (tolerant of junk values). */
export function filtersFromSearch(search: string): AlertFilterState {
  const params = new URLSearchParams(search)
  const level = firstValue(params, 'level')
  const status = firstValue(params, 'status')
  const minScore = Number(params.get('min_score'))
  const page = Number(params.get('page'))
  return {
    level: level !== null && LEVELS.includes(level) ? (level as AlertLevel) : '',
    status: status !== null && STATUSES.includes(status) ? (status as AlertStatus) : '',
    q: firstValue(params, 'q') ?? '',
    host: firstValue(params, 'host') ?? '',
    user_name: firstValue(params, 'user_name') ?? '',
    min_score: Number.isFinite(minScore) && params.has('min_score') ? minScore : null,
    tactic: firstValue(params, 'tactic') ?? '',
    technique: firstValue(params, 'technique') ?? '',
    unmapped: params.get('unmapped') === '1' || params.get('unmapped') === 'true',
    sort: firstValue(params, 'sort') ?? '-score',
    page: Number.isFinite(page) && page > 0 ? Math.floor(page) : 1,
    alert: firstValue(params, 'alert'),
  }
}

/** Serialise the filter state back to a query string (no leading `?`). */
export function searchFromFilters(state: AlertFilterState): string {
  const params = new URLSearchParams()
  if (state.level !== '') {
    params.set('level', state.level)
  }
  if (state.status !== '') {
    params.set('status', state.status)
  }
  if (state.q !== '') {
    params.set('q', state.q)
  }
  if (state.host !== '') {
    params.set('host', state.host)
  }
  if (state.user_name !== '') {
    params.set('user_name', state.user_name)
  }
  if (state.min_score !== null) {
    params.set('min_score', String(state.min_score))
  }
  if (state.tactic !== '') {
    params.set('tactic', state.tactic)
  }
  if (state.technique !== '') {
    params.set('technique', state.technique)
  }
  if (state.unmapped) {
    params.set('unmapped', '1')
  }
  if (state.sort !== '-score' && state.sort !== '') {
    params.set('sort', state.sort)
  }
  if (state.page > 1) {
    params.set('page', String(state.page))
  }
  if (state.alert !== null) {
    params.set('alert', state.alert)
  }
  return params.toString()
}

/** Map the URL state onto the endpoint's filter object. */
export function toAlertFilters(state: AlertFilterState): AlertFilters {
  return {
    level: state.level === '' ? undefined : state.level,
    status: state.status === '' ? undefined : state.status,
    q: state.q === '' ? undefined : state.q,
    host: state.host === '' ? undefined : state.host,
    user_name: state.user_name === '' ? undefined : state.user_name,
    min_score: state.min_score ?? undefined,
    tactic: state.tactic === '' ? undefined : state.tactic,
    technique: state.technique === '' ? undefined : state.technique,
    unmapped: state.unmapped ? true : undefined,
    sort: state.sort === '' ? undefined : state.sort,
    limit: ALERT_PAGE_SIZE,
    offset: (state.page - 1) * ALERT_PAGE_SIZE,
  }
}

/** True when any filter other than sort/page is active (for the empty state). */
export function hasActiveFilters(state: AlertFilterState): boolean {
  return (
    state.level !== '' ||
    state.status !== '' ||
    state.q !== '' ||
    state.host !== '' ||
    state.user_name !== '' ||
    state.min_score !== null ||
    state.tactic !== '' ||
    state.technique !== '' ||
    state.unmapped
  )
}

/** Toggle a sortable column between descending and ascending. */
export function toggleSort(current: string, column: string): string {
  return current === `-${column}` ? column : `-${column}`
}
