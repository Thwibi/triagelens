/**
 * Rules-list filter state and its URL round-trip (spec 07 section 3.10).
 *
 * The filters live in the query string so a filtered catalogue view is a
 * shareable, back-button-friendly URL, exactly like the other list screens.
 */
import type { RuleFilters } from '../../api/endpoints'
import { HEALTH_BUCKETS, RULE_KINDS, RULE_LEVELS } from './ruleFormat'
import type { HealthBucket } from './ruleFormat'

/** Rows per page; the backend caps `limit` at 1000. */
export const RULE_PAGE_SIZE = 100

export interface RuleFilterState {
  readonly kind: string
  readonly level: string
  readonly status: string
  readonly enabled: boolean | null
  readonly tag: string
  readonly technique: string
  readonly health: HealthBucket | ''
  readonly q: string
  readonly page: number
  readonly rule: string | null
}

export const EMPTY_RULE_FILTERS: RuleFilterState = {
  kind: '',
  level: '',
  status: '',
  enabled: null,
  tag: '',
  technique: '',
  health: '',
  q: '',
  page: 1,
  rule: null,
}

function oneOf(value: string, allowed: readonly string[]): string {
  return allowed.includes(value) ? value : ''
}

/** Parse a `URLSearchParams` string into a validated filter state. */
export function filtersFromSearch(search: string): RuleFilterState {
  const params = new URLSearchParams(search)
  const kind = params.get('kind') ?? ''
  const level = params.get('level') ?? ''
  const health = params.get('health') ?? ''
  const enabledRaw = params.get('enabled')
  const pageRaw = Number.parseInt(params.get('page') ?? '1', 10)
  const rule = params.get('rule')
  return {
    kind: oneOf(kind, RULE_KINDS),
    level: oneOf(level, RULE_LEVELS),
    status: params.get('status') ?? '',
    enabled: enabledRaw === 'true' ? true : enabledRaw === 'false' ? false : null,
    tag: params.get('tag') ?? '',
    technique: params.get('technique') ?? '',
    health: oneOf(health, HEALTH_BUCKETS) as HealthBucket | '',
    q: params.get('q') ?? '',
    page: Number.isFinite(pageRaw) && pageRaw > 0 ? pageRaw : 1,
    rule: rule !== null && rule.length > 0 ? rule : null,
  }
}

/** Serialise a filter state to a `URLSearchParams`, dropping empty/neutral keys. */
export function searchFromFilters(state: RuleFilterState): URLSearchParams {
  const params = new URLSearchParams()
  if (state.kind !== '') params.set('kind', state.kind)
  if (state.level !== '') params.set('level', state.level)
  if (state.status !== '') params.set('status', state.status)
  if (state.enabled !== null) params.set('enabled', String(state.enabled))
  if (state.tag !== '') params.set('tag', state.tag)
  if (state.technique !== '') params.set('technique', state.technique)
  if (state.health !== '') params.set('health', state.health)
  if (state.q !== '') params.set('q', state.q)
  if (state.page > 1) params.set('page', String(state.page))
  if (state.rule !== null) params.set('rule', state.rule)
  return params
}

/** Translate the UI state into the query the API expects. */
export function toRuleFilters(state: RuleFilterState): RuleFilters {
  return {
    kind: state.kind === '' ? undefined : state.kind,
    level: state.level === '' ? undefined : state.level,
    status: state.status === '' ? undefined : state.status,
    enabled: state.enabled ?? undefined,
    tag: state.tag === '' ? undefined : state.tag,
    technique: state.technique === '' ? undefined : state.technique,
    health: state.health === '' ? undefined : state.health,
    q: state.q === '' ? undefined : state.q,
    limit: RULE_PAGE_SIZE,
    offset: (state.page - 1) * RULE_PAGE_SIZE,
  }
}

/** True when any filter other than paging or the open drawer is set. */
export function hasActiveFilters(state: RuleFilterState): boolean {
  return (
    state.kind !== '' ||
    state.level !== '' ||
    state.status !== '' ||
    state.enabled !== null ||
    state.tag !== '' ||
    state.technique !== '' ||
    state.health !== '' ||
    state.q !== ''
  )
}
