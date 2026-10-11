/**
 * Event list filters and their URL round-trip (spec 07 sections 3.7 and 4).
 *
 * Filters live in the query string so a filtered view is a shareable deep link
 * (an IOC or alert can pivot here). Parsing and serialising are pure so
 * `EventsPage` stays a thin view.
 */
import type { EventFilters } from '../../api/endpoints'

/** Rows requested per "Load more" step; capped by the backend at 1000. */
export const EVENT_PAGE_SIZE = 200

/** Hard cap the UI will request in one accumulation. */
export const EVENT_MAX_ROWS = 1000

/** The filter state as it appears in the URL (empty string means "unset"). */
export interface EventFilterState {
  readonly q: string
  readonly host: string
  readonly log_type: string
  readonly channel: string
  readonly event_id: number | null
  readonly user_name: string
  readonly src_ip: string
  readonly dst_ip: string
  readonly level: string
  readonly ioc_id: string
  readonly alert_id: string
  readonly from_ms: number | null
  readonly to_ms: number | null
  readonly sort: '-ts' | 'ts'
  readonly limit: number
  readonly event: number | null
}

export const DEFAULT_EVENT_FILTERS: EventFilterState = {
  q: '',
  host: '',
  log_type: '',
  channel: '',
  event_id: null,
  user_name: '',
  src_ip: '',
  dst_ip: '',
  level: '',
  ioc_id: '',
  alert_id: '',
  from_ms: null,
  to_ms: null,
  sort: '-ts',
  limit: EVENT_PAGE_SIZE,
  event: null,
}

const LEVELS: readonly string[] = ['informational', 'low', 'medium', 'high', 'critical']

function firstValue(params: URLSearchParams, key: string): string | null {
  const value = params.get(key)
  return value === null || value.length === 0 ? null : value
}

function intOrNull(params: URLSearchParams, key: string): number | null {
  if (!params.has(key)) {
    return null
  }
  const value = Number(params.get(key))
  return Number.isFinite(value) ? Math.trunc(value) : null
}

/** Read the filter state out of a query string (tolerant of junk values). */
export function filtersFromSearch(search: string): EventFilterState {
  const params = new URLSearchParams(search)
  const level = firstValue(params, 'level')
  const sort = firstValue(params, 'sort')
  const limit = intOrNull(params, 'limit')
  return {
    q: firstValue(params, 'q') ?? '',
    host: firstValue(params, 'host') ?? '',
    log_type: firstValue(params, 'log_type') ?? '',
    channel: firstValue(params, 'channel') ?? '',
    event_id: intOrNull(params, 'event_id'),
    user_name: firstValue(params, 'user_name') ?? '',
    src_ip: firstValue(params, 'src_ip') ?? '',
    dst_ip: firstValue(params, 'dst_ip') ?? '',
    level: level !== null && LEVELS.includes(level) ? level : '',
    ioc_id: firstValue(params, 'ioc_id') ?? '',
    alert_id: firstValue(params, 'alert_id') ?? '',
    from_ms: intOrNull(params, 'from_ms'),
    to_ms: intOrNull(params, 'to_ms'),
    sort: sort === 'ts' ? 'ts' : '-ts',
    limit: limit !== null && limit >= EVENT_PAGE_SIZE ? Math.min(EVENT_MAX_ROWS, limit) : EVENT_PAGE_SIZE,
    event: intOrNull(params, 'event'),
  }
}

/** Serialise the filter state back to a query string (no leading `?`). */
export function searchFromFilters(state: EventFilterState): string {
  const params = new URLSearchParams()
  if (state.q !== '') {
    params.set('q', state.q)
  }
  if (state.host !== '') {
    params.set('host', state.host)
  }
  if (state.log_type !== '') {
    params.set('log_type', state.log_type)
  }
  if (state.channel !== '') {
    params.set('channel', state.channel)
  }
  if (state.event_id !== null) {
    params.set('event_id', String(state.event_id))
  }
  if (state.user_name !== '') {
    params.set('user_name', state.user_name)
  }
  if (state.src_ip !== '') {
    params.set('src_ip', state.src_ip)
  }
  if (state.dst_ip !== '') {
    params.set('dst_ip', state.dst_ip)
  }
  if (state.level !== '') {
    params.set('level', state.level)
  }
  if (state.ioc_id !== '') {
    params.set('ioc_id', state.ioc_id)
  }
  if (state.alert_id !== '') {
    params.set('alert_id', state.alert_id)
  }
  if (state.from_ms !== null) {
    params.set('from_ms', String(state.from_ms))
  }
  if (state.to_ms !== null) {
    params.set('to_ms', String(state.to_ms))
  }
  if (state.sort !== '-ts') {
    params.set('sort', state.sort)
  }
  if (state.limit > EVENT_PAGE_SIZE) {
    params.set('limit', String(state.limit))
  }
  if (state.event !== null) {
    params.set('event', String(state.event))
  }
  return params.toString()
}

/** Map the URL state onto the endpoint's filter object. */
export function toEventFilters(state: EventFilterState): EventFilters {
  return {
    q: state.q === '' ? undefined : state.q,
    host: state.host === '' ? undefined : state.host,
    log_type: state.log_type === '' ? undefined : state.log_type,
    channel: state.channel === '' ? undefined : state.channel,
    event_id: state.event_id ?? undefined,
    user_name: state.user_name === '' ? undefined : state.user_name,
    src_ip: state.src_ip === '' ? undefined : state.src_ip,
    dst_ip: state.dst_ip === '' ? undefined : state.dst_ip,
    level: state.level === '' ? undefined : state.level,
    ioc_id: state.ioc_id === '' ? undefined : state.ioc_id,
    alert_id: state.alert_id === '' ? undefined : state.alert_id,
    from_ms: state.from_ms ?? undefined,
    to_ms: state.to_ms ?? undefined,
    sort: state.sort,
    limit: state.limit,
  }
}

/** True when any filter (not pagination) is set, for the empty state. */
export function hasActiveEventFilters(state: EventFilterState): boolean {
  return (
    state.q !== '' ||
    state.host !== '' ||
    state.log_type !== '' ||
    state.channel !== '' ||
    state.event_id !== null ||
    state.user_name !== '' ||
    state.src_ip !== '' ||
    state.dst_ip !== '' ||
    state.level !== '' ||
    state.ioc_id !== '' ||
    state.alert_id !== '' ||
    state.from_ms !== null ||
    state.to_ms !== null
  )
}
