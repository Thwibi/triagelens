/**
 * IOC tab definitions, filters and their URL round-trip (spec 07 section 3.6).
 *
 * The backend's `type` filter accepts a single IOC type per request, so a tab
 * that covers several types (IPs, Hashes, …) is fetched unfiltered by type and
 * narrowed in the browser; single-type tabs and "All" stay server-paginated.
 * Parsing and serialising are pure so `IocsPage` stays a thin view.
 */
import type { IocFilters } from '../../api/endpoints'
import type { AnalystState, Ioc } from '../../api/types'

/** Rows per page for server-paginated tabs. */
export const IOC_PAGE_SIZE = 50

/** Analyst verdicts that may be set on an indicator (spec 04 section 6). */
export const ANALYST_STATES: readonly AnalystState[] = ['malicious', 'suspicious', 'benign', 'none']

/** Upper bound fetched for grouped tabs before client-side narrowing. */
export const IOC_GROUP_LIMIT = 1000

/** One tab: a label and the backend `type` values it covers. */
export interface IocTab {
  readonly id: string
  readonly label: string
  readonly types: readonly string[]
}

/** Tabs in spec 07 section 3.6 order; `types` empty means "every type". */
const ALL_TAB: IocTab = { id: 'all', label: 'All', types: [] }

export const IOC_TABS: readonly IocTab[] = [
  ALL_TAB,
  { id: 'ip', label: 'IPs', types: ['ipv4', 'ipv6'] },
  { id: 'domain', label: 'Domains', types: ['domain'] },
  { id: 'url', label: 'URLs', types: ['url'] },
  { id: 'hash', label: 'Hashes', types: ['md5', 'sha1', 'sha256'] },
  { id: 'email', label: 'Emails', types: ['email'] },
  { id: 'file', label: 'Files & Paths', types: ['filename', 'filepath'] },
  { id: 'registry', label: 'Registry', types: ['registry'] },
  { id: 'cve', label: 'CVEs', types: ['cve'] },
  { id: 'other', label: 'Other', types: ['user_agent', 'command'] },
]

/** Look a tab up by id, falling back to "All" for an unknown value. */
export function tabById(id: string): IocTab {
  return IOC_TABS.find((tab) => tab.id === id) ?? ALL_TAB
}

/** The filter state as it appears in the URL (empty string means "unset"). */
export interface IocFilterState {
  readonly tab: string
  readonly q: string
  readonly min_confidence: number | null
  readonly include_private: boolean
  readonly include_allowlisted: boolean
  readonly defang: boolean
  readonly state: AnalystState | ''
  readonly sort: string
  readonly order: 'asc' | 'desc'
  readonly page: number
  readonly ioc: string | null
}

export const DEFAULT_IOC_FILTERS: IocFilterState = {
  tab: 'all',
  q: '',
  min_confidence: null,
  include_private: false,
  include_allowlisted: false,
  defang: false,
  state: '',
  sort: 'last_seen',
  order: 'desc',
  page: 1,
  ioc: null,
}

/** Columns whose click sorts server-side (mirrors the backend `_SORTS` set). */
export const IOC_SORTS: readonly string[] = ['last_seen', 'first_seen', 'confidence', 'occurrences', 'value']

const STATES: readonly string[] = ['none', 'malicious', 'suspicious', 'benign']

function firstValue(params: URLSearchParams, key: string): string | null {
  const value = params.get(key)
  return value === null || value.length === 0 ? null : value
}

function isTruthy(params: URLSearchParams, key: string): boolean {
  return params.get(key) === '1' || params.get(key) === 'true'
}

/** Read the filter state out of a query string (tolerant of junk values). */
export function filtersFromSearch(search: string): IocFilterState {
  const params = new URLSearchParams(search)
  const tab = firstValue(params, 'tab')
  const state = firstValue(params, 'state')
  const minConfidence = Number(params.get('min_confidence'))
  const page = Number(params.get('page'))
  const order = firstValue(params, 'order')
  return {
    tab: tab !== null && IOC_TABS.some((entry) => entry.id === tab) ? tab : 'all',
    q: firstValue(params, 'q') ?? '',
    min_confidence:
      Number.isFinite(minConfidence) && params.has('min_confidence') ? Math.min(100, Math.max(0, minConfidence)) : null,
    include_private: isTruthy(params, 'internal'),
    include_allowlisted: isTruthy(params, 'allowlisted'),
    defang: isTruthy(params, 'defang'),
    state: state !== null && STATES.includes(state) ? (state as AnalystState) : '',
    sort: firstValue(params, 'sort') ?? 'last_seen',
    order: order === 'asc' ? 'asc' : 'desc',
    page: Number.isFinite(page) && page > 0 ? Math.floor(page) : 1,
    ioc: firstValue(params, 'ioc'),
  }
}

/** Serialise the filter state back to a query string (no leading `?`). */
export function searchFromFilters(state: IocFilterState): string {
  const params = new URLSearchParams()
  if (state.tab !== 'all') {
    params.set('tab', state.tab)
  }
  if (state.q !== '') {
    params.set('q', state.q)
  }
  if (state.min_confidence !== null) {
    params.set('min_confidence', String(state.min_confidence))
  }
  if (state.include_private) {
    params.set('internal', '1')
  }
  if (state.include_allowlisted) {
    params.set('allowlisted', '1')
  }
  if (state.defang) {
    params.set('defang', '1')
  }
  if (state.state !== '') {
    params.set('state', state.state)
  }
  if (state.sort !== 'last_seen') {
    params.set('sort', state.sort)
  }
  if (state.order !== 'desc') {
    params.set('order', state.order)
  }
  if (state.page > 1) {
    params.set('page', String(state.page))
  }
  if (state.ioc !== null) {
    params.set('ioc', state.ioc)
  }
  return params.toString()
}

/** True when a tab covers more than one type and needs browser-side narrowing. */
export function isGroupedTab(tab: IocTab): boolean {
  return tab.types.length > 1
}

/** Map the URL state onto the endpoint's filter object. */
export function toIocFilters(state: IocFilterState): IocFilters {
  const tab = tabById(state.tab)
  const grouped = isGroupedTab(tab)
  return {
    type: tab.types.length === 1 ? tab.types[0] : undefined,
    q: state.q === '' ? undefined : state.q,
    min_confidence: state.min_confidence ?? undefined,
    state: state.state === '' ? undefined : state.state,
    include_private: state.include_private,
    include_allowlisted: state.include_allowlisted,
    sort: state.sort,
    order: state.order,
    limit: grouped ? IOC_GROUP_LIMIT : IOC_PAGE_SIZE,
    offset: grouped ? 0 : (state.page - 1) * IOC_PAGE_SIZE,
  }
}

/** True when any filter other than tab/sort/page is active. */
export function hasActiveFilters(state: IocFilterState): boolean {
  return (
    state.q !== '' ||
    state.min_confidence !== null ||
    state.include_private ||
    state.include_allowlisted ||
    state.state !== ''
  )
}

/** The rows and total a page should show, narrowing grouped tabs client-side. */
export function iocPage(
  items: readonly Ioc[],
  total: number,
  state: IocFilterState,
): { readonly items: readonly Ioc[]; readonly total: number } {
  const tab = tabById(state.tab)
  if (!isGroupedTab(tab)) {
    return { items, total }
  }
  const narrowed = items.filter((ioc) => tab.types.includes(ioc.type))
  const start = (state.page - 1) * IOC_PAGE_SIZE
  return { items: narrowed.slice(start, start + IOC_PAGE_SIZE), total: narrowed.length }
}
