import { describe, expect, it } from 'vitest'

import {
  DEFAULT_EVENT_FILTERS,
  filtersFromSearch,
  hasActiveEventFilters,
  searchFromFilters,
  toEventFilters,
} from './eventFilters'

describe('eventFilters', () => {
  it('parses an empty query string into the defaults', () => {
    expect(filtersFromSearch('')).toMatchObject({ sort: '-ts', limit: 200, event_id: null, from_ms: null })
  })

  it('round-trips a populated filter state', () => {
    const state = {
      ...DEFAULT_EVENT_FILTERS,
      q: 'powershell AND encoded',
      host: 'web-01',
      event_id: 4688,
      from_ms: 1_700_000_000_000,
      to_ms: 1_700_000_600_000,
      sort: 'ts' as const,
      limit: 400,
      event: 42,
    }
    const search = searchFromFilters(state)
    expect(filtersFromSearch(search)).toEqual(state)
  })

  it('omits default-valued keys from the query string', () => {
    const search = searchFromFilters(DEFAULT_EVENT_FILTERS)
    expect(search).toBe('')
  })

  it('drops an unknown level and unknown sort', () => {
    const state = filtersFromSearch('level=bogus&sort=sideways')
    expect(state.level).toBe('')
    expect(state.sort).toBe('-ts')
  })

  it('maps URL state onto the API filter object, omitting blanks', () => {
    const filters = toEventFilters({ ...DEFAULT_EVENT_FILTERS, host: 'web-01', event_id: 1 })
    expect(filters.host).toBe('web-01')
    expect(filters.event_id).toBe(1)
    expect(filters.q).toBeUndefined()
    expect(filters.level).toBeUndefined()
  })

  it('reports whether any filter is active', () => {
    expect(hasActiveEventFilters(DEFAULT_EVENT_FILTERS)).toBe(false)
    expect(hasActiveEventFilters({ ...DEFAULT_EVENT_FILTERS, host: 'web-01' })).toBe(true)
  })
})
