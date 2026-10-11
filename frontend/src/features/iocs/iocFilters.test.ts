import { describe, expect, it } from 'vitest'

import type { Ioc } from '../../api/types'
import {
  DEFAULT_IOC_FILTERS,
  IOC_GROUP_LIMIT,
  IOC_PAGE_SIZE,
  filtersFromSearch,
  hasActiveFilters,
  iocPage,
  isGroupedTab,
  searchFromFilters,
  tabById,
  toIocFilters,
} from './iocFilters'

function makeIoc(overrides: Partial<Ioc>): Ioc {
  return {
    id: 'i1',
    case_id: 'c1',
    type: 'ipv4',
    value: '1.2.3.4',
    value_norm: '1.2.3.4',
    first_seen_ms: null,
    last_seen_ms: null,
    occurrences: 1,
    confidence: 50,
    is_private: false,
    is_allowlisted: false,
    analyst_state: 'none',
    tags: [],
    ...overrides,
  }
}

describe('iocFilters', () => {
  it('round-trips a populated state', () => {
    const state = {
      ...DEFAULT_IOC_FILTERS,
      tab: 'domain',
      q: 'evil',
      min_confidence: 70,
      include_private: true,
      defang: true,
      state: 'malicious' as const,
      sort: 'confidence',
      order: 'asc' as const,
      page: 3,
    }
    expect(filtersFromSearch(searchFromFilters(state))).toEqual(state)
  })

  it('serialises the defaults to an empty string', () => {
    expect(searchFromFilters(DEFAULT_IOC_FILTERS)).toBe('')
  })

  it('treats single-type tabs as server-filtered', () => {
    const filters = toIocFilters({ ...DEFAULT_IOC_FILTERS, tab: 'domain' })
    expect(filters.type).toBe('domain')
    expect(filters.limit).toBe(IOC_PAGE_SIZE)
  })

  it('fetches grouped tabs unfiltered at the group limit', () => {
    const filters = toIocFilters({ ...DEFAULT_IOC_FILTERS, tab: 'ip' })
    expect(filters.type).toBeUndefined()
    expect(filters.limit).toBe(IOC_GROUP_LIMIT)
    expect(isGroupedTab(tabById('ip'))).toBe(true)
  })

  it('narrows and paginates grouped tabs in the browser', () => {
    const items: readonly Ioc[] = [
      makeIoc({ id: 'a', type: 'ipv4' }),
      makeIoc({ id: 'b', type: 'domain' }),
      makeIoc({ id: 'c', type: 'ipv6' }),
    ]
    const page = iocPage(items, items.length, { ...DEFAULT_IOC_FILTERS, tab: 'ip' })
    expect(page.items.map((ioc) => ioc.id)).toEqual(['a', 'c'])
    expect(page.total).toBe(2)
  })

  it('falls back to the All tab for an unknown tab id', () => {
    expect(tabById('nope').id).toBe('all')
    expect(filtersFromSearch('tab=nope').tab).toBe('all')
  })

  it('reports whether a non-tab filter is active', () => {
    expect(hasActiveFilters(DEFAULT_IOC_FILTERS)).toBe(false)
    expect(hasActiveFilters({ ...DEFAULT_IOC_FILTERS, min_confidence: 50 })).toBe(true)
  })
})
