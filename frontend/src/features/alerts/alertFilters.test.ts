import { describe, expect, it } from 'vitest'

import {
  DEFAULT_ALERT_FILTERS,
  filtersFromSearch,
  hasActiveFilters,
  searchFromFilters,
  toAlertFilters,
  toggleSort,
} from './alertFilters'

describe('filtersFromSearch', () => {
  it('returns defaults for an empty query string', () => {
    expect(filtersFromSearch('')).toEqual(DEFAULT_ALERT_FILTERS)
  })

  it('parses the known keys and coerces numbers', () => {
    const state = filtersFromSearch('level=high&status=triaged&min_score=40&page=3&unmapped=1&technique=T1059')
    expect(state.level).toBe('high')
    expect(state.status).toBe('triaged')
    expect(state.min_score).toBe(40)
    expect(state.page).toBe(3)
    expect(state.unmapped).toBe(true)
    expect(state.technique).toBe('T1059')
  })

  it('ignores unknown enum values and non-positive pages', () => {
    const state = filtersFromSearch('level=bogus&status=bogus&page=0')
    expect(state.level).toBe('')
    expect(state.status).toBe('')
    expect(state.page).toBe(1)
  })
})

describe('searchFromFilters', () => {
  it('omits defaults and round-trips a populated state', () => {
    const populated = {
      ...DEFAULT_ALERT_FILTERS,
      level: 'critical' as const,
      q: 'powershell',
      min_score: 70,
      page: 2,
      alert: 'a1',
    }
    const search = searchFromFilters(populated)
    expect(search).toContain('level=critical')
    expect(search).toContain('q=powershell')
    expect(search).not.toContain('sort=')
    expect(filtersFromSearch(search)).toEqual(populated)
  })

  it('serialises the empty state to an empty string', () => {
    expect(searchFromFilters(DEFAULT_ALERT_FILTERS)).toBe('')
  })
})

describe('toAlertFilters', () => {
  it('maps empty strings to undefined and derives the offset', () => {
    const filters = toAlertFilters({ ...DEFAULT_ALERT_FILTERS, page: 3, level: 'low' })
    expect(filters.level).toBe('low')
    expect(filters.q).toBeUndefined()
    expect(filters.min_score).toBeUndefined()
    expect(filters.offset).toBe(100)
    expect(filters.limit).toBe(50)
  })
})

describe('hasActiveFilters', () => {
  it('is false only when every filter is at its default', () => {
    expect(hasActiveFilters(DEFAULT_ALERT_FILTERS)).toBe(false)
    expect(hasActiveFilters({ ...DEFAULT_ALERT_FILTERS, unmapped: true })).toBe(true)
    expect(hasActiveFilters({ ...DEFAULT_ALERT_FILTERS, technique: 'T1059' })).toBe(true)
  })

  it('does not treat sort or page as filters', () => {
    expect(hasActiveFilters({ ...DEFAULT_ALERT_FILTERS, sort: 'score', page: 4 })).toBe(false)
  })
})

describe('toggleSort', () => {
  it('flips between descending and ascending for the same column', () => {
    expect(toggleSort('-score', 'score')).toBe('score')
    expect(toggleSort('score', 'score')).toBe('-score')
  })

  it('starts a new column descending', () => {
    expect(toggleSort('-score', 'last_seen')).toBe('-last_seen')
  })
})
