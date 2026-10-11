import { describe, expect, it } from 'vitest'

import {
  EMPTY_RULE_FILTERS,
  RULE_PAGE_SIZE,
  filtersFromSearch,
  hasActiveFilters,
  searchFromFilters,
  toRuleFilters,
} from './ruleFilters'

describe('ruleFilters', () => {
  it('parses a full query string', () => {
    const state = filtersFromSearch('kind=sigma&level=high&enabled=false&health=unroutable&page=3&rule=r1')
    expect(state.kind).toBe('sigma')
    expect(state.level).toBe('high')
    expect(state.enabled).toBe(false)
    expect(state.health).toBe('unroutable')
    expect(state.page).toBe(3)
    expect(state.rule).toBe('r1')
  })

  it('rejects unknown enum values and bad page numbers', () => {
    const state = filtersFromSearch('kind=bogus&level=bogus&health=bogus&page=0')
    expect(state.kind).toBe('')
    expect(state.level).toBe('')
    expect(state.health).toBe('')
    expect(state.page).toBe(1)
  })

  it('round-trips a state through the URL, dropping neutral keys', () => {
    const params = searchFromFilters({ ...EMPTY_RULE_FILTERS, q: 'lsass', page: 2 })
    expect(params.get('q')).toBe('lsass')
    expect(params.get('page')).toBe('2')
    expect(params.get('kind')).toBeNull()
    expect(filtersFromSearch(params.toString())).toEqual({ ...EMPTY_RULE_FILTERS, q: 'lsass', page: 2 })
  })

  it('translates paging into a limit and offset', () => {
    const filters = toRuleFilters({ ...EMPTY_RULE_FILTERS, page: 3 })
    expect(filters.limit).toBe(RULE_PAGE_SIZE)
    expect(filters.offset).toBe(RULE_PAGE_SIZE * 2)
  })

  it('reports when a non-paging filter is active', () => {
    expect(hasActiveFilters(EMPTY_RULE_FILTERS)).toBe(false)
    expect(hasActiveFilters({ ...EMPTY_RULE_FILTERS, enabled: true })).toBe(true)
  })
})
