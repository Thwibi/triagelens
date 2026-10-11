import { describe, expect, it } from 'vitest'

import { buildQuery } from './endpoints'

describe('buildQuery', () => {
  it('drops undefined and null values', () => {
    expect(buildQuery({ a: 1, b: undefined, c: null })).toBe('?a=1')
  })

  it('returns an empty string when nothing is set', () => {
    expect(buildQuery({})).toBe('')
    expect(buildQuery({ a: undefined, b: null })).toBe('')
  })

  it('repeats a key once per array element', () => {
    expect(buildQuery({ level: ['high', 'critical'] })).toBe('?level=high&level=critical')
  })

  it('stringifies numbers and booleans', () => {
    expect(buildQuery({ limit: 25, include_private: false })).toBe('?limit=25&include_private=false')
  })

  it('percent-encodes reserved characters', () => {
    expect(buildQuery({ q: 'a b&c=d' })).toBe('?q=a+b%26c%3Dd')
  })

  it('preserves insertion order', () => {
    expect(buildQuery({ sort: '-score', limit: 5, level: ['high'] })).toBe('?sort=-score&limit=5&level=high')
  })
})
