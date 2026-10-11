import { describe, expect, it } from 'vitest'

import { parseCaseId } from './caseRoute'

describe('parseCaseId', () => {
  it.each<[string, string | null]>([
    ['/cases/c1', 'c1'],
    ['/cases/c1/sources', 'c1'],
    ['/cases/c1/sources/42', 'c1'],
    ['/cases/c1/', 'c1'],
    ['/cases/a%2Fb', 'a/b'],
    ['/cases/', null],
    ['/cases', null],
    ['/', null],
    ['/status', null],
    ['/casesx/c1', null],
  ])('parses %s as %s', (pathname, expected) => {
    expect(parseCaseId(pathname)).toBe(expected)
  })

  it('decodes a percent-encoded id once', () => {
    expect(parseCaseId('/cases/a%2520b')).toBe('a%20b')
  })
})
