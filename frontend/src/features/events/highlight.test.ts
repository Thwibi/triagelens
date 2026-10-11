import { describe, expect, it } from 'vitest'

import { highlightSegments } from './highlight'

describe('highlightSegments', () => {
  it('returns a single unmatch segment for empty needles', () => {
    expect(highlightSegments('powershell -enc', [])).toEqual([{ text: 'powershell -enc', match: false }])
  })

  it('marks case-insensitive matches as text segments', () => {
    expect(highlightSegments('PowerShell -Enc ABC', ['powershell', 'abc'])).toEqual([
      { text: 'PowerShell', match: true },
      { text: ' -Enc ', match: false },
      { text: 'ABC', match: true },
    ])
  })

  it('keeps the original casing of the matched text', () => {
    const segments = highlightSegments('Evil.example.com', ['evil.example.com'])
    expect(segments).toEqual([{ text: 'Evil.example.com', match: true }])
  })

  it('merges overlapping matches so ranges never overlap', () => {
    expect(highlightSegments('abcdef', ['abcd', 'cdef'])).toEqual([{ text: 'abcdef', match: true }])
  })

  it('ignores needles shorter than two characters', () => {
    expect(highlightSegments('a b c', ['a'])).toEqual([{ text: 'a b c', match: false }])
  })

  it('returns no segments for an empty string', () => {
    expect(highlightSegments('', ['powershell'])).toEqual([])
  })
})
