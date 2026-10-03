import { describe, expect, it } from 'vitest'

import { formatAttackVersion, formatBytes, formatHash, formatSeconds, truncate } from './format'

describe('formatBytes', () => {
  it.each([
    [0, '0 B'],
    [-1, '0 B'],
    [Number.NaN, '0 B'],
    [512, '512 B'],
    [1024, '1.00 KiB'],
    [1536, '1.50 KiB'],
    [10 * 1024, '10.0 KiB'],
    [1024 ** 2, '1.00 MiB'],
    [1024 ** 3, '1.00 GiB'],
    [1024 ** 4, '1.00 TiB'],
  ])('formats %d as %s', (input, expected) => {
    expect(formatBytes(input)).toBe(expected)
  })

  it('does not invent a unit beyond PiB', () => {
    expect(formatBytes(1024 ** 5)).toBe('1.00 PiB')
    expect(formatBytes(1024 ** 6)).toBe('1024.0 PiB')
  })
})

describe('formatHash', () => {
  it('marks an empty digest as not built', () => {
    expect(formatHash('')).toBe('not built')
  })

  it('keeps short digests intact', () => {
    expect(formatHash('abcdef0123456789')).toBe('abcdef0123456789')
  })

  it('shortens a sha256 digest at both ends', () => {
    const digest = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    expect(formatHash(digest)).toBe('e3b0c442…7852b855')
  })
})

describe('formatAttackVersion', () => {
  it('passes a real version through', () => {
    expect(formatAttackVersion('v16.1')).toBe('v16.1')
  })

  it('reports an absent bundle explicitly', () => {
    expect(formatAttackVersion('')).toBe('bundle not installed')
  })
})

describe('formatSeconds', () => {
  it('uses seconds below a minute', () => {
    expect(formatSeconds(30)).toBe('30s')
  })

  it('converts to whole minutes above a minute', () => {
    expect(formatSeconds(90)).toBe('2m')
  })
})

describe('truncate', () => {
  it('leaves short values alone', () => {
    expect(truncate('abc', 5)).toBe('abc')
  })

  it('adds an ellipsis when cutting', () => {
    expect(truncate('abcdefgh', 5)).toBe('abcd…')
  })

  it('never exceeds the requested length', () => {
    expect(truncate('abcdefgh', 5)).toHaveLength(5)
  })
})