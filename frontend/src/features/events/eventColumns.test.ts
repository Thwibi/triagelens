import { describe, expect, it } from 'vitest'

import { DEFAULT_EVENT_COLUMNS, EVENT_COLUMNS, gridTemplateFor, sanitizeColumns } from './eventColumns'

describe('eventColumns', () => {
  it('defaults to the spec column set', () => {
    expect([...DEFAULT_EVENT_COLUMNS]).toEqual(['time', 'host', 'log_type', 'event', 'user', 'net', 'summary'])
  })

  it('falls back to defaults for a non-array value', () => {
    expect(sanitizeColumns('time')).toEqual([...DEFAULT_EVENT_COLUMNS])
  })

  it('keeps only known columns, in canonical order', () => {
    expect(sanitizeColumns(['summary', 'bogus', 'time'])).toEqual(['time', 'summary'])
  })

  it('falls back to defaults when every entry is unknown', () => {
    expect(sanitizeColumns(['nope'])).toEqual([...DEFAULT_EVENT_COLUMNS])
  })

  it('builds a grid template in canonical column order', () => {
    const template = gridTemplateFor(['summary', 'time'])
    const first = EVENT_COLUMNS.find((column) => column.id === 'time')?.width
    expect(template.startsWith(`${first}`)).toBe(true)
    expect(template).toContain('minmax(16rem,1fr)')
  })
})
