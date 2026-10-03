import { describe, expect, it } from 'vitest'

import type { HealthReport } from '../../api/types'
import {
  FREE_DISK_DEGRADED_BYTES,
  FREE_DISK_ERROR_BYTES,
  buildHealthFields,
  hasBlockingFailure,
  isFullyHealthy,
} from './healthFields'

const HEALTHY: HealthReport = {
  app_version: '0.1.0',
  attack_version: 'v16.1',
  ruleset_hash: 'abc123',
  sqlite_version: '3.50.4',
  fts5: true,
  json1: true,
  workers: 4,
  db_bytes: 1024,
  free_disk_bytes: 50 * FREE_DISK_DEGRADED_BYTES,
  pdf_available: true,
}

function field(report: HealthReport, label: string): { readonly label: string; readonly value: string; readonly state: string } {
  const found = buildHealthFields(report).find((entry) => entry.label === label)
  if (found === undefined) {
    throw new Error(`no health field labelled ${label}`)
  }
  return found
}

describe('buildHealthFields', () => {
  it('returns exactly the ten contract fields in a stable order', () => {
    expect(buildHealthFields(HEALTHY).map((entry) => entry.label)).toEqual([
      'TriageLens version',
      'MITRE ATT&CK',
      'Ruleset hash',
      'SQLite version',
      'FTS5 index',
      'JSON1 functions',
      'Worker processes',
      'Database size',
      'Free disk',
      'PDF export',
    ])
  })

  it('reports every field healthy for a complete report', () => {
    const fields = buildHealthFields(HEALTHY)
    expect(isFullyHealthy(fields)).toBe(true)
    expect(hasBlockingFailure(fields)).toBe(false)
  })

  it('treats missing FTS5 as blocking', () => {
    expect(field({ ...HEALTHY, fts5: false }, 'FTS5 index').state).toBe('error')
  })

  it('treats missing JSON1 as blocking', () => {
    expect(field({ ...HEALTHY, json1: false }, 'JSON1 functions').state).toBe('error')
  })

  it('treats an empty SQLite version as blocking', () => {
    expect(field({ ...HEALTHY, sqlite_version: '' }, 'SQLite version').state).toBe('error')
  })

  it('treats a missing app version as blocking', () => {
    expect(field({ ...HEALTHY, app_version: '' }, 'TriageLens version').state).toBe('error')
  })

  it('degrades rather than blocks when the ATT&CK bundle is absent', () => {
    expect(field({ ...HEALTHY, attack_version: '' }, 'MITRE ATT&CK').state).toBe('degraded')
  })

  it('degrades when the ruleset hash is still empty', () => {
    expect(field({ ...HEALTHY, ruleset_hash: '' }, 'Ruleset hash').state).toBe('degraded')
  })

  it('degrades when PDF export is unavailable', () => {
    expect(field({ ...HEALTHY, pdf_available: false }, 'PDF export').state).toBe('degraded')
  })

  it('degrades on an empty database', () => {
    expect(field({ ...HEALTHY, db_bytes: 0 }, 'Database size').state).toBe('degraded')
  })

  it('blocks when free disk is critically low', () => {
    expect(field({ ...HEALTHY, free_disk_bytes: FREE_DISK_ERROR_BYTES - 1 }, 'Free disk').state).toBe('error')
  })

  it('degrades when free disk is merely low', () => {
    expect(field({ ...HEALTHY, free_disk_bytes: FREE_DISK_ERROR_BYTES + 1 }, 'Free disk').state).toBe('degraded')
  })

  it('flags any blocking field', () => {
    expect(hasBlockingFailure(buildHealthFields({ ...HEALTHY, json1: false }))).toBe(true)
  })

  it('pluralises a single worker correctly', () => {
    expect(field({ ...HEALTHY, workers: 1 }, 'Worker processes').value).toBe('1 worker')
    expect(field({ ...HEALTHY, workers: 4 }, 'Worker processes').value).toBe('4 workers')
  })

  it('blocks when no workers are configured', () => {
    expect(field({ ...HEALTHY, workers: 0 }, 'Worker processes').state).toBe('error')
  })
})