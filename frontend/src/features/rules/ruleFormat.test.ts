import { describe, expect, it } from 'vitest'

import type { Rule } from '../../api/types'
import { healthOf, kindLabel, logsourceSummary, ruleTechniques, toAlertLevel } from './ruleFormat'

function rule(overrides: Partial<Rule> = {}): Rule {
  return {
    id: 'r1',
    title: 'Rule',
    kind: 'custom',
    rule_type: 'detection',
    level: 'high',
    status: 'stable',
    enabled: true,
    tags: [],
    logsource: {},
    file_path: 'custom/r1.yml',
    sha256: 'abc',
    compile_error: null,
    unroutable: false,
    healthy: true,
    updated_at: '2026-10-10T00:00:00Z',
    ...overrides,
  }
}

describe('ruleFormat', () => {
  it('labels known kinds and falls back to the raw string', () => {
    expect(kindLabel('builtin')).toBe('Built-in')
    expect(kindLabel('weird')).toBe('weird')
  })

  it('maps known levels and rejects the rest', () => {
    expect(toAlertLevel('critical')).toBe('critical')
    expect(toAlertLevel('nonsense')).toBeNull()
  })

  it('reports health from compile error, then unroutable, else ok', () => {
    expect(healthOf(rule({ compile_error: 'boom' })).bucket).toBe('compile_error')
    expect(healthOf(rule({ unroutable: true })).bucket).toBe('unroutable')
    expect(healthOf(rule()).bucket).toBe('ok')
  })

  it('extracts ATT&CK techniques from tags', () => {
    expect(ruleTechniques(rule({ tags: ['attack.t1059', 'attack.t1059.001', 'other'] }))).toEqual([
      'T1059',
      'T1059.001',
    ])
  })

  it('summarises a logsource', () => {
    expect(logsourceSummary(rule({ logsource: { category: 'process_creation', product: 'windows' } }))).toBe(
      'process_creation/windows',
    )
    expect(logsourceSummary(rule())).toBe('—')
  })
})
