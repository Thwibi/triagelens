import { describe, expect, it } from 'vitest'

import type { MappingProfile } from '../../api/types'
import {
  buildProfileYaml,
  draftFromProfile,
  guessLogType,
  sampleFieldPaths,
  suggestProfile,
} from './mappingProfile'
import type { ProfileDraft } from './mappingProfile'

function draft(overrides: Partial<ProfileDraft> = {}): ProfileDraft {
  return {
    name: 'my_feed',
    timestampPath: '@timestamp',
    timestampFormat: 'iso8601',
    timezone: '',
    defaultCategory: '',
    appliesWhen: [],
    fields: {},
    categoryRules: [],
    ...overrides,
  }
}

describe('guessLogType', () => {
  it('calls a document opening with a brace JSON', () => {
    expect(guessLogType('{"a":1}')).toBe('generic_json')
    expect(guessLogType('[{"a":1}]')).toBe('generic_json')
  })

  it('calls a header line CSV', () => {
    expect(guessLogType('a,b,c\n1,2,3')).toBe('generic_csv')
  })

  it('skips leading blank lines and defaults to CSV when empty', () => {
    expect(guessLogType('\n\n  {"a":1}')).toBe('generic_json')
    expect(guessLogType('')).toBe('generic_csv')
  })
})

describe('sampleFieldPaths', () => {
  it('walks nested JSON objects to leaf paths and marks arrays', () => {
    const sample = JSON.stringify({ '@timestamp': 't', host: { name: 'h' }, tags: ['x', 'y'], message: 'm' })
    expect(sampleFieldPaths(sample, 'generic_json')).toEqual(['@timestamp', 'host.name', 'message', 'tags[*]'])
  })

  it('unwraps a JSON list under a known key', () => {
    const sample = JSON.stringify({ events: [{ a: 1, b: 2 }] })
    expect(sampleFieldPaths(sample, 'generic_json')).toEqual(['a', 'b'])
  })

  it('reads CSV header names, honouring quoted commas', () => {
    expect(sampleFieldPaths('a,b,"c,d"\n1,2,3', 'generic_csv')).toEqual(['a', 'b', 'c,d'])
  })

  it('returns nothing for an unparseable JSON sample', () => {
    expect(sampleFieldPaths('{not json', 'generic_json')).toEqual([])
  })
})

describe('suggestProfile', () => {
  const profiles: MappingProfile[] = [
    {
      name: 'ecs',
      builtin: true,
      timestamp: { path: '@timestamp', format: 'iso8601' },
      timezone: null,
      default_category: null,
      applies_when: { any_key: ['@timestamp'] },
      fields: {},
      category_rules: [],
    },
    {
      name: 'other',
      builtin: false,
      timestamp: { path: 'ts', format: 'iso8601' },
      timezone: null,
      default_category: null,
      applies_when: { any_key: ['nothing_here'] },
      fields: {},
      category_rules: [],
    },
  ]

  it('picks the profile whose applies_when keys the sample exposes', () => {
    expect(suggestProfile('{"@timestamp":"t"}', profiles)).toBe('ecs')
  })

  it('returns null when no profile matches', () => {
    expect(suggestProfile('{"alpha":1}', profiles)).toBeNull()
  })
})

describe('buildProfileYaml', () => {
  it('emits every block in a stable order', () => {
    const yaml = buildProfileYaml(
      draft({
        timezone: 'UTC',
        defaultCategory: 'process',
        appliesWhen: ['@timestamp', 'event.category'],
        fields: { host: 'host.name', message: 'message' },
        categoryRules: [{ field: 'event.category', value: 'process', lsCategory: 'process' }],
      }),
    )
    expect(yaml).toBe(
      [
        "name: 'my_feed'",
        'timestamp:',
        "  path: '@timestamp'",
        "  format: 'iso8601'",
        "timezone: 'UTC'",
        "default_category: 'process'",
        'applies_when:',
        '  any_key:',
        "    - '@timestamp'",
        "    - 'event.category'",
        'fields:',
        "  host: 'host.name'",
        "  message: 'message'",
        'category_rules:',
        '  - when:',
        "      'event.category': 'process'",
        "    ls_category: 'process'",
        '',
      ].join('\n'),
    )
  })

  it('omits empty optional blocks', () => {
    expect(buildProfileYaml(draft())).toBe(
      ["name: 'my_feed'", 'timestamp:', "  path: '@timestamp'", "  format: 'iso8601'", ''].join('\n'),
    )
  })

  it('escapes single quotes in a scalar', () => {
    expect(buildProfileYaml(draft({ name: "a'b" }))).toContain("name: 'a''b'")
  })

  it('drops blank field paths and incomplete rules', () => {
    const yaml = buildProfileYaml(
      draft({
        fields: { host: 'host.name', message: '   ' },
        categoryRules: [{ field: '', value: 'x', lsCategory: 'y' }],
      }),
    )
    expect(yaml).toContain("  host: 'host.name'")
    expect(yaml).not.toContain('message')
    expect(yaml).not.toContain('category_rules')
  })
})

describe('draftFromProfile', () => {
  it('seeds a new-name draft from an existing profile', () => {
    const profile: MappingProfile = {
      name: 'ecs',
      builtin: true,
      timestamp: { path: '@timestamp', format: 'epoch_ms' },
      timezone: 'UTC',
      default_category: 'network',
      applies_when: { any_key: ['@timestamp'] },
      fields: { host: 'host.name' },
      category_rules: [{ when: { 'event.category': 'network' }, ls_category: 'network' }],
    }
    const seeded = draftFromProfile(profile)
    expect(seeded.name).toBe('ecs_custom')
    expect(seeded.timestampFormat).toBe('epoch_ms')
    expect(seeded.fields).toEqual({ host: 'host.name' })
    expect(seeded.appliesWhen).toEqual(['@timestamp'])
    expect(seeded.categoryRules).toEqual([
      { field: 'event.category', value: 'network', lsCategory: 'network' },
    ])
  })
})
