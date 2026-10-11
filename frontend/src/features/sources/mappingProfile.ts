/**
 * Pure helpers for the custom mapping wizard (spec 07 section 3.11).
 *
 * The wizard edits a `ProfileDraft`, which this module turns into the YAML the
 * backend's profile loader accepts, and back again when an existing profile is
 * loaded as a starting point. Nothing here touches React or the network so the
 * emitter and the sample-path walker can be unit tested directly.
 */

import type { MappingProfile } from '../../api/types'

/** How the wizard renders and validates a normalized column. */
export type FieldKind = 'text' | 'int' | 'level' | 'outcome'

/** One normalized column a profile can populate. */
export interface NormalizedFieldSpec {
  readonly name: string
  readonly label: string
  readonly kind: FieldKind
}

/**
 * The normalized columns the generic engine reads (spec 03 section 6).
 *
 * Kept in the same order as `map_record` reads them, so the mapping form mirrors
 * the engine rather than an arbitrary list.
 */
export const NORMALIZED_FIELDS: readonly NormalizedFieldSpec[] = [
  { name: 'host', label: 'Host', kind: 'text' },
  { name: 'event_id', label: 'Event ID', kind: 'int' },
  { name: 'level', label: 'Level', kind: 'level' },
  { name: 'event_action', label: 'Action', kind: 'text' },
  { name: 'event_outcome', label: 'Outcome', kind: 'outcome' },
  { name: 'user_name', label: 'User', kind: 'text' },
  { name: 'src_ip', label: 'Source IP', kind: 'text' },
  { name: 'src_port', label: 'Source port', kind: 'int' },
  { name: 'dst_ip', label: 'Destination IP', kind: 'text' },
  { name: 'dst_port', label: 'Destination port', kind: 'int' },
  { name: 'process_path', label: 'Process path', kind: 'text' },
  { name: 'process_cmdline', label: 'Process command line', kind: 'text' },
  { name: 'parent_process_path', label: 'Parent process path', kind: 'text' },
  { name: 'file_path', label: 'File path', kind: 'text' },
  { name: 'url', label: 'URL', kind: 'text' },
  { name: 'http_method', label: 'HTTP method', kind: 'text' },
  { name: 'http_status', label: 'HTTP status', kind: 'int' },
  { name: 'user_agent', label: 'User agent', kind: 'text' },
  { name: 'message', label: 'Message', kind: 'text' },
]

/** Timestamp formats the profile loader accepts. */
export const TIMESTAMP_FORMATS: readonly string[] = ['iso8601', 'epoch_s', 'epoch_ms']

/** A category rule being edited. */
export interface CategoryRuleDraft {
  readonly field: string
  readonly value: string
  readonly lsCategory: string
}

/** The editable state behind the wizard's mapping step. */
export interface ProfileDraft {
  readonly name: string
  readonly timestampPath: string
  readonly timestampFormat: string
  readonly timezone: string
  readonly defaultCategory: string
  readonly appliesWhen: readonly string[]
  readonly fields: Readonly<Record<string, string>>
  readonly categoryRules: readonly CategoryRuleDraft[]
}

/** Quote a YAML scalar; single quotes are the escape-safe form. */
function quote(value: string): string {
  return `'${value.replaceAll("'", "''")}'`
}

/**
 * Serialize a draft to the profile YAML the backend loader parses.
 *
 * Only the keys the loader understands are emitted, in a fixed order, so the
 * output is stable and diff-able. Empty optional blocks are omitted rather than
 * written as empty lists, which keeps a profile minimal.
 */
export function buildProfileYaml(draft: ProfileDraft): string {
  const lines: string[] = []
  lines.push(`name: ${quote(draft.name)}`)
  lines.push('timestamp:')
  lines.push(`  path: ${quote(draft.timestampPath)}`)
  lines.push(`  format: ${quote(draft.timestampFormat)}`)
  if (draft.timezone.trim() !== '') {
    lines.push(`timezone: ${quote(draft.timezone.trim())}`)
  }
  if (draft.defaultCategory.trim() !== '') {
    lines.push(`default_category: ${quote(draft.defaultCategory.trim())}`)
  }
  if (draft.appliesWhen.length > 0) {
    lines.push('applies_when:')
    lines.push('  any_key:')
    for (const key of draft.appliesWhen) {
      lines.push(`    - ${quote(key)}`)
    }
  }
  const fieldEntries = Object.entries(draft.fields).filter(([, path]) => path.trim() !== '')
  if (fieldEntries.length > 0) {
    lines.push('fields:')
    for (const [column, path] of fieldEntries) {
      lines.push(`  ${column}: ${quote(path.trim())}`)
    }
  }
  const rules = draft.categoryRules.filter(
    (rule) => rule.field.trim() !== '' && rule.lsCategory.trim() !== '',
  )
  if (rules.length > 0) {
    lines.push('category_rules:')
    for (const rule of rules) {
      lines.push('  - when:')
      lines.push(`      ${quote(rule.field.trim())}: ${quote(rule.value)}`)
      lines.push(`    ls_category: ${quote(rule.lsCategory.trim())}`)
    }
  }
  return `${lines.join('\n')}\n`
}

/** JSON when the first non-blank line opens an object or array, else CSV. */
export function guessLogType(sample: string): 'generic_json' | 'generic_csv' {
  for (const line of sample.split(/\r?\n/)) {
    const trimmed = line.trim()
    if (trimmed !== '') {
      return trimmed.startsWith('{') || trimmed.startsWith('[') ? 'generic_json' : 'generic_csv'
    }
  }
  return 'generic_csv'
}

function walkJson(value: unknown, prefix: string, out: Set<string>): void {
  if (Array.isArray(value)) {
    if (prefix !== '') {
      out.add(`${prefix}[*]`)
    }
    if (value.length > 0) {
      walkJson(value[0], prefix === '' ? '[*]' : `${prefix}[*]`, out)
    }
    return
  }
  if (value !== null && typeof value === 'object') {
    for (const [key, child] of Object.entries(value)) {
      const path = prefix === '' ? key : `${prefix}.${key}`
      if (child !== null && typeof child === 'object') {
        walkJson(child, path, out)
      } else {
        out.add(path)
      }
    }
    return
  }
  if (prefix !== '') {
    out.add(prefix)
  }
}

/** Unwrap the shapes the generic JSON parser accepts to the record to sample. */
function firstJsonRecord(parsed: unknown): unknown {
  if (Array.isArray(parsed)) {
    return parsed[0]
  }
  if (parsed === null || typeof parsed !== 'object') {
    return parsed
  }
  const record = parsed as Record<string, unknown>
  for (const key of ['events', 'records', 'Records']) {
    const candidate = record[key]
    if (Array.isArray(candidate)) {
      return candidate[0]
    }
  }
  const hits = record['hits']
  if (hits !== null && typeof hits === 'object') {
    const inner = (hits as Record<string, unknown>)['hits']
    if (Array.isArray(inner) && inner.length > 0) {
      const source = (inner[0] as Record<string, unknown> | undefined)?.['_source']
      return source ?? inner[0]
    }
  }
  return parsed
}

/** Split one CSV header line, honouring simple double-quoted fields. */
function csvHeader(line: string): string[] {
  const cells: string[] = []
  let cell = ''
  let quoted = false
  for (let i = 0; i < line.length; i += 1) {
    const char = line.charAt(i)
    if (quoted) {
      if (char === '"') {
        if (line.charAt(i + 1) === '"') {
          cell += '"'
          i += 1
        } else {
          quoted = false
        }
      } else {
        cell += char
      }
    } else if (char === '"') {
      quoted = true
    } else if (char === ',') {
      cells.push(cell.trim())
      cell = ''
    } else {
      cell += char
    }
  }
  cells.push(cell.trim())
  return cells.filter((name) => name !== '')
}

/**
 * Field paths a sample exposes, for the mapping dropdowns' autocompletion.
 *
 * JSON is walked to leaf paths (arrays become `[*]`), CSV yields its header
 * names. A sample that does not parse yields no paths rather than throwing, so
 * the wizard stays usable while the operator is still pasting.
 */
export function sampleFieldPaths(
  sample: string,
  logType: 'generic_json' | 'generic_csv',
): readonly string[] {
  if (logType === 'generic_json') {
    let parsed: unknown
    try {
      parsed = JSON.parse(sample)
    } catch {
      try {
        parsed = JSON.parse(sample.split(/\r?\n/).find((line) => line.trim() !== '') ?? '')
      } catch {
        return []
      }
    }
    const out = new Set<string>()
    walkJson(firstJsonRecord(parsed), '', out)
    return [...out].sort()
  }
  const header = sample.split(/\r?\n/).find((line) => line.trim() !== '')
  return header === undefined ? [] : [...new Set(csvHeader(header))].sort()
}

/**
 * The most plausible existing profile for a sample, by `applies_when` key
 * overlap (spec 07 step 2). Returns the profile name, or `null` when none claim
 * any of the sample's keys.
 */
export function suggestProfile(sample: string, profiles: readonly MappingProfile[]): string | null {
  const paths = sampleFieldPaths(sample, guessLogType(sample))
  if (paths.length === 0) {
    return null
  }
  let best: string | null = null
  let bestScore = 0
  for (const profile of profiles) {
    const keys = profile.applies_when.any_key
    const score = keys.filter((key) => paths.some((path) => path === key || path.includes(key))).length
    if (score > bestScore) {
      best = profile.name
      bestScore = score
    }
  }
  return best
}

/** Seed a draft from an existing profile, so it can be edited and saved anew. */
export function draftFromProfile(profile: MappingProfile): ProfileDraft {
  return {
    name: `${profile.name}_custom`,
    timestampPath: profile.timestamp.path,
    timestampFormat: profile.timestamp.format,
    timezone: profile.timezone ?? '',
    defaultCategory: profile.default_category ?? '',
    appliesWhen: profile.applies_when.any_key,
    fields: { ...profile.fields },
    categoryRules: profile.category_rules.map((rule) => {
      const [field = '', value = ''] = Object.entries(rule.when)[0] ?? []
      return { field, value: String(value), lsCategory: rule.ls_category }
    }),
  }
}
