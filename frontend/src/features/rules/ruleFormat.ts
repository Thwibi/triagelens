/**
 * Rule-catalogue presentation constants and helpers (spec 07 section 3.10).
 *
 * Pure functions only: the list, filters and drawer all read the same labels so
 * a level or health string can never render two different ways.
 */
import type { AlertLevel, Rule } from '../../api/types'
import type { StatusTone } from '../../ui/Badge'

/** The three ownership kinds the loader and API recognise (spec 04 section 9). */
export const RULE_KINDS = ['builtin', 'custom', 'sigma'] as const
export type RuleKind = (typeof RULE_KINDS)[number]

/** Rule severities, loudest first (spec 04 section 8). */
export const RULE_LEVELS = ['critical', 'high', 'medium', 'low', 'informational'] as const

/** The rule types the loader emits (spec 04 section 4). */
export const RULE_TYPES = ['detection', 'correlation'] as const

/** Health buckets the catalogue reports (spec 06 `GET /rules/health`). */
export const HEALTH_BUCKETS = ['ok', 'compile_error', 'unroutable'] as const
export type HealthBucket = (typeof HEALTH_BUCKETS)[number]

/** Common Sigma `status` values offered as filter shortcuts (spec 04 section 3). */
export const SIGMA_STATUSES = ['stable', 'test', 'experimental', 'deprecated', 'unsupported'] as const

const KIND_LABEL: Readonly<Record<string, string>> = {
  builtin: 'Built-in',
  custom: 'Custom',
  sigma: 'Sigma',
}

/** Human label for a rule kind, falling back to the raw string. */
export function kindLabel(kind: string): string {
  return KIND_LABEL[kind] ?? kind
}

/** The alert-level vocabulary the severity badge understands, or `null`. */
export function toAlertLevel(level: string): AlertLevel | null {
  switch (level) {
    case 'critical':
      return 'critical'
    case 'high':
      return 'high'
    case 'medium':
      return 'medium'
    case 'low':
      return 'low'
    case 'informational':
      return 'informational'
    default:
      return null
  }
}

/** Health as a label plus a tone (colour is never the only signal). */
export function healthOf(rule: Rule): { readonly bucket: HealthBucket; readonly label: string; readonly tone: StatusTone } {
  if (rule.compile_error !== null) {
    return { bucket: 'compile_error', label: 'Compile error', tone: 'error' }
  }
  if (rule.unroutable) {
    return { bucket: 'unroutable', label: 'Unroutable', tone: 'warn' }
  }
  return { bucket: 'ok', label: 'OK', tone: 'ok' }
}

/** Health bucket label for the counts cards. */
export const HEALTH_LABEL: Readonly<Record<HealthBucket, string>> = {
  ok: 'OK',
  compile_error: 'Compile errors',
  unroutable: 'Unroutable',
}

/** The techniques a rule references, from its `tags` (`attack.t1234`). */
export function ruleTechniques(rule: Rule): readonly string[] {
  const found: string[] = []
  for (const tag of rule.tags) {
    const match = /^attack\.(t\d{4}(?:\.\d{3})?)$/i.exec(tag)
    if (match?.[1] !== undefined) {
      found.push(match[1].toUpperCase())
    }
  }
  return found
}

/** A one-line logsource summary from the rule's `logsource` mapping. */
export function logsourceSummary(rule: Rule): string {
  const parts: string[] = []
  for (const key of ['category', 'product', 'service']) {
    const value = rule.logsource[key]
    if (typeof value === 'string' && value.length > 0) {
      parts.push(value)
    }
  }
  return parts.length > 0 ? parts.join('/') : '—'
}
