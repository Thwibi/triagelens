import type { HealthField, HealthReport, HealthState } from '../../api/types'
import { formatBytes, formatHash } from '../../lib/format'

/**
 * Below this much free disk the tool cannot safely accept another upload, so the
 * value is reported as blocking rather than merely degraded.
 */
export const FREE_DISK_ERROR_BYTES: number = 100 * 1024 * 1024

/** Below this much free disk the tool still works but uploads may fail soon. */
export const FREE_DISK_DEGRADED_BYTES: number = 1024 * 1024 * 1024

function versionField(label: string, value: string, required: boolean, absentLabel: string): HealthField {
  if (value.length === 0) {
    return {
      label,
      value: absentLabel,
      state: required ? 'error' : 'degraded',
    }
  }
  return { label, value, state: 'ok' }
}

function booleanField(label: string, value: boolean, required: boolean): HealthField {
  if (value) {
    return { label, value: 'available', state: 'ok' }
  }
  return {
    label,
    value: required ? 'unavailable' : 'disabled',
    state: required ? 'error' : 'degraded',
  }
}

/**
 * Turn a health report into ordered, classified display rows.
 *
 * Classification lives here rather than in the component so it can be unit
 * tested without rendering, and so the severity rules are stated in one place.
 *
 * `fts5` and `json1` are blocking: without them the ingestion and JSON paths in
 * spec 00 section 5 cannot work. The ATT&CK bundle and the ruleset are
 * degraded-only, because Phase 0 ships neither and the API must still start.
 */
export function buildHealthFields(report: HealthReport): readonly HealthField[] {
  const freeDisk = report.free_disk_bytes
  const diskState: HealthState =
    freeDisk < FREE_DISK_ERROR_BYTES ? 'error' : freeDisk < FREE_DISK_DEGRADED_BYTES ? 'degraded' : 'ok'

  return [
    versionField('TriageLens version', report.app_version, true, 'missing'),
    versionField('MITRE ATT&CK', report.attack_version, false, 'bundle not installed'),
    { label: 'Ruleset hash', value: formatHash(report.ruleset_hash), state: report.ruleset_hash.length === 0 ? 'degraded' : 'ok' },
    versionField('SQLite version', report.sqlite_version, true, 'missing'),
    booleanField('FTS5 index', report.fts5, true),
    booleanField('JSON1 functions', report.json1, true),
    {
      label: 'Worker processes',
      value: report.workers === 1 ? '1 worker' : `${report.workers} workers`,
      state: report.workers >= 1 ? 'ok' : 'error',
    },
    { label: 'Database size', value: formatBytes(report.db_bytes), state: report.db_bytes > 0 ? 'ok' : 'degraded' },
    { label: 'Free disk', value: formatBytes(freeDisk), state: diskState },
    booleanField('PDF export', report.pdf_available, false),
  ]
}

/** True when at least one field is blocking, i.e. the tool cannot be used. */
export function hasBlockingFailure(fields: readonly HealthField[]): boolean {
  return fields.some((field) => field.state === 'error')
}

/** True when nothing is wrong at all. */
export function isFullyHealthy(fields: readonly HealthField[]): boolean {
  return fields.every((field) => field.state === 'ok')
}