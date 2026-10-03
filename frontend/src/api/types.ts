/**
 * Typed wire types for the Phase 0 API surface.
 *
 * Every type mirrors the backend payload exactly; the compiler rejects any drift
 * at the call site instead of failing silently at runtime.
 */

/** `GET /api/health` response body. Every field is required by spec 08. */
export interface HealthReport {
  readonly app_version: string
  readonly attack_version: string
  readonly ruleset_hash: string
  readonly sqlite_version: string
  readonly fts5: boolean
  readonly json1: boolean
  readonly workers: number
  readonly db_bytes: number
  readonly free_disk_bytes: number
  readonly pdf_available: boolean
}

/** Stable error code from the spec 06 envelope. */
export type ApiErrorCode =
  | 'VALIDATION_ERROR'
  | 'UNAUTHORIZED'
  | 'NOT_FOUND'
  | 'CONFLICT'
  | 'INTERNAL'
  | 'UPLOAD_TOO_LARGE'
  | 'FORBIDDEN_PATH'
  | 'ARCHIVE_REJECTED'
  | 'PARSE_ERROR'
  | 'CAPABILITY_MISSING'
  | 'JOB_NOT_FOUND'

/** Every known code, for runtime validation of server responses. */
export const API_ERROR_CODES: readonly ApiErrorCode[] = [
  'VALIDATION_ERROR',
  'UNAUTHORIZED',
  'NOT_FOUND',
  'CONFLICT',
  'INTERNAL',
  'UPLOAD_TOO_LARGE',
  'FORBIDDEN_PATH',
  'ARCHIVE_REJECTED',
  'PARSE_ERROR',
  'CAPABILITY_MISSING',
  'JOB_NOT_FOUND',
] as const satisfies readonly ApiErrorCode[]

/** True when `value` is one of the spec 06 error codes. */
export function isApiErrorCode(value: string): value is ApiErrorCode {
  return (API_ERROR_CODES as readonly string[]).includes(value)
}

/** Machine-readable error envelope returned by every non-2xx API response. */
export interface ApiErrorEnvelope {
  readonly error: {
    readonly code: ApiErrorCode
    readonly message: string
    readonly details?: Readonly<Record<string, unknown>>
  }
}

/** One health field rendered as a labelled row. */
export interface HealthField {
  readonly label: string
  readonly value: string
  readonly state: HealthState
}

/** Visual state for a health field: OK, degraded, or a blocking problem. */
export type HealthState = 'ok' | 'degraded' | 'error'

/** Which health fields are required to be present for the app to be usable. */
export const REQUIRED_HEALTH_FIELDS: readonly (keyof HealthReport)[] = [
  'app_version',
  'attack_version',
  'ruleset_hash',
  'sqlite_version',
  'fts5',
  'json1',
  'workers',
  'db_bytes',
  'free_disk_bytes',
  'pdf_available',
] as const satisfies readonly (keyof HealthReport)[]