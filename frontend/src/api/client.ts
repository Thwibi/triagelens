import type { ApiErrorCode, ApiErrorEnvelope, HealthReport } from './types'
import { isApiErrorCode, REQUIRED_HEALTH_FIELDS } from './types'

/** Error raised for any non-2xx API response, carrying the server's code. */
export class ApiError extends Error {
  readonly status: number
  readonly code: ApiErrorCode
  readonly details: Readonly<Record<string, unknown>> | undefined

  constructor(status: number, envelope: ApiErrorEnvelope | null) {
    super(envelope?.error.message ?? `request failed with status ${status}`)
    this.name = 'ApiError'
    this.status = status
    this.code = envelope?.error.code ?? 'INTERNAL'
    this.details = envelope?.error.details
  }
}

/** Raised when a 200 response does not match the contract the UI relies on. */
export class ContractError extends Error {
  readonly field: string

  constructor(message: string, field: string) {
    super(message)
    this.name = 'ContractError'
    this.field = field
  }
}

/** Injection seam so tests can supply a fetch implementation. */
export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>

const DEFAULT_TIMEOUT_MS = 10_000

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/**
 * Narrow an untrusted JSON body to an error envelope.
 *
 * Returns `null` when the body is not an envelope, so a proxy HTML error page
 * cannot be mistaken for a structured API error. An unrecognised code collapses
 * to `INTERNAL` rather than reaching the UI as free text.
 */
export function parseErrorEnvelope(body: unknown): ApiErrorEnvelope | null {
  if (!isRecord(body) || !isRecord(body['error'])) {
    return null
  }
  const error = body['error']
  const code = error['code']
  const message = error['message']
  if (typeof code !== 'string' || typeof message !== 'string') {
    return null
  }
  if (!isApiErrorCode(code)) {
    return { error: { code: 'INTERNAL', message } }
  }
  const details = error['details']
  return {
    error: {
      code,
      message,
      ...(isRecord(details) ? { details } : {}),
    },
  }
}

async function readBody(response: Response): Promise<unknown> {
  const text = await response.text()
  if (text.length === 0) {
    return null
  }
  try {
    return JSON.parse(text) as unknown
  } catch {
    return null
  }
}

/**
 * Perform a GET against the local API and return the parsed body.
 *
 * `AbortSignal` support is deliberate: a hung request must not leave the status
 * view spinning forever.
 */
export async function getJson(
  path: string,
  options: { readonly signal?: AbortSignal; readonly timeoutMs?: number; readonly fetchImpl?: FetchLike } = {},
): Promise<unknown> {
  const doFetch = options.fetchImpl ?? ((input, init) => fetch(input, init))
  const controller = new AbortController()
  const timeout = setTimeout(() => {
    controller.abort()
  }, options.timeoutMs ?? DEFAULT_TIMEOUT_MS)

  const onExternalAbort = (): void => {
    controller.abort()
  }
  options.signal?.addEventListener('abort', onExternalAbort)

  try {
    const response = await doFetch(path, {
      method: 'GET',
      headers: { Accept: 'application/json' },
      credentials: 'same-origin',
      cache: 'no-store',
      signal: controller.signal,
    })
    const body = await readBody(response)
    if (!response.ok) {
      throw new ApiError(response.status, parseErrorEnvelope(body))
    }
    return body
  } finally {
    clearTimeout(timeout)
    options.signal?.removeEventListener('abort', onExternalAbort)
  }
}

function requireBoolean(body: Record<string, unknown>, field: string): boolean {
  const value = body[field]
  if (typeof value !== 'boolean') {
    throw new ContractError(`health field "${field}" must be a boolean`, field)
  }
  return value
}

function requireInteger(body: Record<string, unknown>, field: string): number {
  const value = body[field]
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) {
    throw new ContractError(`health field "${field}" must be a non-negative integer`, field)
  }
  return value
}

function requireString(body: Record<string, unknown>, field: string): string {
  const value = body[field]
  if (typeof value !== 'string') {
    throw new ContractError(`health field "${field}" must be a string`, field)
  }
  return value
}

/**
 * Validate a health payload field by field.
 *
 * A missing field is a contract violation, not a display problem, so it throws
 * instead of rendering `undefined`.
 */
export function parseHealthReport(body: unknown): HealthReport {
  if (!isRecord(body)) {
    throw new ContractError('health response must be a JSON object', '<root>')
  }
  for (const field of REQUIRED_HEALTH_FIELDS) {
    if (!(field in body)) {
      throw new ContractError(`health response is missing "${field}"`, field)
    }
  }
  return {
    app_version: requireString(body, 'app_version'),
    attack_version: requireString(body, 'attack_version'),
    ruleset_hash: requireString(body, 'ruleset_hash'),
    sqlite_version: requireString(body, 'sqlite_version'),
    fts5: requireBoolean(body, 'fts5'),
    json1: requireBoolean(body, 'json1'),
    workers: requireInteger(body, 'workers'),
    db_bytes: requireInteger(body, 'db_bytes'),
    free_disk_bytes: requireInteger(body, 'free_disk_bytes'),
    pdf_available: requireBoolean(body, 'pdf_available'),
  }
}

/** Fetch and validate `GET /api/health`. */
export async function fetchHealth(options: { readonly signal?: AbortSignal; readonly fetchImpl?: FetchLike } = {}): Promise<HealthReport> {
  return parseHealthReport(await getJson('/api/health', options))
}