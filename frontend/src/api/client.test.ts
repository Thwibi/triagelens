import { describe, expect, it, vi } from 'vitest'

import { ApiError, ContractError, fetchHealth, parseErrorEnvelope, parseHealthReport } from './client'
import type { FetchLike } from './client'
import type { HealthReport } from './types'

const VALID: HealthReport = {
  app_version: '0.1.0',
  attack_version: 'v16.1',
  ruleset_hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  sqlite_version: '3.50.4',
  fts5: true,
  json1: true,
  workers: 7,
  db_bytes: 321_176,
  free_disk_bytes: 381_278_871_552,
  pdf_available: false,
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(body === null ? '' : JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

/** Resolve to a canned response without an `await`, so no rule objects. */
function respond(body: unknown, status = 200): Promise<Response> {
  return Promise.resolve(jsonResponse(body, status))
}

describe('parseHealthReport', () => {
  it('accepts a complete payload', () => {
    expect(parseHealthReport(VALID)).toEqual(VALID)
  })

  it.each(['app_version', 'attack_version', 'ruleset_hash', 'sqlite_version', 'fts5', 'json1', 'workers', 'db_bytes', 'free_disk_bytes', 'pdf_available'])(
    'rejects a payload missing %s',
    (field) => {
      const partial: Record<string, unknown> = Object.fromEntries(
        Object.entries(VALID).filter(([key]) => key !== field),
      )
      expect(() => parseHealthReport(partial)).toThrow(ContractError)
    },
  )

  it('rejects a non-object body', () => {
    expect(() => parseHealthReport('nope')).toThrow(/must be a JSON object/)
    expect(() => parseHealthReport(null)).toThrow(ContractError)
    expect(() => parseHealthReport([1, 2, 3])).toThrow(ContractError)
  })

  it('rejects a wrong-typed field instead of coercing it', () => {
    expect(() => parseHealthReport({ ...VALID, workers: '7' })).toThrow(/non-negative integer/)
    expect(() => parseHealthReport({ ...VALID, fts5: 'true' })).toThrow(/must be a boolean/)
    expect(() => parseHealthReport({ ...VALID, sqlite_version: 3 })).toThrow(/must be a string/)
  })

  it('rejects a negative byte count', () => {
    expect(() => parseHealthReport({ ...VALID, free_disk_bytes: -1 })).toThrow(/non-negative integer/)
  })

  it('rejects a fractional worker count', () => {
    expect(() => parseHealthReport({ ...VALID, workers: 1.5 })).toThrow(/non-negative integer/)
  })
})

describe('parseErrorEnvelope', () => {
  it('extracts a well-formed envelope', () => {
    expect(parseErrorEnvelope({ error: { code: 'NOT_FOUND', message: 'gone' } })).toEqual({
      error: { code: 'NOT_FOUND', message: 'gone' },
    })
  })

  it('keeps details when present', () => {
    const parsed = parseErrorEnvelope({ error: { code: 'VALIDATION_ERROR', message: 'bad', details: { field: 'x' } } })
    expect(parsed?.error.details).toEqual({ field: 'x' })
  })

  it('collapses an unrecognised code to INTERNAL', () => {
    expect(parseErrorEnvelope({ error: { code: 'TOTALLY_NEW', message: 'boom' } })).toEqual({
      error: { code: 'INTERNAL', message: 'boom' },
    })
  })

  it.each([
    ['a bare string', 'boom'],
    ['an HTML proxy page', '<html>502</html>'],
    ['an error object missing code', { error: { message: 'x' } }],
    ['an error object with a non-string code', { error: { code: 7, message: 'x' } }],
    ['null', null],
  ])('returns null for %s', (_label, body) => {
    expect(parseErrorEnvelope(body)).toBeNull()
  })
})

describe('fetchHealth', () => {
  it('returns the validated report on success', async () => {
    const fetchImpl = vi.fn<FetchLike>(() => respond(VALID))
    await expect(fetchHealth({ fetchImpl })).resolves.toEqual(VALID)
    expect(fetchImpl).toHaveBeenCalledWith('/api/health', expect.objectContaining({ method: 'GET' }))
  })

  it('sends an Accept header and disables caching', async () => {
    const fetchImpl = vi.fn<FetchLike>(() => respond(VALID))
    await fetchHealth({ fetchImpl })
    const init = fetchImpl.mock.calls[0]?.[1]
    expect(init?.headers).toEqual({ Accept: 'application/json' })
    expect(init?.cache).toBe('no-store')
  })

  it('raises ApiError with the server code on 401', async () => {
    const fetchImpl: FetchLike = () => respond({ error: { code: 'UNAUTHORIZED', message: 'missing bearer token' } }, 401)
    await expect(fetchHealth({ fetchImpl })).rejects.toBeInstanceOf(ApiError)
    await expect(fetchHealth({ fetchImpl })).rejects.toMatchObject({
      status: 401,
      code: 'UNAUTHORIZED',
      message: 'missing bearer token',
    })
  })

  it('falls back to a generic message for a non-JSON error body', async () => {
    const fetchImpl: FetchLike = () => Promise.resolve(new Response('<html>bad gateway</html>', { status: 502 }))
    await expect(fetchHealth({ fetchImpl })).rejects.toMatchObject({
      status: 502,
      code: 'INTERNAL',
      message: 'request failed with status 502',
    })
  })

  it('treats an empty 200 body as a contract violation', async () => {
    const fetchImpl: FetchLike = () => Promise.resolve(new Response('', { status: 200 }))
    await expect(fetchHealth({ fetchImpl })).rejects.toBeInstanceOf(ContractError)
  })

  it('propagates an external abort', async () => {
    const controller = new AbortController()
    const fetchImpl: FetchLike = (_input, init) =>
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => {
          reject(new DOMException('aborted', 'AbortError'))
        })
      })
    const pending = fetchHealth({ fetchImpl, signal: controller.signal })
    controller.abort()
    await expect(pending).rejects.toMatchObject({ name: 'AbortError' })
  })
})