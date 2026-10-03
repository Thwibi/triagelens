import { render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { MemoryRouter } from 'react-router-dom'

import type { HealthReport } from '../../api/types'
import { StatusPage, overallState } from './StatusPage'

const HEALTHY: HealthReport = {
  app_version: '0.1.0',
  attack_version: 'v16.1',
  ruleset_hash: 'abc123',
  sqlite_version: '3.50.4',
  fts5: true,
  json1: true,
  workers: 4,
  db_bytes: 1024 * 1024,
  free_disk_bytes: 50 * 1024 * 1024 * 1024,
  pdf_available: true,
}

function stubHealth(body: unknown, status = 200): void {
  vi.stubGlobal(
    'fetch',
    vi.fn(() => Promise.resolve(new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }))),
  )
}

function renderStatus(): void {
  render(
    <MemoryRouter>
      <StatusPage />
    </MemoryRouter>,
  )
}

describe('overallState', () => {
  it('prefers error over degraded over ok', () => {
    expect(overallState(['ok', 'degraded'])).toBe('degraded')
    expect(overallState(['degraded', 'error'])).toBe('error')
    expect(overallState(['ok', 'ok'])).toBe('ok')
  })
})

describe('StatusPage', () => {
  it('shows the loading state before the first response', async () => {
    renderStatus()
    expect(await screen.findByRole('heading', { name: /checking local services/i })).toBeInTheDocument()
  })

  it('renders every health field once loaded', async () => {
    stubHealth(HEALTHY)
    renderStatus()
    expect(await screen.findByRole('heading', { name: /service status/i })).toBeInTheDocument()
    for (const label of ['SQLite version', 'FTS5 index', 'JSON1 functions', 'Free disk', 'Database size']) {
      expect(screen.getByText(label)).toBeInTheDocument()
    }
    expect(screen.getByText('All checks passed')).toBeInTheDocument()
  })

  it('surfaces a degraded summary when an optional capability is off', async () => {
    stubHealth({ ...HEALTHY, pdf_available: false })
    renderStatus()
    expect(await screen.findByText('Running with reduced capability')).toBeInTheDocument()
    expect(screen.getByText(/1 of 10 checks need attention/)).toBeInTheDocument()
  })

  it('surfaces a blocked summary when FTS5 is missing', async () => {
    stubHealth({ ...HEALTHY, fts5: false })
    renderStatus()
    expect(await screen.findByText('Not ready to accept logs')).toBeInTheDocument()
    expect(screen.getByText(/required for ingestion/)).toBeInTheDocument()
  })

  it('shows an alert with the server error code when the API returns 401', async () => {
    stubHealth({ error: { code: 'UNAUTHORIZED', message: 'missing bearer token' } }, 401)
    renderStatus()
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('UNAUTHORIZED')
    expect(screen.getByText(/requires the configured bearer token/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument()
  })

  it('reports an unreachable API distinctly from a server error', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.reject(new TypeError('Failed to fetch'))),
    )
    renderStatus()
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('UNREACHABLE')
    expect(alert).toHaveTextContent('Failed to fetch')
  })

  it('reports a contract violation when a field is missing', async () => {
    const partial: Record<string, unknown> = Object.fromEntries(
      Object.entries(HEALTHY).filter(([key]) => key !== 'db_bytes'),
    )
    stubHealth(partial)
    renderStatus()
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('CONTRACT')
    expect(alert).toHaveTextContent('db_bytes')
  })
})