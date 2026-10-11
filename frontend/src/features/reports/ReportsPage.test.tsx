import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'

import type { Report } from '../../api/types'
import { ToastProvider } from '../../ui/ToastProvider'
import { ReportsPage } from './ReportsPage'

const HTML_REPORT: Report = {
  id: 'r1',
  case_id: 'c1',
  format: 'html',
  sha256: 'a'.repeat(64),
  created_at: '2026-01-02T03:04:05.000Z',
  options: {
    format: 'html',
    statuses: ['new'],
    events_per_alert: 10,
    iocs: true,
    mitre: true,
    timeline: true,
    entities: true,
    appendix_raw: false,
  },
}

const HEALTH = {
  app_version: '0.1.0',
  attack_version: '14',
  ruleset_hash: 'f'.repeat(64),
  sqlite_version: '3.45.0',
  fts5: true,
  json1: true,
  workers: 2,
  db_bytes: 1024,
  free_disk_bytes: 1_000_000_000,
  pdf_available: false,
}

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } })
}

function fakeJob(): Record<string, unknown> {
  return {
    id: 'j1',
    case_id: 'c1',
    kind: 'report',
    source_id: null,
    status: 'queued',
    stage: null,
    progress: 0,
    message: null,
    error: null,
    created_at: '2026-01-02T03:04:05.000Z',
    started_at: null,
    finished_at: null,
  }
}

function stubFetch(handler: (url: string, init?: RequestInit) => Response): ReturnType<typeof vi.fn> {
  const mock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
    return Promise.resolve(handler(url, init))
  })
  vi.stubGlobal('fetch', mock)
  return mock
}

function defaultHandler(url: string): Response {
  if (url.includes('/reports/alerts.csv')) {
    return new Response('', { status: 200 })
  }
  if (url.includes('/reports/') && url.includes('/download')) {
    return new Response('<html><body><h1>Report</h1></body></html>', {
      status: 200,
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Disposition': 'attachment; filename=r1.html',
      },
    })
  }
  if (url.includes('/reports')) {
    return jsonResponse({ items: [HTML_REPORT], total: 1, limit: 50, offset: 0 })
  }
  if (url.includes('/jobs')) {
    return jsonResponse({ items: [], total: 0, limit: 50, offset: 0 })
  }
  if (url.includes('/health')) {
    return jsonResponse(HEALTH)
  }
  return jsonResponse({ items: [], total: 0 })
}

function renderReports(): void {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={client}>
      <ToastProvider>
        <MemoryRouter initialEntries={['/cases/c1/reports']}>
          <Routes>
            <Route path="/cases/:caseId/reports" element={<ReportsPage />} />
          </Routes>
        </MemoryRouter>
      </ToastProvider>
    </QueryClientProvider>,
  )
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('ReportsPage', () => {
  it('renders the report history with a truncated SHA-256', async () => {
    stubFetch((url) => defaultHandler(url))
    renderReports()

    expect(await screen.findByText('html')).toBeInTheDocument()
    expect(screen.getByText('aaaaaaaa…aaaaaaaa')).toBeInTheDocument()
  })

  it('submits the options form to the report endpoint', async () => {
    const fetchMock = stubFetch((url, init) => {
      if (url.endsWith('/cases/c1/reports') && init?.method === 'POST') {
        return jsonResponse(fakeJob())
      }
      return defaultHandler(url)
    })
    const user = userEvent.setup()
    renderReports()

    await screen.findByText('html')
    await user.click(screen.getByRole('button', { name: 'Generate' }))

    await waitFor(() => {
      const post = fetchMock.mock.calls.find(
        ([input, init]) => String(input).endsWith('/cases/c1/reports') && init?.method === 'POST',
      )
      expect(post).toBeDefined()
    })
    const call = fetchMock.mock.calls.find(
      ([input, init]) => String(input).endsWith('/cases/c1/reports') && init?.method === 'POST',
    )
    const body = JSON.parse(String(call?.[1]?.body)) as { format: string; include: { alerts: string[] } }
    expect(body.format).toBe('html')
    expect(body.include.alerts).toContain('new')
  })

  it('previews an HTML report inside a sandboxed iframe', async () => {
    stubFetch((url) => defaultHandler(url))
    const user = userEvent.setup()
    renderReports()

    await screen.findByText('html')
    await user.click(screen.getByRole('button', { name: /Preview/ }))

    const frame = await screen.findByTitle('Report preview')
    expect(frame.getAttribute('sandbox')).toBe('')
    expect(frame.getAttribute('srcdoc')).toContain('<h1>Report</h1>')
  })

  it('disables PDF when the optional dependency is absent', async () => {
    stubFetch((url) => defaultHandler(url))
    renderReports()

    const pdf = await screen.findByRole('radio', { name: 'PDF' })
    expect(pdf).toBeDisabled()
  })
})
