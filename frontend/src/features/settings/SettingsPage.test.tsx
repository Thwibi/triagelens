import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { Toasts } from '../../components/Toasts'
import { ThemeProvider } from '../../theme/ThemeProvider'
import { ToastProvider } from '../../ui/ToastProvider'
import { SettingsPage } from './SettingsPage'

const SETTINGS = {
  settings: {
    detection: { profile: 'standard', auto_run_after_ingest: true, rule_timeout_seconds: 120 },
    storage: { data_dir: './data' },
    ioc: { allow_enrichment: false },
    limits: { max_upload_gb: 10 },
  },
  overrides: {},
  allowlist: [
    { id: 1, scope: 'global', case_id: null, kind: 'domain', value: 'example.com', note: null },
  ],
}

const HEALTH = {
  app_version: '1.0.0',
  attack_version: '15.1',
  ruleset_hash: 'abcdef0123456789',
  sqlite_version: '3.45',
  fts5: true,
  json1: true,
  workers: 4,
  db_bytes: 1024,
  free_disk_bytes: 2048,
  pdf_available: false,
}

function respond(body: unknown, status = 200): Promise<Response> {
  return Promise.resolve(
    new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }),
  )
}

function stubFetch(responder: (url: string, init?: RequestInit) => unknown): ReturnType<typeof vi.fn> {
  const mock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
    const body = responder(url, init)
    return body instanceof Promise ? body : respond(body)
  })
  vi.stubGlobal('fetch', mock)
  return mock
}

function renderSettings(): void {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={client}>
      <ThemeProvider>
        <ToastProvider>
          <Toasts />
          <MemoryRouter initialEntries={['/cases/c1/settings']}>
            <Routes>
              <Route path="/cases/:caseId/settings" element={<SettingsPage />} />
            </Routes>
          </MemoryRouter>
        </ToastProvider>
      </ThemeProvider>
    </QueryClientProvider>,
  )
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('SettingsPage', () => {
  it('shows the detection profile and allowlist entries', async () => {
    stubFetch((url) => (url.includes('/api/health') ? HEALTH : url.includes('/api/cases') ? { items: [], total: 0 } : SETTINGS))
    renderSettings()

    expect(await screen.findByDisplayValue('standard')).toBeInTheDocument()
    expect(screen.getByText('example.com')).toBeInTheDocument()
  })

  it('updates the detection profile through the select', async () => {
    const fetchMock = stubFetch((url, init) =>
      url.includes('/api/health')
        ? HEALTH
        : init?.method === 'PUT'
          ? SETTINGS
          : url.includes('/api/cases')
            ? { items: [], total: 0 }
            : SETTINGS,
    )
    const user = userEvent.setup()
    renderSettings()

    const select = await screen.findByDisplayValue('standard')
    await user.selectOptions(select, 'full')

    await waitFor(() => {
      expect(fetchMock.mock.calls.some(([, init]) => init?.method === 'PUT')).toBe(true)
    })
  })

  it('opens the About dialog with live versions', async () => {
    stubFetch((url) => (url.includes('/api/health') ? HEALTH : url.includes('/api/cases') ? { items: [], total: 0 } : SETTINGS))
    const user = userEvent.setup()
    renderSettings()

    await screen.findByDisplayValue('standard')
    await user.click(screen.getByRole('button', { name: 'About' }))

    expect(await screen.findByRole('dialog', { name: 'About TriageLens' })).toBeInTheDocument()
    const dialog = screen.getByRole('dialog', { name: 'About TriageLens' })
    expect(within(dialog).getByText('15.1')).toBeInTheDocument()
    expect(within(dialog).getByText(/Detection Rule License \(DRL\) 1\.1/)).toBeInTheDocument()
    expect(within(dialog).getByText(/MITRE ATT&CK/)).toBeInTheDocument()
  })

  it('vacuums the database and reports the reclaimed space', async () => {
    const fetchMock = stubFetch((url) => {
      if (url.includes('/api/health')) return HEALTH
      if (url.includes('/api/cases')) return { items: [], total: 0 }
      if (url.includes('/api/maintenance/vacuum')) {
        return { ok: true, db_bytes_before: 1024, db_bytes_after: 512 }
      }
      return SETTINGS
    })
    const user = userEvent.setup()
    renderSettings()

    await screen.findByDisplayValue('standard')
    await user.click(screen.getByRole('button', { name: 'Vacuum' }))

    expect(await screen.findByText(/compacted/)).toBeInTheDocument()
    expect(
      fetchMock.mock.calls.some(
        ([input, init]) =>
          String(input).includes('/api/maintenance/vacuum') && init?.method === 'POST',
      ),
    ).toBe(true)
  })

  it('verifies the audit chain and reports the row count', async () => {
    stubFetch((url) => {
      if (url.includes('/api/health')) return HEALTH
      if (url.includes('/api/cases')) return { items: [], total: 0 }
      if (url.includes('/api/maintenance/verify-audit')) return { chain_ok: true, rows_checked: 12 }
      return SETTINGS
    })
    const user = userEvent.setup()
    renderSettings()

    await screen.findByDisplayValue('standard')
    await user.click(screen.getByRole('button', { name: 'Verify audit chain' }))

    expect(await screen.findByText(/Audit chain verified/)).toBeInTheDocument()
  })

  it('reports failed evidence verification', async () => {
    stubFetch((url) => {
      if (url.includes('/api/health')) return HEALTH
      if (url.includes('/api/cases')) return { items: [], total: 0 }
      if (url.includes('/api/maintenance/verify-hashes')) {
        return {
          ok: false,
          checked: 3,
          mismatched: [{ source_id: 's1', case_id: 'c1', path: '/data/a' }],
          missing: [],
        }
      }
      return SETTINGS
    })
    const user = userEvent.setup()
    renderSettings()

    await screen.findByDisplayValue('standard')
    await user.click(screen.getByRole('button', { name: 'Verify evidence hashes' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('1 of 3 originals failed verification')
  })
})
