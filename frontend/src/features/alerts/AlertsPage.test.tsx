import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'

import type { Alert } from '../../api/types'
import { ToastProvider } from '../../ui/ToastProvider'
import { AlertsPage } from './AlertsPage'

vi.mock('@tanstack/react-virtual', () => ({
  useVirtualizer: (options: { readonly count: number }) => ({
    getTotalSize: () => options.count * 48,
    getVirtualItems: () =>
      Array.from({ length: options.count }, (_, index) => ({ index, key: index, start: index * 48, size: 48 })),
    scrollToIndex: () => undefined,
  }),
}))

const ALERT: Alert = {
  id: 'al_1',
  case_id: 'c1',
  rule_id: 'r1',
  rule_title: 'PowerShell encoded command',
  rule_kind: 'sigma',
  rule_type: 'sigma',
  level: 'high',
  score: 82,
  status: 'new',
  analyst_notes: null,
  tactics: [{ shortname: 'execution', name: 'Execution' }],
  techniques: [{ id: 'T1059.001', name: 'PowerShell', tactics: ['execution'], source: 'tag' }],
  groups_software: [],
  unresolved_tags: [],
  host: 'web-01',
  user_name: 'alice',
  first_seen_ms: 1_700_000_000_000,
  last_seen_ms: 1_700_000_100_000,
  match_count: 3,
  false_positives: [],
  references: [],
}

const ALERT_TWO: Alert = {
  ...ALERT,
  id: 'al_2',
  rule_title: 'Suspicious logon',
  level: 'medium',
  score: 40,
  host: 'web-02',
  user_name: null,
  match_count: 1,
}

function respond(body: unknown, status = 200): Promise<Response> {
  return Promise.resolve(
    new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }),
  )
}

type Responder = (url: string, init: RequestInit | undefined) => { body: unknown; status?: number }

function stubFetch(responder: Responder): ReturnType<typeof vi.fn> {
  const mock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
    const result = responder(url, init)
    return respond(result.body, result.status ?? 200)
  })
  vi.stubGlobal('fetch', mock)
  return mock
}

function renderAlerts(): void {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={client}>
      <ToastProvider>
        <MemoryRouter initialEntries={['/cases/c1/alerts']}>
          <Routes>
            <Route path="/cases/:caseId/alerts" element={<AlertsPage />} />
          </Routes>
        </MemoryRouter>
      </ToastProvider>
    </QueryClientProvider>,
  )
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('AlertsPage', () => {
  it('renders alert rows with their rule, host and count', async () => {
    stubFetch(() => ({ body: { items: [ALERT, ALERT_TWO], total: 2 } }))
    renderAlerts()

    expect(await screen.findByText('PowerShell encoded command')).toBeInTheDocument()
    expect(screen.getByText('Suspicious logon')).toBeInTheDocument()
    expect(screen.getByText('web-01')).toBeInTheDocument()
    expect(screen.getByText('82')).toBeInTheDocument()
  })

  it('shows the empty state when there are no alerts', async () => {
    stubFetch(() => ({ body: { items: [], total: 0 } }))
    renderAlerts()

    expect(await screen.findByText('No alerts yet')).toBeInTheDocument()
  })

  it('bulk-updates the selected alerts', async () => {
    const fetchMock = stubFetch((url, init) => {
      if (url === '/api/alerts/bulk' && init?.method === 'POST') {
        return { body: { items: [{ ...ALERT, status: 'true_positive' }], updated: 1 } }
      }
      return { body: { items: [ALERT, ALERT_TWO], total: 2 } }
    })
    const user = userEvent.setup()
    renderAlerts()

    await screen.findByText('PowerShell encoded command')
    await user.click(screen.getByRole('checkbox', { name: 'Select all on this page' }))
    await user.selectOptions(screen.getByLabelText('Bulk status'), 'true_positive')

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        '/api/alerts/bulk',
        expect.objectContaining({ method: 'POST' }),
      )
    })
  })

  it('sets a verdict on the active row with the keyboard', async () => {
    const fetchMock = stubFetch((url, init) => {
      if (url === '/api/alerts/al_1' && init?.method === 'PATCH') {
        return { body: { item: { ...ALERT, status: 'true_positive' } } }
      }
      return { body: { items: [ALERT, ALERT_TWO], total: 2 } }
    })
    const user = userEvent.setup()
    renderAlerts()

    await screen.findByText('PowerShell encoded command')
    screen.getByRole('table').focus()
    await user.keyboard('t')

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        '/api/alerts/al_1',
        expect.objectContaining({ method: 'PATCH' }),
      )
    })
  })
})
