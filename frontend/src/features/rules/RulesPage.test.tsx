import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'

import type { Rule } from '../../api/types'
import { ToastProvider } from '../../ui/ToastProvider'
import { RulesPage } from './RulesPage'

const RULE: Rule = {
  id: 'r1',
  title: 'Suspicious lsass access',
  kind: 'sigma',
  rule_type: 'detection',
  level: 'high',
  status: 'stable',
  enabled: true,
  tags: ['attack.t1003.001'],
  logsource: { product: 'windows' },
  file_path: 'sigma/windows/r1.yml',
  sha256: 'abc123',
  compile_error: null,
  unroutable: false,
  healthy: true,
  updated_at: '2026-10-10T00:00:00Z',
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
    return body instanceof Response || body instanceof Promise ? Promise.resolve(body) : respond(body)
  })
  vi.stubGlobal('fetch', mock)
  return mock
}

function renderRules(): void {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={client}>
      <ToastProvider>
        <MemoryRouter initialEntries={['/cases/c1/rules']}>
          <Routes>
            <Route path="/cases/:caseId/rules" element={<RulesPage />} />
          </Routes>
        </MemoryRouter>
      </ToastProvider>
    </QueryClientProvider>,
  )
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('RulesPage', () => {
  it('renders rule rows', async () => {
    stubFetch((url) => (url.includes('/rules/health') ? { total: 1, ok: 1 } : { items: [RULE], total: 1 }))
    renderRules()

    expect(await screen.findByText('Suspicious lsass access')).toBeInTheDocument()
    expect(screen.getByText('T1003.001')).toBeInTheDocument()
  })

  it('shows the empty state when the catalogue is empty', async () => {
    stubFetch((url) => (url.includes('/rules/health') ? { total: 0 } : { items: [], total: 0 }))
    renderRules()

    expect(await screen.findByText('No rules in the catalogue')).toBeInTheDocument()
  })

  it('toggles a rule through the enabled checkbox', async () => {
    const fetchMock = stubFetch((url, init) =>
      url.includes('/rules/health')
        ? { total: 1, ok: 1 }
        : init?.method === 'PATCH'
          ? { item: { ...RULE, enabled: false } }
          : { items: [RULE], total: 1 },
    )
    const user = userEvent.setup()
    renderRules()

    await screen.findByText('Suspicious lsass access')
    await user.click(screen.getByRole('checkbox', { name: 'Enable Suspicious lsass access' }))

    await waitFor(() => {
      expect(fetchMock.mock.calls.some(([, init]) => init?.method === 'PATCH')).toBe(true)
    })
  })

  it('opens the create drawer from the New rule button', async () => {
    stubFetch((url) => (url.includes('/rules/health') ? { total: 0 } : { items: [], total: 0 }))
    const user = userEvent.setup()
    renderRules()

    await screen.findByText('No rules in the catalogue')
    await user.click(screen.getByRole('button', { name: 'New rule' }))

    expect(await screen.findByRole('dialog', { name: 'New rule' })).toBeInTheDocument()
  })
})
