import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'

import type { Ioc } from '../../api/types'
import { ToastProvider } from '../../ui/ToastProvider'
import { IocsPage } from './IocsPage'

const IPV4: Ioc = {
  id: 'i1',
  case_id: 'c1',
  type: 'ipv4',
  value: '203.0.113.9',
  value_norm: '203.0.113.9',
  first_seen_ms: 1_700_000_000_000,
  last_seen_ms: 1_700_000_100_000,
  occurrences: 12,
  confidence: 80,
  is_private: false,
  is_allowlisted: false,
  analyst_state: 'suspicious',
  tags: [],
}

function respond(body: unknown): Promise<Response> {
  return Promise.resolve(
    new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } }),
  )
}

function stubFetch(responder: (url: string) => unknown): ReturnType<typeof vi.fn> {
  const mock = vi.fn((input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
    return respond(responder(url))
  })
  vi.stubGlobal('fetch', mock)
  return mock
}

function renderIocs(): void {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={client}>
      <ToastProvider>
        <MemoryRouter initialEntries={['/cases/c1/iocs']}>
          <Routes>
            <Route path="/cases/:caseId/iocs" element={<IocsPage />} />
          </Routes>
        </MemoryRouter>
      </ToastProvider>
    </QueryClientProvider>,
  )
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('IocsPage', () => {
  it('renders indicator rows', async () => {
    stubFetch(() => ({ items: [IPV4], total: 1 }))
    renderIocs()

    expect(await screen.findByText('203.0.113.9')).toBeInTheDocument()
    expect(screen.getByText('ipv4')).toBeInTheDocument()
    expect(screen.getByText('12')).toBeInTheDocument()
  })

  it('shows the empty state when there are no indicators', async () => {
    stubFetch(() => ({ items: [], total: 0 }))
    renderIocs()

    expect(await screen.findByText('No indicators yet')).toBeInTheDocument()
  })

  it('requests a single-type filter when a single-type tab is chosen', async () => {
    const fetchMock = stubFetch(() => ({ items: [], total: 0 }))
    const user = userEvent.setup()
    renderIocs()

    await screen.findByText('No indicators yet')
    await user.click(screen.getByRole('tab', { name: 'Domains' }))

    await waitFor(() => {
      expect(fetchMock.mock.calls.some(([input]) => String(input).includes('type=domain'))).toBe(true)
    })
  })
})
