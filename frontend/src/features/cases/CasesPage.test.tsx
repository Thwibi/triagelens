import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'

import type { Case } from '../../api/types'
import { CasesPage } from './CasesPage'

const CASE_A: Case = {
  id: 'c1',
  name: 'Phishing wave',
  description: 'Mailbox exports',
  default_timezone: 'UTC',
  created_at: '2026-10-08T10:00:00Z',
  updated_at: '2026-10-08T10:00:00Z',
  counts: { sources: 2, events: 120, alerts: 3, iocs: 5 },
}

const CASE_B: Case = {
  id: 'c2',
  name: 'Lateral movement',
  description: null,
  default_timezone: 'UTC',
  created_at: '2026-10-09T10:00:00Z',
  updated_at: '2026-10-09T10:00:00Z',
  counts: { sources: 0, events: 0, alerts: 0, iocs: 0 },
}

type Responder = (url: string, init: RequestInit | undefined) => { body: unknown; status?: number }

function stubFetch(responder: Responder): ReturnType<typeof vi.fn> {
  const mock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
    const { body, status = 200 } = responder(url, init)
    return Promise.resolve(
      new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }),
    )
  })
  vi.stubGlobal('fetch', mock)
  return mock
}

function renderCases(): void {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <CasesPage />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('CasesPage', () => {
  it('lists cases with their counts', async () => {
    stubFetch(() => ({ body: { items: [CASE_A, CASE_B], total: 2 } }))
    renderCases()

    expect(await screen.findByRole('heading', { name: 'Phishing wave' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Lateral movement' })).toBeInTheDocument()
    expect(screen.getByText('120')).toBeInTheDocument()
  })

  it('offers an empty state when there are no cases', async () => {
    stubFetch(() => ({ body: { items: [], total: 0 } }))
    renderCases()

    expect(await screen.findByText('Create your first case')).toBeInTheDocument()
  })

  it('shows a retryable error panel when the list fails', async () => {
    stubFetch(() => ({ body: { error: { code: 'INTERNAL', message: 'boom' } }, status: 500 }))
    renderCases()

    expect(await screen.findByText('Cannot load cases')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument()
  })

  it('creates a case from the new-case form', async () => {
    const user = userEvent.setup()
    const fetchMock = stubFetch((url, init) => {
      if (init?.method === 'POST' && url === '/api/cases') {
        return { body: CASE_A, status: 201 }
      }
      return { body: { items: [CASE_B], total: 1 } }
    })
    renderCases()

    await screen.findByRole('heading', { name: 'Lateral movement' })
    await user.click(screen.getByRole('button', { name: /new case/i }))
    await user.type(screen.getByLabelText('Name'), 'Fresh case')
    await user.click(screen.getByRole('button', { name: /create case/i }))

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        '/api/cases',
        expect.objectContaining({ method: 'POST' }),
      )
    })
  })
})
