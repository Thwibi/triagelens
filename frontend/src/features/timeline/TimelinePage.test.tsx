import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'

import type { Alert, Ioc } from '../../api/types'
import { TimelinePage } from './TimelinePage'

const ALERT: Alert = {
  id: 'al_1',
  case_id: 'c1',
  rule_id: 'r1',
  rule_title: 'Suspicious logon',
  rule_kind: 'sigma',
  rule_type: 'sigma',
  level: 'high',
  score: 70,
  status: 'new',
  analyst_notes: null,
  tactics: [],
  techniques: [],
  groups_software: [],
  unresolved_tags: [],
  host: 'web-01',
  user_name: 'alice',
  first_seen_ms: 1_700_000_000_000,
  last_seen_ms: 1_700_000_050_000,
  match_count: 1,
  false_positives: [],
  references: [],
}

const IOC: Ioc = {
  id: 'i1',
  case_id: 'c1',
  type: 'ipv4',
  value: '203.0.113.9',
  value_norm: '203.0.113.9',
  first_seen_ms: 1_700_000_000_000,
  last_seen_ms: 1_700_000_050_000,
  occurrences: 3,
  confidence: 90,
  is_private: false,
  is_allowlisted: false,
  analyst_state: 'malicious',
  tags: [],
}

function respond(body: unknown): Promise<Response> {
  return Promise.resolve(
    new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } }),
  )
}

function stubFetch(responder: (url: string) => unknown): void {
  vi.stubGlobal(
    'fetch',
    vi.fn((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
      return respond(responder(url))
    }),
  )
}

function renderTimeline(): void {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/cases/c1/timeline']}>
        <Routes>
          <Route path="/cases/:caseId/timeline" element={<TimelinePage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('TimelinePage', () => {
  it('shows the empty state when the timeline has no buckets', async () => {
    stubFetch((url) => {
      if (url.startsWith('/api/cases/c1/timeline')) {
        return { bucket_ms: 60_000, buckets: [] }
      }
      if (url.startsWith('/api/cases/c1/alerts')) {
        return { items: [], total: 0 }
      }
      return { items: [], total: 0 }
    })
    renderTimeline()

    expect(await screen.findByText('No events in range')).toBeInTheDocument()
    expect(screen.getByText('No alerts in the selected range.')).toBeInTheDocument()
  })

  it('lists alerts and notable indicators in the selected range', async () => {
    stubFetch((url) => {
      if (url.startsWith('/api/cases/c1/timeline')) {
        return { bucket_ms: 60_000, buckets: [] }
      }
      if (url.startsWith('/api/cases/c1/alerts')) {
        return { items: [ALERT], total: 1 }
      }
      return { items: [IOC], total: 1 }
    })
    renderTimeline()

    expect(await screen.findByText('Suspicious logon')).toBeInTheDocument()
    expect(await screen.findByText('203.0.113.9')).toBeInTheDocument()
  })
})
