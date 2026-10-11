import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'

import type { Entity } from '../../api/types'
import { EntitiesPage } from './EntitiesPage'

const ENTITIES: readonly Entity[] = [
  { kind: 'host', name: 'web-01', event_count: 1200, alert_count: 0 },
  { kind: 'user', name: 'alice', event_count: 40, alert_count: 0 },
]

function renderEntities(): void {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/cases/c1/entities']}>
        <Routes>
          <Route path="/cases/:caseId/entities" element={<EntitiesPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('EntitiesPage', () => {
  it('lists hosts and users with their counts', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(new Response(JSON.stringify(ENTITIES), { status: 200, headers: { 'Content-Type': 'application/json' } })),
      ),
    )
    renderEntities()

    expect(await screen.findByText('web-01')).toBeInTheDocument()
    expect(screen.getByText('alice')).toBeInTheDocument()
    expect(screen.getByText('Hosts')).toBeInTheDocument()
    expect(screen.getByText('Users')).toBeInTheDocument()
  })

  it('shows the empty state when there are no entities', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(new Response(JSON.stringify([]), { status: 200, headers: { 'Content-Type': 'application/json' } })),
      ),
    )
    renderEntities()

    expect(await screen.findByText('No entities yet')).toBeInTheDocument()
  })
})
