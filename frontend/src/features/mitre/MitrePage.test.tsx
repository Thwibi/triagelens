import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'

import type { CaseMitreMatrix, MitreStaticMatrix } from '../../api/types'
import { ToastProvider } from '../../ui/ToastProvider'
import { MitrePage } from './MitrePage'

const CASE_MATRIX: CaseMitreMatrix = {
  attack_version: 'v16.1',
  unmapped_alert_count: 2,
  tactics: [
    {
      shortname: 'execution',
      name: 'Execution',
      techniques: [
        {
          id: 'T1059',
          name: 'Command and Scripting Interpreter',
          alert_count: 3,
          max_level: 'high',
          alert_ids: ['a1', 'a2', 'a3'],
          subtechniques: [
            { id: 'T1059.001', name: 'PowerShell', alert_count: 1, max_level: 'critical', alert_ids: ['a1'], subtechniques: [] },
          ],
        },
      ],
    },
  ],
}

const EMPTY_CASE_MATRIX: CaseMitreMatrix = {
  attack_version: 'v16.1',
  unmapped_alert_count: 0,
  tactics: [{ shortname: 'execution', name: 'Execution', techniques: [] }],
}

const STATIC_MATRIX: MitreStaticMatrix = {
  attack_version: 'v16.1',
  tactics: [
    {
      shortname: 'execution',
      name: 'Execution',
      techniques: [
        {
          id: 'T1059',
          name: 'Command and Scripting Interpreter',
          subtechniques: [
            { id: 'T1059.001', name: 'PowerShell', subtechniques: [] },
            { id: 'T1059.003', name: 'Windows Command Shell', subtechniques: [] },
          ],
        },
        { id: 'T1204', name: 'User Execution', subtechniques: [] },
      ],
    },
  ],
}

function respond(body: unknown): Promise<Response> {
  return Promise.resolve(
    new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } }),
  )
}

function stubFetch(caseMatrix: CaseMitreMatrix): void {
  vi.stubGlobal(
    'fetch',
    vi.fn((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
      if (url === '/api/mitre/matrix') {
        return respond(STATIC_MATRIX)
      }
      if (url === '/api/cases/c1/mitre') {
        return respond(caseMatrix)
      }
      return respond({})
    }),
  )
}

function renderMitre(): void {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={client}>
      <ToastProvider>
        <MemoryRouter initialEntries={['/cases/c1/mitre']}>
          <Routes>
            <Route path="/cases/:caseId/mitre" element={<MitrePage />} />
          </Routes>
        </MemoryRouter>
      </ToastProvider>
    </QueryClientProvider>,
  )
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('MitrePage', () => {
  it('renders fired techniques linking to the filtered alerts list', async () => {
    stubFetch(CASE_MATRIX)
    renderMitre()

    expect(await screen.findByRole('heading', { name: 'ATT&CK Coverage' })).toBeInTheDocument()
    const link = screen.getByRole('link', { name: /T1059/ })
    expect(link).toHaveAttribute('href', '/cases/c1/alerts?technique=T1059')
    expect(screen.getByText(/2 alerts have no ATT&CK technique/)).toBeInTheDocument()
  })

  it('shows the empty state when nothing has fired', async () => {
    stubFetch(EMPTY_CASE_MATRIX)
    renderMitre()

    expect(await screen.findByText('No ATT&CK mappings yet')).toBeInTheDocument()
  })

  it('switches to the full matrix and expands sub-techniques', async () => {
    stubFetch(CASE_MATRIX)
    const user = userEvent.setup()
    renderMitre()

    await screen.findByRole('heading', { name: 'ATT&CK Coverage' })
    await user.click(screen.getByRole('button', { name: 'Full matrix' }))

    expect(await screen.findByRole('link', { name: /T1204/ })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Expand T1059' }))
    expect(screen.getByRole('link', { name: /T1059\.003/ })).toBeInTheDocument()
  })
})
