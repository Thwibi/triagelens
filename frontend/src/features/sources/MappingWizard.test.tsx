import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'

import type { MappingProfile } from '../../api/types'
import { ToastProvider } from '../../ui/ToastProvider'
import { MappingWizard } from './MappingWizard'

const PROFILE: MappingProfile = {
  name: 'ecs',
  builtin: true,
  timestamp: { path: '@timestamp', format: 'iso8601' },
  timezone: null,
  default_category: null,
  applies_when: { any_key: ['@timestamp'] },
  fields: { host: 'host.name' },
  category_rules: [],
}

function respond(body: unknown, status = 200): Promise<Response> {
  return Promise.resolve(
    new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }),
  )
}

function stubFetch(): void {
  vi.stubGlobal(
    'fetch',
    vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
      if (url === '/api/profiles/preview') {
        return respond({
          log_type: 'generic_json',
          rows: [{ host: 'web-01', message: 'hello' }],
          errors: [],
          row_count: 1,
          error_count: 0,
        })
      }
      if (url === '/api/profiles' && (init?.method ?? 'GET') === 'GET') {
        return respond({ items: [PROFILE], total: 1 })
      }
      return respond({})
    }),
  )
}

function renderWizard(): void {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={client}>
      <ToastProvider>
        <MappingWizard source={null} onClose={() => undefined} />
      </ToastProvider>
    </QueryClientProvider>,
  )
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('MappingWizard', () => {
  it('walks the sample, match, map steps', async () => {
    stubFetch()
    const user = userEvent.setup()
    renderWizard()

    expect(screen.getByRole('heading', { name: 'Custom mapping' })).toBeInTheDocument()

    const next = screen.getByRole('button', { name: 'Next' })
    expect(next).toBeDisabled()

    fireEvent.change(screen.getByLabelText('Sample'), {
      target: { value: '{"@timestamp":"2026-10-08T10:00:00Z","host":{"name":"web-01"}}' },
    })
    fireEvent.change(screen.getByLabelText('Profile name'), { target: { value: 'my_feed' } })
    expect(next).toBeEnabled()

    await user.click(next)
    expect(await screen.findByText('ecs')).toBeInTheDocument()
    expect(screen.getByText('suggested')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Start blank' }))
    expect(screen.getByLabelText('Timestamp path')).toBeInTheDocument()

    const nextAtMap = screen.getByRole('button', { name: 'Next' })
    expect(nextAtMap).toBeDisabled()
    await user.type(screen.getByLabelText('Timestamp path'), '@timestamp')
    expect(nextAtMap).toBeEnabled()
  })

  it('runs a preview and renders normalized rows', async () => {
    stubFetch()
    const user = userEvent.setup()
    renderWizard()

    fireEvent.change(screen.getByLabelText('Sample'), {
      target: { value: '{"@timestamp":"2026-10-08T10:00:00Z"}' },
    })
    fireEvent.change(screen.getByLabelText('Profile name'), { target: { value: 'my_feed' } })
    await user.click(screen.getByRole('button', { name: 'Next' }))
    await user.click(await screen.findByRole('button', { name: 'Start blank' }))
    await user.type(screen.getByLabelText('Timestamp path'), '@timestamp')
    await user.click(screen.getByRole('button', { name: 'Next' }))

    await user.click(screen.getByRole('button', { name: 'Run preview' }))

    expect(await screen.findByText('web-01')).toBeInTheDocument()
    expect(screen.getByText('hello')).toBeInTheDocument()
    expect(screen.getByText('1 rows · 0 errors')).toBeInTheDocument()
  })
})
