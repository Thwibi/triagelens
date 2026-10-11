import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'

import type { EventRecord } from '../../api/types'
import { ToastProvider } from '../../ui/ToastProvider'
import { saveFile } from '../../lib/download'
import { EventsPage } from './EventsPage'

vi.mock('../../lib/download', () => ({ saveFile: vi.fn() }))

vi.mock('@tanstack/react-virtual', () => ({
  useVirtualizer: (options: { readonly count: number }) => ({
    getTotalSize: () => options.count * 40,
    getVirtualItems: () =>
      Array.from({ length: options.count }, (_, index) => ({ index, key: index, start: index * 40, size: 40 })),
    scrollToIndex: () => undefined,
  }),
}))

function makeEvent(overrides: Partial<EventRecord>): EventRecord {
  return {
    id: 1,
    case_id: 'c1',
    source_id: 'src_1',
    record_ref: 'rec-1',
    ts_ms: 1_700_000_000_000,
    ts_iso: '2023-11-14T00:00:00Z',
    log_type: 'windows',
    ls_category: null,
    host: 'web-01',
    channel: 'Security',
    provider: 'Microsoft-Windows-Security',
    app_name: null,
    event_id: 4688,
    level: 'informational',
    event_action: 'Process Create',
    event_outcome: null,
    user_name: 'alice',
    target_user_name: null,
    domain: null,
    src_ip: '10.0.0.5',
    src_port: 51000,
    dst_ip: '10.0.0.9',
    dst_port: 445,
    protocol: 'tcp',
    process_pid: 1234,
    process_path: 'C:\\Windows\\System32\\cmd.exe',
    process_cmdline: 'cmd.exe /c whoami',
    parent_process_path: null,
    parent_process_cmdline: null,
    file_path: null,
    registry_key: null,
    registry_value: null,
    url: null,
    url_path: null,
    url_query: null,
    http_method: null,
    http_status: null,
    user_agent: null,
    bytes_out: null,
    message: 'A process was created',
    fields: {},
    ...overrides,
  }
}

function respond(body: unknown, status = 200): Promise<Response> {
  return Promise.resolve(
    new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }),
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

function renderEvents(initial = '/cases/c1/events'): void {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={client}>
      <ToastProvider>
        <MemoryRouter initialEntries={[initial]}>
          <Routes>
            <Route path="/cases/:caseId/events" element={<EventsPage />} />
          </Routes>
        </MemoryRouter>
      </ToastProvider>
    </QueryClientProvider>,
  )
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('EventsPage', () => {
  it('renders event rows from the list endpoint', async () => {
    stubFetch((url) => {
      if (url.startsWith('/api/cases/c1/events/count')) {
        return { count: 2 }
      }
      if (url.startsWith('/api/cases/c1/events/facets')) {
        return { facets: { host: [{ value: 'web-01', count: 2 }] } }
      }
      return { items: [makeEvent({ id: 1, message: 'A process was created' }), makeEvent({ id: 2, message: 'A user logged on' })], total: 2 }
    })
    renderEvents()

    expect(await screen.findByText('A process was created')).toBeInTheDocument()
    expect(screen.getByText('A user logged on')).toBeInTheDocument()
    expect(screen.getByText(/2 matching/)).toBeInTheDocument()
  })

  it('shows the empty state when there are no events', async () => {
    stubFetch((url) => {
      if (url.startsWith('/api/cases/c1/events/count')) {
        return { count: 0 }
      }
      if (url.startsWith('/api/cases/c1/events/facets')) {
        return { facets: {} }
      }
      return { items: [], total: 0 }
    })
    renderEvents()

    expect(await screen.findByText('No events yet')).toBeInTheDocument()
  })

  it('debounces the search box into a fired query', async () => {
    const fetchMock = stubFetch((url) => {
      if (url.startsWith('/api/cases/c1/events/count')) {
        return { count: 0 }
      }
      if (url.startsWith('/api/cases/c1/events/facets')) {
        return { facets: {} }
      }
      return { items: [], total: 0 }
    })
    const user = userEvent.setup()
    renderEvents()

    await user.type(screen.getByLabelText('Search events'), 'powershell')

    await waitFor(
      () => {
        expect(fetchMock.mock.calls.some(([input]) => String(input).includes('q=powershell'))).toBe(true)
      },
      { timeout: 2000 },
    )
  })

  it('applies a facet value as a filter', async () => {
    const fetchMock = stubFetch((url) => {
      if (url.startsWith('/api/cases/c1/events/count')) {
        return { count: 2 }
      }
      if (url.startsWith('/api/cases/c1/events/facets')) {
        return { facets: { host: [{ value: 'web-01', count: 2 }] } }
      }
      return { items: [makeEvent({ id: 1 })], total: 2 }
    })
    const user = userEvent.setup()
    renderEvents()

    await screen.findByText('A process was created')
    const sidebar = screen.getByRole('complementary', { name: 'Event filters' })
    await user.click(within(sidebar).getByRole('button', { name: /web-01/ }))

    await waitFor(() => {
      expect(fetchMock.mock.calls.some(([input]) => String(input).includes('host=web-01'))).toBe(true)
    })
  })

  it('exports the current result set through the streaming endpoint', async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
      if (url.includes('/events/export')) {
        return Promise.resolve(
          new Response('id,host\n', {
            status: 200,
            headers: {
              'Content-Type': 'text/csv; charset=utf-8',
              'Content-Disposition': 'attachment; filename=events-c1.csv',
            },
          }),
        )
      }
      if (url.startsWith('/api/cases/c1/events/count')) {
        return respond({ count: 1 })
      }
      if (url.startsWith('/api/cases/c1/events/facets')) {
        return respond({ facets: {} })
      }
      return respond({ items: [makeEvent({ id: 1 })], total: 1 })
    })
    vi.stubGlobal('fetch', fetchMock)
    const user = userEvent.setup()
    renderEvents()

    await screen.findByText('A process was created')
    await user.click(screen.getByRole('button', { name: 'Export CSV' }))

    await waitFor(() => {
      const urls = fetchMock.mock.calls.map(([input]) =>
        typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url,
      )
      expect(urls.some((url) => url.includes('/events/export') && url.includes('format=csv'))).toBe(true)
    })
    expect(saveFile).toHaveBeenCalled()
  })
})
