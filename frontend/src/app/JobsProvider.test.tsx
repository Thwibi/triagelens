import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, render } from '@testing-library/react'
import type { ReactElement } from 'react'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'

import type { Job } from '../api/types'
import { ToastProvider } from '../ui/ToastProvider'
import type { SocketLike } from '../ws/jobsSocket'
import { JobsProvider } from './JobsProvider'

function makeJob(overrides: Partial<Job>): Job {
  return {
    id: 'j1',
    case_id: 'c1',
    kind: 'report',
    source_id: null,
    status: 'done',
    stage: null,
    progress: 1,
    message: null,
    error: null,
    created_at: '2026-01-02T03:04:05.000Z',
    started_at: null,
    finished_at: '2026-01-02T03:05:05.000Z',
    ...overrides,
  }
}

interface FakeSocket {
  readonly socket: SocketLike
  readonly emit: (frame: unknown) => void
}

function makeSocket(): FakeSocket {
  type Listener = (event: { readonly data: unknown }) => void
  const listeners = new Map<string, Listener[]>()
  const socket: SocketLike = {
    addEventListener: (type, listener) => {
      const list = listeners.get(type) ?? []
      list.push(listener)
      listeners.set(type, list)
    },
    send: vi.fn(),
    close: vi.fn(),
  }
  const emit = (frame: unknown): void => {
    for (const listener of listeners.get('message') ?? []) {
      listener({ data: JSON.stringify(frame) })
    }
  }
  return { socket, emit }
}

function renderProvider(socket: SocketLike, queryClient: QueryClient): ReactElement {
  return (
    <QueryClientProvider client={queryClient}>
      <ToastProvider>
        <MemoryRouter initialEntries={['/cases/c1']}>
          <JobsProvider createSocket={() => socket}>
            <div>child</div>
          </JobsProvider>
        </MemoryRouter>
      </ToastProvider>
    </QueryClientProvider>
  )
}

describe('JobsProvider', () => {
  it('refreshes the report history when a report job finishes', () => {
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries')
    const { socket, emit } = makeSocket()
    render(renderProvider(socket, queryClient))

    act(() => {
      emit({ type: 'job.update', job: makeJob({ status: 'done' }) })
    })

    expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['case', 'c1', 'reports'] })
  })

  it('does not refresh report history while a report job is still running', () => {
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries')
    const { socket, emit } = makeSocket()
    render(renderProvider(socket, queryClient))

    act(() => {
      emit({ type: 'job.update', job: makeJob({ status: 'running' }) })
    })

    expect(invalidateSpy).not.toHaveBeenCalledWith({ queryKey: ['case', 'c1', 'reports'] })
  })
})
