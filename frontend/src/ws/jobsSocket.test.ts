import { afterEach, describe, expect, it, vi } from 'vitest'

import type { ServerFrame } from '../api/types'
import { JobsSocket, isServerFrame, socketUrl } from './jobsSocket'
import type { ConnectionStatus } from './jobsSocket'

/** A controllable stand-in for a browser WebSocket. */
class FakeSocket {
  readonly sent: string[] = []
  private readonly listeners = new Map<string, ((event: { readonly data: unknown }) => void)[]>()

  addEventListener(type: string, listener: (event: { readonly data: unknown }) => void): void {
    const list = this.listeners.get(type) ?? []
    list.push(listener)
    this.listeners.set(type, list)
  }

  send(data: string): void {
    this.sent.push(data)
  }

  close(): void {
    this.emit('close')
  }

  emit(type: string): void {
    for (const listener of this.listeners.get(type) ?? []) {
      listener({ data: undefined })
    }
  }

  emitMessage(data: unknown): void {
    for (const listener of this.listeners.get('message') ?? []) {
      listener({ data })
    }
  }
}

interface Harness {
  readonly socket: JobsSocket
  readonly sockets: FakeSocket[]
  readonly frames: ServerFrame[]
  readonly statuses: ConnectionStatus[]
}

function harness(minDelayMs = 1_000, maxDelayMs = 4_000): Harness {
  const sockets: FakeSocket[] = []
  const frames: ServerFrame[] = []
  const statuses: ConnectionStatus[] = []
  const socket = new JobsSocket({
    url: 'ws://localhost/api/ws/cases/c1',
    onFrame: (frame) => frames.push(frame),
    onStatus: (status) => statuses.push(status),
    createSocket: () => {
      const fake = new FakeSocket()
      sockets.push(fake)
      return fake
    },
    minDelayMs,
    maxDelayMs,
  })
  return { socket, sockets, frames, statuses }
}

afterEach(() => {
  vi.useRealTimers()
})

describe('isServerFrame', () => {
  it.each(['job.stage', 'job.update', 'source.update', 'alerts.changed', 'needs_input', 'error', 'ping'])(
    'accepts %s',
    (type) => {
      expect(isServerFrame({ type })).toBe(true)
    },
  )

  it.each([null, 'ping', 7, [], { type: 'made.up' }, { no: 'type' }])('rejects %o', (value) => {
    expect(isServerFrame(value)).toBe(false)
  })
})

describe('socketUrl', () => {
  it('uses ws for http and mirrors the host', () => {
    const location = { protocol: 'http:', host: 'localhost:8000' } as Location
    expect(socketUrl('/api/ws/cases/c1', location)).toBe('ws://localhost:8000/api/ws/cases/c1')
  })

  it('uses wss for https', () => {
    const location = { protocol: 'https:', host: 'tl.example' } as Location
    expect(socketUrl('/api/ws/jobs/j1', location)).toBe('wss://tl.example/api/ws/jobs/j1')
  })
})

describe('JobsSocket', () => {
  it('opens and reports the lifecycle', () => {
    const { socket, sockets, statuses } = harness()
    socket.start()
    expect(sockets).toHaveLength(1)
    expect(statuses).toEqual(['connecting'])

    sockets[0]?.emit('open')
    expect(statuses).toEqual(['connecting', 'open'])
  })

  it('forwards known frames and drops malformed ones', () => {
    const { socket, sockets, frames } = harness()
    socket.start()
    sockets[0]?.emit('open')

    sockets[0]?.emitMessage(JSON.stringify({ type: 'job.update', job_id: 'j1', status: 'succeeded' }))
    sockets[0]?.emitMessage(JSON.stringify({ type: 'needs_input', job_id: 'j1', source_id: 's1', candidates: [] }))
    sockets[0]?.emitMessage('not json')
    sockets[0]?.emitMessage(JSON.stringify({ type: 'made.up' }))
    sockets[0]?.emitMessage(JSON.stringify({ no: 'type' }))

    expect(frames.map((frame) => frame.type)).toEqual(['job.update', 'needs_input'])
  })

  it('answers a ping with a pong without surfacing it', () => {
    const { socket, sockets, frames } = harness()
    socket.start()
    sockets[0]?.emit('open')

    sockets[0]?.emitMessage(JSON.stringify({ type: 'ping' }))

    expect(sockets[0]?.sent).toEqual([JSON.stringify({ type: 'pong' })])
    expect(frames).toEqual([])
  })

  it('reconnects with exponential backoff capped at the maximum', () => {
    vi.useFakeTimers()
    const { socket, sockets, statuses } = harness(1_000, 4_000)
    socket.start()
    sockets[0]?.emit('open')

    sockets[0]?.emit('close')
    expect(statuses.at(-1)).toBe('reconnecting')

    vi.advanceTimersByTime(999)
    expect(sockets).toHaveLength(1)
    vi.advanceTimersByTime(1)
    expect(sockets).toHaveLength(2)

    sockets[1]?.emit('close')
    vi.advanceTimersByTime(1_999)
    expect(sockets).toHaveLength(2)
    vi.advanceTimersByTime(1)
    expect(sockets).toHaveLength(3)

    sockets[2]?.emit('close')
    vi.advanceTimersByTime(3_999)
    expect(sockets).toHaveLength(3)
    vi.advanceTimersByTime(1)
    expect(sockets).toHaveLength(4)

    sockets[3]?.emit('close')
    vi.advanceTimersByTime(5_000)
    expect(sockets).toHaveLength(5)
  })

  it('resets the backoff after a successful open', () => {
    vi.useFakeTimers()
    const { socket, sockets } = harness(1_000, 4_000)
    socket.start()
    sockets[0]?.emit('open')
    sockets[0]?.emit('close')
    vi.advanceTimersByTime(1_000)
    sockets[1]?.emit('open')
    sockets[1]?.emit('close')
    vi.advanceTimersByTime(1_000)
    expect(sockets).toHaveLength(3)
  })

  it('stops reconnecting after stop', () => {
    vi.useFakeTimers()
    const { socket, sockets, statuses } = harness()
    socket.start()
    sockets[0]?.emit('close')
    socket.stop()
    vi.advanceTimersByTime(60_000)
    expect(sockets).toHaveLength(1)
    expect(statuses.at(-1)).toBe('closed')
  })

  it('ignores a stale socket closing after a newer one connected', () => {
    vi.useFakeTimers()
    const { socket, sockets } = harness()
    socket.start()
    sockets[0]?.emit('close')
    vi.advanceTimersByTime(1_000)
    expect(sockets).toHaveLength(2)

    sockets[0]?.emit('close')
    vi.advanceTimersByTime(60_000)
    expect(sockets).toHaveLength(2)
  })
})
