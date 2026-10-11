import type { ServerFrame } from '../api/types'

/** Connection lifecycle surfaced to the UI (spec 07 section 4). */
export type ConnectionStatus = 'connecting' | 'open' | 'reconnecting' | 'closed'

/**
 * The subset of `WebSocket` the client uses.
 *
 * Declared structurally so a test can supply a fake without pulling in a full
 * browser WebSocket, and so the real one is adapted once in `defaultSocket`.
 */
export interface SocketLike {
  addEventListener(type: 'open' | 'close' | 'error', listener: () => void): void
  addEventListener(type: 'message', listener: (event: { readonly data: unknown }) => void): void
  send(data: string): void
  close(): void
}

const KNOWN_FRAME_TYPES: ReadonlySet<string> = new Set([
  'job.stage',
  'job.update',
  'source.update',
  'alerts.changed',
  'needs_input',
  'error',
  'ping',
])

/** True for a frame this client knows how to handle. */
export function isServerFrame(value: unknown): value is ServerFrame {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as { type?: unknown }).type === 'string' &&
    KNOWN_FRAME_TYPES.has((value as { type: string }).type)
  )
}

export interface JobsSocketOptions {
  readonly url: string
  readonly onFrame: (frame: ServerFrame) => void
  readonly onStatus?: (status: ConnectionStatus) => void
  readonly createSocket?: (url: string) => SocketLike
  readonly minDelayMs?: number
  readonly maxDelayMs?: number
}

const DEFAULT_MIN_DELAY_MS = 1_000
const DEFAULT_MAX_DELAY_MS = 15_000

function defaultSocket(url: string): SocketLike {
  return new WebSocket(url)
}

/** Turn an API path into an absolute `ws`/`wss` URL for the current origin. */
export function socketUrl(path: string, location: Location = window.location): string {
  const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:'
  return `${protocol}//${location.host}${path}`
}

/**
 * Server-push job/case subscription with exponential backoff.
 *
 * The reconnect window is 1 s (doubling) up to 15 s, matching spec 06 section 4.
 * A `ping` frame is answered with a `pong` so an idle socket is not reaped, and
 * it never reaches the frame handler. Every other known frame is forwarded; an
 * unknown frame is dropped rather than thrown, so a newer server cannot crash an
 * older client.
 */
export class JobsSocket {
  private readonly options: JobsSocketOptions
  private readonly minDelay: number
  private readonly maxDelay: number
  private socket: SocketLike | null = null
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null
  private stopped = true
  private delay: number
  private status: ConnectionStatus = 'closed'

  constructor(options: JobsSocketOptions) {
    this.options = options
    this.minDelay = options.minDelayMs ?? DEFAULT_MIN_DELAY_MS
    this.maxDelay = options.maxDelayMs ?? DEFAULT_MAX_DELAY_MS
    this.delay = this.minDelay
  }

  /** Open the socket and keep it open until `stop`. */
  start(): void {
    if (!this.stopped) {
      return
    }
    this.stopped = false
    this.delay = this.minDelay
    this.connect()
  }

  /** Close the socket and cancel any pending reconnect. */
  stop(): void {
    this.stopped = true
    if (this.reconnectTimer !== null) {
      clearTimeout(this.reconnectTimer)
      this.reconnectTimer = null
    }
    this.socket?.close()
    this.socket = null
    this.setStatus('closed')
  }

  private connect(): void {
    if (this.stopped) {
      return
    }
    this.setStatus('connecting')
    const socket = (this.options.createSocket ?? defaultSocket)(this.options.url)
    this.socket = socket
    socket.addEventListener('open', () => {
      if (this.stopped || this.socket !== socket) {
        return
      }
      this.delay = this.minDelay
      this.setStatus('open')
    })
    socket.addEventListener('message', (event) => {
      this.handleMessage(event.data)
    })
    socket.addEventListener('close', () => {
      this.handleDrop(socket)
    })
    socket.addEventListener('error', () => {
      this.handleDrop(socket)
    })
  }

  private handleMessage(data: unknown): void {
    let parsed: unknown
    try {
      parsed = JSON.parse(typeof data === 'string' ? data : String(data))
    } catch {
      return
    }
    if (!isServerFrame(parsed)) {
      return
    }
    if (parsed.type === 'ping') {
      try {
        this.socket?.send(JSON.stringify({ type: 'pong' }))
      } catch {
        // A send on a closing socket throws; the close handler reconnects.
      }
      return
    }
    this.options.onFrame(parsed)
  }

  private handleDrop(socket: SocketLike): void {
    if (this.stopped || this.socket !== socket) {
      return
    }
    this.socket = null
    this.setStatus('reconnecting')
    this.scheduleReconnect()
  }

  private scheduleReconnect(): void {
    if (this.reconnectTimer !== null || this.stopped) {
      return
    }
    const wait = this.delay
    this.delay = Math.min(this.delay * 2, this.maxDelay)
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null
      this.connect()
    }, wait)
  }

  private setStatus(status: ConnectionStatus): void {
    if (this.status === status) {
      return
    }
    this.status = status
    this.options.onStatus?.(status)
  }
}
