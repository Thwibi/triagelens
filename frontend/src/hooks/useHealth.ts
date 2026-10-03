import { useCallback, useEffect, useRef, useState } from 'react'

import { ApiError, ContractError, fetchHealth } from '../api/client'
import type { HealthReport } from '../api/types'

/** Lifecycle of a health poll. */
export type HealthPhase = 'idle' | 'loading' | 'ready' | 'error'

/** Everything the status view needs, with no raw exceptions leaking out. */
export interface HealthState {
  readonly phase: HealthPhase
  readonly report: HealthReport | null
  readonly errorCode: string | null
  readonly errorMessage: string | null
  /** True when the failure is an authentication problem the user can fix. */
  readonly needsAuth: boolean
  readonly lastCheckedAt: number | null
  readonly refresh: () => void
}

function describe(error: unknown): { readonly code: string; readonly message: string; readonly needsAuth: boolean } {
  if (error instanceof ApiError) {
    if (error.status === 401) {
      return { code: error.code, message: 'A bearer token is required for this host.', needsAuth: true }
    }
    return { code: error.code, message: error.message, needsAuth: false }
  }
  if (error instanceof ContractError) {
    return { code: 'CONTRACT', message: `Unexpected response: ${error.message}`, needsAuth: false }
  }
  if (error instanceof DOMException && error.name === 'AbortError') {
    return { code: 'ABORTED', message: 'The health request was cancelled.', needsAuth: false }
  }
  const message = error instanceof Error ? error.message : String(error)
  return { code: 'UNREACHABLE', message: `Cannot reach the local API: ${message}`, needsAuth: false }
}

/**
 * Poll `GET /api/health` on an interval.
 *
 * Polling stops while the tab is hidden and resumes (with an immediate refresh)
 * when it becomes visible again, so a background tab does not hammer the local
 * API. In-flight requests are aborted on unmount and before each refresh.
 */
export function useHealth(pollIntervalMs: number): HealthState {
  const [phase, setPhase] = useState<HealthPhase>('idle')
  const [report, setReport] = useState<HealthReport | null>(null)
  const [error, setError] = useState<{ code: string; message: string; needsAuth: boolean } | null>(null)
  const [lastCheckedAt, setLastCheckedAt] = useState<number | null>(null)
  const [nonce, setNonce] = useState(0)
  const controllerRef = useRef<AbortController | null>(null)

  const refresh = useCallback((): void => {
    setNonce((value) => value + 1)
  }, [])

  useEffect(() => {
    let cancelled = false

    const load = async (): Promise<void> => {
      controllerRef.current?.abort()
      const controller = new AbortController()
      controllerRef.current = controller
      setPhase('loading')
      try {
        const next = await fetchHealth({ signal: controller.signal })
        if (cancelled) {
          return
        }
        setReport(next)
        setError(null)
        setPhase('ready')
        setLastCheckedAt(Date.now())
      } catch (caught) {
        if (cancelled || (caught instanceof DOMException && caught.name === 'AbortError')) {
          return
        }
        setReport(null)
        setError(describe(caught))
        setPhase('error')
      }
    }

    const onVisibility = (): void => {
      if (document.visibilityState === 'visible') {
        void load()
      }
    }

    void load()
    const timer = window.setInterval(() => {
      if (document.visibilityState === 'visible') {
        void load()
      }
    }, pollIntervalMs)
    document.addEventListener('visibilitychange', onVisibility)

    return () => {
      cancelled = true
      window.clearInterval(timer)
      document.removeEventListener('visibilitychange', onVisibility)
      controllerRef.current?.abort()
    }
  }, [pollIntervalMs, nonce])

  return {
    phase,
    report,
    errorCode: error?.code ?? null,
    errorMessage: error?.message ?? null,
    needsAuth: error?.needsAuth ?? false,
    lastCheckedAt,
    refresh,
  }
}