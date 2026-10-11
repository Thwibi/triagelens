import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'
import type { ReactElement, ReactNode } from 'react'
import { useQueryClient } from '@tanstack/react-query'

import type { Job, LogTypeCandidate, ServerFrame } from '../api/types'
import { invalidateCaseData, invalidateReports } from '../api/invalidate'
import { queryKeys } from '../api/queryKeys'
import type { ConnectionStatus, SocketLike } from '../ws/jobsSocket'
import { JobsSocket, socketUrl } from '../ws/jobsSocket'
import { useToast } from '../ui/ToastProvider'
import { useCaseId } from './caseRoute'

/** Live per-job progress from `job.stage` frames, keyed by job id. */
export interface JobStage {
  readonly stage: string
  readonly progress: number
  readonly rateEps: number
  readonly events: number
  readonly errors: number
}

/** A `needs_input` prompt: which source needs a log-type decision, and the guesses. */
export interface NeedsInput {
  readonly jobId: string
  readonly sourceId: string
  readonly candidates: readonly LogTypeCandidate[]
}

export interface JobsContextValue {
  readonly connection: ConnectionStatus
  readonly stages: ReadonlyMap<string, JobStage>
  readonly needsInput: ReadonlyMap<string, NeedsInput>
  readonly drawerOpen: boolean
  readonly openDrawer: () => void
  readonly closeDrawer: () => void
  readonly toggleDrawer: () => void
}

const JobsContext = createContext<JobsContextValue | null>(null)

export interface JobsProviderProps {
  readonly children: ReactNode
  /** Test seam: build the socket without a real WebSocket. */
  readonly createSocket?: (url: string) => SocketLike
}

/**
 * Owns the case WebSocket and the UI state it drives.
 *
 * Frames are projected onto the query cache (so screens re-render from one
 * source of truth) and onto small local maps for the live bits the cache does
 * not model: in-flight stage/progress and outstanding `needs_input` prompts.
 * The socket is torn down whenever the selected case changes.
 */
export function JobsProvider({ children, createSocket }: JobsProviderProps): ReactElement {
  const caseId = useCaseId()
  const queryClient = useQueryClient()
  const { push } = useToast()
  const [connection, setConnection] = useState<ConnectionStatus>('closed')
  const [stages, setStages] = useState<ReadonlyMap<string, JobStage>>(() => new Map())
  const [needsInput, setNeedsInput] = useState<ReadonlyMap<string, NeedsInput>>(() => new Map())
  const [drawerOpen, setDrawerOpen] = useState(false)

  const handleFrame = useCallback(
    (frame: ServerFrame): void => {
      switch (frame.type) {
        case 'job.update': {
          const job: Job = frame.job
          queryClient.setQueryData(queryKeys.job(job.id), job)
          if (caseId !== null) {
            void queryClient.invalidateQueries({ queryKey: queryKeys.jobs(caseId) })
            if (job.kind === 'report' && job.status !== 'queued' && job.status !== 'running') {
              invalidateReports(queryClient, caseId)
            }
          }
          break
        }
        case 'job.stage':
          setStages((current) => {
            const next = new Map(current)
            next.set(frame.job_id, {
              stage: frame.stage,
              progress: frame.progress,
              rateEps: frame.rate_eps,
              events: frame.events,
              errors: frame.errors,
            })
            return next
          })
          break
        case 'source.update':
          if (caseId !== null) {
            void queryClient.invalidateQueries({ queryKey: queryKeys.sources(caseId) })
          }
          break
        case 'needs_input':
          setNeedsInput((current) => {
            const next = new Map(current)
            next.set(frame.source_id, {
              jobId: frame.job_id,
              sourceId: frame.source_id,
              candidates: frame.candidates,
            })
            return next
          })
          if (caseId !== null) {
            void queryClient.invalidateQueries({ queryKey: queryKeys.sources(caseId) })
          }
          break
        case 'alerts.changed':
          if (caseId !== null) {
            invalidateCaseData(queryClient, caseId)
          }
          break
        case 'error':
          push('error', `${frame.message} (${frame.code})`)
          break
        case 'ping':
          // Answered inside the socket; never forwarded to a frame handler.
          break
      }
    },
    [caseId, push, queryClient],
  )

  useEffect(() => {
    if (caseId === null) {
      setConnection('closed')
      return undefined
    }
    setStages(new Map())
    setNeedsInput(new Map())
    const socket = new JobsSocket({
      url: socketUrl(`/api/ws/cases/${encodeURIComponent(caseId)}`),
      onFrame: handleFrame,
      onStatus: setConnection,
      ...(createSocket ? { createSocket } : {}),
    })
    socket.start()
    return () => {
      socket.stop()
    }
  }, [caseId, createSocket, handleFrame])

  const openDrawer = useCallback((): void => {
    setDrawerOpen(true)
  }, [])
  const closeDrawer = useCallback((): void => {
    setDrawerOpen(false)
  }, [])
  const toggleDrawer = useCallback((): void => {
    setDrawerOpen((open) => !open)
  }, [])

  const value = useMemo<JobsContextValue>(
    () => ({ connection, stages, needsInput, drawerOpen, openDrawer, closeDrawer, toggleDrawer }),
    [closeDrawer, connection, drawerOpen, needsInput, openDrawer, stages, toggleDrawer],
  )

  return <JobsContext.Provider value={value}>{children}</JobsContext.Provider>
}

export function useJobs(): JobsContextValue {
  const value = useContext(JobsContext)
  if (value === null) {
    throw new Error('useJobs must be used inside a JobsProvider')
  }
  return value
}
