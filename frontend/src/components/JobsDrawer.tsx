import type { ReactElement } from 'react'
import { useEffect } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { X } from 'lucide-react'

import { useCaseJobsQuery } from '../api/hooks'
import { cancelJob } from '../api/endpoints'
import { invalidateCaseData } from '../api/invalidate'
import type { Job } from '../api/types'
import { useCaseId } from '../app/caseRoute'
import { useJobs } from '../app/JobsProvider'
import { formatSince } from '../lib/format'
import { Button } from '../ui/Button'
import { JobProgress } from './JobProgress'
import { StatusBadge } from '../ui/Badge'
import { SkeletonRows } from '../ui/Skeleton'

const TERMINAL: ReadonlySet<string> = new Set(['done', 'failed', 'cancelled', 'needs_input'])

function JobRow({ job }: { readonly job: Job }): ReactElement {
  const caseId = useCaseId()
  const queryClient = useQueryClient()
  const { stages } = useJobs()
  const stage = stages.get(job.id)
  const progress = stage?.progress ?? job.progress
  const cancel = useMutation({
    mutationFn: (id: string) => cancelJob(id),
    onSuccess: () => {
      if (caseId !== null) {
        invalidateCaseData(queryClient, caseId)
      }
    },
  })

  return (
    <li className="space-y-1 rounded-[var(--radius-card)] border border-border bg-surface-2/60 p-3">
      <div className="flex items-center justify-between gap-2">
        <span className="font-mono text-xs text-muted">
          {job.kind} · {job.id.slice(0, 8)}
        </span>
        <StatusBadge status={job.status} />
      </div>
      {job.status === 'running' || job.status === 'queued' ? <JobProgress value={progress} label={job.kind} /> : null}
      <p className="text-xs text-muted">
        {stage?.stage !== undefined ? `${stage.stage} · ${stage.rateEps.toFixed(0)}/s` : job.message ?? ''}
        {job.error !== null ? <span className="text-sev-critical-text"> {job.error}</span> : null}
      </p>
      <div className="flex items-center justify-between">
        <span className="text-xs text-muted">{formatSince(Date.parse(job.created_at))}</span>
        {TERMINAL.has(job.status) ? null : (
          <Button
            variant="ghost"
            onClick={() => {
              cancel.mutate(job.id)
            }}
          >
            Cancel
          </Button>
        )}
      </div>
    </li>
  )
}

/**
 * Right drawer listing the selected case's jobs, with live progress from the
 * WebSocket (spec 07 section 2).
 */
export function JobsDrawer(): ReactElement | null {
  const caseId = useCaseId()
  const { drawerOpen, closeDrawer } = useJobs()
  const jobsQuery = useCaseJobsQuery(caseId)

  useEffect(() => {
    if (!drawerOpen) {
      return undefined
    }
    const onKey = (event: KeyboardEvent): void => {
      if (event.key === 'Escape') {
        closeDrawer()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => {
      window.removeEventListener('keydown', onKey)
    }
  }, [closeDrawer, drawerOpen])

  if (!drawerOpen || caseId === null) {
    return null
  }

  return (
    <aside
      role="dialog"
      aria-modal="false"
      aria-label="Jobs"
      className="fixed inset-y-0 right-0 z-20 flex w-[26rem] max-w-full flex-col border-l border-border bg-surface shadow-xl"
    >
      <div className="flex items-center justify-between border-b border-border px-4 py-2">
        <h2 className="text-sm font-medium text-text">Jobs</h2>
        <Button variant="ghost" aria-label="Close jobs" onClick={closeDrawer}>
          <X aria-hidden="true" size={16} />
        </Button>
      </div>
      <div className="flex-1 overflow-auto p-3">
        {jobsQuery.isPending ? <SkeletonRows rows={4} /> : null}
        {jobsQuery.isError ? <p className="text-sm text-sev-critical-text">Could not load jobs.</p> : null}
        {jobsQuery.data !== undefined ? (
          jobsQuery.data.items.length === 0 ? (
            <p className="text-sm text-muted">No jobs yet for this case.</p>
          ) : (
            <ul className="space-y-2">
              {jobsQuery.data.items.map((job) => (
                <JobRow key={job.id} job={job} />
              ))}
            </ul>
          )
        ) : null}
      </div>
    </aside>
  )
}
