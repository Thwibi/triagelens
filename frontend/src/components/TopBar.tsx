import type { ReactElement } from 'react'
import { useNavigate } from 'react-router-dom'
import { ListChecks, Moon, Sun } from 'lucide-react'

import { useCaseJobsQuery, useCaseQuery, useCasesQuery } from '../api/hooks'
import { useJobs } from '../app/JobsProvider'
import { useCaseId } from '../app/caseRoute'
import { useTheme } from '../theme/ThemeProvider'
import { Button } from '../ui/Button'

const ACTIVE_STATUSES: ReadonlySet<string> = new Set(['queued', 'running'])

/**
 * Top bar: case switcher, current case name, theme toggle, and the running-jobs
 * indicator that opens the jobs drawer (spec 07 section 2).
 */
export function TopBar(): ReactElement {
  const caseId = useCaseId()
  const navigate = useNavigate()
  const cases = useCasesQuery()
  const current = useCaseQuery(caseId)
  const jobsQuery = useCaseJobsQuery(caseId)
  const { theme, toggleTheme } = useTheme()
  const { toggleDrawer, drawerOpen } = useJobs()

  const activeJobs = (jobsQuery.data?.items ?? []).filter((job) => ACTIVE_STATUSES.has(job.status))

  return (
    <header className="flex flex-wrap items-center gap-3 border-b border-border bg-surface px-4 py-2">
      <label className="flex items-center gap-2 text-sm">
        <span className="sr-only">Select case</span>
        <select
          className="rounded-[var(--radius-control)] border border-border bg-surface-2 px-2 py-1 text-sm text-text"
          value={caseId ?? ''}
          onChange={(event) => {
            const value = event.target.value
            void navigate(value === '' ? '/' : `/cases/${encodeURIComponent(value)}`)
          }}
        >
          <option value="">All cases</option>
          {(cases.data?.items ?? []).map((item) => (
            <option key={item.id} value={item.id}>
              {item.name}
            </option>
          ))}
        </select>
      </label>

      {caseId !== null ? (
        <h1 className="truncate text-sm font-medium text-text">
          {current.data?.name ?? 'Loading case…'}
          {current.data === undefined ? null : (
            <span className="ml-2 font-mono text-xs text-muted">
              {current.data.counts.events.toLocaleString()} events
            </span>
          )}
        </h1>
      ) : (
        <h1 className="text-sm font-medium text-muted">No case selected</h1>
      )}

      <div className="ml-auto flex items-center gap-1">
        <Button
          variant="ghost"
          aria-pressed={drawerOpen}
          aria-label={`Running jobs (${activeJobs.length})`}
          disabled={caseId === null}
          onClick={toggleDrawer}
        >
          <ListChecks aria-hidden="true" size={16} />
          Jobs
          <span className="rounded-full bg-surface-2 px-1.5 text-xs text-muted">{activeJobs.length}</span>
        </Button>
        <Button
          variant="ghost"
          aria-label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
          onClick={toggleTheme}
        >
          {theme === 'dark' ? <Sun aria-hidden="true" size={16} /> : <Moon aria-hidden="true" size={16} />}
        </Button>
      </div>
    </header>
  )
}
