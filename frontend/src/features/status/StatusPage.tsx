import type { ReactElement } from 'react'

import type { HealthState } from '../../api/types'
import { buildHealthFields, hasBlockingFailure } from './healthFields'
import { HealthRow } from './HealthRow'
import { useHealth } from '../../hooks/useHealth'

const HEALTH_POLL_MS = 30_000

const SUMMARY_STYLES: Readonly<Record<HealthState, { readonly wrapper: string; readonly headline: string; readonly detail: string }>> = {
  ok: {
    wrapper: 'border-emerald-700 bg-emerald-950/40',
    headline: 'All checks passed',
    detail: 'TriageLens is ready to accept log sources.',
  },
  degraded: {
    wrapper: 'border-amber-700 bg-amber-950/40',
    headline: 'Running with reduced capability',
    detail: 'Some optional features are unavailable; core triage still works.',
  },
  error: {
    wrapper: 'border-red-700 bg-red-950/40',
    headline: 'Not ready to accept logs',
    detail: 'A required capability is missing. Check the details below.',
  },
}

/** Reduce per-field states to one overall verdict: error beats degraded beats ok. */
export function overallState(states: readonly HealthState[]): HealthState {
  if (states.includes('error')) {
    return 'error'
  }
  if (states.includes('degraded')) {
    return 'degraded'
  }
  return 'ok'
}

/**
 * Service status view.
 *
 * Renders the live `GET /api/health` contract, classifies each field, and makes
 * unreachable/auth/contract failures distinguishable instead of collapsing them
 * into one "something went wrong".
 */
export function StatusPage(): ReactElement {
  const { phase, report, errorCode, errorMessage, needsAuth, lastCheckedAt, refresh } = useHealth(HEALTH_POLL_MS)

  if (phase === 'error') {
    return (
      <section aria-labelledby="status-error-heading" className="space-y-4">
        <h1 id="status-error-heading" className="text-xl font-semibold text-slate-100">
          Cannot read service status
        </h1>
        <p role="alert" className="rounded border border-red-800 bg-red-950/40 p-4 text-sm text-red-100">
          <span className="font-mono">{errorCode}</span>: {errorMessage}
        </p>
        {needsAuth ? (
          <p className="text-sm text-slate-400">
            This instance is bound to a non-loopback address, so the API requires the configured bearer token.
          </p>
        ) : null}
        <button
          type="button"
          onClick={refresh}
          className="rounded border border-slate-700 px-3 py-1.5 text-sm text-slate-200 hover:bg-slate-800"
        >
          Retry
        </button>
      </section>
    )
  }

  if (phase !== 'ready' || report === null) {
    return (
      <section aria-labelledby="status-loading-heading" aria-busy="true" className="space-y-4">
        <h1 id="status-loading-heading" className="text-xl font-semibold text-slate-100">
          Checking local services…
        </h1>
        <div className="h-2 w-48 animate-pulse rounded bg-slate-800" />
      </section>
    )
  }

  const fields = buildHealthFields(report)
  const state = overallState(fields.map((field) => field.state))
  const summary = SUMMARY_STYLES[state]
  const degraded = fields.filter((field) => field.state !== 'ok')

  return (
    <section aria-labelledby="status-heading" className="space-y-6">
      <header className="flex flex-wrap items-baseline justify-between gap-3">
        <h1 id="status-heading" className="text-xl font-semibold text-slate-100">
          Service status
        </h1>
        <button
          type="button"
          onClick={refresh}
          className="rounded border border-slate-700 px-3 py-1.5 text-sm text-slate-200 hover:bg-slate-800"
        >
          Refresh
        </button>
      </header>

      <div role="status" className={`rounded border p-4 ${summary.wrapper}`}>
        <p className="text-sm font-medium text-slate-100">{summary.headline}</p>
        <p className="text-sm text-slate-300">{summary.detail}</p>
        {degraded.length > 0 ? (
          <p className="mt-2 text-sm text-slate-300">
            {degraded.length} of {fields.length} checks need attention.
            {hasBlockingFailure(fields) ? ' At least one is required for ingestion.' : null}
          </p>
        ) : null}
      </div>

      <dl className="rounded border border-slate-800 bg-slate-900/40 px-4 py-2">
        {fields.map((field) => (
          <HealthRow key={field.label} field={field} />
        ))}
      </dl>

      <footer className="text-xs text-slate-500">
        {lastCheckedAt === null ? null : <>Last checked {new Date(lastCheckedAt).toLocaleTimeString()}. </>}
        Status is polled every 30 seconds while this tab is visible.
      </footer>
    </section>
  )
}

export { HEALTH_POLL_MS }