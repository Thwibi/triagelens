import type { ReactElement } from 'react'

import { Button } from './Button'

export interface ErrorPanelProps {
  readonly title?: string
  readonly code?: string | null
  readonly message: string
  readonly onRetry?: () => void
}

/** Inline failure panel with an optional retry (spec 07 section 4). */
export function ErrorPanel({ title = 'Something went wrong', code, message, onRetry }: ErrorPanelProps): ReactElement {
  return (
    <section role="alert" className="rounded-[var(--radius-card)] border border-sev-critical/50 bg-sev-critical/10 p-4">
      <h2 className="text-sm font-medium text-text">{title}</h2>
      <p className="mt-1 text-sm text-text">
        {code !== null && code !== undefined ? <span className="font-mono text-xs text-muted">{code}</span> : null}
        {code !== null && code !== undefined ? ': ' : null}
        {message}
      </p>
      {onRetry !== undefined ? (
        <div className="mt-3">
          <Button onClick={onRetry}>Retry</Button>
        </div>
      ) : null}
    </section>
  )
}
