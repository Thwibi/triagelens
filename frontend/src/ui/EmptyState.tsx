import type { ReactElement, ReactNode } from 'react'

export interface EmptyStateProps {
  readonly title: string
  readonly detail?: ReactNode
  readonly action?: ReactNode
}

/** Purposeful empty state with a primary action (spec 07 section 4). */
export function EmptyState({ title, detail, action }: EmptyStateProps): ReactElement {
  return (
    <section className="flex flex-col items-center gap-3 rounded-[var(--radius-card)] border border-dashed border-border bg-surface/50 px-6 py-12 text-center">
      <h2 className="text-base font-medium text-text">{title}</h2>
      {detail !== undefined ? <p className="max-w-md text-sm text-muted">{detail}</p> : null}
      {action !== undefined ? <div className="mt-1">{action}</div> : null}
    </section>
  )
}
