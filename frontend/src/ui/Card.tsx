import type { ReactElement, ReactNode } from 'react'

/** A titled surface panel used across the dashboard screens. */
export function Card({
  title,
  children,
  actions,
}: {
  readonly title: string
  readonly children: ReactNode
  readonly actions?: ReactNode
}): ReactElement {
  return (
    <section className="rounded-[var(--radius-card)] border border-border bg-surface p-4">
      <div className="mb-2 flex items-center justify-between gap-2">
        <h2 className="text-sm font-medium text-text">{title}</h2>
        {actions}
      </div>
      {children}
    </section>
  )
}
