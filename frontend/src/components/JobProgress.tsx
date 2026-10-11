import type { ReactElement } from 'react'

import { formatPercent } from '../lib/format'

/** A slim progress bar used by job rows and ingest rows. */
export function JobProgress({ value, label }: { readonly value: number; readonly label?: string }): ReactElement {
  const clamped = Math.min(Math.max(Number.isFinite(value) ? value : 0, 0), 1)
  return (
    <div
      role="progressbar"
      aria-valuenow={Math.round(clamped * 100)}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-label={label ?? 'Progress'}
      className="h-1.5 w-full overflow-hidden rounded-full bg-surface-2"
    >
      <div className="h-full bg-accent transition-[width]" style={{ width: formatPercent(clamped) }} />
    </div>
  )
}
