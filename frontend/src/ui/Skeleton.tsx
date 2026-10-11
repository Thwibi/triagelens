import type { ReactElement } from 'react'

/** A single shimmering placeholder block (spec 07 section 4: skeletons, not spinners). */
export function Skeleton({ className = '' }: { readonly className?: string }): ReactElement {
  return <div aria-hidden="true" className={`animate-pulse rounded bg-surface-2 ${className}`} />
}

/** A short stack of skeleton lines for a table or card body. */
export function SkeletonRows({ rows = 5 }: { readonly rows?: number }): ReactElement {
  return (
    <div role="status" aria-busy="true" aria-label="Loading" className="space-y-2">
      {Array.from({ length: rows }, (_, index) => (
        <Skeleton key={index} className="h-8 w-full" />
      ))}
    </div>
  )
}
