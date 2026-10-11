import type { ReactElement } from 'react'
import { Link } from 'react-router-dom'

/** Shown for any URL that has no registered route. */
export function NotFoundPage(): ReactElement {
  return (
    <section aria-labelledby="notfound-heading" className="space-y-3">
      <h1 id="notfound-heading" className="text-xl font-semibold text-text">
        Page not found
      </h1>
      <p className="text-sm text-muted">
        That route is not part of this build. TriageLens registers a page only once the feature behind it exists.
      </p>
      <Link to="/" className="inline-block rounded border border-border px-3 py-1.5 text-sm text-text hover:bg-surface-2">
        Back to status
      </Link>
    </section>
  )
}