import type { ReactElement } from 'react'
import { Link } from 'react-router-dom'

/** Shown for any URL that has no registered route. */
export function NotFoundPage(): ReactElement {
  return (
    <section aria-labelledby="notfound-heading" className="space-y-3">
      <h1 id="notfound-heading" className="text-xl font-semibold text-slate-100">
        Page not found
      </h1>
      <p className="text-sm text-slate-400">
        That route is not part of this build. TriageLens registers a page only once the feature behind it exists.
      </p>
      <Link to="/" className="inline-block rounded border border-slate-700 px-3 py-1.5 text-sm text-slate-200 hover:bg-slate-800">
        Back to status
      </Link>
    </section>
  )
}