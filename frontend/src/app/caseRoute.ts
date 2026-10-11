import { useLocation } from 'react-router-dom'

const CASE_PATH = /^\/cases\/([^/]+)(?:\/.*)?$/

/**
 * Extract the case id from a pathname, or `null` when the route is not
 * case-scoped.
 *
 * Kept as a pure function so the many callers (rail, top bar, jobs provider)
 * share one definition of "which case is open" and tests do not need a router.
 */
export function parseCaseId(pathname: string): string | null {
  const match = CASE_PATH.exec(pathname)
  const raw = match?.[1]
  if (raw === undefined || raw.length === 0) {
    return null
  }
  return decodeURIComponent(raw)
}

/** The selected case id from the current location, or `null` on non-case routes. */
export function useCaseId(): string | null {
  const { pathname } = useLocation()
  return parseCaseId(pathname)
}
