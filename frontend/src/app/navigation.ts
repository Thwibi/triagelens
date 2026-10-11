/**
 * Navigation table.
 *
 * The rail renders only entries that have a registered route, so the menu can
 * never advertise a page that does not exist. As later phases add screens, they
 * are appended here and in the router together.
 */

export interface NavItem {
  readonly path: string
  readonly label: string
}

/** Top-level destinations, always available. */
export const PRIMARY_NAV: readonly NavItem[] = [
  { path: '/', label: 'Cases' },
  { path: '/status', label: 'Status' },
]

export interface CaseNavItem {
  readonly segment: string
  readonly label: string
}

/** Per-case destinations, shown once a case is selected. */
export const CASE_NAV: readonly CaseNavItem[] = [
  { segment: '', label: 'Overview' },
  { segment: 'sources', label: 'Sources' },
  { segment: 'events', label: 'Events' },
  { segment: 'timeline', label: 'Timeline' },
  { segment: 'alerts', label: 'Alerts' },
  { segment: 'iocs', label: 'IOCs' },
  { segment: 'mitre', label: 'ATT&CK' },
  { segment: 'entities', label: 'Entities' },
  { segment: 'rules', label: 'Rules' },
  { segment: 'reports', label: 'Reports' },
  { segment: 'settings', label: 'Settings' },
]

/** Build the absolute path for a per-case destination. */
export function caseNavPath(caseId: string, segment: string): string {
  const base = `/cases/${encodeURIComponent(caseId)}`
  return segment === '' ? base : `${base}/${segment}`
}
