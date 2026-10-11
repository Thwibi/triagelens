import type { ReactElement } from 'react'

import { useCaseId } from '../app/caseRoute'
import { useJobs } from '../app/JobsProvider'

/**
 * Offline/disconnected banner shown while the live socket is not open
 * (spec 07 section 4). Screens still work from their cached REST data.
 */
export function ConnectionBanner(): ReactElement | null {
  const caseId = useCaseId()
  const { connection } = useJobs()
  if (caseId === null || connection === 'open' || connection === 'closed') {
    return null
  }
  return (
    <div role="status" className="border-b border-sev-medium/40 bg-sev-medium/10 px-4 py-1.5 text-xs text-sev-medium-text">
      {connection === 'connecting' ? 'Connecting to live updates…' : 'Live updates disconnected — reconnecting…'}
    </div>
  )
}
