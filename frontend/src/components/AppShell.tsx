import type { ReactElement } from 'react'
import { Outlet } from 'react-router-dom'

import { ConnectionBanner } from './ConnectionBanner'
import { JobsDrawer } from './JobsDrawer'
import { LeftRail } from './LeftRail'
import { TopBar } from './TopBar'
import { Toasts } from './Toasts'

/**
 * Application shell: left rail, top bar, scrolled content, and the right drawer
 * (spec 07 section 2). Routing content is rendered through the outlet.
 */
export function AppShell(): ReactElement {
  return (
    <div className="flex h-full flex-col">
      <div className="flex min-h-0 flex-1">
        <LeftRail />
        <div className="flex min-w-0 flex-1 flex-col">
          <TopBar />
          <ConnectionBanner />
          <main className="min-h-0 flex-1 overflow-auto p-4">
            <Outlet />
          </main>
        </div>
      </div>
      <JobsDrawer />
      <Toasts />
      <footer className="border-t border-border px-4 py-1.5 text-xs text-muted">
        Offline by design: no telemetry, no outbound requests, no external assets.
      </footer>
    </div>
  )
}
