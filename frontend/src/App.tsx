import type { ReactElement } from 'react'
import { NavLink, Route, Routes } from 'react-router-dom'

import { StatusPage } from './features/status/StatusPage'
import { NotFoundPage } from './features/errors/NotFoundPage'

/**
 * Application shell.
 *
 * Only routes that exist are registered: Phase 0 ships the status view, and any
 * other URL lands on a real not-found page rather than an empty stub. Navigation
 * entries are derived from the registered routes so the menu cannot advertise
 * a page that does not exist.
 */
const ROUTES = [{ path: '/', label: 'Status', end: true }] as const

const NAV_LINK_CLASS = ({ isActive }: { isActive: boolean }): string =>
  isActive
    ? 'rounded bg-slate-800 px-3 py-1.5 text-sm text-slate-100'
    : 'rounded px-3 py-1.5 text-sm text-slate-400 hover:bg-slate-800 hover:text-slate-200'

export function App(): ReactElement {
  return (
    <div className="mx-auto flex min-h-full max-w-4xl flex-col gap-6 p-6">
      <header className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-4">
        <div>
          <h1 className="text-lg font-semibold tracking-tight text-slate-100">TriageLens</h1>
          <p className="text-xs text-slate-500">Local log triage. Nothing leaves this machine.</p>
        </div>
        <nav aria-label="Sections" className="flex gap-1">
          {ROUTES.map((route) => (
            <NavLink key={route.path} to={route.path} end={route.end} className={NAV_LINK_CLASS}>
              {route.label}
            </NavLink>
          ))}
        </nav>
      </header>

      <main className="flex-1">
        <Routes>
          <Route path="/" element={<StatusPage />} />
          <Route path="*" element={<NotFoundPage />} />
        </Routes>
      </main>

      <footer className="border-t border-slate-800 pt-3 text-xs text-slate-600">
        Offline by design: no telemetry, no outbound requests, no external assets.
      </footer>
    </div>
  )
}

export { ROUTES }