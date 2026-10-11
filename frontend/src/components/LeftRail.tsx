import type { ReactElement } from 'react'
import { NavLink } from 'react-router-dom'
import { Activity, ChevronsLeft, ChevronsRight, FileCode2, FileInput, LayoutDashboard, LayoutGrid, ListTree, ScrollText, Settings, ShieldAlert, Target, Users } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { useState } from 'react'

import { CASE_NAV, PRIMARY_NAV, caseNavPath } from '../app/navigation'
import { useCaseId } from '../app/caseRoute'

const PRIMARY_ICON: Readonly<Record<string, LucideIcon>> = {
  '/': ListTree,
  '/status': LayoutDashboard,
}

const CASE_ICON: Readonly<Record<string, LucideIcon>> = {
  '': ListTree,
  sources: FileInput,
  events: ScrollText,
  timeline: Activity,
  alerts: ShieldAlert,
  iocs: Target,
  mitre: LayoutGrid,
  entities: Users,
  rules: FileCode2,
  settings: Settings,
}

function linkClass(collapsed: boolean): (args: { isActive: boolean }) => string {
  return ({ isActive }) =>
    `flex items-center gap-2 rounded-[var(--radius-control)] px-2 py-1.5 text-sm ${
      isActive ? 'bg-surface-2 text-text' : 'text-muted hover:bg-surface-2 hover:text-text'
    } ${collapsed ? 'justify-center' : ''}`
}

/**
 * Left rail: the case switcher lives in the top bar, so the rail is pure
 * navigation. It collapses to icons for the 768–1279 px breakpoint
 * (spec 07 section 2).
 */
export function LeftRail(): ReactElement {
  const caseId = useCaseId()
  const [collapsed, setCollapsed] = useState(false)

  return (
    <nav
      aria-label="Sections"
      className={`flex shrink-0 flex-col gap-4 border-r border-border bg-surface p-2 ${collapsed ? 'w-14' : 'w-56'}`}
    >
      <div className={`flex items-center ${collapsed ? 'justify-center' : 'justify-between'} px-1`}>
        {collapsed ? null : (
          <span className="text-sm font-semibold tracking-tight text-text">TriageLens</span>
        )}
        <button
          type="button"
          aria-label={collapsed ? 'Expand navigation' : 'Collapse navigation'}
          onClick={() => {
            setCollapsed((value) => !value)
          }}
          className="rounded p-1 text-muted hover:bg-surface-2 hover:text-text"
        >
          {collapsed ? <ChevronsRight aria-hidden="true" size={16} /> : <ChevronsLeft aria-hidden="true" size={16} />}
        </button>
      </div>

      <ul className="space-y-1">
        {PRIMARY_NAV.map((item) => {
          const Icon = PRIMARY_ICON[item.path] ?? ListTree
          return (
            <li key={item.path}>
              <NavLink to={item.path} end={item.path === '/'} className={linkClass(collapsed)} title={item.label}>
                <Icon aria-hidden="true" size={16} />
                {collapsed ? null : item.label}
              </NavLink>
            </li>
          )
        })}
      </ul>

      {caseId !== null ? (
        <div className="space-y-1">
          {collapsed ? null : (
            <p className="px-2 text-xs font-medium uppercase tracking-wide text-muted">Case</p>
          )}
          <ul className="space-y-1">
            {CASE_NAV.map((item) => {
              const Icon = CASE_ICON[item.segment] ?? ListTree
              return (
                <li key={item.segment}>
                  <NavLink
                    to={caseNavPath(caseId, item.segment)}
                    end
                    className={linkClass(collapsed)}
                    title={item.label}
                  >
                    <Icon aria-hidden="true" size={16} />
                    {collapsed ? null : item.label}
                  </NavLink>
                </li>
              )
            })}
          </ul>
        </div>
      ) : null}
    </nav>
  )
}
