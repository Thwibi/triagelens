import type { ReactElement } from 'react'
import { Route, Routes } from 'react-router-dom'

import { AppShell } from './components/AppShell'
import { NotFoundPage } from './features/errors/NotFoundPage'
import { AlertsPage } from './features/alerts/AlertsPage'
import { CasesPage } from './features/cases/CasesPage'
import { EventsPage } from './features/events/EventsPage'
import { EntitiesPage } from './features/entities/EntitiesPage'
import { IocsPage } from './features/iocs/IocsPage'
import { MitrePage } from './features/mitre/MitrePage'
import { OverviewPage } from './features/overview/OverviewPage'
import { ReportsPage } from './features/reports/ReportsPage'
import { RulesPage } from './features/rules/RulesPage'
import { SettingsPage } from './features/settings/SettingsPage'
import { SourcesPage } from './features/sources/SourcesPage'
import { StatusPage } from './features/status/StatusPage'
import { TimelinePage } from './features/timeline/TimelinePage'

/**
 * Route table.
 *
 * Only screens that exist are registered; every other URL lands on a real
 * not-found page rather than an empty stub (see `app/navigation.ts`).
 */
export function App(): ReactElement {
  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route path="/" element={<CasesPage />} />
        <Route path="/status" element={<StatusPage />} />
        <Route path="/cases/:caseId" element={<OverviewPage />} />
        <Route path="/cases/:caseId/sources" element={<SourcesPage />} />
        <Route path="/cases/:caseId/events" element={<EventsPage />} />
        <Route path="/cases/:caseId/timeline" element={<TimelinePage />} />
        <Route path="/cases/:caseId/alerts" element={<AlertsPage />} />
        <Route path="/cases/:caseId/iocs" element={<IocsPage />} />
        <Route path="/cases/:caseId/mitre" element={<MitrePage />} />
        <Route path="/cases/:caseId/entities" element={<EntitiesPage />} />
        <Route path="/cases/:caseId/rules" element={<RulesPage />} />
        <Route path="/cases/:caseId/reports" element={<ReportsPage />} />
        <Route path="/cases/:caseId/settings" element={<SettingsPage />} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  )
}
