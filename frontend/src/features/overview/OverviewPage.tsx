import type { ReactElement } from 'react'
import { Bar, CartesianGrid, ComposedChart, Line, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'

import {
  useCaseMitreQuery,
  useCaseQuery,
  useDetectionRunsQuery,
  useEntitiesQuery,
  useEventCountQuery,
  useIocsQuery,
  useSourcesQuery,
  useTimelineQuery,
  useTopAlertsQuery,
} from '../../api/hooks'
import { useCaseId } from '../../app/caseRoute'
import type { AlertLevel } from '../../api/types'
import { formatHash, formatNumber, formatPercent, formatTimestamp } from '../../lib/format'
import { Card } from '../../ui/Card'
import { CopyButton } from '../../ui/CopyButton'
import { ErrorPanel } from '../../ui/ErrorPanel'
import { SeverityBadge } from '../../ui/Badge'
import { Skeleton } from '../../ui/Skeleton'

const LEVEL_RANK: Readonly<Record<AlertLevel, number>> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  informational: 0,
}

const LEVEL_BORDER: Readonly<Record<AlertLevel, string>> = {
  critical: 'var(--sev-critical)',
  high: 'var(--sev-high)',
  medium: 'var(--sev-medium)',
  low: 'var(--sev-low)',
  informational: 'var(--sev-info)',
}

function loudest(levels: readonly (AlertLevel | null)[]): AlertLevel | null {
  let best: AlertLevel | null = null
  for (const level of levels) {
    if (level !== null && (best === null || LEVEL_RANK[level] > LEVEL_RANK[best])) {
      best = level
    }
  }
  return best
}

function KpiTile({ label, value }: { readonly label: string; readonly value: string }): ReactElement {
  return (
    <div className="rounded-[var(--radius-card)] border border-border bg-surface p-3">
      <p className="text-xs uppercase tracking-wide text-muted">{label}</p>
      <p className="mt-1 font-mono text-xl text-text">{value}</p>
    </div>
  )
}

function TopAlerts(): ReactElement {
  const caseId = useCaseId()
  const alerts = useTopAlertsQuery(caseId, 5)
  if (alerts.isPending) {
    return <Skeleton className="h-40 w-full" />
  }
  if (alerts.isError) {
    return <p className="text-sm text-muted">No detection run yet.</p>
  }
  if (alerts.data.items.length === 0) {
    return <p className="text-sm text-muted">No alerts. Run detection after ingesting sources.</p>
  }
  return (
    <ul className="space-y-2">
      {alerts.data.items.map((alert) => (
        <li key={alert.id} className="flex items-start gap-3 border-b border-border pb-2 last:border-0">
          <SeverityBadge level={alert.level} />
          <div className="min-w-0 flex-1">
            <p className="truncate text-sm text-text">{alert.rule_title}</p>
            <p className="mt-0.5 flex flex-wrap gap-1">
              {alert.techniques.slice(0, 3).map((technique) => (
                <span key={technique.id} className="rounded bg-surface-2 px-1.5 py-0.5 font-mono text-xs text-muted">
                  {technique.id}
                </span>
              ))}
              {alert.host !== null ? <span className="text-xs text-muted">· {alert.host}</span> : null}
            </p>
          </div>
          <span className="font-mono text-sm text-text">{alert.score}</span>
        </li>
      ))}
    </ul>
  )
}

function MiniTimeline(): ReactElement {
  const caseId = useCaseId()
  const timeline = useTimelineQuery(caseId)
  if (timeline.isPending) {
    return <Skeleton className="h-40 w-full" />
  }
  if (timeline.data === undefined) {
    return <p className="text-sm text-muted">No events.</p>
  }
  const data = timeline.data.buckets.map((bucket) => ({
    t: bucket.t_ms,
    events: bucket.count,
    alerts: bucket.alert_count,
  }))
  if (data.length === 0) {
    return <p className="text-sm text-muted">No events.</p>
  }
  return (
    <div className="h-40 w-full" role="img" aria-label="Event volume over time with alert markers">
      <ResponsiveContainer width="100%" height="100%">
        <ComposedChart data={data} margin={{ top: 4, right: 8, bottom: 0, left: -16 }}>
          <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" />
          <XAxis
            dataKey="t"
            tickFormatter={(value: number) => new Date(value).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
            stroke="var(--muted)"
            fontSize={11}
          />
          <YAxis stroke="var(--muted)" fontSize={11} width={40} allowDecimals={false} />
          <Tooltip
            contentStyle={{ background: 'var(--surface-2)', border: '1px solid var(--border)', fontSize: 12 }}
            labelFormatter={(value) => formatTimestamp(Number(value))}
          />
          <Bar dataKey="events" fill="var(--accent)" />
          <Line dataKey="alerts" stroke="var(--sev-critical)" dot={false} strokeWidth={2} />
        </ComposedChart>
      </ResponsiveContainer>
    </div>
  )
}

function MitreStrip(): ReactElement {
  const caseId = useCaseId()
  const mitre = useCaseMitreQuery(caseId)
  if (mitre.isPending) {
    return <Skeleton className="h-12 w-full" />
  }
  if (mitre.data === undefined) {
    return <p className="text-sm text-muted">ATT&CK matrix unavailable.</p>
  }
  const matrix = mitre.data
  const maxCount = Math.max(1, ...matrix.tactics.flatMap((tactic) => tactic.techniques.map((t) => t.alert_count)))
  return (
    <ul className="flex flex-wrap gap-1">
      {matrix.tactics.map((tactic) => {
        const count = tactic.techniques.reduce((sum, technique) => sum + technique.alert_count, 0)
        const level = loudest(tactic.techniques.map((technique) => technique.max_level))
        const intensity = count === 0 ? 0 : 0.25 + 0.75 * (count / maxCount)
        return (
          <li
            key={tactic.shortname}
            title={`${tactic.name}: ${count} alerts`}
            className="flex-1 rounded px-1.5 py-2 text-center text-[10px]"
            style={{
              backgroundColor: count === 0 ? 'var(--surface-2)' : `color-mix(in srgb, var(--accent) ${Math.round(intensity * 100)}%, transparent)`,
              border: level !== null ? `1px solid ${LEVEL_BORDER[level]}` : '1px solid var(--border)',
              minWidth: '3.5rem',
            }}
          >
            <span className="block truncate text-muted">{tactic.shortname}</span>
            <span className="font-mono text-text">{count}</span>
          </li>
        )
      })}
    </ul>
  )
}

function AttackerCandidates(): ReactElement {
  const caseId = useCaseId()
  const iocs = useIocsQuery(caseId, { type: 'ipv4', include_private: false, sort: 'confidence', order: 'desc', limit: 5 })
  if (iocs.isPending) {
    return <Skeleton className="h-32 w-full" />
  }
  const items = iocs.data?.items ?? []
  if (items.length === 0) {
    return <p className="text-sm text-muted">No external IP indicators.</p>
  }
  return (
    <ul className="space-y-1">
      {items.map((ioc) => (
        <li key={ioc.id} className="flex items-center justify-between gap-2 text-sm">
          <span className="font-mono text-text">{ioc.value}</span>
          <span className="text-xs text-muted">
            conf {ioc.confidence} · {formatNumber(ioc.occurrences)} occ
          </span>
        </li>
      ))}
    </ul>
  )
}

function IngestHealth(): ReactElement {
  const caseId = useCaseId()
  const sources = useSourcesQuery(caseId)
  if (sources.isPending) {
    return <Skeleton className="h-32 w-full" />
  }
  const items = sources.data?.items ?? []
  if (items.length === 0) {
    return <p className="text-sm text-muted">No sources yet.</p>
  }
  return (
    <ul className="space-y-1">
      {items.map((source) => {
        const total = source.event_count + source.error_count
        const rate = total === 0 ? 0 : source.error_count / total
        return (
          <li key={source.id} className="flex items-center justify-between gap-2 text-sm">
            <span className="truncate text-text">{source.filename}</span>
            <span className={rate > 0 ? 'text-sev-medium' : 'text-muted'}>{formatPercent(rate)} errors</span>
          </li>
        )
      })}
    </ul>
  )
}

function LastRun(): ReactElement {
  const caseId = useCaseId()
  const runs = useDetectionRunsQuery(caseId)
  if (runs.isPending) {
    return <Skeleton className="h-20 w-full" />
  }
  const run = runs.data?.items[0]
  if (run === undefined) {
    return <p className="text-sm text-muted">Detection has not run for this case.</p>
  }
  return (
    <dl className="space-y-1 text-sm">
      <div className="flex justify-between">
        <dt className="text-muted">Profile</dt>
        <dd className="text-text">{run.profile}</dd>
      </div>
      <div className="flex justify-between">
        <dt className="text-muted">Alerts produced</dt>
        <dd className="font-mono text-text">{formatNumber(run.counts.alerts)}</dd>
      </div>
      <div className="flex justify-between">
        <dt className="text-muted">ATT&CK version</dt>
        <dd className="text-text">{run.attack_version}</dd>
      </div>
      <div className="flex items-center justify-between gap-2">
        <dt className="text-muted">Ruleset hash</dt>
        <dd className="flex items-center gap-1 font-mono text-xs text-text">
          {formatHash(run.ruleset_hash)}
          <CopyButton value={run.ruleset_hash} label="Copy ruleset hash" />
        </dd>
      </div>
    </dl>
  )
}

/** Case overview dashboard (spec 07 section 3.2). */
export function OverviewPage(): ReactElement {
  const caseId = useCaseId()
  const caseQuery = useCaseQuery(caseId)
  const events = useEventCountQuery(caseId)
  const sources = useSourcesQuery(caseId)
  const iocs = useIocsQuery(caseId, { include_private: false, include_allowlisted: false, limit: 1 })
  const entities = useEntitiesQuery(caseId)

  if (caseId === null) {
    return <ErrorPanel message="No case is selected." />
  }
  if (caseQuery.isError) {
    return (
      <ErrorPanel
        title="Cannot load case"
        message="The case may have been deleted."
        onRetry={() => {
          void caseQuery.refetch()
        }}
      />
    )
  }

  const hostCount = (entities.data ?? []).filter((entity) => entity.kind === 'host').length

  return (
    <section aria-labelledby="overview-heading" className="space-y-4">
      <h1 id="overview-heading" className="text-xl font-semibold text-text">
        Overview
      </h1>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        <KpiTile label="Events" value={formatNumber(events.data ?? caseQuery.data?.counts.events ?? 0)} />
        <KpiTile label="Sources" value={formatNumber((sources.data?.items.length ?? 0))} />
        <KpiTile label="Alerts" value={formatNumber(caseQuery.data?.counts.alerts ?? 0)} />
        <KpiTile label="External IOCs" value={formatNumber(iocs.data?.total ?? iocs.data?.items.length ?? 0)} />
        <KpiTile label="Hosts" value={formatNumber(hostCount)} />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Top alerts by score">
          <TopAlerts />
        </Card>
        <Card title="Event volume">
          <MiniTimeline />
        </Card>
        <Card title="ATT&CK coverage">
          <MitreStrip />
        </Card>
        <Card title="Top external indicators">
          <AttackerCandidates />
        </Card>
        <Card title="Ingest health">
          <IngestHealth />
        </Card>
        <Card title="Last detection run">
          <LastRun />
        </Card>
      </div>
    </section>
  )
}
