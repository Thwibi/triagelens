import { useMemo } from 'react'
import type { ReactElement } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { Bar, Brush, CartesianGrid, ComposedChart, Line, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'

import { useAlertsQuery, useFilteredTimelineQuery, useIocsQuery } from '../../api/hooks'
import type { Alert, Ioc } from '../../api/types'
import { useCaseId } from '../../app/caseRoute'
import { caseNavPath } from '../../app/navigation'
import { formatNumber, formatTimestamp } from '../../lib/format'
import { AnalystStateBadge, SeverityBadge } from '../../ui/Badge'
import { Button } from '../../ui/Button'
import { EmptyState } from '../../ui/EmptyState'
import { ErrorPanel } from '../../ui/ErrorPanel'
import { Skeleton } from '../../ui/Skeleton'
import {
  extentMs,
  filterByRange,
  logTypeColor,
  seriesKeys,
  toChartData,
  zoomRange,
} from './timelineBuckets'

const BUCKETS: readonly { readonly value: string; readonly label: string }[] = [
  { value: 'auto', label: 'Auto' },
  { value: '1m', label: '1 minute' },
  { value: '5m', label: '5 minutes' },
  { value: '1h', label: '1 hour' },
  { value: '1d', label: '1 day' },
]

function isBucket(value: string | null): value is 'auto' | '1m' | '5m' | '1h' | '1d' {
  return value === 'auto' || value === '1m' || value === '5m' || value === '1h' || value === '1d'
}

function intOrNull(value: string | null): number | null {
  if (value === null || value === '') {
    return null
  }
  const parsed = Number(value)
  return Number.isFinite(parsed) ? Math.trunc(parsed) : null
}

function notable(ioc: Ioc): boolean {
  return ioc.analyst_state === 'malicious' || ioc.analyst_state === 'suspicious' || ioc.confidence >= 60
}

/** Timeline screen (spec 07 section 3.8). */
export function TimelinePage(): ReactElement {
  const caseId = useCaseId()
  const [params, setParams] = useSearchParams()

  const bucketParam = params.get('bucket')
  const bucket = isBucket(bucketParam) ? bucketParam : 'auto'
  const from = intOrNull(params.get('from_ms'))
  const to = intOrNull(params.get('to_ms'))

  const setRange = (nextFrom: number | null, nextTo: number | null): void => {
    const next = new URLSearchParams(params)
    if (nextFrom === null) {
      next.delete('from_ms')
    } else {
      next.set('from_ms', String(nextFrom))
    }
    if (nextTo === null) {
      next.delete('to_ms')
    } else {
      next.set('to_ms', String(nextTo))
    }
    setParams(next, { replace: true })
  }

  const timeline = useFilteredTimelineQuery(caseId, {}, bucket)
  const alerts = useAlertsQuery(caseId, { sort: '-last_seen', limit: 200 })
  const iocs = useIocsQuery(caseId, { sort: 'confidence', order: 'desc', limit: 200 })

  const buckets = useMemo(() => timeline.data?.buckets ?? [], [timeline.data])
  const keys = useMemo(() => seriesKeys(buckets), [buckets])
  const data = useMemo(() => toChartData(buckets), [buckets])
  const extent = extentMs(buckets)

  const alertsInRange = filterByRange(alerts.data?.items ?? [], (alert: Alert) => alert.last_seen_ms, from, to)
  const iocsInRange = filterByRange(iocs.data?.items ?? [], (ioc: Ioc) => ioc.last_seen_ms, from, to).filter(notable)

  if (caseId === null) {
    return <ErrorPanel message="No case is selected." />
  }

  return (
    <section aria-labelledby="timeline-heading" className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h1 id="timeline-heading" className="text-xl font-semibold text-text">
          Timeline
        </h1>
        <div className="flex flex-wrap items-center gap-2">
          <label className="flex items-center gap-1 text-xs text-muted">
            Bucket
            <select
              value={bucket}
              className="rounded-[var(--radius-control)] border border-border bg-surface px-2 py-1 text-xs text-text"
              onChange={(event) => {
                const next = new URLSearchParams(params)
                next.set('bucket', event.target.value)
                setParams(next, { replace: true })
              }}
            >
              {BUCKETS.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </label>
          <Button
            variant="ghost"
            disabled={extent === null}
            onClick={() => {
              if (extent !== null) {
                const next = zoomRange(from, to, extent, 0.5)
                setRange(next.from, next.to)
              }
            }}
          >
            Zoom in
          </Button>
          <Button
            variant="ghost"
            disabled={extent === null}
            onClick={() => {
              if (extent !== null) {
                const next = zoomRange(from, to, extent, 2)
                setRange(next.from, next.to)
              }
            }}
          >
            Zoom out
          </Button>
          {from !== null || to !== null ? (
            <Button variant="ghost" onClick={() => { setRange(null, null) }}>
              Clear range
            </Button>
          ) : null}
        </div>
      </div>

      <p className="text-xs text-muted">
        {from !== null || to !== null
          ? `Selected range: ${formatTimestamp(from ?? extent?.min ?? null)} – ${formatTimestamp(to ?? extent?.max ?? null)}`
          : 'Selected range: entire case'}
      </p>

      {timeline.isError ? (
        <ErrorPanel title="Cannot load timeline" message="The timeline query failed." onRetry={() => { void timeline.refetch() }} />
      ) : timeline.isPending ? (
        <Skeleton className="h-72 w-full" />
      ) : data.length === 0 ? (
        <EmptyState title="No events in range" detail="Import a log source to populate the timeline." />
      ) : (
        <div className="h-72 w-full" role="group" aria-label="Event volume over time by log type with alert markers">
          <ResponsiveContainer width="100%" height="100%">
            <ComposedChart data={data} margin={{ top: 8, right: 12, bottom: 0, left: -12 }}>
              <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" />
              <XAxis
                dataKey="t_ms"
                tickFormatter={(value: number) => new Date(value).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                stroke="var(--muted)"
                fontSize={11}
              />
              <YAxis stroke="var(--muted)" fontSize={11} width={44} allowDecimals={false} />
              <Tooltip
                contentStyle={{ background: 'var(--surface-2)', border: '1px solid var(--border)', fontSize: 12 }}
                labelFormatter={(value) => formatTimestamp(Number(value))}
              />
              {keys.map((key, index) => (
                <Bar key={key} dataKey={key} stackId="events" fill={logTypeColor(index)} name={key} />
              ))}
              <Line dataKey="alert_count" name="alerts" stroke="var(--sev-critical)" strokeWidth={2} dot={{ r: 2 }} />
              <Brush
                dataKey="t_ms"
                height={22}
                stroke="var(--muted)"
                travellerWidth={8}
                onChange={(range: { startIndex?: number; endIndex?: number }) => {
                  const start = range.startIndex === undefined ? undefined : data[range.startIndex]
                  const end = range.endIndex === undefined ? undefined : data[range.endIndex]
                  setRange(start?.t_ms ?? null, end?.t_ms ?? null)
                }}
              />
            </ComposedChart>
          </ResponsiveContainer>
        </div>
      )}

      {keys.length > 0 ? (
        <ul className="flex flex-wrap gap-3 text-xs text-muted">
          {keys.map((key, index) => (
            <li key={key} className="flex items-center gap-1">
              <span aria-hidden="true" className="inline-block h-2.5 w-2.5 rounded-sm" style={{ backgroundColor: logTypeColor(index) }} />
              <span className="font-mono text-text">{key}</span>
            </li>
          ))}
        </ul>
      ) : null}

      <div className="grid gap-4 lg:grid-cols-2">
        <div className="space-y-2">
          <h2 className="text-sm font-medium text-text">Alerts in range</h2>
          {alertsInRange.length === 0 ? (
            <p className="text-sm text-muted">No alerts in the selected range.</p>
          ) : (
            <ul className="space-y-1">
              {alertsInRange.slice(0, 50).map((alert) => (
                <li key={alert.id} className="flex items-center justify-between gap-2 border-b border-border/60 pb-1 text-sm">
                  <Link
                    to={`${caseNavPath(caseId, 'alerts')}?alert=${encodeURIComponent(alert.id)}`}
                    className="min-w-0 truncate text-accent-text hover:underline"
                  >
                    {alert.rule_title}
                  </Link>
                  <span className="flex shrink-0 items-center gap-2">
                    <SeverityBadge level={alert.level} />
                    <span className="font-mono text-xs text-muted">{formatTimestamp(alert.last_seen_ms)}</span>
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>
        <div className="space-y-2">
          <h2 className="text-sm font-medium text-text">Notable indicators in range</h2>
          {iocsInRange.length === 0 ? (
            <p className="text-sm text-muted">No notable indicators in the selected range.</p>
          ) : (
            <ul className="space-y-1">
              {iocsInRange.slice(0, 50).map((ioc) => (
                <li key={ioc.id} className="flex items-center justify-between gap-2 border-b border-border/60 pb-1 text-sm">
                  <Link
                    to={`${caseNavPath(caseId, 'iocs')}?ioc=${encodeURIComponent(ioc.id)}`}
                    className="min-w-0 truncate font-mono text-text hover:underline"
                  >
                    {ioc.value}
                  </Link>
                  <span className="flex shrink-0 items-center gap-2">
                    <AnalystStateBadge state={ioc.analyst_state} />
                    <span className="font-mono text-xs text-muted">conf {formatNumber(ioc.confidence)}</span>
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </section>
  )
}
