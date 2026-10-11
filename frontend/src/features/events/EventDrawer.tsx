import { useState } from 'react'
import type { ReactElement } from 'react'
import { Link } from 'react-router-dom'
import { X } from 'lucide-react'

import { useEventQuery, useEventsQuery } from '../../api/hooks'
import type { EventDetail, EventRecord } from '../../api/types'
import { useCaseId } from '../../app/caseRoute'
import { caseNavPath } from '../../app/navigation'
import { defang, formatNumber, formatTimestamp } from '../../lib/format'
import { SeverityBadge } from '../../ui/Badge'
import { Button } from '../../ui/Button'
import { CodeBlock } from '../../ui/CodeBlock'
import { CopyButton } from '../../ui/CopyButton'
import { ErrorPanel } from '../../ui/ErrorPanel'
import { SkeletonRows } from '../../ui/Skeleton'
import { highlightSegments } from './highlight'

/** The normalized fields shown as a labelled table (spec 07 section 3.7). */
const NORMALIZED: readonly (readonly [string, keyof EventRecord])[] = [
  ['Time', 'ts_iso'],
  ['Host', 'host'],
  ['Log type', 'log_type'],
  ['Category', 'ls_category'],
  ['Channel', 'channel'],
  ['Provider', 'provider'],
  ['Event ID', 'event_id'],
  ['Level', 'level'],
  ['Action', 'event_action'],
  ['Outcome', 'event_outcome'],
  ['User', 'user_name'],
  ['Target user', 'target_user_name'],
  ['Domain', 'domain'],
  ['Source IP', 'src_ip'],
  ['Source port', 'src_port'],
  ['Destination IP', 'dst_ip'],
  ['Destination port', 'dst_port'],
  ['Protocol', 'protocol'],
  ['Process', 'process_path'],
  ['Command line', 'process_cmdline'],
  ['Parent process', 'parent_process_path'],
  ['Parent command', 'parent_process_cmdline'],
  ['File', 'file_path'],
  ['Registry key', 'registry_key'],
  ['URL', 'url'],
  ['HTTP method', 'http_method'],
  ['HTTP status', 'http_status'],
  ['User agent', 'user_agent'],
  ['Bytes out', 'bytes_out'],
  ['Message', 'message'],
]

function scalar(value: unknown): string {
  if (value === null || value === undefined) {
    return '—'
  }
  if (typeof value === 'string') {
    return value
  }
  if (typeof value === 'number' || typeof value === 'boolean') {
    return String(value)
  }
  return JSON.stringify(value)
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/** A recursive key/value view of a decoded provider record. */
function FieldTree({ data, depth = 0 }: { readonly data: Record<string, unknown>; readonly depth?: number }): ReactElement {
  return (
    <ul className="space-y-0.5" style={{ paddingLeft: depth === 0 ? 0 : 12 }}>
      {Object.entries(data).map(([key, value]) => (
        <li key={key} className="text-xs">
          <div className="flex items-start justify-between gap-2">
            <span className="text-muted">{key}</span>
            <span className="flex items-center gap-1">
              {isRecord(value) || Array.isArray(value) ? null : (
                <>
                  <span className="break-all font-mono text-text">{scalar(value)}</span>
                  <CopyButton value={scalar(value)} label={`Copy ${key}`} />
                </>
              )}
            </span>
          </div>
          {isRecord(value) ? <FieldTree data={value} depth={depth + 1} /> : null}
          {Array.isArray(value) ? (
            <ul className="space-y-0.5" style={{ paddingLeft: 12 }}>
              {value.map((item, index) => (
                <li key={index} className="break-all font-mono text-xs text-text">
                  {isRecord(item) ? <FieldTree data={item} depth={depth + 1} /> : scalar(item)}
                </li>
              ))}
            </ul>
          ) : null}
        </li>
      ))}
    </ul>
  )
}

/** Raw event text with IOC ranges highlighted using text nodes only. */
function HighlightedRaw({ text, needles }: { readonly text: string; readonly needles: readonly string[] }): ReactElement {
  const segments = highlightSegments(text, needles)
  return (
    <pre aria-label="Raw event (highlighted)" className="max-h-96 overflow-auto whitespace-pre-wrap break-all rounded border border-border p-2 font-mono text-xs text-text">
      {segments.map((segment, index) =>
        segment.match ? (
          <mark key={index} className="rounded bg-sev-medium/30 text-text">{segment.text}</mark>
        ) : (
          <span key={index}>{segment.text}</span>
        ),
      )}
    </pre>
  )
}

function Section({ title, children }: { readonly title: string; readonly children: ReactElement | ReactElement[] | null }): ReactElement {
  return (
    <section className="space-y-2 border-t border-border pt-3">
      <h3 className="text-xs font-medium uppercase tracking-wide text-muted">{title}</h3>
      {children}
    </section>
  )
}

/** Surrounding events in the same host within a window (spec 07 section 3.7). */
function SurroundingEvents({ caseId, event }: { readonly caseId: string; readonly event: EventDetail }): ReactElement {
  const windowMs = 30_000
  const query = useEventsQuery(caseId, {
    host: event.host ?? undefined,
    from_ms: event.ts_ms === null ? undefined : event.ts_ms - windowMs,
    to_ms: event.ts_ms === null ? undefined : event.ts_ms + windowMs,
    sort: 'ts',
    limit: 50,
  })
  return (
    <div className="space-y-1 rounded border border-border bg-surface-2/40 p-2">
      <p className="text-xs text-muted">±30s on {event.host ?? 'this host'}</p>
      {query.isPending ? <SkeletonRows rows={2} /> : null}
      {query.isError ? <p className="text-xs text-sev-critical">Could not load surrounding events.</p> : null}
      {query.isSuccess ? (
        query.data.items.length === 0 ? (
          <p className="text-xs text-muted">No nearby events.</p>
        ) : (
          <ul className="space-y-0.5">
            {query.data.items.map((item) => (
              <li key={item.id} className="flex gap-2 text-xs">
                <span className="font-mono text-muted">{formatTimestamp(item.ts_ms)}</span>
                <span className="truncate text-text">{item.message ?? item.event_action ?? item.log_type ?? 'event'}</span>
              </li>
            ))}
          </ul>
        )
      ) : null}
    </div>
  )
}

/** Event detail drawer (spec 07 section 3.7). */
export function EventDrawer({ eventId, onClose }: { readonly eventId: number; readonly onClose: () => void }): ReactElement {
  const caseId = useCaseId()
  const detail = useEventQuery(eventId)
  const [rawMode, setRawMode] = useState<'highlight' | 'source'>('highlight')
  const [wrap, setWrap] = useState(true)
  const [defanged, setDefanged] = useState(false)
  const [showSurrounding, setShowSurrounding] = useState(false)

  const needles = (detail.data?.iocs ?? []).flatMap((ioc) => [ioc.value, ioc.value_norm])

  return (
    <aside
      role="dialog"
      aria-modal="true"
      aria-label="Event detail"
      tabIndex={-1}
      className="fixed inset-y-0 right-0 z-30 flex w-[46rem] max-w-full flex-col border-l border-border bg-surface shadow-xl"
    >
      <div className="flex items-center justify-between border-b border-border px-4 py-2">
        <h2 className="truncate text-sm font-medium text-text">
          Event {detail.data !== undefined ? `#${detail.data.id}` : ''}
        </h2>
        <Button variant="ghost" aria-label="Close event" onClick={onClose}>
          <X aria-hidden="true" size={16} />
        </Button>
      </div>
      <div className="flex-1 space-y-3 overflow-auto p-4">
        {detail.isPending ? <SkeletonRows rows={6} /> : null}
        {detail.isError ? (
          <ErrorPanel title="Cannot load event" message="The event may have been removed." onRetry={() => { void detail.refetch() }} />
        ) : null}
        {detail.data !== undefined ? (
          <>
            <dl className="grid grid-cols-2 gap-x-4 gap-y-1">
              {NORMALIZED.map(([label, key]) => {
                const value = detail.data[key]
                return (
                  <div key={key} className="flex justify-between gap-2 text-xs">
                    <dt className="text-muted">{label}</dt>
                    <dd className="truncate font-mono text-text">{scalar(value)}</dd>
                  </div>
                )
              })}
            </dl>

            <Section title="Related alerts">
              {detail.data.alerts.length === 0 ? (
                <p className="text-sm text-muted">No alerts reference this event.</p>
              ) : (
                <ul className="space-y-1">
                  {detail.data.alerts.map((alert) => (
                    <li key={alert.id} className="flex items-center justify-between gap-2 text-xs">
                      <Link
                        to={`${caseNavPath(caseId ?? '', 'alerts')}?alert=${encodeURIComponent(alert.id)}`}
                        className="min-w-0 truncate text-accent hover:underline"
                      >
                        {alert.rule_title}
                      </Link>
                      <span className="flex items-center gap-2">
                        <SeverityBadge level={alert.level} />
                        <span className="font-mono text-muted">{alert.score}</span>
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </Section>

            <Section title="Indicators">
              <div className="space-y-2">
                <label className="flex items-center gap-2 text-xs text-muted">
                  <input type="checkbox" checked={defanged} onChange={(event) => { setDefanged(event.target.checked) }} />
                  Defang values
                </label>
                {detail.data.iocs.length === 0 ? (
                  <p className="text-sm text-muted">No indicators in this event.</p>
                ) : (
                  <ul className="flex flex-wrap gap-1">
                    {detail.data.iocs.map((ioc) => {
                      const shown = defanged ? defang(ioc.value) : ioc.value
                      return (
                        <li key={ioc.id} className="inline-flex items-center gap-1 rounded bg-surface-2 px-1.5 py-0.5 text-xs">
                          <span className="font-mono text-muted">{ioc.type}</span>
                          <Link to={`${caseNavPath(caseId ?? '', 'iocs')}?ioc=${encodeURIComponent(ioc.id)}`} className="break-all font-mono text-text hover:underline">
                            {shown}
                          </Link>
                          <CopyButton value={shown} label={`Copy ${ioc.type}`} />
                        </li>
                      )
                    })}
                  </ul>
                )}
              </div>
            </Section>

            <Section title="Original fields">
              {Object.keys(detail.data.fields).length === 0 ? (
                <p className="text-sm text-muted">No decoded fields.</p>
              ) : (
                <FieldTree data={detail.data.fields} />
              )}
            </Section>

            <Section title="Raw">
              <div className="space-y-2">
                <div className="flex flex-wrap items-center gap-2">
                  <div role="group" aria-label="Raw view mode" className="inline-flex overflow-hidden rounded-[var(--radius-control)] border border-border">
                    <button
                      type="button"
                      aria-pressed={rawMode === 'highlight'}
                      className={`px-2 py-1 text-xs ${rawMode === 'highlight' ? 'bg-accent text-black' : 'bg-surface-2 text-text'}`}
                      onClick={() => { setRawMode('highlight') }}
                    >
                      Highlighted
                    </button>
                    <button
                      type="button"
                      aria-pressed={rawMode === 'source'}
                      className={`px-2 py-1 text-xs ${rawMode === 'source' ? 'bg-accent text-black' : 'bg-surface-2 text-text'}`}
                      onClick={() => { setRawMode('source') }}
                    >
                      Source
                    </button>
                  </div>
                  <label className="flex items-center gap-1 text-xs text-muted">
                    <input type="checkbox" checked={wrap} onChange={(event) => { setWrap(event.target.checked) }} />
                    Wrap
                  </label>
                </div>
                {detail.data.raw === null ? (
                  <p className="text-sm text-muted">No raw record stored.</p>
                ) : rawMode === 'highlight' ? (
                  <HighlightedRaw text={detail.data.raw} needles={needles} />
                ) : (
                  <CodeBlock value={detail.data.raw} language="plain" wrap={wrap} ariaLabel="Raw event" />
                )}
                <p className="text-xs text-muted">Indicator matches are shown as plain text marks; nothing is rendered as markup.</p>
              </div>
            </Section>

            <Section title="Surrounding events">
              <div className="space-y-2">
                <Button variant="ghost" onClick={() => { setShowSurrounding((value) => !value) }}>
                  {showSurrounding ? 'Hide surrounding events' : 'Show surrounding events'}
                </Button>
                {showSurrounding && caseId !== null ? <SurroundingEvents caseId={caseId} event={detail.data} /> : null}
              </div>
            </Section>

            <p className="text-xs text-muted">
              Evidence count: {formatNumber(detail.data.alerts.length)} alert(s) reference this event.
            </p>
          </>
        ) : null}
      </div>
    </aside>
  )
}
