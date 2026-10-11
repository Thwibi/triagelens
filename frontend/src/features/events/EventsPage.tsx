import { useEffect, useMemo, useRef, useState } from 'react'
import type { ReactElement } from 'react'
import { useMutation } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import { useVirtualizer } from '@tanstack/react-virtual'
import { Download, HelpCircle, SlidersHorizontal, X } from 'lucide-react'

import { useCaseId } from '../../app/caseRoute'
import { useEventCountFilteredQuery, useEventFacetsQuery, useEventsQuery } from '../../api/hooks'
import { exportEvents } from '../../api/endpoints'
import type { EventExportFormat } from '../../api/endpoints'
import type { EventRecord } from '../../api/types'
import { saveFile } from '../../lib/download'
import { formatNumber, formatTimestamp } from '../../lib/format'
import { loadPref, savePref } from '../../lib/prefs'
import { Button } from '../../ui/Button'
import { EmptyState } from '../../ui/EmptyState'
import { ErrorPanel } from '../../ui/ErrorPanel'
import { SkeletonRows } from '../../ui/Skeleton'
import { useToast } from '../../ui/ToastProvider'
import { EventDrawer } from './EventDrawer'
import { DEFAULT_EVENT_COLUMNS, EVENT_COLUMNS, EVENT_COLUMNS_STORAGE_KEY, gridTemplateFor, sanitizeColumns } from './eventColumns'
import type { EventFilterState } from './eventFilters'
import {
  DEFAULT_EVENT_FILTERS,
  EVENT_MAX_ROWS,
  EVENT_PAGE_SIZE,
  filtersFromSearch,
  hasActiveEventFilters,
  searchFromFilters,
  toEventFilters,
} from './eventFilters'

/** Facet columns shown in the sidebar and the filter each one drives. */
type FacetKey = 'host' | 'log_type' | 'channel' | 'event_id' | 'user_name' | 'src_ip'

const FACETS: readonly { readonly column: string; readonly label: string; readonly key: FacetKey }[] = [
  { column: 'host', label: 'Host', key: 'host' },
  { column: 'log_type', label: 'Log type', key: 'log_type' },
  { column: 'channel', label: 'Channel', key: 'channel' },
  { column: 'event_id', label: 'Event ID', key: 'event_id' },
  { column: 'user_name', label: 'User', key: 'user_name' },
  { column: 'src_ip', label: 'Source IP', key: 'src_ip' },
]

const DENSITY_KEY = 'triagelens.events.density'
const SEARCH_DEBOUNCE_MS = 300
/** The export can stream up to a million rows, far beyond the JSON default. */
const EXPORT_TIMEOUT_MS = 300_000

function netText(event: EventRecord): string {
  const source = event.src_ip === null ? '—' : `${event.src_ip}${event.src_port === null ? '' : `:${String(event.src_port)}`}`
  const dest = event.dst_ip === null ? '—' : `${event.dst_ip}${event.dst_port === null ? '' : `:${String(event.dst_port)}`}`
  return `${source} → ${dest}`
}

/** Plain-text value of a column, shared by the table and the CSV export. */
function cellText(id: string, event: EventRecord): string {
  switch (id) {
    case 'time':
      return formatTimestamp(event.ts_ms)
    case 'host':
      return event.host ?? ''
    case 'log_type':
      return event.log_type ?? ''
    case 'event':
      return [event.event_id, event.event_action].filter((value) => value !== null && value !== '').join(' ')
    case 'user':
      return event.user_name ?? ''
    case 'net':
      return netText(event)
    case 'summary':
      return event.message ?? event.event_action ?? ''
    case 'channel':
      return event.channel ?? ''
    case 'level':
      return event.level ?? ''
    case 'source':
      return event.source_id
    case 'process':
      return event.process_path ?? ''
    case 'file':
      return event.file_path ?? ''
    case 'url':
      return event.url ?? ''
    default:
      return ''
  }
}

function FilterChip({ label, value, onClear }: { readonly label: string; readonly value: string; readonly onClear: () => void }): ReactElement {
  return (
    <span className="inline-flex items-center gap-1 rounded-full border border-border bg-surface-2 px-2 py-0.5 text-xs text-text">
      <span className="text-muted">{label}</span>
      <span className="font-mono">{value}</span>
      <button type="button" aria-label={`Clear ${label} filter`} onClick={onClear} className="text-muted hover:text-text">
        <X aria-hidden="true" size={12} />
      </button>
    </span>
  )
}

/** Events browser (spec 07 section 3.7). */
export function EventsPage(): ReactElement {
  const caseId = useCaseId()
  const { push } = useToast()
  const [params, setParams] = useSearchParams()
  const state = useMemo(() => filtersFromSearch(params.toString()), [params])

  const [search, setSearch] = useState(state.q)
  const [density, setDensity] = useState<'compact' | 'comfortable'>(() =>
    loadPref<'compact' | 'comfortable'>(DENSITY_KEY, 'compact'),
  )
  const [columns, setColumns] = useState<string[]>(() =>
    sanitizeColumns(loadPref<unknown>(EVENT_COLUMNS_STORAGE_KEY, DEFAULT_EVENT_COLUMNS)),
  )

  useEffect(() => {
    savePref(DENSITY_KEY, density)
  }, [density])
  useEffect(() => {
    savePref(EVENT_COLUMNS_STORAGE_KEY, columns)
  }, [columns])

  const update = (partial: Partial<EventFilterState>): void => {
    const next = { ...state, ...partial }
    setParams(new URLSearchParams(searchFromFilters(next)), { replace: true })
  }

  const applyFacet = (key: FacetKey, value: string | number): void => {
    switch (key) {
      case 'host':
        update({ host: String(value) })
        break
      case 'log_type':
        update({ log_type: String(value) })
        break
      case 'channel':
        update({ channel: String(value) })
        break
      case 'event_id':
        update({ event_id: Number(value) })
        break
      case 'user_name':
        update({ user_name: String(value) })
        break
      case 'src_ip':
        update({ src_ip: String(value) })
        break
    }
  }

  useEffect(() => {
    setSearch(state.q)
  }, [state.q])

  useEffect(() => {
    if (search === state.q) {
      return undefined
    }
    const handle = window.setTimeout(() => {
      update({ q: search })
    }, SEARCH_DEBOUNCE_MS)
    return () => {
      window.clearTimeout(handle)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [search, state.q])

  const filters = toEventFilters(state)
  const countFilters = toEventFilters({ ...state, limit: EVENT_PAGE_SIZE, sort: '-ts' })
  const eventsQuery = useEventsQuery(caseId, filters)
  const countQuery = useEventCountFilteredQuery(caseId, countFilters)
  const facetsQuery = useEventFacetsQuery(caseId, countFilters)

  const rows = eventsQuery.data?.items ?? []
  const total = countQuery.data ?? rows.length

  const parentRef = useRef<HTMLDivElement>(null)
  const rowHeight = density === 'compact' ? 40 : 56
  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => rowHeight,
    overscan: 12,
  })

  const template = gridTemplateFor(columns)
  const active = hasActiveEventFilters(state)

  const toggleColumn = (id: string, checked: boolean): void => {
    const next = checked ? [...columns, id] : columns.filter((column) => column !== id)
    setColumns(sanitizeColumns(next))
  }

  const exportMutation = useMutation({
    mutationFn: (format: EventExportFormat) => {
      if (caseId === null) {
        throw new Error('No case is selected.')
      }
      return exportEvents(caseId, format, filters, { timeoutMs: EXPORT_TIMEOUT_MS })
    },
    onSuccess: (file, format) => {
      saveFile(file, `events-${caseId ?? 'case'}.${format}`)
      push('success', 'Export ready')
    },
    onError: () => {
      push('error', 'Could not export events')
    },
  })

  return (
    <div className="flex h-full">
      <div className="flex min-w-0 flex-1 flex-col">
        <div className="flex flex-wrap items-center gap-2 border-b border-border p-3">
          <div className="relative min-w-[16rem] flex-1">
            <input
              type="search"
              value={search}
              onChange={(event) => { setSearch(event.target.value) }}
              placeholder="Search events (FTS5)"
              aria-label="Search events"
              className="w-full rounded-[var(--radius-control)] border border-border bg-surface px-3 py-1.5 text-sm text-text outline-none focus:border-accent"
            />
          </div>
          <details className="relative">
            <summary className="flex cursor-pointer list-none items-center gap-1 rounded-[var(--radius-control)] border border-border px-2 py-1.5 text-xs text-muted">
              <HelpCircle aria-hidden="true" size={14} /> Search help
            </summary>
            <div className="absolute right-0 z-20 mt-1 w-80 rounded-[var(--radius-card)] border border-border bg-surface p-3 text-xs text-muted shadow-lg">
              <p className="mb-1 font-medium text-text">Full-text syntax</p>
              <ul className="space-y-1">
                <li><code className="font-mono text-text">AND</code> / <code className="font-mono text-text">OR</code> / <code className="font-mono text-text">NOT</code> — boolean operators</li>
                <li><code className="font-mono text-text">&quot;exact phrase&quot;</code> — phrase match</li>
                <li><code className="font-mono text-text">prefix*</code> — prefix match</li>
                <li><code className="font-mono text-text">process_cmdline:powershell</code> — column-scoped term</li>
              </ul>
            </div>
          </details>
          <div className="flex items-center gap-1">
            <Button variant="ghost" onClick={() => { update({ sort: state.sort === '-ts' ? 'ts' : '-ts' }) }} aria-label="Toggle sort order">
              {state.sort === '-ts' ? 'Newest first' : 'Oldest first'}
            </Button>
            <Button variant="ghost" onClick={() => { setDensity(density === 'compact' ? 'comfortable' : 'compact') }} aria-label="Toggle density">
              {density === 'compact' ? 'Compact' : 'Comfortable'}
            </Button>
          </div>
          <details className="relative">
            <summary className="flex cursor-pointer list-none items-center gap-1 rounded-[var(--radius-control)] border border-border px-2 py-1.5 text-xs text-muted">
              <SlidersHorizontal aria-hidden="true" size={14} /> Columns
            </summary>
            <fieldset className="absolute right-0 z-20 mt-1 w-56 rounded-[var(--radius-card)] border border-border bg-surface p-2 shadow-lg">
              <legend className="px-1 text-xs text-muted">Visible columns</legend>
              {EVENT_COLUMNS.map((column) => (
                <label key={column.id} className="flex items-center gap-2 px-1 py-0.5 text-xs text-text">
                  <input
                    type="checkbox"
                    checked={columns.includes(column.id)}
                    onChange={(event) => { toggleColumn(column.id, event.target.checked) }}
                  />
                  {column.label}
                </label>
              ))}
            </fieldset>
          </details>
          <div className="flex items-center gap-1">
            <Button
              variant="ghost"
              onClick={() => { exportMutation.mutate('csv') }}
              aria-label="Export CSV"
              disabled={rows.length === 0 || exportMutation.isPending}
            >
              <Download aria-hidden="true" size={14} /> CSV
            </Button>
            <Button
              variant="ghost"
              onClick={() => { exportMutation.mutate('jsonl') }}
              aria-label="Export JSONL"
              disabled={rows.length === 0 || exportMutation.isPending}
            >
              <Download aria-hidden="true" size={14} /> JSONL
            </Button>
          </div>
        </div>

        {(state.host !== '' || state.log_type !== '' || state.channel !== '' || state.event_id !== null || state.user_name !== '' || state.src_ip !== '' || state.dst_ip !== '' || state.ioc_id !== '' || state.alert_id !== '') ? (
          <div className="flex flex-wrap items-center gap-1 border-b border-border px-3 py-2">
            {state.host !== '' ? <FilterChip label="host" value={state.host} onClear={() => { update({ host: '' }) }} /> : null}
            {state.log_type !== '' ? <FilterChip label="log type" value={state.log_type} onClear={() => { update({ log_type: '' }) }} /> : null}
            {state.channel !== '' ? <FilterChip label="channel" value={state.channel} onClear={() => { update({ channel: '' }) }} /> : null}
            {state.event_id !== null ? <FilterChip label="event id" value={String(state.event_id)} onClear={() => { update({ event_id: null }) }} /> : null}
            {state.user_name !== '' ? <FilterChip label="user" value={state.user_name} onClear={() => { update({ user_name: '' }) }} /> : null}
            {state.src_ip !== '' ? <FilterChip label="src ip" value={state.src_ip} onClear={() => { update({ src_ip: '' }) }} /> : null}
            {state.dst_ip !== '' ? <FilterChip label="dst ip" value={state.dst_ip} onClear={() => { update({ dst_ip: '' }) }} /> : null}
            {state.ioc_id !== '' ? <FilterChip label="ioc" value={state.ioc_id} onClear={() => { update({ ioc_id: '' }) }} /> : null}
            {state.alert_id !== '' ? <FilterChip label="alert" value={state.alert_id} onClear={() => { update({ alert_id: '' }) }} /> : null}
          </div>
        ) : null}

        <div className="flex items-center justify-between border-b border-border px-3 py-1 text-xs text-muted">
          <span>
            {countQuery.isSuccess ? `${formatNumber(total)} matching` : 'Counting…'}
            {rows.length > 0 ? ` · showing ${formatNumber(rows.length)}` : ''}
          </span>
          {rows.length < total && rows.length < state.limit ? (
            <Button variant="ghost" onClick={() => { update({ limit: Math.min(EVENT_MAX_ROWS, state.limit + EVENT_PAGE_SIZE) }) }}>
              Load more
            </Button>
          ) : null}
        </div>

        <div className="min-h-0 flex-1 overflow-hidden">
          {eventsQuery.isError ? (
            <div className="p-4">
              <ErrorPanel title="Cannot load events" message="The events query failed." onRetry={() => { void eventsQuery.refetch() }} />
            </div>
          ) : eventsQuery.isLoading ? (
            <div className="p-4">
              <SkeletonRows rows={8} />
            </div>
          ) : rows.length === 0 ? (
            <div className="p-4">
              <EmptyState
                title={active ? 'No events match the filters' : 'No events yet'}
                detail={active ? 'Adjust or clear the filters to broaden the search.' : 'Import a log source to populate the timeline.'}
              />
            </div>
          ) : (
            <div className="flex h-full flex-col">
              <div className="sticky top-0 z-10 grid gap-2 border-b border-border bg-surface px-3 py-2 text-xs font-medium uppercase tracking-wide text-muted" style={{ gridTemplateColumns: template }}>
                {EVENT_COLUMNS.filter((column) => columns.includes(column.id)).map((column) => (
                  <span key={column.id}>{column.label}</span>
                ))}
              </div>
              <div ref={parentRef} className="min-h-0 flex-1 overflow-auto">
                <div style={{ height: virtualizer.getTotalSize(), position: 'relative', width: '100%' }}>
                  {virtualizer.getVirtualItems().map((virtualRow) => {
                    const event = rows[virtualRow.index]
                    if (event === undefined) {
                      return null
                    }
                    return (
                      <button
                        key={event.id}
                        type="button"
                        onClick={() => { update({ event: event.id }) }}
                        className="absolute left-0 grid w-full gap-2 border-b border-border/60 px-3 text-left text-sm hover:bg-surface-2"
                        style={{ top: virtualRow.start, height: virtualRow.size, gridTemplateColumns: template }}
                      >
                        {columns.map((id) => (
                          <span key={id} className="truncate font-mono text-xs text-text">
                            {cellText(id, event)}
                          </span>
                        ))}
                      </button>
                    )
                  })}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      <aside
        aria-label="Event filters"
        tabIndex={0}
        className="w-64 shrink-0 space-y-4 overflow-auto border-l border-border bg-surface p-3"
      >
        <div className="flex items-center justify-between">
          <h2 className="text-xs font-medium uppercase tracking-wide text-muted">Facets</h2>
          {active ? (
            <button type="button" className="text-xs text-accent-text hover:underline" onClick={() => { update(DEFAULT_EVENT_FILTERS) }}>
              Reset
            </button>
          ) : null}
        </div>
        {FACETS.map((facet) => {
          const values = facetsQuery.data?.facets[facet.column] ?? []
          return (
            <section key={facet.column} className="space-y-1">
              <h3 className="text-xs font-medium text-text">{facet.label}</h3>
              {facetsQuery.isPending ? <SkeletonRows rows={3} /> : null}
              {values.length === 0 && facetsQuery.isSuccess ? <p className="text-xs text-muted">No values</p> : null}
              <ul className="space-y-0.5">
                {values.map((value) => {
                  return (
                    <li key={`${facet.column}:${String(value.value)}`}>
                      <button
                        type="button"
                        className="flex w-full items-center justify-between gap-2 rounded px-1 py-0.5 text-left text-xs hover:bg-surface-2"
                        onClick={() => { applyFacet(facet.key, value.value) }}
                      >
                        <span className="min-w-0 truncate font-mono text-text">{String(value.value)}</span>
                        <span className="shrink-0 text-muted">{formatNumber(value.count)}</span>
                      </button>
                    </li>
                  )
                })}
              </ul>
            </section>
          )
        })}
      </aside>

      {state.event !== null ? (
        <EventDrawer eventId={state.event} onClose={() => { update({ event: null }) }} />
      ) : null}
    </div>
  )
}
