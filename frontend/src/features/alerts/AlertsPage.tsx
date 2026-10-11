import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { CSSProperties, KeyboardEvent, ReactElement } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useVirtualizer } from '@tanstack/react-virtual'
import { ArrowDown, ArrowUp } from 'lucide-react'

import { bulkUpdateAlerts, patchAlert } from '../../api/endpoints'
import { useAlertsQuery } from '../../api/hooks'
import { invalidateAlertDetail, invalidateAlerts } from '../../api/invalidate'
import type { AlertStatus } from '../../api/types'
import { useCaseId } from '../../app/caseRoute'
import { caseNavPath } from '../../app/navigation'
import { formatNumber, formatTimestamp } from '../../lib/format'
import { AlertStatusBadge, SeverityBadge } from '../../ui/Badge'
import { Button } from '../../ui/Button'
import { EmptyState } from '../../ui/EmptyState'
import { ErrorPanel } from '../../ui/ErrorPanel'
import { SkeletonRows } from '../../ui/Skeleton'
import { useToast } from '../../ui/ToastProvider'
import { AlertDrawer } from './AlertDrawer'
import {
  ALERT_PAGE_SIZE,
  ALERT_SORTABLE,
  filtersFromSearch,
  hasActiveFilters,
  searchFromFilters,
  toAlertFilters,
  toggleSort,
} from './alertFilters'
import type { AlertFilterState } from './alertFilters'

const GRID = '2rem 7rem 4.5rem minmax(12rem,1fr) 12rem 9rem 8rem 10rem 4.5rem 8rem'
const ROW_HEIGHT = 48

const STATUS_OPTIONS: readonly AlertStatus[] = ['triaged', 'true_positive', 'false_positive', 'benign']
const STATUS_LABEL: Readonly<Record<AlertStatus, string>> = {
  new: 'New',
  triaged: 'Triaged',
  true_positive: 'True positive',
  false_positive: 'False positive',
  benign: 'Benign',
}
const LEVEL_OPTIONS = ['critical', 'high', 'medium', 'low', 'informational'] as const

function SortHeader({
  column,
  label,
  state,
  onSort,
}: {
  readonly column: string
  readonly label: string
  readonly state: AlertFilterState
  readonly onSort: (column: string) => void
}): ReactElement {
  const active = state.sort === column || state.sort === `-${column}`
  return (
    <button
      type="button"
      className="flex items-center gap-1 text-left text-xs font-medium uppercase tracking-wide text-muted hover:text-text"
      onClick={() => { onSort(column) }}
    >
      {label}
      {active ? (state.sort.startsWith('-') ? <ArrowDown aria-hidden="true" size={12} /> : <ArrowUp aria-hidden="true" size={12} />) : null}
    </button>
  )
}

function ScoreCell({ score }: { readonly score: number }): ReactElement {
  return (
    <span className="flex items-center gap-1.5">
      <span aria-hidden="true" className="h-1.5 w-8 overflow-hidden rounded bg-surface-2">
        <span className="block h-full bg-accent" style={{ width: `${Math.min(100, Math.max(0, score))}%` }} />
      </span>
      <span className="font-mono text-xs text-text">{score}</span>
    </span>
  )
}

/** Alerts list with URL filters, a virtualized table and bulk triage (spec 07 section 3.4). */
export function AlertsPage(): ReactElement {
  const caseId = useCaseId()
  const queryClient = useQueryClient()
  const { push } = useToast()
  const [params, setParams] = useSearchParams()
  const state = useMemo(() => filtersFromSearch(params.toString()), [params])
  const filters = useMemo(() => toAlertFilters(state), [state])
  const alerts = useAlertsQuery(caseId, filters)

  const [selected, setSelected] = useState<ReadonlySet<string>>(() => new Set())
  const [activeIndex, setActiveIndex] = useState(0)
  const [searchText, setSearchText] = useState(state.q)
  const scrollRef = useRef<HTMLDivElement | null>(null)

  const update = useCallback(
    (patch: Partial<AlertFilterState>) => {
      const keys = Object.keys(patch) as (keyof AlertFilterState)[]
      const resetsPage = keys.some((key) => key !== 'page' && key !== 'alert')
      const page = 'page' in patch ? patch.page ?? 1 : resetsPage ? 1 : state.page
      setParams(searchFromFilters({ ...state, ...patch, page }))
    },
    [state, setParams],
  )

  useEffect(() => {
    setSearchText(state.q)
  }, [state.q])

  useEffect(() => {
    if (searchText === state.q) {
      return undefined
    }
    const handle = setTimeout(() => { update({ q: searchText }) }, 300)
    return () => { clearTimeout(handle) }
  }, [searchText, state.q, update])

  const single = useMutation({
    mutationFn: ({ id, status }: { readonly id: string; readonly status: AlertStatus }) => patchAlert(id, { status }),
    onSuccess: (_data, variables) => {
      if (caseId !== null) {
        invalidateAlerts(queryClient, caseId)
      }
      invalidateAlertDetail(queryClient, variables.id)
      push('success', 'Verdict updated')
    },
  })

  const bulk = useMutation({
    mutationFn: ({ ids, status }: { readonly ids: readonly string[]; readonly status: AlertStatus }) =>
      bulkUpdateAlerts({ ids: [...ids], status }),
    onSuccess: (data) => {
      if (caseId !== null) {
        invalidateAlerts(queryClient, caseId)
      }
      setSelected(new Set())
      push('success', `${formatNumber(data.updated)} alerts updated`)
    },
  })

  const rows = useMemo(() => alerts.data?.items ?? [], [alerts.data])
  const total = alerts.data?.total ?? rows.length
  const totalPages = Math.max(1, Math.ceil(total / ALERT_PAGE_SIZE))

  const rowVirtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 12,
  })

  useEffect(() => {
    if (activeIndex >= 0 && activeIndex < rows.length) {
      rowVirtualizer.scrollToIndex(activeIndex)
    }
  }, [activeIndex, rows.length, rowVirtualizer])

  useEffect(() => {
    if (activeIndex >= rows.length) {
      setActiveIndex(0)
    }
  }, [activeIndex, rows.length])

  const toggleSelected = useCallback((id: string) => {
    setSelected((current) => {
      const next = new Set(current)
      if (next.has(id)) {
        next.delete(id)
      } else {
        next.add(id)
      }
      return next
    })
  }, [])

  const onTableKey = useCallback(
    (event: KeyboardEvent<HTMLDivElement>) => {
      const row = rows[activeIndex]
      if (row === undefined) {
        return
      }
      switch (event.key) {
        case 'j':
          setActiveIndex((index) => Math.min(index + 1, rows.length - 1))
          break
        case 'k':
          setActiveIndex((index) => Math.max(index - 1, 0))
          break
        case 'Enter':
          update({ alert: row.id })
          break
        case 'x':
          toggleSelected(row.id)
          break
        case 't':
          single.mutate({ id: row.id, status: 'true_positive' })
          break
        case 'f':
          single.mutate({ id: row.id, status: 'false_positive' })
          break
        case 'b':
          single.mutate({ id: row.id, status: 'benign' })
          break
        default:
          return
      }
      event.preventDefault()
    },
    [activeIndex, rows, single, toggleSelected, update],
  )

  if (caseId === null) {
    return <ErrorPanel message="No case is selected." />
  }

  const activeFilters = hasActiveFilters(state)

  return (
    <section aria-labelledby="alerts-heading" className="flex h-full flex-col gap-3">
      <div className="flex items-center justify-between gap-3">
        <h1 id="alerts-heading" className="text-xl font-semibold text-text">
          Alerts
        </h1>
        <input
          type="search"
          value={searchText}
          onChange={(event) => { setSearchText(event.target.value) }}
          placeholder="Search rules (q)"
          aria-label="Search alerts"
          className="w-64 rounded border border-border bg-surface-2 px-2 py-1 text-sm text-text"
        />
      </div>

      <div className="flex flex-wrap items-end gap-2 rounded-[var(--radius-card)] border border-border bg-surface p-2">
        <label className="text-xs text-muted">
          Level
          <select
            className="mt-1 block rounded border border-border bg-surface-2 px-2 py-1 text-sm text-text"
            value={state.level}
            onChange={(event) => { update({ level: event.target.value as AlertFilterState['level'] }) }}
          >
            <option value="">All</option>
            {LEVEL_OPTIONS.map((level) => (
              <option key={level} value={level}>{level}</option>
            ))}
          </select>
        </label>
        <label className="text-xs text-muted">
          Status
          <select
            className="mt-1 block rounded border border-border bg-surface-2 px-2 py-1 text-sm text-text"
            value={state.status}
            onChange={(event) => { update({ status: event.target.value as AlertFilterState['status'] }) }}
          >
            <option value="">All</option>
            <option value="new">New</option>
            {STATUS_OPTIONS.map((status) => (
              <option key={status} value={status}>{STATUS_LABEL[status]}</option>
            ))}
          </select>
        </label>
        <label className="text-xs text-muted">
          Host
          <input
            className="mt-1 block w-36 rounded border border-border bg-surface-2 px-2 py-1 text-sm text-text"
            value={state.host}
            onChange={(event) => { update({ host: event.target.value }) }}
          />
        </label>
        <label className="text-xs text-muted">
          User
          <input
            className="mt-1 block w-36 rounded border border-border bg-surface-2 px-2 py-1 text-sm text-text"
            value={state.user_name}
            onChange={(event) => { update({ user_name: event.target.value }) }}
          />
        </label>
        <label className="text-xs text-muted">
          Min score
          <input
            type="number"
            min={0}
            max={100}
            className="mt-1 block w-20 rounded border border-border bg-surface-2 px-2 py-1 text-sm text-text"
            value={state.min_score ?? ''}
            onChange={(event) => {
              const value = event.target.value === '' ? null : Number(event.target.value)
              update({ min_score: value !== null && Number.isFinite(value) ? value : null })
            }}
          />
        </label>
        <label className="flex items-center gap-1 text-xs text-muted">
          <input type="checkbox" checked={state.unmapped} onChange={(event) => { update({ unmapped: event.target.checked }) }} />
          Unmapped only
        </label>
        {activeFilters ? (
          <Button variant="ghost" onClick={() => { setParams('') }}>Clear</Button>
        ) : null}
      </div>

      {alerts.isError ? (
        <ErrorPanel title="Cannot load alerts" message="The case may have no detection run yet." onRetry={() => { void alerts.refetch() }} />
      ) : null}

      {alerts.isPending ? <SkeletonRows rows={8} /> : null}

      {alerts.isSuccess && rows.length === 0 ? (
        activeFilters ? (
          <EmptyState
            title="No alerts match these filters"
            detail="Adjust or clear the filters to see more."
            action={<Button onClick={() => { setParams('') }}>Clear filters</Button>}
          />
        ) : (
          <EmptyState
            title="No alerts yet"
            detail="Run detection after ingesting sources to populate this list."
            action={<Link to={caseNavPath(caseId, 'sources')}><Button variant="primary">Go to Sources</Button></Link>}
          />
        )
      ) : null}

      {rows.length > 0 ? (
        <div className="flex min-h-0 flex-1 flex-col rounded-[var(--radius-card)] border border-border bg-surface">
          <div role="row" style={{ gridTemplateColumns: GRID }} className="grid items-center gap-2 border-b border-border px-2 py-2">
            <input
              type="checkbox"
              aria-label="Select all on this page"
              checked={rows.every((row) => selected.has(row.id))}
              onChange={(event) => {
                setSelected((current) => {
                  const next = new Set(current)
                  for (const row of rows) {
                    if (event.target.checked) {
                      next.add(row.id)
                    } else {
                      next.delete(row.id)
                    }
                  }
                  return next
                })
              }}
            />
            <span className="text-xs font-medium uppercase tracking-wide text-muted">Severity</span>
            <SortHeader column="score" label="Score" state={state} onSort={(column) => { update({ sort: toggleSort(state.sort, ALERT_SORTABLE[column] ?? column) }) }} />
            <SortHeader column="rule_title" label="Rule" state={state} onSort={(column) => { update({ sort: toggleSort(state.sort, ALERT_SORTABLE[column] ?? column) }) }} />
            <span className="text-xs font-medium uppercase tracking-wide text-muted">Techniques</span>
            <span className="text-xs font-medium uppercase tracking-wide text-muted">Host</span>
            <span className="text-xs font-medium uppercase tracking-wide text-muted">User</span>
            <SortHeader column="last_seen" label="Last seen" state={state} onSort={(column) => { update({ sort: toggleSort(state.sort, ALERT_SORTABLE[column] ?? column) }) }} />
            <SortHeader column="match_count" label="Count" state={state} onSort={(column) => { update({ sort: toggleSort(state.sort, ALERT_SORTABLE[column] ?? column) }) }} />
            <span className="text-xs font-medium uppercase tracking-wide text-muted">Status</span>
          </div>

          <div
            ref={scrollRef}
            role="table"
            aria-rowcount={total}
            aria-label="Alerts"
            tabIndex={0}
            onKeyDown={onTableKey}
            className="min-h-0 flex-1 overflow-auto outline-none focus-visible:ring-2 focus-visible:ring-accent"
          >
            <div role="rowgroup" style={{ height: rowVirtualizer.getTotalSize(), position: 'relative' }}>
              {rowVirtualizer.getVirtualItems().map((item) => {
                const row = rows[item.index]
                if (row === undefined) {
                  return null
                }
                const isActive = item.index === activeIndex
                const style: CSSProperties = {
                  position: 'absolute',
                  top: 0,
                  left: 0,
                  width: '100%',
                  height: item.size,
                  transform: `translateY(${item.start}px)`,
                  gridTemplateColumns: GRID,
                }
                return (
                  <div
                    role="row"
                    key={row.id}
                    aria-rowindex={item.index + 2}
                    style={style}
                    className={`grid items-center gap-2 border-b border-border px-2 text-sm ${isActive ? 'bg-surface-2' : ''} ${selected.has(row.id) ? 'bg-accent/5' : ''}`}
                    onClick={() => { setActiveIndex(item.index) }}
                  >
                    <input
                      type="checkbox"
                      aria-label={`Select ${row.rule_title}`}
                      checked={selected.has(row.id)}
                      onChange={() => { toggleSelected(row.id) }}
                    />
                    <SeverityBadge level={row.level} />
                    <ScoreCell score={row.score} />
                    <button type="button" className="truncate text-left text-text hover:underline" onClick={() => { update({ alert: row.id }) }}>
                      {row.rule_title}
                    </button>
                    <span className="flex flex-wrap gap-1 overflow-hidden">
                      {row.techniques.slice(0, 2).map((technique) => (
                        <span key={technique.id} className="rounded bg-surface-2 px-1 font-mono text-xs text-muted">{technique.id}</span>
                      ))}
                      {row.techniques.length > 2 ? <span className="text-xs text-muted">+{row.techniques.length - 2}</span> : null}
                    </span>
                    <span className="truncate text-xs text-muted">{row.host ?? '—'}</span>
                    <span className="truncate text-xs text-muted">{row.user_name ?? '—'}</span>
                    <span className="truncate text-xs text-muted">{formatTimestamp(row.last_seen_ms)}</span>
                    <span className="font-mono text-xs text-text">{row.match_count}</span>
                    <AlertStatusBadge status={row.status} />
                  </div>
                )
              })}
            </div>
          </div>
        </div>
      ) : null}

      {total > ALERT_PAGE_SIZE ? (
        <div className="flex items-center justify-between text-xs text-muted">
          <span>
            Page {state.page} of {totalPages} · {formatNumber(total)} alerts
          </span>
          <span className="flex gap-2">
            <Button disabled={state.page <= 1} onClick={() => { update({ page: state.page - 1 }) }}>Previous</Button>
            <Button disabled={state.page >= totalPages} onClick={() => { update({ page: state.page + 1 }) }}>Next</Button>
          </span>
        </div>
      ) : null}

      {selected.size > 0 ? (
        <div className="flex items-center gap-3 rounded-[var(--radius-card)] border border-border bg-surface-2 p-2" role="region" aria-label="Bulk actions">
          <span className="text-sm text-text">{formatNumber(selected.size)} selected</span>
          <select
            aria-label="Bulk status"
            className="rounded border border-border bg-surface px-2 py-1 text-sm text-text"
            defaultValue=""
            onChange={(event) => {
              const value = event.target.value
              if (value !== '') {
                bulk.mutate({ ids: [...selected], status: value as AlertStatus })
                event.target.value = ''
              }
            }}
          >
            <option value="" disabled>Set status…</option>
            {STATUS_OPTIONS.map((status) => (
              <option key={status} value={status}>{STATUS_LABEL[status]}</option>
            ))}
          </select>
          <Button variant="ghost" onClick={() => { setSelected(new Set()) }}>Clear selection</Button>
        </div>
      ) : null}

      {state.alert !== null ? <AlertDrawer alertId={state.alert} onClose={() => { update({ alert: null }) }} /> : null}
    </section>
  )
}
