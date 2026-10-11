import { useCallback, useEffect, useMemo, useState } from 'react'
import type { ReactElement } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useMutation } from '@tanstack/react-query'
import { ArrowDown, ArrowUp, Download } from 'lucide-react'

import { exportIocs } from '../../api/endpoints'
import type { IocExportFormat } from '../../api/endpoints'
import { useIocsQuery } from '../../api/hooks'
import { useCaseId } from '../../app/caseRoute'
import { saveFile } from '../../lib/download'
import { defang, formatNumber, formatTimestamp } from '../../lib/format'
import { AnalystStateBadge } from '../../ui/Badge'
import { Button } from '../../ui/Button'
import { CopyButton } from '../../ui/CopyButton'
import { EmptyState } from '../../ui/EmptyState'
import { ErrorPanel } from '../../ui/ErrorPanel'
import { SkeletonRows } from '../../ui/Skeleton'
import { useToast } from '../../ui/ToastProvider'
import { IocDrawer } from './IocDrawer'
import {
  IOC_PAGE_SIZE,
  IOC_SORTS,
  IOC_TABS,
  hasActiveFilters,
  iocPage,
  filtersFromSearch,
  searchFromFilters,
  tabById,
  toIocFilters,
} from './iocFilters'
import type { IocFilterState } from './iocFilters'

const GRID = '2rem minmax(16rem,2fr) 7rem 8rem 5rem 11rem 11rem 8rem'
const STATES = ['none', 'malicious', 'suspicious', 'benign'] as const
const FORMATS: readonly IocExportFormat[] = ['csv', 'txt', 'stix', 'json']
const SORT_LABEL: Readonly<Record<string, string>> = {
  last_seen: 'Last seen',
  first_seen: 'First seen',
  confidence: 'Confidence',
  occurrences: 'Occurrences',
  value: 'Value',
}

function ConfidenceBar({ value }: { readonly value: number }): ReactElement {
  return (
    <span className="flex items-center gap-1.5">
      <span aria-hidden="true" className="h-1.5 w-10 overflow-hidden rounded bg-surface-2">
        <span className="block h-full bg-accent" style={{ width: `${Math.min(100, Math.max(0, value))}%` }} />
      </span>
      <span className="font-mono text-xs text-text">{value}</span>
    </span>
  )
}

function SortHeader({
  column,
  label,
  state,
  onSort,
}: {
  readonly column: string
  readonly label: string
  readonly state: IocFilterState
  readonly onSort: (column: string) => void
}): ReactElement {
  const active = state.sort === column
  return (
    <button
      type="button"
      className="flex items-center gap-1 text-left text-xs font-medium uppercase tracking-wide text-muted hover:text-text"
      onClick={() => { onSort(column) }}
    >
      {label}
      {active ? (state.order === 'desc' ? <ArrowDown aria-hidden="true" size={12} /> : <ArrowUp aria-hidden="true" size={12} />) : null}
    </button>
  )
}

/** Indicators list with tabs, filters and bulk export (spec 07 section 3.6). */
export function IocsPage(): ReactElement {
  const caseId = useCaseId()
  const { push } = useToast()
  const [params, setParams] = useSearchParams()
  const state = useMemo(() => filtersFromSearch(params.toString()), [params])
  const filters = useMemo(() => toIocFilters(state), [state])
  const iocs = useIocsQuery(caseId, filters)

  const [selected, setSelected] = useState<ReadonlySet<string>>(() => new Set())
  const [searchText, setSearchText] = useState(state.q)
  const [format, setFormat] = useState<IocExportFormat>('csv')

  const update = useCallback(
    (patch: Partial<IocFilterState>) => {
      const keys = Object.keys(patch) as (keyof IocFilterState)[]
      const resetsPage = keys.some((key) => key !== 'page' && key !== 'ioc')
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

  const page = useMemo(
    () => iocPage(iocs.data?.items ?? [], iocs.data?.total ?? 0, state),
    [iocs.data, state],
  )
  const totalPages = Math.max(1, Math.ceil(page.total / IOC_PAGE_SIZE))

  const exportMutation = useMutation({
    mutationFn: () => {
      if (caseId === null) {
        throw new Error('No case is selected.')
      }
      const active = toIocFilters(state)
      return exportIocs(caseId, {
        format,
        ids: selected.size > 0 ? [...selected] : undefined,
        filters: {
          type: active.type,
          min_confidence: active.min_confidence,
          q: active.q,
          state: active.state,
          include_private: active.include_private,
          include_allowlisted: active.include_allowlisted,
          sort: active.sort,
          order: active.order,
        },
        defang: state.defang,
      })
    },
    onSuccess: (file) => {
      if (caseId !== null) {
        saveFile(file, `iocs-${caseId}.${format}`)
      }
      push('success', 'Export ready')
    },
    onError: () => { push('error', 'Could not export indicators') },
  })

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

  const onSort = useCallback(
    (column: string) => {
      if (state.sort === column) {
        update({ order: state.order === 'desc' ? 'asc' : 'desc' })
      } else {
        update({ sort: column, order: 'desc' })
      }
    },
    [state.sort, state.order, update],
  )

  if (caseId === null) {
    return <ErrorPanel message="No case is selected." />
  }

  const tab = tabById(state.tab)
  const rows = page.items
  const activeFilters = hasActiveFilters(state) || state.tab !== 'all'

  return (
    <section aria-labelledby="iocs-heading" className="flex h-full flex-col gap-3">
      <div className="flex items-center justify-between gap-3">
        <h1 id="iocs-heading" className="text-xl font-semibold text-text">Indicators</h1>
        <input
          type="search"
          value={searchText}
          onChange={(event) => { setSearchText(event.target.value) }}
          placeholder="Search values (q)"
          aria-label="Search indicators"
          className="w-64 rounded border border-border bg-surface-2 px-2 py-1 text-sm text-text"
        />
      </div>

      <div role="tablist" aria-label="Indicator type" className="flex flex-wrap gap-1">
        {IOC_TABS.map((entry) => (
          <button
            key={entry.id}
            type="button"
            role="tab"
            aria-selected={state.tab === entry.id}
            className={`rounded-[var(--radius-control)] px-2 py-1 text-sm ${state.tab === entry.id ? 'bg-accent text-black' : 'bg-surface-2 text-muted hover:text-text'}`}
            onClick={() => { update({ tab: entry.id }) }}
          >
            {entry.label}
          </button>
        ))}
      </div>

      <div className="flex flex-wrap items-end gap-3 rounded-[var(--radius-card)] border border-border bg-surface p-2">
        <label className="text-xs text-muted">
          State
          <select
            className="mt-1 block rounded border border-border bg-surface-2 px-2 py-1 text-sm text-text"
            value={state.state}
            onChange={(event) => { update({ state: event.target.value as IocFilterState['state'] }) }}
          >
            <option value="">All</option>
            {STATES.map((value) => (
              <option key={value} value={value}>{value}</option>
            ))}
          </select>
        </label>
        <label className="text-xs text-muted">
          Sort
          <select
            className="mt-1 block rounded border border-border bg-surface-2 px-2 py-1 text-sm text-text"
            value={state.sort}
            onChange={(event) => { update({ sort: event.target.value }) }}
          >
            {IOC_SORTS.map((value) => (
              <option key={value} value={value}>{SORT_LABEL[value] ?? value}</option>
            ))}
          </select>
        </label>
        <label className="text-xs text-muted">
          Min confidence <span className="font-mono text-text">{state.min_confidence ?? 0}</span>
          <input
            type="range"
            min={0}
            max={100}
            value={state.min_confidence ?? 0}
            onChange={(event) => {
              const value = Number(event.target.value)
              update({ min_confidence: value === 0 ? null : value })
            }}
            className="mt-2 block w-40"
          />
        </label>
        <label className="flex items-center gap-1 text-xs text-muted">
          <input type="checkbox" checked={state.include_private} onChange={(event) => { update({ include_private: event.target.checked }) }} />
          Show internal
        </label>
        <label className="flex items-center gap-1 text-xs text-muted">
          <input type="checkbox" checked={state.include_allowlisted} onChange={(event) => { update({ include_allowlisted: event.target.checked }) }} />
          Show allowlisted
        </label>
        <label className="flex items-center gap-1 text-xs text-muted">
          <input type="checkbox" checked={state.defang} onChange={(event) => { update({ defang: event.target.checked }) }} />
          Defang values
        </label>
        {activeFilters ? (
          <Button variant="ghost" onClick={() => { setParams('') }}>Clear</Button>
        ) : null}
      </div>

      {iocs.isError ? (
        <ErrorPanel title="Cannot load indicators" message="The case may have no sources yet." onRetry={() => { void iocs.refetch() }} />
      ) : null}

      {iocs.isPending ? <SkeletonRows rows={8} /> : null}

      {iocs.isSuccess && rows.length === 0 ? (
        activeFilters ? (
          <EmptyState
            title="No indicators match these filters"
            detail="Adjust or clear the filters to see more."
            action={<Button onClick={() => { setParams('') }}>Clear filters</Button>}
          />
        ) : (
          <EmptyState title="No indicators yet" detail="Ingest sources to extract indicators from their events." />
        )
      ) : null}

      {rows.length > 0 ? (
        <>
          <div className="flex items-center justify-between gap-3 rounded-[var(--radius-card)] border border-border bg-surface px-2 py-2">
            <span className="text-xs text-muted">
              {formatNumber(page.total)} indicators · {tab.label}
            </span>
            <span className="flex items-center gap-2">
              <label className="text-xs text-muted">
                Export
                <select
                  className="ml-1 rounded border border-border bg-surface-2 px-2 py-1 text-sm text-text"
                  value={format}
                  onChange={(event) => { setFormat(event.target.value as IocExportFormat) }}
                >
                  {FORMATS.map((value) => <option key={value} value={value}>{value.toUpperCase()}</option>)}
                </select>
              </label>
              <Button disabled={exportMutation.isPending} onClick={() => { exportMutation.mutate() }}>
                <Download aria-hidden="true" size={14} />
                {selected.size > 0 ? `Export ${formatNumber(selected.size)}` : 'Export'}
              </Button>
            </span>
          </div>

          <div className="flex min-h-0 flex-1 flex-col rounded-[var(--radius-card)] border border-border bg-surface">
            <div
              role="table"
              aria-label="Indicators"
              aria-rowcount={rows.length + 1}
              tabIndex={0}
              className="min-h-0 flex-1 overflow-auto outline-none focus-visible:ring-2 focus-visible:ring-accent"
            >
              <div role="rowgroup" className="sticky top-0 z-10 border-b border-border bg-surface">
                <div role="row" style={{ gridTemplateColumns: GRID }} className="grid items-center gap-2 px-2 py-2">
                  <div role="columnheader">
                    <input
                      type="checkbox"
                      aria-label="Select all on this page"
                      checked={rows.length > 0 && rows.every((row) => selected.has(row.id))}
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
                  </div>
                  <span role="columnheader" className="text-xs font-medium uppercase tracking-wide text-muted">Value</span>
                  <span role="columnheader" className="text-xs font-medium uppercase tracking-wide text-muted">Type</span>
                  <div role="columnheader">
                    <SortHeader column="confidence" label="Confidence" state={state} onSort={onSort} />
                  </div>
                  <div role="columnheader">
                    <SortHeader column="occurrences" label="Count" state={state} onSort={onSort} />
                  </div>
                  <div role="columnheader">
                    <SortHeader column="first_seen" label="First seen" state={state} onSort={onSort} />
                  </div>
                  <div role="columnheader">
                    <SortHeader column="last_seen" label="Last seen" state={state} onSort={onSort} />
                  </div>
                  <span role="columnheader" className="text-xs font-medium uppercase tracking-wide text-muted">State</span>
                </div>
              </div>
              {rows.map((ioc) => {
                const shown = state.defang ? defang(ioc.value) : ioc.value
                return (
                  <div
                    role="row"
                    key={ioc.id}
                    style={{ gridTemplateColumns: GRID }}
                    className={`grid items-center gap-2 border-b border-border px-2 py-2 text-sm ${selected.has(ioc.id) ? 'bg-accent/5' : ''}`}
                  >
                    <div role="cell">
                      <input
                        type="checkbox"
                        aria-label={`Select ${ioc.value}`}
                        checked={selected.has(ioc.id)}
                        onChange={() => { toggleSelected(ioc.id) }}
                      />
                    </div>
                    <span role="cell" className="flex min-w-0 items-center gap-1">
                      <button
                        type="button"
                        className="min-w-0 truncate text-left font-mono text-text hover:underline"
                        title={ioc.value}
                        onClick={() => { update({ ioc: ioc.id }) }}
                      >
                        {shown}
                      </button>
                      <CopyButton value={state.defang ? defang(ioc.value) : ioc.value} label={`Copy ${ioc.type}`} />
                    </span>
                    <span role="cell" className="font-mono text-xs text-muted">{ioc.type}</span>
                    <div role="cell">
                      <ConfidenceBar value={ioc.confidence} />
                    </div>
                    <span role="cell" className="font-mono text-xs text-text">{formatNumber(ioc.occurrences)}</span>
                    <span role="cell" className="truncate text-xs text-muted">{formatTimestamp(ioc.first_seen_ms)}</span>
                    <span role="cell" className="truncate text-xs text-muted">{formatTimestamp(ioc.last_seen_ms)}</span>
                    <div role="cell">
                      <AnalystStateBadge state={ioc.analyst_state} />
                    </div>
                  </div>
                )
              })}
            </div>
          </div>

          {page.total > IOC_PAGE_SIZE ? (
            <div className="flex items-center justify-between text-xs text-muted">
              <span>Page {state.page} of {totalPages} · {formatNumber(page.total)} indicators</span>
              <span className="flex gap-2">
                <Button disabled={state.page <= 1} onClick={() => { update({ page: state.page - 1 }) }}>Previous</Button>
                <Button disabled={state.page >= totalPages} onClick={() => { update({ page: state.page + 1 }) }}>Next</Button>
              </span>
            </div>
          ) : null}
        </>
      ) : null}

      {state.ioc !== null ? <IocDrawer iocId={state.ioc} onClose={() => { update({ ioc: null }) }} /> : null}
    </section>
  )
}
