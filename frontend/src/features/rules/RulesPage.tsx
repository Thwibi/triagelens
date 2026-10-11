import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { DragEvent, ReactElement } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Download, Upload } from 'lucide-react'

import { exportRules, importRules, setRuleEnabled } from '../../api/endpoints'
import { useRulesHealthQuery, useRulesQuery } from '../../api/hooks'
import { invalidateRules } from '../../api/invalidate'
import type { RuleImportResult } from '../../api/types'
import { formatNumber } from '../../lib/format'
import { saveFile } from '../../lib/download'
import { Button } from '../../ui/Button'
import { EmptyState } from '../../ui/EmptyState'
import { ErrorPanel } from '../../ui/ErrorPanel'
import { SkeletonRows } from '../../ui/Skeleton'
import { useToast } from '../../ui/ToastProvider'
import {
  RULE_KINDS,
  RULE_LEVELS,
  HEALTH_BUCKETS,
  HEALTH_LABEL,
  SIGMA_STATUSES,
  healthOf,
  kindLabel,
  logsourceSummary,
  ruleTechniques,
  toAlertLevel,
} from './ruleFormat'
import type { HealthBucket } from './ruleFormat'
import {
  RULE_PAGE_SIZE,
  filtersFromSearch,
  hasActiveFilters,
  searchFromFilters,
  toRuleFilters,
} from './ruleFilters'
import type { RuleFilterState } from './ruleFilters'
import { RuleDrawer } from './RuleDrawer'
import { SeverityBadge } from '../../ui/Badge'

const GRID = '3rem minmax(12rem,2fr) 6rem 5rem 10rem 8rem 8rem'

const HEALTH_CLASS: Readonly<Record<string, string>> = {
  ok: 'text-accent-text',
  unroutable: 'text-sev-medium-text',
  compile_error: 'text-sev-critical-text',
}

function HealthBadge({ rule }: { readonly rule: Parameters<typeof healthOf>[0] }): ReactElement {
  const health = healthOf(rule)
  return (
    <span className={`inline-flex items-center gap-1.5 text-xs font-medium ${HEALTH_CLASS[health.bucket] ?? 'text-muted'}`}>
      <span aria-hidden="true" className="size-1.5 rounded-full bg-current" />
      {health.label}
    </span>
  )
}

function ImportResult({ result }: { readonly result: RuleImportResult }): ReactElement {
  return (
    <section className="space-y-1 rounded border border-border bg-surface-2 p-2 text-xs">
      <p className="text-text">
        Imported {formatNumber(result.imported)} rule(s) from {result.files.length} file(s); synced{' '}
        {formatNumber(result.synced)}, removed {formatNumber(result.stale_removed)} stale.
      </p>
      {result.problems.length > 0 ? (
        <ul className="space-y-0.5">
          {result.problems.map((problem) => (
            <li key={`${problem.where}:${problem.error}`}>
              <span className="font-mono text-muted">{problem.where}</span>: {problem.error}
            </li>
          ))}
        </ul>
      ) : null}
    </section>
  )
}

/** The rule catalogue with filters, import/export and health (spec 07 section 3.10). */
export function RulesPage(): ReactElement {
  const queryClient = useQueryClient()
  const { push } = useToast()
  const [params, setParams] = useSearchParams()
  const state = useMemo(() => filtersFromSearch(params.toString()), [params])
  const filters = useMemo(() => toRuleFilters(state), [state])
  const rules = useRulesQuery(filters)
  const health = useRulesHealthQuery()
  const [tab, setTab] = useState<'catalogue' | 'health'>('catalogue')
  const [searchText, setSearchText] = useState(state.q)
  const [dragging, setDragging] = useState(false)
  const [importResult, setImportResult] = useState<RuleImportResult | null>(null)
  const fileInput = useRef<HTMLInputElement | null>(null)

  const update = useCallback(
    (patch: Partial<RuleFilterState>) => {
      const keys = Object.keys(patch) as (keyof RuleFilterState)[]
      const resetsPage = keys.some((key) => key !== 'page' && key !== 'rule')
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

  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { readonly id: string; readonly enabled: boolean }) => setRuleEnabled(id, enabled),
    onSuccess: () => { invalidateRules(queryClient) },
    onError: (error) => {
      push('error', error instanceof Error ? error.message : 'Could not change rule state')
    },
  })

  const doImport = useMutation({
    mutationFn: (files: readonly File[]) => importRules(files),
    onSuccess: (result) => {
      setImportResult(result)
      invalidateRules(queryClient)
      push('success', `Import queued: ${formatNumber(result.imported)} rule(s)`)
    },
    onError: (error) => {
      push('error', error instanceof Error ? error.message : 'Import failed')
    },
  })

  const doExport = useMutation({
    mutationFn: () => exportRules(),
    onSuccess: (file) => { saveFile(file, 'rules.zip') },
    onError: (error) => {
      push('error', error instanceof Error ? error.message : 'Export failed')
    },
  })

  const onDrop = useCallback(
    (event: DragEvent<HTMLDivElement>) => {
      event.preventDefault()
      setDragging(false)
      const files = Array.from(event.dataTransfer.files)
      if (files.length > 0) {
        doImport.mutate(files)
      }
    },
    [doImport],
  )

  const rows = useMemo(() => rules.data?.items ?? [], [rules.data])
  const total = rules.data?.total ?? rows.length
  const totalPages = Math.max(1, Math.ceil(total / RULE_PAGE_SIZE))
  const activeFilters = hasActiveFilters(state)
  const counts = HEALTH_BUCKETS.map((bucket) => ({ bucket, value: health.data?.[bucket] ?? 0 }))

  return (
    <section aria-labelledby="rules-heading" className="flex h-full flex-col gap-3">
      <div className="flex items-center justify-between gap-3">
        <h1 id="rules-heading" className="text-xl font-semibold text-text">
          Rules
        </h1>
        <div className="flex items-center gap-2">
          <input
            ref={fileInput}
            type="file"
            accept=".yml,.yaml,.zip"
            multiple
            hidden
            onChange={(event) => {
              const files = Array.from(event.target.files ?? [])
              if (files.length > 0) {
                doImport.mutate(files)
              }
              event.target.value = ''
            }}
          />
          <Button onClick={() => { update({ rule: 'new' }) }} variant="primary">
            New rule
          </Button>
          <Button disabled={doImport.isPending} onClick={() => { fileInput.current?.click() }}>
            <Upload aria-hidden="true" size={14} />
            {doImport.isPending ? 'Importing…' : 'Import'}
          </Button>
          <Button disabled={doExport.isPending} onClick={() => { doExport.mutate() }}>
            <Download aria-hidden="true" size={14} />
            {doExport.isPending ? 'Exporting…' : 'Export'}
          </Button>
        </div>
      </div>

      <div role="tablist" aria-label="Rules views" className="flex gap-1">
        {(['catalogue', 'health'] as const).map((value) => (
          <button
            key={value}
            role="tab"
            type="button"
            aria-selected={tab === value}
            onClick={() => { setTab(value) }}
            className={`rounded-[var(--radius-control)] px-3 py-1 text-sm ${tab === value ? 'bg-surface-2 text-text' : 'text-muted hover:text-text'}`}
          >
            {value === 'catalogue' ? 'Catalogue' : 'Health'}
          </button>
        ))}
      </div>

      {tab === 'health' ? (
        <div className="flex flex-wrap gap-2">
          {counts.map(({ bucket, value }) => (
            <button
              key={bucket}
              type="button"
              onClick={() => {
                update({ health: state.health === bucket ? '' : bucket })
                setTab('catalogue')
              }}
              className={`rounded-[var(--radius-card)] border border-border bg-surface px-3 py-2 text-left ${state.health === bucket ? 'ring-2 ring-accent' : ''}`}
            >
              <span className="block text-lg font-semibold text-text">{formatNumber(value)}</span>
              <span className="block text-xs text-muted">{HEALTH_LABEL[bucket]}</span>
            </button>
          ))}
          <div className="rounded-[var(--radius-card)] border border-border bg-surface px-3 py-2">
            <span className="block text-lg font-semibold text-text">{formatNumber(health.data?.total ?? 0)}</span>
            <span className="block text-xs text-muted">Total</span>
          </div>
          <p className="basis-full text-xs text-muted">
            Bucket counts come from <span className="font-mono">/rules/health</span>; never-present fields and timeouts
            are recorded per detection run, not in the catalogue, so they are not shown here.
          </p>
        </div>
      ) : null}

      {importResult !== null ? <ImportResult result={importResult} /> : null}

      <div
        onDragOver={(event) => { event.preventDefault(); setDragging(true) }}
        onDragLeave={() => { setDragging(false) }}
        onDrop={onDrop}
        className={`flex flex-wrap items-end gap-2 rounded-[var(--radius-card)] border bg-surface p-2 ${dragging ? 'border-accent' : 'border-border'}`}
      >
        <label className="text-xs text-muted">
          Kind
          <select
            className="mt-1 block rounded border border-border bg-surface-2 px-2 py-1 text-sm text-text"
            value={state.kind}
            onChange={(event) => { update({ kind: event.target.value }) }}
          >
            <option value="">All</option>
            {RULE_KINDS.map((kind) => (
              <option key={kind} value={kind}>{kindLabel(kind)}</option>
            ))}
          </select>
        </label>
        <label className="text-xs text-muted">
          Level
          <select
            className="mt-1 block rounded border border-border bg-surface-2 px-2 py-1 text-sm text-text"
            value={state.level}
            onChange={(event) => { update({ level: event.target.value }) }}
          >
            <option value="">All</option>
            {RULE_LEVELS.map((level) => (
              <option key={level} value={level}>{level}</option>
            ))}
          </select>
        </label>
        <label className="text-xs text-muted">
          Status
          <select
            className="mt-1 block rounded border border-border bg-surface-2 px-2 py-1 text-sm text-text"
            value={state.status}
            onChange={(event) => { update({ status: event.target.value }) }}
          >
            <option value="">All</option>
            {SIGMA_STATUSES.map((status) => (
              <option key={status} value={status}>{status}</option>
            ))}
          </select>
        </label>
        <label className="text-xs text-muted">
          Enabled
          <select
            className="mt-1 block rounded border border-border bg-surface-2 px-2 py-1 text-sm text-text"
            value={state.enabled === null ? '' : String(state.enabled)}
            onChange={(event) => {
              const value = event.target.value
              update({ enabled: value === '' ? null : value === 'true' })
            }}
          >
            <option value="">All</option>
            <option value="true">Enabled</option>
            <option value="false">Disabled</option>
          </select>
        </label>
        <label className="text-xs text-muted">
          Health
          <select
            className="mt-1 block rounded border border-border bg-surface-2 px-2 py-1 text-sm text-text"
            value={state.health}
            onChange={(event) => { update({ health: event.target.value as HealthBucket | '' }) }}
          >
            <option value="">All</option>
            {HEALTH_BUCKETS.map((bucket) => (
              <option key={bucket} value={bucket}>{HEALTH_LABEL[bucket]}</option>
            ))}
          </select>
        </label>
        <label className="text-xs text-muted">
          Tag
          <input
            className="mt-1 block w-32 rounded border border-border bg-surface-2 px-2 py-1 text-sm text-text"
            value={state.tag}
            onChange={(event) => { update({ tag: event.target.value }) }}
          />
        </label>
        <label className="text-xs text-muted">
          Technique
          <input
            className="mt-1 block w-28 rounded border border-border bg-surface-2 px-2 py-1 text-sm text-text"
            value={state.technique}
            onChange={(event) => { update({ technique: event.target.value }) }}
            placeholder="T1059"
          />
        </label>
        <label className="text-xs text-muted">
          Search
          <input
            type="search"
            className="mt-1 block w-40 rounded border border-border bg-surface-2 px-2 py-1 text-sm text-text"
            value={searchText}
            onChange={(event) => { setSearchText(event.target.value) }}
            placeholder="title or id"
          />
        </label>
        {activeFilters ? (
          <Button variant="ghost" onClick={() => { setParams('') }}>Clear</Button>
        ) : null}
      </div>

      {rules.isError ? (
        <ErrorPanel title="Cannot load rules" message="The catalogue could not be read." onRetry={() => { void rules.refetch() }} />
      ) : null}

      {rules.isPending ? <SkeletonRows rows={8} /> : null}

      {rules.isSuccess && rows.length === 0 ? (
        <EmptyState
          title={activeFilters ? 'No rules match these filters' : 'No rules in the catalogue'}
          detail={activeFilters ? 'Adjust or clear the filters to see more.' : 'Import a rule file or create a custom rule to get started.'}
          action={activeFilters ? <Button onClick={() => { setParams('') }}>Clear filters</Button> : <Button onClick={() => { update({ rule: 'new' }) }} variant="primary">Create rule</Button>}
        />
      ) : null}

      {rows.length > 0 ? (
        <div className="flex min-h-0 flex-1 flex-col rounded-[var(--radius-card)] border border-border bg-surface">
          <div
            role="table"
            aria-label="Rules"
            aria-rowcount={rows.length + 1}
            tabIndex={0}
            className="min-h-0 flex-1 overflow-auto outline-none focus-visible:ring-2 focus-visible:ring-accent"
          >
            <div role="rowgroup" className="sticky top-0 z-10 border-b border-border bg-surface">
              <div role="row" style={{ gridTemplateColumns: GRID }} className="grid items-center gap-2 px-2 py-2 text-xs font-medium uppercase tracking-wide text-muted">
                <span role="columnheader">Enabled</span>
                <span role="columnheader">Title</span>
                <span role="columnheader">Level</span>
                <span role="columnheader">Kind</span>
                <span role="columnheader">Logsource</span>
                <span role="columnheader">Techniques</span>
                <span role="columnheader">Health</span>
              </div>
            </div>
            {rows.map((rule) => {
              const level = toAlertLevel(rule.level)
              return (
                <div
                  key={rule.id}
                  role="row"
                  style={{ gridTemplateColumns: GRID }}
                  className="grid items-center gap-2 border-b border-border px-2 py-2 text-sm"
                >
                  <div role="cell">
                    <input
                      type="checkbox"
                      aria-label={`Enable ${rule.title}`}
                      checked={rule.enabled}
                      onChange={(event) => { toggle.mutate({ id: rule.id, enabled: event.target.checked }) }}
                    />
                  </div>
                  <div role="cell" className="min-w-0">
                    <button
                      type="button"
                      className="w-full truncate text-left text-text hover:underline"
                      onClick={() => { update({ rule: rule.id }) }}
                    >
                      {rule.title}
                    </button>
                  </div>
                  <span role="cell">{level !== null ? <SeverityBadge level={level} /> : <span className="text-xs text-muted">{rule.level}</span>}</span>
                  <span role="cell" className="text-xs text-muted">{kindLabel(rule.kind)}</span>
                  <span role="cell" className="truncate text-xs text-muted">{logsourceSummary(rule)}</span>
                  <span role="cell" className="truncate text-xs text-muted">{ruleTechniques(rule).join(', ') || '—'}</span>
                  <div role="cell">
                    <HealthBadge rule={rule} />
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      ) : null}

      {total > RULE_PAGE_SIZE ? (
        <div className="flex items-center justify-between text-xs text-muted">
          <span>Page {state.page} of {totalPages} · {formatNumber(total)} rules</span>
          <span className="flex gap-2">
            <Button disabled={state.page <= 1} onClick={() => { update({ page: state.page - 1 }) }}>Previous</Button>
            <Button disabled={state.page >= totalPages} onClick={() => { update({ page: state.page + 1 }) }}>Next</Button>
          </span>
        </div>
      ) : null}

      {state.rule !== null ? (
        <RuleDrawer ruleId={state.rule === 'new' ? null : state.rule} onClose={() => { update({ rule: null }) }} />
      ) : null}
    </section>
  )
}
