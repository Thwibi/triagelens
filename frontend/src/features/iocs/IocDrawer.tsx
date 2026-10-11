import { useEffect, useRef, useState } from 'react'
import type { ReactElement } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { ExternalLink, X } from 'lucide-react'

import { patchIoc } from '../../api/endpoints'
import { useIocQuery } from '../../api/hooks'
import { invalidateIocs } from '../../api/invalidate'
import type { AnalystState, IocOccurrence } from '../../api/types'
import { useCaseId } from '../../app/caseRoute'
import { caseNavPath } from '../../app/navigation'
import { defang, formatNumber, formatTimestamp } from '../../lib/format'
import { AnalystStateBadge } from '../../ui/Badge'
import { Button } from '../../ui/Button'
import { CopyButton } from '../../ui/CopyButton'
import { ErrorPanel } from '../../ui/ErrorPanel'
import { SkeletonRows } from '../../ui/Skeleton'
import { useToast } from '../../ui/ToastProvider'
import { ANALYST_STATES } from './iocFilters'

function Section({ title, children }: { readonly title: string; readonly children: ReactElement | ReactElement[] | null }): ReactElement {
  return (
    <section className="space-y-2 border-t border-border pt-3">
      <h3 className="text-xs font-medium uppercase tracking-wide text-muted">{title}</h3>
      {children}
    </section>
  )
}

function OccurrenceRow({ occurrence }: { readonly occurrence: IocOccurrence }): ReactElement {
  return (
    <li className="rounded border border-border bg-surface-2/50 px-2 py-1 text-xs">
      <div className="flex items-center justify-between gap-2">
        <span className="font-mono text-muted">{formatTimestamp(occurrence.ts_ms)}</span>
        <span className="flex items-center gap-1">
          {occurrence.decoded_from !== null ? (
            <span className="rounded bg-sev-medium/20 px-1 text-[10px] text-sev-medium" title={`Decoded from ${occurrence.decoded_from}`}>
              decoded
            </span>
          ) : null}
          <span className="font-mono text-muted">{occurrence.field}</span>
        </span>
      </div>
      <p className="mt-0.5 flex flex-wrap gap-x-3 text-muted">
        <span>{occurrence.host ?? '—'}</span>
        <span>{occurrence.log_type ?? '—'}</span>
        <span>{occurrence.role}</span>
      </p>
      {occurrence.message !== null ? (
        <p className="mt-0.5 line-clamp-2 break-all font-mono text-text">{occurrence.message}</p>
      ) : null}
    </li>
  )
}

/** IOC detail drawer: occurrences and analyst actions (spec 07 section 3.6). */
export function IocDrawer({ iocId, onClose }: { readonly iocId: string; readonly onClose: () => void }): ReactElement {
  const caseId = useCaseId()
  const queryClient = useQueryClient()
  const { push } = useToast()
  const detail = useIocQuery(iocId)
  const panel = useRef<HTMLDivElement | null>(null)
  const [defanged, setDefanged] = useState(false)
  const [tagInput, setTagInput] = useState('')

  useEffect(() => {
    const onKey = (event: KeyboardEvent): void => {
      if (event.key === 'Escape') {
        onClose()
      }
    }
    window.addEventListener('keydown', onKey)
    panel.current?.focus()
    return () => { window.removeEventListener('keydown', onKey) }
  }, [onClose])

  const onChanged = (): void => {
    if (caseId !== null) {
      invalidateIocs(queryClient, caseId, iocId)
    }
  }

  const verdict = useMutation({
    mutationFn: (next: AnalystState) => patchIoc(iocId, { analyst_state: next }),
    onSuccess: () => {
      onChanged()
      push('success', 'Indicator updated')
    },
  })

  const keep = useMutation({
    mutationFn: () => patchIoc(iocId, { analyst_state: 'benign', allowlist: true }),
    onSuccess: () => {
      onChanged()
      push('success', 'Added to the allowlist')
    },
  })

  const addTag = useMutation({
    mutationFn: (tags: readonly string[]) => patchIoc(iocId, { tags }),
    onSuccess: () => {
      setTagInput('')
      onChanged()
      push('success', 'Tag added')
    },
  })

  const shown = detail.data === undefined ? '' : defanged ? defang(detail.data.value) : detail.data.value

  return (
    <aside
      ref={panel}
      role="dialog"
      aria-modal="true"
      aria-label="Indicator detail"
      tabIndex={-1}
      className="fixed inset-y-0 right-0 z-30 flex w-[40rem] max-w-full flex-col border-l border-border bg-surface shadow-xl"
    >
      <div className="flex items-center justify-between border-b border-border px-4 py-2">
        <h2 className="truncate font-mono text-sm font-medium text-text">{detail.data?.type ?? 'Indicator'}</h2>
        <Button variant="ghost" aria-label="Close indicator" onClick={onClose}>
          <X aria-hidden="true" size={16} />
        </Button>
      </div>
      <div className="flex-1 space-y-3 overflow-auto p-4">
        {detail.isPending ? <SkeletonRows rows={6} /> : null}
        {detail.isError ? (
          <ErrorPanel title="Cannot load indicator" message="The indicator may have been removed." onRetry={() => { void detail.refetch() }} />
        ) : null}
        {detail.data !== undefined ? (
          <>
            <div className="space-y-1">
              <div className="flex items-start justify-between gap-2">
                <span className="break-all font-mono text-sm text-text">{shown}</span>
                <span className="flex shrink-0 items-center gap-1">
                  <CopyButton value={defang(detail.data.value)} label="Copy defanged indicator" />
                  <CopyButton value={detail.data.value} label="Copy indicator" />
                </span>
              </div>
              <label className="flex items-center gap-2 text-xs text-muted">
                <input type="checkbox" checked={defanged} onChange={(event) => { setDefanged(event.target.checked) }} />
                Defang value
              </label>
            </div>

            <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
              <div className="flex justify-between gap-2">
                <dt className="text-muted">Confidence</dt>
                <dd className="font-mono text-text">{detail.data.confidence}</dd>
              </div>
              <div className="flex justify-between gap-2">
                <dt className="text-muted">Occurrences</dt>
                <dd className="font-mono text-text">{formatNumber(detail.data.occurrences)}</dd>
              </div>
              <div className="flex justify-between gap-2">
                <dt className="text-muted">First seen</dt>
                <dd className="font-mono text-text">{formatTimestamp(detail.data.first_seen_ms)}</dd>
              </div>
              <div className="flex justify-between gap-2">
                <dt className="text-muted">Last seen</dt>
                <dd className="font-mono text-text">{formatTimestamp(detail.data.last_seen_ms)}</dd>
              </div>
            </dl>

            <div className="flex flex-wrap items-center gap-2">
              <AnalystStateBadge state={detail.data.analyst_state} />
              {detail.data.is_private ? <span className="rounded bg-surface-2 px-1.5 py-0.5 text-xs text-muted">internal</span> : null}
              {detail.data.is_allowlisted ? <span className="rounded bg-surface-2 px-1.5 py-0.5 text-xs text-muted">allowlisted</span> : null}
            </div>

            <Section title="Actions">
              <div className="space-y-2">
                <div className="flex flex-wrap gap-2">
                  {ANALYST_STATES.map((state) => (
                    <Button
                      key={state}
                      variant="ghost"
                      disabled={verdict.isPending || detail.data.analyst_state === state}
                      onClick={() => { verdict.mutate(state) }}
                    >
                      Mark {state}
                    </Button>
                  ))}
                </div>
                <Button
                  variant="ghost"
                  disabled={keep.isPending || detail.data.is_allowlisted}
                  onClick={() => { keep.mutate() }}
                >
                  Add to allowlist
                </Button>
                {caseId !== null ? (
                  <Link
                    to={`${caseNavPath(caseId, 'events')}?ioc_id=${encodeURIComponent(iocId)}`}
                    className="inline-flex items-center gap-1 text-xs text-accent hover:underline"
                  >
                    Pivot to Events filtered by this indicator
                    <ExternalLink aria-hidden="true" size={12} />
                  </Link>
                ) : null}
              </div>
            </Section>

            <Section title="Tags">
              <div className="space-y-2">
                {detail.data.tags.length === 0 ? (
                  <p className="text-sm text-muted">No tags.</p>
                ) : (
                  <ul className="flex flex-wrap gap-1">
                    {detail.data.tags.map((tag) => (
                      <li key={tag} className="rounded bg-surface-2 px-1.5 py-0.5 text-xs text-muted">{tag}</li>
                    ))}
                  </ul>
                )}
                <form
                  className="flex gap-2"
                  onSubmit={(event) => {
                    event.preventDefault()
                    const value = tagInput.trim()
                    if (value !== '' && !detail.data.tags.includes(value)) {
                      addTag.mutate([...detail.data.tags, value])
                    }
                  }}
                >
                  <input
                    value={tagInput}
                    onChange={(event) => { setTagInput(event.target.value) }}
                    placeholder="Add tag"
                    aria-label="New tag"
                    className="w-40 rounded border border-border bg-surface-2 px-2 py-1 text-sm text-text"
                  />
                  <Button type="submit" disabled={addTag.isPending || tagInput.trim() === ''}>Add</Button>
                </form>
              </div>
            </Section>

            <Section title={`Occurrences (${formatNumber(detail.data.occurrences)})`}>
              {detail.data.occurrences_preview.length === 0 ? (
                <p className="text-sm text-muted">No stored occurrences.</p>
              ) : (
                <ul className="space-y-1">
                  {detail.data.occurrences_preview.map((occurrence) => (
                    <OccurrenceRow key={`${occurrence.event_id}-${occurrence.field}-${occurrence.role}`} occurrence={occurrence} />
                  ))}
                </ul>
              )}
            </Section>
          </>
        ) : null}
      </div>
    </aside>
  )
}
