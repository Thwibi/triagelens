import { useEffect, useRef, useState } from 'react'
import type { ReactElement } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { ChevronDown, ExternalLink, X } from 'lucide-react'

import { listAlertEvidence, patchAlert } from '../../api/endpoints'
import { useAlertQuery } from '../../api/hooks'
import { invalidateAlertDetail, invalidateAlerts } from '../../api/invalidate'
import type { AlertDetail, AlertEventBrief, AlertIoc, AlertStatus } from '../../api/types'
import { caseNavPath } from '../../app/navigation'
import { useCaseId } from '../../app/caseRoute'
import { defang, formatNumber, formatTimestamp } from '../../lib/format'
import { AlertStatusBadge, SeverityBadge } from '../../ui/Badge'
import { Button } from '../../ui/Button'
import { CodeBlock } from '../../ui/CodeBlock'
import { CopyButton } from '../../ui/CopyButton'
import { ErrorPanel } from '../../ui/ErrorPanel'
import { SkeletonRows } from '../../ui/Skeleton'
import { useToast } from '../../ui/ToastProvider'

/** Statuses an analyst may set (spec 04 section 6: `new` is not one). */
const ANALYST_STATUSES: readonly AlertStatus[] = ['triaged', 'true_positive', 'false_positive', 'benign']

const STATUS_LABEL: Readonly<Record<AlertStatus, string>> = {
  new: 'New',
  triaged: 'Triaged',
  true_positive: 'True positive',
  false_positive: 'False positive',
  benign: 'Benign',
}

/** The public ATT&CK page for a technique, with `.` as the URL separator. */
function attackUrl(techniqueId: string): string {
  return `https://attack.mitre.org/techniques/${techniqueId.replace('.', '/')}/`
}

function Section({ title, children }: { readonly title: string; readonly children: ReactElement | ReactElement[] | null }): ReactElement {
  return (
    <section className="space-y-2 border-t border-border pt-3">
      <h3 className="text-xs font-medium uppercase tracking-wide text-muted">{title}</h3>
      {children}
    </section>
  )
}

function ScorePopover({ detail }: { readonly detail: AlertDetail }): ReactElement {
  return (
    <details className="relative">
      <summary className="inline-flex cursor-pointer items-center gap-1 text-xs text-muted">
        Why this score
        <ChevronDown aria-hidden="true" size={12} />
      </summary>
      <ul className="mt-1 space-y-0.5 rounded border border-border bg-surface-2 p-2 text-xs">
        {detail.score_breakdown.length === 0 ? (
          <li className="text-muted">No scoring components recorded.</li>
        ) : (
          detail.score_breakdown.map((row) => (
            <li key={row.label} className="flex items-center justify-between gap-4">
              <span className="text-text">{row.label}</span>
              <span className="font-mono text-muted">{row.delta >= 0 ? `+${row.delta}` : String(row.delta)}</span>
            </li>
          ))
        )}
      </ul>
    </details>
  )
}

function AttackBlock({ detail }: { readonly detail: AlertDetail }): ReactElement {
  const caseId = useCaseId()
  const [offline] = useState(() => typeof navigator !== 'undefined' && !navigator.onLine)
  const mitreHref = caseId === null ? '#' : caseNavPath(caseId, 'mitre')
  return (
    <Section title="ATT&CK">
      <div className="space-y-2">
        {detail.techniques.length === 0 ? (
          <p className="text-sm text-muted">No technique mapping. The rule declared no ATT&CK tags.</p>
        ) : (
          <ul className="flex flex-wrap gap-1">
            {detail.techniques.map((technique) => (
              <li key={technique.id} className="inline-flex items-center gap-1 rounded bg-surface-2 px-1.5 py-0.5 text-xs">
                <a className="font-mono text-accent-text hover:underline" href={`${mitreHref}${mitreHref.includes('?') ? '&' : '?'}technique=${encodeURIComponent(technique.id)}`}>
                  {technique.id} {technique.name}
                </a>
                {technique.source === 'fallback' ? <span className="rounded bg-sev-medium/20 px-1 text-[10px] text-sev-medium-text">inferred</span> : null}
                <a className="text-muted hover:text-text" href={attackUrl(technique.id)} target="_blank" rel="noopener noreferrer" aria-label={`Open ${technique.id} on attack.mitre.org`}>
                  <ExternalLink aria-hidden="true" size={12} />
                </a>
              </li>
            ))}
          </ul>
        )}
        {detail.tactics.length > 0 ? (
          <ul className="flex flex-wrap gap-1">
            {detail.tactics.map((tactic) => (
              <li key={tactic.shortname} className="rounded border border-border px-1.5 py-0.5 text-xs text-muted">
                {tactic.name}
              </li>
            ))}
          </ul>
        ) : null}
        {detail.groups_software.length > 0 ? (
          <ul className="flex flex-wrap gap-1">
            {detail.groups_software.map((group) => (
              <li key={group.id} className="rounded bg-surface-2 px-1.5 py-0.5 text-xs text-muted">
                {group.kind}: {group.name}
              </li>
            ))}
          </ul>
        ) : null}
        {detail.unresolved_tags.length > 0 ? (
          <p className="text-xs text-sev-medium-text">Unresolved tags: {detail.unresolved_tags.join(', ')}</p>
        ) : null}
        {offline ? <p className="text-xs text-muted">Offline: external ATT&CK links are shown but not reachable.</p> : null}
      </div>
    </Section>
  )
}

function RuleBlock({ detail }: { readonly detail: AlertDetail }): ReactElement {
  const [showYaml, setShowYaml] = useState(false)
  return (
    <Section title="Rule">
      <div className="space-y-2 text-sm">
        <p className="text-text">{detail.rule?.description ?? detail.rule_title}</p>
        <p className="flex flex-wrap gap-3 text-xs text-muted">
          <span>Level: {detail.level}</span>
          <span>Kind: {detail.rule_kind}</span>
          <span>Status: {detail.status}</span>
        </p>
        {detail.false_positives.length > 0 ? (
          <div>
            <p className="text-xs text-muted">Known false positives</p>
            <ul className="list-disc pl-5 text-xs text-text">
              {detail.false_positives.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </div>
        ) : null}
        {detail.references.length > 0 ? (
          <div>
            <p className="text-xs text-muted">References</p>
            <ul className="space-y-0.5 text-xs">
              {detail.references.map((reference) => (
                <li key={reference} className="break-all font-mono text-muted">{reference}</li>
              ))}
            </ul>
          </div>
        ) : null}
        {detail.rule !== undefined ? (
          <div className="space-y-1">
            <Button variant="ghost" onClick={() => { setShowYaml((value) => !value) }}>
              {showYaml ? 'Hide rule YAML' : 'View rule YAML'}
            </Button>
            {showYaml ? <CodeBlock value={detail.rule.yaml} language="yaml" wrap ariaLabel="Rule YAML" /> : null}
          </div>
        ) : null}
      </div>
    </Section>
  )
}

function EvidenceRow({ event }: { readonly event: AlertEventBrief }): ReactElement {
  const [open, setOpen] = useState(false)
  return (
    <li className="rounded border border-border bg-surface-2/50">
      <button
        type="button"
        className="flex w-full items-center justify-between gap-2 px-2 py-1 text-left text-xs"
        aria-expanded={open}
        onClick={() => { setOpen((value) => !value) }}
      >
        <span className="font-mono text-muted">{formatTimestamp(event.ts_ms)}</span>
        <span className="truncate text-text">{event.message ?? event.event_action ?? event.log_type ?? 'event'}</span>
      </button>
      {open ? (
        <dl className="grid grid-cols-2 gap-x-4 gap-y-0.5 border-t border-border px-2 py-1 text-xs">
          {([['Host', event.host], ['User', event.user_name], ['Source IP', event.src_ip], ['Destination IP', event.dst_ip], ['Action', event.event_action], ['Event ID', event.event_id]] as const).map(([label, value]) => (
            <div key={label} className="flex justify-between gap-2">
              <dt className="text-muted">{label}</dt>
              <dd className="truncate font-mono text-text">{value ?? '—'}</dd>
            </div>
          ))}
        </dl>
      ) : null}
    </li>
  )
}

function EvidenceBlock({ detail }: { readonly detail: AlertDetail }): ReactElement {
  const all = useMutation({
    mutationFn: () => listAlertEvidence(detail.id, 1, 1000),
  })
  const loaded = all.data?.items ?? []
  const seen = new Set(detail.events.map((event) => event.id))
  const extra = loaded.filter((event) => !seen.has(event.id))
  return (
    <Section title={`Evidence (${formatNumber(detail.match_count)})`}>
      <div className="space-y-2">
        {detail.events.length === 0 ? (
          <p className="text-sm text-muted">No stored evidence sample.</p>
        ) : (
          <ul className="space-y-1">
            {detail.events.map((event) => (
              <EvidenceRow key={event.id} event={event} />
            ))}
          </ul>
        )}
        {all.isPending ? <SkeletonRows rows={2} /> : null}
        {all.isError ? <p className="text-xs text-sev-critical-text">Could not load all matches.</p> : null}
        {extra.length > 0 ? (
          <ul className="space-y-1">
            {extra.map((event) => (
              <EvidenceRow key={event.id} event={event} />
            ))}
          </ul>
        ) : null}
        <Button
          variant="ghost"
          disabled={all.isPending}
          onClick={() => { all.mutate() }}
        >
          Load all matches
        </Button>
      </div>
    </Section>
  )
}

function IocsBlock({ iocs }: { readonly iocs: readonly AlertIoc[] }): ReactElement {
  const [defanged, setDefanged] = useState(false)
  const grouped = new Map<string, AlertIoc[]>()
  for (const ioc of iocs) {
    const list = grouped.get(ioc.type) ?? []
    list.push(ioc)
    grouped.set(ioc.type, list)
  }
  return (
    <Section title="Indicators">
      <div className="space-y-2">
        <label className="flex items-center gap-2 text-xs text-muted">
          <input type="checkbox" checked={defanged} onChange={(event) => { setDefanged(event.target.checked) }} />
          Defang values
        </label>
        {iocs.length === 0 ? (
          <p className="text-sm text-muted">No indicators linked to this alert.</p>
        ) : (
          <div className="space-y-2">
            {[...grouped.entries()].map(([type, list]) => (
              <div key={type}>
                <p className="text-xs text-muted">{type}</p>
                <ul className="space-y-0.5">
                  {list.map((ioc) => {
                    const shown = defanged ? defang(ioc.value) : ioc.value
                    return (
                      <li key={ioc.id} className="flex items-center justify-between gap-2">
                        <span className="break-all font-mono text-xs text-text">{shown}</span>
                        <CopyButton value={shown} label={`Copy ${type} indicator`} />
                      </li>
                    )
                  })}
                </ul>
              </div>
            ))}
          </div>
        )}
      </div>
    </Section>
  )
}

function AnalystPanel({ detail }: { readonly detail: AlertDetail }): ReactElement {
  const caseId = useCaseId()
  const queryClient = useQueryClient()
  const { push } = useToast()
  const original = detail.analyst_notes ?? ''
  const [notes, setNotes] = useState(original)
  const [saved, setSaved] = useState(false)

  const status = useMutation({
    mutationFn: (next: AlertStatus) => patchAlert(detail.id, { status: next }),
    onSuccess: () => {
      if (caseId !== null) {
        invalidateAlerts(queryClient, caseId)
      }
      invalidateAlertDetail(queryClient, detail.id)
      push('success', 'Verdict updated')
    },
  })

  const saveNotes = useMutation({
    mutationFn: (value: string) => patchAlert(detail.id, { analyst_notes: value }),
    onSuccess: () => {
      invalidateAlertDetail(queryClient, detail.id)
      setSaved(true)
    },
  })

  const saveRef = useRef(saveNotes)
  saveRef.current = saveNotes

  useEffect(() => {
    if (notes === original) {
      return undefined
    }
    const handle = setTimeout(() => {
      saveRef.current.mutate(notes)
    }, 1_000)
    return () => { clearTimeout(handle) }
  }, [notes, original])

  useEffect(() => {
    if (!saved) {
      return undefined
    }
    const handle = setTimeout(() => { setSaved(false) }, 5_000)
    return () => { clearTimeout(handle) }
  }, [saved])

  return (
    <Section title="Analyst">
      <div className="space-y-3">
        <label className="block text-xs text-muted">
          Verdict
          <select
            className="mt-1 block w-full rounded border border-border bg-surface-2 px-2 py-1 text-sm text-text"
            value={detail.status}
            disabled={status.isPending}
            onChange={(event) => { status.mutate(event.target.value as AlertStatus) }}
          >
            {detail.status === 'new' ? <option value="new">New</option> : null}
            {ANALYST_STATUSES.map((value) => (
              <option key={value} value={value}>
                {STATUS_LABEL[value]}
              </option>
            ))}
          </select>
        </label>
        <label className="block text-xs text-muted">
          Notes
          <textarea
            className="mt-1 block h-24 w-full rounded border border-border bg-surface-2 px-2 py-1 text-sm text-text"
            value={notes}
            onChange={(event) => { setNotes(event.target.value) }}
          />
        </label>
        <p aria-live="polite" className="text-xs text-muted">
          {saveNotes.isPending ? 'Saving…' : saved ? 'Saved' : ''}
        </p>
      </div>
    </Section>
  )
}

/** The seven-block alert drawer (spec 07 section 3.4). */
export function AlertDrawer({ alertId, onClose }: { readonly alertId: string; readonly onClose: () => void }): ReactElement | null {
  const alert = useAlertQuery(alertId)
  const panel = useRef<HTMLDivElement | null>(null)

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

  return (
    <aside
      ref={panel}
      role="dialog"
      aria-modal="true"
      aria-label="Alert detail"
      tabIndex={-1}
      className="fixed inset-y-0 right-0 z-30 flex w-[40rem] max-w-full flex-col border-l border-border bg-surface shadow-xl"
    >
      <div className="flex items-center justify-between border-b border-border px-4 py-2">
        <h2 className="truncate text-sm font-medium text-text">{alert.data?.rule_title ?? 'Alert'}</h2>
        <Button variant="ghost" aria-label="Close alert" onClick={onClose}>
          <X aria-hidden="true" size={16} />
        </Button>
      </div>
      <div className="flex-1 space-y-3 overflow-auto p-4">
        {alert.isPending ? <SkeletonRows rows={6} /> : null}
        {alert.isError ? (
          <ErrorPanel title="Cannot load alert" message="The alert may have been removed." onRetry={() => { void alert.refetch() }} />
        ) : null}
        {alert.data !== undefined ? (
          <>
            <div className="flex items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <SeverityBadge level={alert.data.level} />
                <span className="font-mono text-lg text-text">{alert.data.score}</span>
              </div>
              <AlertStatusBadge status={alert.data.status} />
            </div>
            <ScorePopover detail={alert.data} />
            {alert.data.host !== null || alert.data.user_name !== null ? (
              <p className="text-xs text-muted">
                {alert.data.host !== null ? `Host: ${alert.data.host}` : ''}
                {alert.data.host !== null && alert.data.user_name !== null ? ' · ' : ''}
                {alert.data.user_name !== null ? `User: ${alert.data.user_name}` : ''}
              </p>
            ) : null}
            <AttackBlock detail={alert.data} />
            <RuleBlock detail={alert.data} />
            <EvidenceBlock detail={alert.data} />
            <IocsBlock iocs={alert.data.iocs} />
            <Section title="Entities">
              <ul className="space-y-0.5 text-sm">
                {alert.data.host !== null ? (
                  <li className="flex justify-between">
                    <span className="text-text">host {alert.data.host}</span>
                    <span className="font-mono text-xs text-muted">{formatNumber(alert.data.match_count)}</span>
                  </li>
                ) : null}
                {alert.data.user_name !== null ? (
                  <li className="flex justify-between">
                    <span className="text-text">user {alert.data.user_name}</span>
                    <span className="font-mono text-xs text-muted">{formatNumber(alert.data.match_count)}</span>
                  </li>
                ) : null}
                {alert.data.host === null && alert.data.user_name === null ? (
                  <li className="text-sm text-muted">No host or user on this alert.</li>
                ) : null}
              </ul>
            </Section>
            <AnalystPanel detail={alert.data} />
          </>
        ) : null}
      </div>
    </aside>
  )
}
