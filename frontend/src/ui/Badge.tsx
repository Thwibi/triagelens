import type { ReactElement } from 'react'
import { AlertCircle, AlertTriangle, Info, MinusCircle, ShieldAlert } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'

import type { AlertLevel, AlertStatus, AnalystState } from '../api/types'

const SEVERITY: Readonly<Record<AlertLevel, { readonly label: string; readonly icon: LucideIcon; readonly className: string }>> = {
  critical: { label: 'Critical', icon: ShieldAlert, className: 'text-sev-critical-text' },
  high: { label: 'High', icon: AlertTriangle, className: 'text-sev-high-text' },
  medium: { label: 'Medium', icon: AlertCircle, className: 'text-sev-medium-text' },
  low: { label: 'Low', icon: Info, className: 'text-sev-low-text' },
  informational: { label: 'Info', icon: MinusCircle, className: 'text-sev-info-text' },
}

/**
 * Severity as icon + label + colour (spec 07 section 1).
 *
 * Colour is never the only signal, so the badge stays legible to a colour-blind
 * analyst and in a monochrome screenshot.
 */
export function SeverityBadge({ level }: { readonly level: AlertLevel }): ReactElement {
  const { label, icon: Icon, className } = SEVERITY[level]
  return (
    <span className={`inline-flex items-center gap-1 text-xs font-medium ${className}`}>
      <Icon aria-hidden="true" size={14} />
      {label}
    </span>
  )
}

export type StatusTone = 'neutral' | 'progress' | 'ok' | 'warn' | 'error'

const TONE_CLASS: Readonly<Record<StatusTone, string>> = {
  neutral: 'text-muted',
  progress: 'text-sev-low-text',
  ok: 'text-accent-text',
  warn: 'text-sev-medium-text',
  error: 'text-sev-critical-text',
}

const SOURCE_STATUS: Readonly<Record<string, { readonly label: string; readonly tone: StatusTone }>> = {
  queued: { label: 'Queued', tone: 'neutral' },
  needs_input: { label: 'Needs input', tone: 'warn' },
  parsing: { label: 'Parsing', tone: 'progress' },
  detecting: { label: 'Detecting', tone: 'progress' },
  done: { label: 'Done', tone: 'ok' },
  failed: { label: 'Failed', tone: 'error' },
  cancelled: { label: 'Cancelled', tone: 'neutral' },
}

/** A source/job status chip with a tone colour and a text label. */
export function StatusBadge({ status }: { readonly status: string }): ReactElement {
  const entry = SOURCE_STATUS[status] ?? { label: status, tone: 'neutral' as const }
  return (
    <span className={`inline-flex items-center gap-1.5 text-xs font-medium ${TONE_CLASS[entry.tone]}`}>
      <span aria-hidden="true" className="size-1.5 rounded-full bg-current" />
      {entry.label}
    </span>
  )
}

/** An analyst verdict (spec 04 section 6), shown with a text label and tone. */
export const ALERT_STATUS_LABELS: Readonly<Record<AlertStatus, string>> = {
  new: 'New',
  triaged: 'Triaged',
  true_positive: 'True positive',
  false_positive: 'False positive',
  benign: 'Benign',
}

const ALERT_STATUS_TONE: Readonly<Record<AlertStatus, StatusTone>> = {
  new: 'neutral',
  triaged: 'progress',
  true_positive: 'error',
  false_positive: 'ok',
  benign: 'neutral',
}

/** A status chip that reads the verdict as text, never colour alone. */
export function AlertStatusBadge({ status }: { readonly status: AlertStatus }): ReactElement {
  return (
    <span className={`inline-flex items-center gap-1.5 text-xs font-medium ${TONE_CLASS[ALERT_STATUS_TONE[status]]}`}>
      <span aria-hidden="true" className="size-1.5 rounded-full bg-current" />
      {ALERT_STATUS_LABELS[status]}
    </span>
  )
}

/** Human labels for an indicator's analyst verdict (spec 07 section 3.6). */
export const ANALYST_STATE_LABELS: Readonly<Record<AnalystState, string>> = {
  none: 'Unknown',
  malicious: 'Malicious',
  suspicious: 'Suspicious',
  benign: 'Benign',
}

const ANALYST_STATE_TONE: Readonly<Record<AnalystState, StatusTone>> = {
  none: 'neutral',
  malicious: 'error',
  suspicious: 'warn',
  benign: 'ok',
}

/** A chip showing an indicator's analyst verdict, as text plus tone. */
export function AnalystStateBadge({ state }: { readonly state: AnalystState }): ReactElement {
  return (
    <span className={`inline-flex items-center gap-1.5 text-xs font-medium ${TONE_CLASS[ANALYST_STATE_TONE[state]]}`}>
      <span aria-hidden="true" className="size-1.5 rounded-full bg-current" />
      {ANALYST_STATE_LABELS[state]}
    </span>
  )
}
