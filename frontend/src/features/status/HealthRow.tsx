import type { ReactElement } from 'react'

import type { HealthField, HealthState } from '../../api/types'

const STATE_STYLES: Readonly<Record<HealthState, { readonly dot: string; readonly label: string; readonly text: string }>> = {
  ok: {
    dot: 'bg-accent',
    label: 'OK',
    text: 'text-text',
  },
  degraded: {
    dot: 'bg-sev-medium',
    label: 'Degraded',
    text: 'text-text',
  },
  error: {
    dot: 'bg-sev-critical',
    label: 'Blocked',
    text: 'text-text',
  },
}

/**
 * One health row: the label is the `<dt>` and the value the `<dd>`.
 *
 * A `<div>` wrapper is used because HTML only permits `dt`/`dd` groupings
 * inside `dl` when they are wrapped in a `div`.
 */
export function HealthRow({ field }: { readonly field: HealthField }): ReactElement {
  const style = STATE_STYLES[field.state]
  return (
    <div className="grid grid-cols-[1fr_auto] items-baseline gap-x-4 border-b border-border py-2 last:border-b-0">
      <dt className="text-sm text-muted">{field.label}</dt>
      <dd className={`flex items-center gap-2 font-mono text-sm ${style.text}`}>
        <span aria-hidden="true" className={`inline-block size-2 rounded-full ${style.dot}`} />
        <span>{field.value}</span>
        <span className="sr-only">status: {style.label}</span>
      </dd>
    </div>
  )
}

export { STATE_STYLES }