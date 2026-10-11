import type { ReactElement } from 'react'
import { X } from 'lucide-react'

import notices from '../../../../THIRD_PARTY_NOTICES.md?raw'
import { useHealthQuery } from '../../api/hooks'
import { formatBytes, formatNumber } from '../../lib/format'
import { Button } from '../../ui/Button'
import { ErrorPanel } from '../../ui/ErrorPanel'
import { SkeletonRows } from '../../ui/Skeleton'

function Row({ label, value }: { readonly label: string; readonly value: string }): ReactElement {
  return (
    <div className="flex justify-between gap-4">
      <dt className="text-muted">{label}</dt>
      <dd className="font-mono text-text">{value}</dd>
    </div>
  )
}

/**
 * About dialog: the live runtime diagnostics (spec 07 section 3.13).
 *
 * The third-party licence texts (SigmaHQ DRL 1.1, MITRE ATT&CK terms) ship in
 * `THIRD_PARTY_NOTICES.md` and are bundled verbatim, so the dialog reproduces
 * the exact notices the repository packages without a runtime fetch.
 */
export function AboutDialog({ onClose }: { readonly onClose: () => void }): ReactElement {
  const health = useHealthQuery()
  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/40 p-4" role="presentation">
      <div
        role="dialog"
        aria-modal="true"
        aria-label="About TriageLens"
        className="w-[32rem] max-w-full space-y-3 rounded-[var(--radius-card)] border border-border bg-surface p-4 shadow-xl"
      >
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-medium text-text">About TriageLens</h2>
          <Button variant="ghost" aria-label="Close about" onClick={onClose}>
            <X aria-hidden="true" size={16} />
          </Button>
        </div>
        {health.isPending ? <SkeletonRows rows={4} /> : null}
        {health.isError ? (
          <ErrorPanel title="Cannot read diagnostics" message="The health endpoint is unavailable." onRetry={() => { void health.refetch() }} />
        ) : null}
        {health.data !== undefined ? (
          <dl className="space-y-0.5 text-xs">
            <Row label="Application" value={health.data.app_version} />
            <Row label="ATT&CK data" value={health.data.attack_version} />
            <Row label="SQLite" value={health.data.sqlite_version} />
            <Row label="Ruleset hash" value={health.data.ruleset_hash.slice(0, 16)} />
            <Row label="Workers" value={formatNumber(health.data.workers)} />
            <Row label="Database" value={formatBytes(health.data.db_bytes)} />
            <Row label="Free disk" value={formatBytes(health.data.free_disk_bytes)} />
            <Row label="FTS5" value={health.data.fts5 ? 'available' : 'missing'} />
            <Row label="JSON1" value={health.data.json1 ? 'available' : 'missing'} />
            <Row label="PDF export" value={health.data.pdf_available ? 'available' : 'not installed'} />
          </dl>
        ) : null}
        <details className="rounded-[var(--radius-card)] border border-border">
          <summary className="cursor-pointer px-2 py-1 text-xs text-muted">
            Third-party licence notices
          </summary>
          <pre className="max-h-48 overflow-auto whitespace-pre-wrap px-2 pb-2 text-[0.6875rem] leading-snug text-muted">
            {notices}
          </pre>
        </details>
      </div>
    </div>
  )
}
