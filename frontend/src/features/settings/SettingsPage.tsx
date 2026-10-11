import { useMemo, useRef, useState } from 'react'
import type { ReactElement, ReactNode } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Trash2, Upload } from 'lucide-react'

import {
  createAllowlistEntry,
  deleteAllowlistEntry,
  importAttackBundle,
  rebuildFts,
  updateSettings,
  vacuumDatabase,
  verifyAuditChain,
  verifyHashes,
} from '../../api/endpoints'
import { useAuditLogQuery, useCasesQuery, useHealthQuery, useSettingsQuery } from '../../api/hooks'
import { invalidateSettings } from '../../api/invalidate'
import { queryKeys } from '../../api/queryKeys'
import type { SettingsPayload } from '../../api/types'
import { useCaseId } from '../../app/caseRoute'
import { loadPref, savePref } from '../../lib/prefs'
import { formatBytes, formatNumber, formatTimestamp } from '../../lib/format'
import { useTheme } from '../../theme/ThemeProvider'
import { Button } from '../../ui/Button'
import { ErrorPanel } from '../../ui/ErrorPanel'
import { SkeletonRows } from '../../ui/Skeleton'
import { useToast } from '../../ui/ToastProvider'
import { AboutDialog } from './AboutDialog'

/** Global allowlist entry kinds (spec 05 section 5). */
const ALLOWLIST_KINDS = ['domain', 'domain_suffix', 'ip', 'cidr', 'hash', 'regex'] as const

const DENSITY_KEY = 'triagelens.events.density'
const DETECTION_PROFILES = ['fast', 'standard', 'full'] as const

function Section({ title, children, note }: { readonly title: string; readonly children: ReactNode; readonly note?: string }): ReactElement {
  return (
    <section className="space-y-2 rounded-[var(--radius-card)] border border-border bg-surface p-3">
      <h2 className="text-xs font-medium uppercase tracking-wide text-muted">{title}</h2>
      {children}
      {note !== undefined ? <p className="text-xs text-muted">{note}</p> : null}
    </section>
  )
}

function readSection(payload: SettingsPayload | undefined, name: string): Record<string, unknown> {
  const value = payload?.settings[name]
  if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
    return value as Record<string, unknown>
  }
  return {}
}

function readValue(section: Record<string, unknown>, key: string): string {
  const value = section[key]
  if (typeof value === 'string') return value
  if (typeof value === 'number') return String(value)
  if (typeof value === 'boolean') return value ? 'yes' : 'no'
  return '—'
}

function ReadRow({ label, value }: { readonly label: string; readonly value: string }): ReactElement {
  return (
    <div className="flex justify-between gap-4 text-xs">
      <dt className="text-muted">{label}</dt>
      <dd className="font-mono text-text">{value}</dd>
    </div>
  )
}

function AllowlistEditor({ payload }: { readonly payload: SettingsPayload | undefined }): ReactElement {
  const queryClient = useQueryClient()
  const { push } = useToast()
  const [kind, setKind] = useState<string>('domain')
  const [value, setValue] = useState('')
  const [note, setNote] = useState('')

  const add = useMutation({
    mutationFn: () => createAllowlistEntry({ kind, value, ...(note === '' ? {} : { note }) }),
    onSuccess: () => {
      invalidateSettings(queryClient)
      setValue('')
      setNote('')
      push('success', 'Allowlist entry added')
    },
    onError: (error) => { push('error', error instanceof Error ? error.message : 'Could not add entry') },
  })

  const remove = useMutation({
    mutationFn: (id: number) => deleteAllowlistEntry(id),
    onSuccess: () => {
      invalidateSettings(queryClient)
      push('success', 'Allowlist entry removed')
    },
    onError: (error) => { push('error', error instanceof Error ? error.message : 'Could not remove entry') },
  })

  const entries = payload?.allowlist ?? []

  return (
    <Section title="Allowlist" note="Global entries suppress an indicator in every case.">
      <div className="flex flex-wrap items-end gap-2">
        <label className="text-xs text-muted">
          Kind
          <select
            className="mt-1 block rounded border border-border bg-surface-2 px-2 py-1 text-sm text-text"
            value={kind}
            onChange={(event) => { setKind(event.target.value) }}
          >
            {ALLOWLIST_KINDS.map((option) => (
              <option key={option} value={option}>{option}</option>
            ))}
          </select>
        </label>
        <label className="text-xs text-muted">
          Value
          <input
            className="mt-1 block w-56 rounded border border-border bg-surface-2 px-2 py-1 text-sm text-text"
            value={value}
            onChange={(event) => { setValue(event.target.value) }}
          />
        </label>
        <label className="text-xs text-muted">
          Note
          <input
            className="mt-1 block w-40 rounded border border-border bg-surface-2 px-2 py-1 text-sm text-text"
            value={note}
            onChange={(event) => { setNote(event.target.value) }}
          />
        </label>
        <Button variant="primary" disabled={add.isPending || value.trim() === ''} onClick={() => { add.mutate() }}>
          Add
        </Button>
      </div>
      {entries.length === 0 ? (
        <p className="text-sm text-muted">No global allowlist entries.</p>
      ) : (
        <table className="w-full text-left text-xs">
          <thead>
            <tr className="text-muted">
              <th className="py-1">Kind</th>
              <th className="py-1">Value</th>
              <th className="py-1">Note</th>
              <th className="py-1" />
            </tr>
          </thead>
          <tbody>
            {entries.map((entry) => (
              <tr key={entry.id} className="border-t border-border">
                <td className="py-1 text-muted">{entry.kind}</td>
                <td className="break-all py-1 font-mono text-text">{entry.value}</td>
                <td className="py-1 text-muted">{entry.note ?? '—'}</td>
                <td className="py-1 text-right">
                  <Button variant="ghost" aria-label={`Remove ${entry.value}`} disabled={remove.isPending} onClick={() => { remove.mutate(entry.id) }}>
                    <Trash2 aria-hidden="true" size={14} />
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Section>
  )
}

function AuditViewer({ caseId }: { readonly caseId: string | null }): ReactElement {
  const cases = useCasesQuery()
  const [selected, setSelected] = useState(caseId ?? '')
  const [order, setOrder] = useState<'desc' | 'asc'>('desc')
  const query = useMemo(() => ({ limit: 100, order }), [order])
  const audit = useAuditLogQuery(selected === '' ? null : selected, query)

  return (
    <Section title="Audit log">
      <div className="flex flex-wrap items-end gap-2">
        <label className="text-xs text-muted">
          Case
          <select
            className="mt-1 block rounded border border-border bg-surface-2 px-2 py-1 text-sm text-text"
            value={selected}
            onChange={(event) => { setSelected(event.target.value) }}
          >
            <option value="">Select a case…</option>
            {(cases.data?.items ?? []).map((item) => (
              <option key={item.id} value={item.id}>{item.name}</option>
            ))}
          </select>
        </label>
        <label className="text-xs text-muted">
          Order
          <select
            className="mt-1 block rounded border border-border bg-surface-2 px-2 py-1 text-sm text-text"
            value={order}
            onChange={(event) => { setOrder(event.target.value === 'asc' ? 'asc' : 'desc') }}
          >
            <option value="desc">Newest first</option>
            <option value="asc">Oldest first</option>
          </select>
        </label>
      </div>
      {selected === '' ? (
        <p className="text-sm text-muted">Choose a case to view its audit chain.</p>
      ) : audit.isPending ? (
        <SkeletonRows rows={4} />
      ) : audit.isError ? (
        <ErrorPanel title="Cannot load audit log" message="The audit chain could not be read." onRetry={() => { void audit.refetch() }} />
      ) : (
        <>
          <p className={`text-xs font-medium ${audit.data.chain_ok ? 'text-accent' : 'text-sev-critical'}`}>
            {audit.data.chain_ok
              ? `Chain verified · ${formatNumber(audit.data.rows_checked)} rows`
              : `Chain broken at row ${formatNumber(audit.data.broken_at ?? 0)}: ${audit.data.broken_reason ?? 'unknown'}`}
          </p>
          <ul className="divide-y divide-border">
            {audit.data.items.map((entry) => (
              <li key={entry.id} className="flex items-start justify-between gap-3 py-1 text-xs">
                <span className="text-text">{entry.action}</span>
                <span className="truncate text-muted">{formatTimestamp(Date.parse(entry.ts))}</span>
              </li>
            ))}
          </ul>
        </>
      )}
    </Section>
  )
}

/**
 * Data-maintenance actions (spec 10 section 5, spec 07 section 3.13).
 *
 * Four one-shot operations over the whole store. Each reports its outcome in a
 * toast; vacuuming also refreshes health because the database size it shows
 * changes. The buttons share a busy flag so two writers cannot overlap.
 */
function DataMaintenance(): ReactElement {
  const queryClient = useQueryClient()
  const { push } = useToast()

  const vacuum = useMutation({
    mutationFn: () => vacuumDatabase(),
    onSuccess: (result) => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.health() })
      const reclaimed = result.db_bytes_before - result.db_bytes_after
      push(
        'success',
        reclaimed > 0 ? `Database compacted, ${formatBytes(reclaimed)} reclaimed` : 'Database compacted',
      )
    },
    onError: (error) => { push('error', error instanceof Error ? error.message : 'Vacuum failed') },
  })

  const rebuild = useMutation({
    mutationFn: () => rebuildFts(),
    onSuccess: (result) => {
      push('success', `Search index rebuilt · ${formatNumber(result.indexed)} events`)
    },
    onError: (error) => { push('error', error instanceof Error ? error.message : 'Rebuild failed') },
  })

  const hashes = useMutation({
    mutationFn: () => verifyHashes(),
    onSuccess: (result) => {
      if (result.ok) {
        push('success', `All ${formatNumber(result.checked)} originals verified`)
      } else {
        const failed = result.mismatched.length + result.missing.length
        push('error', `${formatNumber(failed)} of ${formatNumber(result.checked)} originals failed verification`)
      }
    },
    onError: (error) => { push('error', error instanceof Error ? error.message : 'Verification failed') },
  })

  const audit = useMutation({
    mutationFn: () => verifyAuditChain(),
    onSuccess: (result) => {
      if (result.chain_ok) {
        push('success', `Audit chain verified · ${formatNumber(result.rows_checked)} rows`)
      } else {
        push('error', `Audit chain broken at row ${formatNumber(result.broken_at ?? 0)}`)
      }
    },
    onError: (error) => { push('error', error instanceof Error ? error.message : 'Verification failed') },
  })

  const busy = vacuum.isPending || rebuild.isPending || hashes.isPending || audit.isPending

  return (
    <div className="flex flex-wrap gap-2 pt-1">
      <Button disabled={busy} onClick={() => { vacuum.mutate() }}>
        {vacuum.isPending ? 'Vacuuming…' : 'Vacuum'}
      </Button>
      <Button disabled={busy} onClick={() => { rebuild.mutate() }}>
        {rebuild.isPending ? 'Rebuilding…' : 'Rebuild search index'}
      </Button>
      <Button disabled={busy} onClick={() => { hashes.mutate() }}>
        {hashes.isPending ? 'Verifying…' : 'Verify evidence hashes'}
      </Button>
      <Button disabled={busy} onClick={() => { audit.mutate() }}>
        {audit.isPending ? 'Verifying…' : 'Verify audit chain'}
      </Button>
    </div>
  )
}

/** Settings: general, detection, allowlist, ATT&CK, enrichment, data, audit (spec 07 section 3.13). */
export function SettingsPage(): ReactElement {  const caseId = useCaseId()
  const queryClient = useQueryClient()
  const { push } = useToast()
  const { theme, setTheme } = useTheme()
  const settings = useSettingsQuery()
  const health = useHealthQuery()
  const [density, setDensity] = useState<'compact' | 'comfortable'>(() =>
    loadPref<'compact' | 'comfortable'>(DENSITY_KEY, 'compact'),
  )
  const [aboutOpen, setAboutOpen] = useState(false)
  const fileInput = useRef<HTMLInputElement | null>(null)

  const payload = settings.data
  const detection = readSection(payload, 'detection')
  const storage = readSection(payload, 'storage')
  const ioc = readSection(payload, 'ioc')
  const limits = readSection(payload, 'limits')

  const profileMutation = useMutation({
    mutationFn: (profile: string) => updateSettings({ 'detection.profile': profile }),
    onSuccess: () => {
      invalidateSettings(queryClient)
      push('success', 'Detection profile updated')
    },
    onError: (error) => { push('error', error instanceof Error ? error.message : 'Could not update profile') },
  })

  const attackImport = useMutation({
    mutationFn: (bundle: File) => importAttackBundle(bundle),
    onSuccess: (result) => {
      push('success', `ATT&CK updated to ${result.attack_version} (${formatNumber(result.techniques)} techniques)`)
    },
    onError: (error) => { push('error', error instanceof Error ? error.message : 'Import failed') },
  })

  return (
    <section aria-labelledby="settings-heading" className="mx-auto flex max-w-4xl flex-col gap-3">
      <div className="flex items-center justify-between">
        <h1 id="settings-heading" className="text-xl font-semibold text-text">Settings</h1>
        <Button onClick={() => { setAboutOpen(true) }}>About</Button>
      </div>

      {settings.isError ? (
        <ErrorPanel title="Cannot load settings" message="The settings endpoint is unavailable." onRetry={() => { void settings.refetch() }} />
      ) : null}
      {settings.isPending ? <SkeletonRows rows={6} /> : null}

      {payload !== undefined ? (
        <>
          <Section title="General" note="Theme applies immediately. Density controls the Events table row height.">
            <label className="block text-xs text-muted">
              Theme
              <select
                className="mt-1 block rounded border border-border bg-surface-2 px-2 py-1 text-sm text-text"
                value={theme}
                onChange={(event) => { setTheme(event.target.value === 'light' ? 'light' : 'dark') }}
              >
                <option value="dark">Dark</option>
                <option value="light">Light</option>
              </select>
            </label>
            <label className="block text-xs text-muted">
              Density
              <select
                className="mt-1 block rounded border border-border bg-surface-2 px-2 py-1 text-sm text-text"
                value={density}
                onChange={(event) => {
                  const next = event.target.value === 'comfortable' ? 'comfortable' : 'compact'
                  setDensity(next)
                  savePref(DENSITY_KEY, next)
                }}
              >
                <option value="compact">Compact</option>
                <option value="comfortable">Comfortable</option>
              </select>
            </label>
            <p className="text-xs text-muted">
              Per-case timezones are set on the case itself; there is no global timezone setting in this deployment.
            </p>
          </Section>

          <Section title="Detection" note="Only the profile is analyst-editable; limits come from config.toml.">
            <label className="block text-xs text-muted">
              Profile
              <select
                className="mt-1 block rounded border border-border bg-surface-2 px-2 py-1 text-sm text-text"
                value={readValue(detection, 'profile')}
                disabled={profileMutation.isPending}
                onChange={(event) => { profileMutation.mutate(event.target.value) }}
              >
                {DETECTION_PROFILES.map((profile) => (
                  <option key={profile} value={profile}>{profile}</option>
                ))}
              </select>
            </label>
            <dl className="space-y-0.5">
              <ReadRow label="Auto-run after ingest" value={readValue(detection, 'auto_run_after_ingest')} />
              <ReadRow label="Sync rules on startup" value={readValue(detection, 'sync_rules_on_startup')} />
              <ReadRow label="Rule timeout (s)" value={readValue(detection, 'rule_timeout_seconds')} />
              <ReadRow label="Alert group window (min)" value={readValue(detection, 'alert_group_window_minutes')} />
              <ReadRow label="Max sample events / alert" value={readValue(detection, 'max_sample_events_per_alert')} />
            </dl>
          </Section>

          <AllowlistEditor payload={payload} />

          <Section title="ATT&CK data" note="Import a STIX 2.1 bundle to replace the catalogue; the bundled data ships offline.">
            <dl className="space-y-0.5">
              <ReadRow label="ATT&CK version" value={health.data?.attack_version ?? '—'} />
            </dl>
            <input
              ref={fileInput}
              type="file"
              accept=".json"
              hidden
              onChange={(event) => {
                const file = event.target.files?.[0]
                if (file !== undefined) {
                  attackImport.mutate(file)
                }
                event.target.value = ''
              }}
            />
            <Button disabled={attackImport.isPending} onClick={() => { fileInput.current?.click() }}>
              <Upload aria-hidden="true" size={14} />
              {attackImport.isPending ? 'Importing…' : 'Import bundle'}
            </Button>
          </Section>

          <Section title="Enrichment" note="Enrichment is opt-in and disabled by default; this deployment exposes no key-entry field.">
            <dl className="space-y-0.5">
              <ReadRow label="Allow outbound enrichment" value={readValue(ioc, 'allow_enrichment')} />
            </dl>
          </Section>

          <Section title="Data" note="Disk and database figures come from the health endpoint.">
            <dl className="space-y-0.5">
              <ReadRow label="Data directory" value={readValue(storage, 'data_dir')} />
              <ReadRow label="Database size" value={health.data !== undefined ? formatBytes(health.data.db_bytes) : '—'} />
              <ReadRow label="Free disk" value={health.data !== undefined ? formatBytes(health.data.free_disk_bytes) : '—'} />
              <ReadRow label="Worker processes" value={health.data !== undefined ? formatNumber(health.data.workers) : '—'} />
              <ReadRow label="Max upload (GB)" value={readValue(limits, 'max_upload_gb')} />
            </dl>
            <DataMaintenance />
          </Section>

          <AuditViewer caseId={caseId} />
        </>
      ) : null}

      {aboutOpen ? <AboutDialog onClose={() => { setAboutOpen(false) }} /> : null}
    </section>
  )
}
