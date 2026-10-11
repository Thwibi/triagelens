import { useState } from 'react'
import type { ReactElement } from 'react'
import { useMutation } from '@tanstack/react-query'
import { Download, Eye, X } from 'lucide-react'

import { useCaseId } from '../../app/caseRoute'
import { createReport, downloadReport } from '../../api/endpoints'
import { useCaseJobsQuery, useHealthQuery, useReportsQuery } from '../../api/hooks'
import type { AlertStatus, Report, ReportFormat, ReportRequestBody } from '../../api/types'
import { ALERT_STATUSES } from '../../api/types'
import { saveFile } from '../../lib/download'
import { formatHash, formatTimestamp } from '../../lib/format'
import { ALERT_STATUS_LABELS } from '../../ui/Badge'
import { Button } from '../../ui/Button'
import { Card } from '../../ui/Card'
import { CopyButton } from '../../ui/CopyButton'
import { EmptyState } from '../../ui/EmptyState'
import { ErrorPanel } from '../../ui/ErrorPanel'
import { SkeletonRows } from '../../ui/Skeleton'
import { useToast } from '../../ui/ToastProvider'

/** The four formats a report can be rendered as (spec 08 section 1). */
const FORMATS: readonly ReportFormat[] = ['html', 'pdf', 'md', 'json']

/** Upper bound on evidence events kept per alert (spec 07 section 3.12). */
const MAX_EVENTS_PER_ALERT = 50

interface PreviewState {
  readonly id: string
  readonly html: string
}

/** Reports screen: options form, sandboxed HTML preview and history (spec 07 3.12). */
export function ReportsPage(): ReactElement {
  const caseId = useCaseId()
  const { push } = useToast()
  const reports = useReportsQuery(caseId)
  const jobs = useCaseJobsQuery(caseId)
  const health = useHealthQuery()

  const [format, setFormat] = useState<ReportFormat>('html')
  const [title, setTitle] = useState('')
  const [analyst, setAnalyst] = useState('')
  const [statuses, setStatuses] = useState<readonly AlertStatus[]>(ALERT_STATUSES)
  const [eventsPerAlert, setEventsPerAlert] = useState(10)
  const [includeIocs, setIncludeIocs] = useState(true)
  const [includeMitre, setIncludeMitre] = useState(true)
  const [includeTimeline, setIncludeTimeline] = useState(true)
  const [includeEntities, setIncludeEntities] = useState(true)
  const [includeAppendix, setIncludeAppendix] = useState(false)
  const [preview, setPreview] = useState<PreviewState | null>(null)

  const pdfAvailable = health.data?.pdf_available ?? false

  const buildBody = (): ReportRequestBody => ({
    format,
    title: title.trim() === '' ? undefined : title.trim(),
    analyst: analyst.trim() === '' ? undefined : analyst.trim(),
    include: {
      alerts: [...statuses],
      iocs: includeIocs,
      mitre: includeMitre,
      timeline: includeTimeline,
      entities: includeEntities,
      appendix_raw: includeAppendix,
      events_per_alert: eventsPerAlert,
    },
  })

  const createMutation = useMutation({
    mutationFn: () => {
      if (caseId === null) {
        throw new Error('No case is selected.')
      }
      return createReport(caseId, buildBody())
    },
    onSuccess: () => {
      push('success', 'Report queued')
    },
    onError: () => {
      push('error', 'Could not start the report')
    },
  })

  const downloadMutation = useMutation({
    mutationFn: async (report: Report) => {
      const file = await downloadReport(report.id)
      saveFile(file, `${report.id}.${report.format}`)
    },
    onSuccess: () => {
      push('success', 'Download started')
    },
    onError: () => {
      push('error', 'Could not download the report')
    },
  })

  const previewMutation = useMutation({
    mutationFn: async (report: Report) => {
      const file = await downloadReport(report.id)
      return { id: report.id, html: await file.blob.text() }
    },
    onSuccess: (data) => {
      setPreview(data)
    },
    onError: () => {
      push('error', 'Could not load the report preview')
    },
  })

  const toggleStatus = (status: AlertStatus, checked: boolean): void => {
    setStatuses((current) =>
      checked ? ALERT_STATUSES.filter((item) => item === status || current.includes(item)) : current.filter((item) => item !== status),
    )
  }

  if (caseId === null) {
    return <ErrorPanel message="No case is selected." />
  }

  const rows = reports.data?.items ?? []
  const reportJob = jobs.data?.items.find((job) => job.kind === 'report')
  const jobRunning = reportJob !== undefined && (reportJob.status === 'queued' || reportJob.status === 'running')

  return (
    <section aria-labelledby="reports-heading" className="space-y-4">
      <h1 id="reports-heading" className="text-xl font-semibold text-text">
        Reports
      </h1>

      <div className="grid gap-4 lg:grid-cols-[24rem_minmax(0,1fr)]">
        <Card title="Generate a report">
          <form
            className="space-y-3"
            onSubmit={(event) => {
              event.preventDefault()
              createMutation.mutate()
            }}
          >
            <fieldset className="space-y-1">
              <legend className="text-xs font-medium text-text">Format</legend>
              <div className="flex flex-wrap gap-2">
                {FORMATS.map((value) => {
                  const disabled = value === 'pdf' && !pdfAvailable
                  return (
                    <label key={value} className="flex items-center gap-1 text-xs text-text">
                      <input
                        type="radio"
                        name="report-format"
                        value={value}
                        checked={format === value}
                        disabled={disabled}
                        onChange={() => { setFormat(value) }}
                      />
                      {value.toUpperCase()}
                    </label>
                  )
                })}
              </div>
              {!pdfAvailable && (
                <p className="text-xs text-muted">PDF is unavailable: the optional WeasyPrint dependency is not installed.</p>
              )}
            </fieldset>

            <label className="block space-y-1 text-xs text-text">
              <span className="font-medium">Title</span>
              <input
                type="text"
                value={title}
                maxLength={200}
                onChange={(event) => { setTitle(event.target.value) }}
                placeholder="Case report"
                className="w-full rounded-[var(--radius-control)] border border-border bg-surface px-2 py-1 text-sm text-text outline-none focus:border-accent"
              />
            </label>

            <label className="block space-y-1 text-xs text-text">
              <span className="font-medium">Analyst</span>
              <input
                type="text"
                value={analyst}
                maxLength={200}
                onChange={(event) => { setAnalyst(event.target.value) }}
                placeholder="Name"
                className="w-full rounded-[var(--radius-control)] border border-border bg-surface px-2 py-1 text-sm text-text outline-none focus:border-accent"
              />
            </label>

            <fieldset className="space-y-1">
              <legend className="text-xs font-medium text-text">Alert statuses</legend>
              <div className="flex flex-wrap gap-x-3 gap-y-1">
                {ALERT_STATUSES.map((status) => (
                  <label key={status} className="flex items-center gap-1 text-xs text-text">
                    <input
                      type="checkbox"
                      checked={statuses.includes(status)}
                      onChange={(event) => { toggleStatus(status, event.target.checked) }}
                    />
                    {ALERT_STATUS_LABELS[status]}
                  </label>
                ))}
              </div>
            </fieldset>

            <label className="block space-y-1 text-xs text-text">
              <span className="font-medium">Events per alert (0–{MAX_EVENTS_PER_ALERT})</span>
              <input
                type="number"
                min={0}
                max={MAX_EVENTS_PER_ALERT}
                value={eventsPerAlert}
                onChange={(event) => {
                  const next = Number(event.target.value)
                  setEventsPerAlert(Number.isFinite(next) ? Math.min(MAX_EVENTS_PER_ALERT, Math.max(0, Math.trunc(next))) : 0)
                }}
                className="w-24 rounded-[var(--radius-control)] border border-border bg-surface px-2 py-1 text-sm text-text outline-none focus:border-accent"
              />
            </label>

            <fieldset className="space-y-1">
              <legend className="text-xs font-medium text-text">Include sections</legend>
              <div className="grid grid-cols-2 gap-1">
                {([
                  ['IOCs', includeIocs, setIncludeIocs],
                  ['ATT&CK', includeMitre, setIncludeMitre],
                  ['Timeline', includeTimeline, setIncludeTimeline],
                  ['Entities', includeEntities, setIncludeEntities],
                  ['Raw appendix', includeAppendix, setIncludeAppendix],
                ] as const).map(([label, checked, setter]) => (
                  <label key={label} className="flex items-center gap-1 text-xs text-text">
                    <input type="checkbox" checked={checked} onChange={(event) => { setter(event.target.checked) }} />
                    {label}
                  </label>
                ))}
              </div>
            </fieldset>

            <div className="flex items-center gap-2">
              <Button type="submit" variant="primary" disabled={createMutation.isPending || jobRunning}>
                {jobRunning ? 'Generating…' : 'Generate'}
              </Button>
              {reportJob !== undefined ? (
                <span className="text-xs text-muted">
                  {reportJob.status}
                  {reportJob.message !== null ? ` · ${reportJob.message}` : ''}
                </span>
              ) : null}
            </div>
          </form>
        </Card>

        <Card title="History">
          {reports.isError ? (
            <ErrorPanel title="Cannot load reports" message="The reports query failed." onRetry={() => { void reports.refetch() }} />
          ) : reports.isPending ? (
            <SkeletonRows rows={5} />
          ) : rows.length === 0 ? (
            <EmptyState title="No reports yet" detail="Generate one to build a shareable case report." />
          ) : (
            <table className="w-full border-collapse text-sm">
              <thead>
                <tr className="border-b border-border text-left text-xs uppercase tracking-wide text-muted">
                  <th scope="col" className="py-1 pr-2">Created</th>
                  <th scope="col" className="py-1 pr-2">Format</th>
                  <th scope="col" className="py-1 pr-2">SHA-256</th>
                  <th scope="col" className="py-1 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((report) => (
                  <tr key={report.id} className="border-b border-border/60 align-middle">
                    <td className="py-1 pr-2 text-text">{formatTimestamp(Date.parse(report.created_at))}</td>
                    <td className="py-1 pr-2 font-mono uppercase text-text">{report.format}</td>
                    <td className="py-1 pr-2">
                      <span className="inline-flex items-center gap-1">
                        <span className="font-mono text-xs text-muted" title={report.sha256}>{formatHash(report.sha256)}</span>
                        <CopyButton value={report.sha256} label="Copy SHA-256" />
                      </span>
                    </td>
                    <td className="py-1 text-right">
                      <div className="inline-flex items-center gap-1">
                        {report.format === 'html' ? (
                          <Button
                            variant="ghost"
                            aria-label={`Preview ${report.id}`}
                            disabled={previewMutation.isPending}
                            onClick={() => { previewMutation.mutate(report) }}
                          >
                            <Eye aria-hidden="true" size={14} /> Preview
                          </Button>
                        ) : null}
                        <Button
                          variant="ghost"
                          aria-label={`Download ${report.id}`}
                          disabled={downloadMutation.isPending}
                          onClick={() => { downloadMutation.mutate(report) }}
                        >
                          <Download aria-hidden="true" size={14} /> Download
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      </div>

      {preview !== null ? (
        <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/40 p-4" role="presentation">
          <div
            role="dialog"
            aria-modal="true"
            aria-label="Report preview"
            className="flex h-[90vh] w-[64rem] max-w-full flex-col gap-2 rounded-[var(--radius-card)] border border-border bg-surface p-4 shadow-xl"
          >
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-medium text-text">Report preview</h2>
              <Button variant="ghost" aria-label="Close preview" onClick={() => { setPreview(null) }}>
                <X aria-hidden="true" size={16} />
              </Button>
            </div>
            <iframe
              title="Report preview"
              sandbox=""
              srcDoc={preview.html}
              className="min-h-0 w-full flex-1 rounded border border-border bg-white"
            />
          </div>
        </div>
      ) : null}
    </section>
  )
}
