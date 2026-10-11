import type { ReactElement } from 'react'
import { useEffect, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Download, FolderUp, Trash2, Upload } from 'lucide-react'

import { deleteSource, listParseErrors, patchSource, resolveSource, runDetection, sourceDownloadUrl, uploadSources } from '../../api/endpoints'
import { useCaseId } from '../../app/caseRoute'
import { useCaseJobsQuery, useDetectionRunsQuery, useSourcesQuery } from '../../api/hooks'
import { useJobs } from '../../app/JobsProvider'
import { invalidateCaseData } from '../../api/invalidate'
import type { DetectionProfile, Source } from '../../api/types'
import { formatBytes, formatHash, formatNumber } from '../../lib/format'
import { Button } from '../../ui/Button'
import { CopyButton } from '../../ui/CopyButton'
import { EmptyState } from '../../ui/EmptyState'
import { ErrorPanel } from '../../ui/ErrorPanel'
import { JobProgress } from '../../components/JobProgress'
import { SkeletonRows } from '../../ui/Skeleton'
import { StatusBadge } from '../../ui/Badge'
import { useToast } from '../../ui/ToastProvider'
import { MappingWizard } from './MappingWizard'

const AUTO_RUN_KEY = 'triagelens.autorun'
const TERMINAL_SOURCE: ReadonlySet<string> = new Set(['done', 'failed', 'cancelled'])

function isSyslogLike(logType: string | null): boolean {
  return logType === null || logType.includes('syslog')
}

function Dropzone({ caseId }: { readonly caseId: string }): ReactElement {
  const queryClient = useQueryClient()
  const { push } = useToast()
  const inputRef = useRef<HTMLInputElement>(null)
  const [dragging, setDragging] = useState(false)
  const upload = useMutation({
    mutationFn: (files: readonly File[]) => uploadSources(caseId, files),
    onSuccess: (_data, files) => {
      invalidateCaseData(queryClient, caseId)
      push('info', `Queued ${files.length} file${files.length === 1 ? '' : 's'} for ingest.`)
    },
    onError: () => {
      push('error', 'Upload failed.')
    },
  })

  const submit = (files: FileList | null): void => {
    if (files !== null && files.length > 0) {
      upload.mutate(Array.from(files))
    }
  }

  return (
    <div
      onDragOver={(event) => {
        event.preventDefault()
        setDragging(true)
      }}
      onDragLeave={() => {
        setDragging(false)
      }}
      onDrop={(event) => {
        event.preventDefault()
        setDragging(false)
        submit(event.dataTransfer.files)
      }}
      className={`flex flex-col items-center gap-2 rounded-[var(--radius-card)] border border-dashed p-6 text-center ${
        dragging ? 'border-accent bg-accent/10' : 'border-border bg-surface/50'
      }`}
    >
      <Upload aria-hidden="true" size={20} className="text-muted" />
      <p className="text-sm text-text">Drop log files, folders or archives here</p>
      <div className="flex gap-2">
        <Button
          variant="primary"
          onClick={() => {
            inputRef.current?.click()
          }}
          disabled={upload.isPending}
        >
          Choose files
        </Button>
        <Button
          onClick={() => {
            inputRef.current?.click()
          }}
          disabled={upload.isPending}
        >
          <FolderUp aria-hidden="true" size={15} />
          Choose folder
        </Button>
      </div>
      <input
        ref={inputRef}
        type="file"
        multiple
        aria-label="Choose files to ingest"
        className="hidden"
        onChange={(event) => {
          submit(event.target.files)
          event.target.value = ''
        }}
      />
      {upload.isPending ? <p className="text-xs text-muted">Uploading…</p> : null}
    </div>
  )
}

function ParseErrorsDialog({ sourceId, onClose }: { readonly sourceId: string; readonly onClose: () => void }): ReactElement {
  const errors = useQuery({ queryKey: ['parse-errors', sourceId], queryFn: ({ signal }) => listParseErrors(sourceId, 1, { signal }) })
  return (
    <div role="dialog" aria-modal="true" aria-label="Parse errors" className="fixed inset-0 z-30 grid place-items-center bg-black/50 p-4">
      <div className="max-h-[80vh] w-full max-w-2xl overflow-auto rounded-[var(--radius-card)] border border-border bg-surface p-4">
        <div className="flex items-center justify-between">
          <h2 className="text-base font-medium text-text">Parse errors</h2>
          <Button onClick={onClose}>Close</Button>
        </div>
        {errors.isPending ? <SkeletonRows rows={4} /> : null}
        {errors.data !== undefined ? (
          errors.data.items.length === 0 ? (
            <p className="mt-2 text-sm text-muted">No malformed records.</p>
          ) : (
            <table className="mt-2 w-full text-left text-sm">
              <thead>
                <tr className="text-muted">
                  <th className="py-1">Record</th>
                  <th className="py-1">Reason</th>
                </tr>
              </thead>
              <tbody>
                {errors.data.items.map((error) => (
                  <tr key={error.record_ref} className="border-t border-border">
                    <td className="py-1 font-mono text-xs text-text">{error.record_ref}</td>
                    <td className="py-1 text-text">{error.reason}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )
        ) : null}
      </div>
    </div>
  )
}

function NeedsInputPrompt({ source }: { readonly source: Source }): ReactElement | null {
  const caseId = useCaseId()
  const queryClient = useQueryClient()
  const { push } = useToast()
  const { needsInput } = useJobs()
  const [choice, setChoice] = useState('')
  const [mapping, setMapping] = useState(false)
  const prompt = needsInput.get(source.id)
  const resolve = useMutation({
    mutationFn: () => resolveSource(source.id, { log_type: choice }),
    onSuccess: () => {
      if (caseId !== null) {
        invalidateCaseData(queryClient, caseId)
      }
      push('info', 'Resuming ingest.')
    },
  })

  const candidates = prompt?.candidates ?? []
  if (source.status !== 'needs_input') {
    return null
  }
  return (
    <div className="mt-2 flex flex-wrap items-center gap-2 rounded bg-sev-medium/10 p-2 text-sm">
      <span className="text-sev-medium-text">Which log type is this?</span>
      <label className="flex items-center gap-1">
        <span className="sr-only">Log type</span>
        <input
          list={`candidates-${source.id}`}
          value={choice}
          onChange={(event) => {
            setChoice(event.target.value)
          }}
          placeholder="log type"
          className="rounded-[var(--radius-control)] border border-border bg-surface-2 px-2 py-1 font-mono text-xs text-text"
        />
        <datalist id={`candidates-${source.id}`}>
          {candidates.map((candidate) => (
            <option key={candidate.log_type} value={candidate.log_type}>
              {Math.round(candidate.score * 100)}%
            </option>
          ))}
        </datalist>
      </label>
      <Button
        variant="primary"
        disabled={choice.trim() === '' || resolve.isPending}
        onClick={() => {
          resolve.mutate()
        }}
      >
        Resume
      </Button>
      <Button
        onClick={() => {
          setMapping(true)
        }}
      >
        Custom mapping…
      </Button>
      {mapping ? (
        <MappingWizard
          source={source}
          onClose={() => {
            setMapping(false)
          }}
        />
      ) : null}
    </div>
  )
}

function SourceRow({ source }: { readonly source: Source }): ReactElement {
  const caseId = useCaseId()
  const queryClient = useQueryClient()
  const { push } = useToast()
  const [showErrors, setShowErrors] = useState(false)
  const [logType, setLogType] = useState(source.log_type ?? '')
  const [timezone, setTimezone] = useState(source.timezone ?? '')
  const [year, setYear] = useState(source.assumed_year === null ? '' : String(source.assumed_year))

  const patch = useMutation({
    mutationFn: () =>
      patchSource(source.id, {
        ...(logType !== (source.log_type ?? '') ? { log_type: logType } : {}),
        ...(timezone !== (source.timezone ?? '') ? { timezone } : {}),
        ...(year !== (source.assumed_year === null ? '' : String(source.assumed_year)) ? { assumed_year: Number(year) } : {}),
      }),
    onSuccess: (result) => {
      if (caseId !== null) {
        invalidateCaseData(queryClient, caseId)
      }
      if (result.job !== undefined) {
        push('info', 'Re-parsing with the new type.')
      }
    },
  })

  const remove = useMutation({
    mutationFn: () => deleteSource(source.id),
    onSuccess: () => {
      if (caseId !== null) {
        invalidateCaseData(queryClient, caseId)
      }
    },
  })

  const dirty =
    logType !== (source.log_type ?? '') ||
    timezone !== (source.timezone ?? '') ||
    year !== (source.assumed_year === null ? '' : String(source.assumed_year))

  return (
    <li className="space-y-2 rounded-[var(--radius-card)] border border-border bg-surface p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="min-w-0 flex-1 truncate text-sm text-text" title={source.filename}>
          {source.filename}
        </span>
        <StatusBadge status={source.status} />
      </div>

      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted">
        <span>{formatBytes(source.size_bytes)}</span>
        <span className="flex items-center gap-1 font-mono">
          SHA-256 {formatHash(source.sha256)}
          <CopyButton value={source.sha256} label="Copy SHA-256" />
        </span>
        <span className="font-mono">
          {source.log_type ?? 'unrecognised'}
          {source.detect_confidence !== null ? ` (${Math.round(source.detect_confidence * 100)}%)` : ''}
        </span>
        <span>
          {formatNumber(source.event_count)} events · {formatNumber(source.error_count)} errors
        </span>
      </div>

      {source.status === 'parsing' || source.status === 'queued' ? <JobProgress value={0} label="Ingest progress" /> : null}

      <NeedsInputPrompt source={source} />

      {isSyslogLike(source.log_type) || source.status === 'needs_input' ? (
        <div className="flex flex-wrap items-end gap-2 text-xs">
          <label className="flex flex-col gap-1">
            <span className="text-muted">Log type</span>
            <input
              value={logType}
              onChange={(event) => {
                setLogType(event.target.value)
              }}
              className="rounded-[var(--radius-control)] border border-border bg-surface-2 px-2 py-1 font-mono text-text"
            />
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-muted">Timezone</span>
            <input
              value={timezone}
              onChange={(event) => {
                setTimezone(event.target.value)
              }}
              placeholder="UTC"
              className="rounded-[var(--radius-control)] border border-border bg-surface-2 px-2 py-1 font-mono text-text"
            />
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-muted">Assumed year</span>
            <input
              value={year}
              onChange={(event) => {
                setYear(event.target.value)
              }}
              inputMode="numeric"
              className="w-20 rounded-[var(--radius-control)] border border-border bg-surface-2 px-2 py-1 font-mono text-text"
            />
          </label>
          <Button
            variant="primary"
            disabled={!dirty || patch.isPending}
            onClick={() => {
              patch.mutate()
            }}
          >
            Save & re-parse
          </Button>
        </div>
      ) : null}

      <div className="flex flex-wrap gap-2">
        {source.error_count > 0 ? (
          <Button
            onClick={() => {
              setShowErrors(true)
            }}
          >
            View parse errors
          </Button>
        ) : null}
        <a
          href={sourceDownloadUrl(source.id)}
          className="inline-flex items-center gap-1.5 rounded-[var(--radius-control)] border border-border bg-surface-2 px-3 py-1.5 text-sm text-text hover:bg-surface"
        >
          <Download aria-hidden="true" size={15} /> Download
        </a>
        <Button
          variant="danger"
          disabled={remove.isPending}
          onClick={() => {
            remove.mutate()
          }}
        >
          <Trash2 aria-hidden="true" size={15} /> Delete
        </Button>
      </div>

      {showErrors ? (
        <ParseErrorsDialog
          sourceId={source.id}
          onClose={() => {
            setShowErrors(false)
          }}
        />
      ) : null}
    </li>
  )
}

function readProfile(value: string | undefined): DetectionProfile {
  return value === 'fast' || value === 'full' ? value : 'standard'
}

function SourcesFooter({ caseId }: { readonly caseId: string }): ReactElement {
  const queryClient = useQueryClient()
  const { push } = useToast()
  const runs = useDetectionRunsQuery(caseId)
  const jobs = useCaseJobsQuery(caseId)
  const [profile, setProfile] = useState<DetectionProfile>(() => readProfile(runs.data?.items[0]?.profile))
  const [autoRun, setAutoRun] = useState(() => window.localStorage.getItem(AUTO_RUN_KEY) === 'true')
  const seenIngest = useRef<Set<string>>(new Set())
  const seeded = useRef(false)

  const detect = useMutation({
    mutationFn: () => runDetection(caseId, { profile }),
    onSuccess: () => {
      invalidateCaseData(queryClient, caseId)
      push('info', 'Detection queued.')
    },
  })

  useEffect(() => {
    if (jobs.data === undefined) {
      return
    }
    const terminalIngest = jobs.data.items.filter(
      (job) => job.kind === 'ingest' && (job.status === 'done' || job.status === 'failed' || job.status === 'cancelled'),
    )
    if (!seeded.current) {
      // The first load lists history; only jobs that finish while the screen is
      // open should trigger a run, so seed the set without firing.
      for (const job of terminalIngest) {
        seenIngest.current.add(job.id)
      }
      seeded.current = true
      return
    }
    let finishedSuccessfully = false
    for (const job of terminalIngest) {
      if (!seenIngest.current.has(job.id)) {
        seenIngest.current.add(job.id)
        finishedSuccessfully = finishedSuccessfully || job.status === 'done'
      }
    }
    if (finishedSuccessfully && autoRun && !detect.isPending) {
      detect.mutate()
    }
  }, [autoRun, detect, jobs.data])

  return (
    <div className="flex flex-wrap items-center gap-3 rounded-[var(--radius-card)] border border-border bg-surface p-3">
      <label className="flex items-center gap-2 text-sm">
        <span className="text-muted">Profile</span>
        <select
          value={profile}
          onChange={(event) => {
            setProfile(event.target.value as DetectionProfile)
          }}
          className="rounded-[var(--radius-control)] border border-border bg-surface-2 px-2 py-1 text-text"
        >
          <option value="fast">fast</option>
          <option value="standard">standard</option>
          <option value="full">full</option>
        </select>
      </label>
      <Button
        variant="primary"
        disabled={detect.isPending}
        onClick={() => {
          detect.mutate()
        }}
      >
        Run detection
      </Button>
      <label className="ml-auto flex items-center gap-2 text-sm text-muted">
        <input
          type="checkbox"
          checked={autoRun}
          onChange={(event) => {
            setAutoRun(event.target.checked)
            window.localStorage.setItem(AUTO_RUN_KEY, String(event.target.checked))
          }}
        />
        Auto-run after ingest
      </label>
    </div>
  )
}

/** Sources upload and ingest screen (spec 07 section 3.3). */
export function SourcesPage(): ReactElement {
  const caseId = useCaseId()
  const sources = useSourcesQuery(caseId)

  if (caseId === null) {
    return <ErrorPanel message="No case is selected." />
  }

  const items = sources.data?.items ?? []
  const active = items.some((source) => !TERMINAL_SOURCE.has(source.status))

  return (
    <section aria-labelledby="sources-heading" className="space-y-4">
      <h1 id="sources-heading" className="text-xl font-semibold text-text">
        Sources
      </h1>

      <Dropzone caseId={caseId} />

      {sources.isPending ? <SkeletonRows rows={3} /> : null}
      {sources.isError ? (
        <ErrorPanel
          title="Cannot load sources"
          message="The local API did not return the source list."
          onRetry={() => {
            void sources.refetch()
          }}
        />
      ) : null}
      {sources.data !== undefined && items.length === 0 ? (
        <EmptyState title="No sources yet" detail="Drop log files above to start this case." />
      ) : null}
      {items.length > 0 ? (
        <ul className="space-y-2">
          {items.map((source) => (
            <SourceRow key={source.id} source={source} />
          ))}
        </ul>
      ) : null}

      <SourcesFooter caseId={caseId} />

      {active ? <p className="text-xs text-muted">Ingest in progress — this list updates live.</p> : null}
    </section>
  )
}
