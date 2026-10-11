import type { ReactElement } from 'react'
import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Plus, Trash2 } from 'lucide-react'

import {
  getProfile,
  listProfiles,
  previewProfile,
  resolveSource,
  saveProfile,
  sourceDownloadUrl,
} from '../../api/endpoints'
import type { PreviewRow, ProfilePreview, Source } from '../../api/types'
import { invalidateCaseData } from '../../api/invalidate'
import { Button } from '../../ui/Button'
import { ErrorPanel } from '../../ui/ErrorPanel'
import { useToast } from '../../ui/ToastProvider'
import {
  NORMALIZED_FIELDS,
  TIMESTAMP_FORMATS,
  buildProfileYaml,
  draftFromProfile,
  guessLogType,
  sampleFieldPaths,
  suggestProfile,
} from './mappingProfile'
import type { CategoryRuleDraft, ProfileDraft } from './mappingProfile'

const NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]*$/

const PREVIEW_COLUMNS: readonly (keyof PreviewRow)[] = [
  'ts_iso',
  'host',
  'user_name',
  'level',
  'event_action',
  'src_ip',
  'dst_ip',
  'url',
  'message',
]

const STEP_LABELS: readonly string[] = ['Sample', 'Match', 'Map', 'Preview', 'Save']

function emptyDraft(): ProfileDraft {
  return {
    name: '',
    timestampPath: '',
    timestampFormat: 'iso8601',
    timezone: '',
    defaultCategory: '',
    appliesWhen: [],
    fields: {},
    categoryRules: [],
  }
}

/** One cell of the preview table, rendered as text (never `innerHTML`). */
function cell(row: PreviewRow, column: keyof PreviewRow): string {
  const value = row[column]
  if (value === null || value === undefined) {
    return '—'
  }
  const text =
    typeof value === 'number' ? String(value) : typeof value === 'string' ? value : JSON.stringify(value)
  return text.length > 80 ? `${text.slice(0, 77)}…` : text
}

function StepList({ step }: { readonly step: number }): ReactElement {
  return (
    <ol className="flex flex-wrap gap-2 text-xs text-muted">
      {STEP_LABELS.map((label, index) => {
        const number = index + 1
        const state = number === step ? 'current' : number < step ? 'done' : 'todo'
        return (
          <li
            key={label}
            aria-current={state === 'current' ? 'step' : undefined}
            className={`rounded-[var(--radius-control)] border px-2 py-1 ${
              state === 'current'
                ? 'border-accent text-text'
                : state === 'done'
                  ? 'border-border text-text'
                  : 'border-border'
            }`}
          >
            {number}. {label}
          </li>
        )
      })}
    </ol>
  )
}

export interface MappingWizardProps {
  readonly source: Source | null
  readonly onClose: () => void
}

/**
 * The five-step custom mapping wizard (spec 07 section 3.11).
 *
 * Steps are a linear state machine over one `ProfileDraft`; the sample and the
 * draft YAML are the only inputs the backend sees, through `/profiles/preview`
 * for the dry run and `PUT /profiles/{name}` to persist. Closing the dialog at
 * any point abandons the draft and saves nothing.
 */
export function MappingWizard({ source, onClose }: MappingWizardProps): ReactElement {
  const queryClient = useQueryClient()
  const { push } = useToast()
  const [step, setStep] = useState(1)
  const [sample, setSample] = useState('')
  const [logType, setLogType] = useState<'generic_json' | 'generic_csv'>('generic_json')
  const [draft, setDraft] = useState<ProfileDraft>(emptyDraft)
  const [appliesText, setAppliesText] = useState('')
  const [preview, setPreview] = useState<ProfilePreview | null>(null)
  const [loadError, setLoadError] = useState<string | null>(null)

  const profiles = useQuery({ queryKey: ['profiles', 'list'], queryFn: ({ signal }) => listProfiles({ signal }) })

  const paths = useMemo(() => sampleFieldPaths(sample, logType), [sample, logType])
  const suggestion = useMemo(
    () => (profiles.data === undefined ? null : suggestProfile(sample, profiles.data.items)),
    [profiles.data, sample],
  )

  const nameValid = NAME_PATTERN.test(draft.name)
  const timestampValid = draft.timestampPath.trim() !== ''

  const previewRun = useMutation({
    mutationFn: () =>
      previewProfile({ sample, yaml: buildProfileYaml(draft), log_type: logType, limit: 20 }),
    onSuccess: (result) => {
      setPreview(result)
    },
    onError: () => {
      setPreview(null)
    },
  })

  const save = useMutation({
    mutationFn: async () => {
      await saveProfile(draft.name, buildProfileYaml(draft))
      if (source !== null) {
        await resolveSource(source.id, { log_type: logType })
      }
    },
    onSuccess: () => {
      if (source !== null) {
        invalidateCaseData(queryClient, source.case_id)
      }
      push('info', `Saved profile ${draft.name} and queued a re-parse.`)
      onClose()
    },
  })

  const loadExisting = useMutation({
    mutationFn: (name: string) => getProfile(name),
    onSuccess: (profile) => {
      const seeded = draftFromProfile(profile)
      setDraft(seeded)
      setAppliesText(seeded.appliesWhen.join('\n'))
      setLoadError(null)
      setStep(3)
    },
    onError: () => {
      setLoadError('Could not load that profile.')
    },
  })

  const fetchSample = useMutation({
    mutationFn: async () => {
      if (source === null) {
        return ''
      }
      const response = await fetch(sourceDownloadUrl(source.id))
      const text = await response.text()
      return text.split(/\r?\n/).slice(0, 50).join('\n')
    },
    onSuccess: (text) => {
      if (text !== '') {
        setSample(text)
        setLogType(guessLogType(text))
      }
    },
  })

  const updateDraft = (patch: Partial<ProfileDraft>): void => {
    setDraft((current) => ({ ...current, ...patch }))
  }

  const setField = (column: string, path: string): void => {
    setDraft((current) => ({ ...current, fields: { ...current.fields, [column]: path } }))
  }

  const setRule = (index: number, patch: Partial<CategoryRuleDraft>): void => {
    setDraft((current) => ({
      ...current,
      categoryRules: current.categoryRules.map((rule, i) => (i === index ? { ...rule, ...patch } : rule)),
    }))
  }

  const addRule = (): void => {
    setDraft((current) => ({
      ...current,
      categoryRules: [...current.categoryRules, { field: '', value: '', lsCategory: '' }],
    }))
  }

  const removeRule = (index: number): void => {
    setDraft((current) => ({
      ...current,
      categoryRules: current.categoryRules.filter((_, i) => i !== index),
    }))
  }

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Custom mapping"
      className="fixed inset-0 z-40 grid place-items-center bg-black/50 p-4"
    >
      <div className="flex max-h-[90vh] w-full max-w-3xl flex-col gap-3 overflow-auto rounded-[var(--radius-card)] border border-border bg-surface p-4">
        <div className="flex items-center justify-between">
          <h2 className="text-base font-medium text-text">Custom mapping</h2>
          <Button onClick={onClose}>Cancel</Button>
        </div>
        <StepList step={step} />

        {step === 1 ? (
          <section className="space-y-3">
            <p className="text-sm text-muted">
              Paste a few lines of the file to map. The sample is never stored; it is used only to
              suggest fields and to dry-run the profile.
            </p>
            {source !== null ? (
              <Button disabled={fetchSample.isPending} onClick={() => { fetchSample.mutate() }}>
                Use first lines of {source.filename}
              </Button>
            ) : null}
            <textarea
              rows={8}
              value={sample}
              aria-label="Sample"
              onChange={(event) => {
                setSample(event.target.value)
                setLogType(guessLogType(event.target.value))
                setPreview(null)
              }}
              placeholder='{"@timestamp":"2026-10-08T10:00:00Z","host.name":"web-01","message":"..."}'
              className="w-full rounded-[var(--radius-control)] border border-border bg-surface-2 p-2 font-mono text-xs text-text"
            />
            <div className="grid gap-3 sm:grid-cols-2">
              <label className="flex flex-col gap-1 text-sm">
                <span className="text-muted">Log type</span>
                <select
                  value={logType}
                  onChange={(event) => {
                    setLogType(event.target.value === 'generic_json' ? 'generic_json' : 'generic_csv')
                  }}
                  className="rounded-[var(--radius-control)] border border-border bg-surface-2 px-2 py-1 text-text"
                >
                  <option value="generic_json">generic_json</option>
                  <option value="generic_csv">generic_csv</option>
                </select>
              </label>
              <label className="flex flex-col gap-1 text-sm">
                <span className="text-muted">Profile name</span>
                <input
                  value={draft.name}
                  aria-label="Profile name"
                  onChange={(event) => {
                    updateDraft({ name: event.target.value })
                  }}
                  className="rounded-[var(--radius-control)] border border-border bg-surface-2 px-2 py-1 font-mono text-text"
                />
                {draft.name !== '' && !nameValid ? (
                  <span className="text-xs text-sev-critical-text">
                    Use letters, digits, dot, dash or underscore; start alphanumeric.
                  </span>
                ) : null}
              </label>
            </div>
          </section>
        ) : null}

        {step === 2 ? (
          <section className="space-y-3">
            <p className="text-sm text-muted">
              A saved profile can be the starting point. The suggested match comes from the
              profile&apos;s <code>applies_when</code> keys.
            </p>
            {loadError !== null ? <p className="text-sm text-sev-critical-text">{loadError}</p> : null}
            {profiles.isPending ? <p className="text-sm text-muted">Loading profiles…</p> : null}
            {profiles.data !== undefined ? (
              <ul className="max-h-64 space-y-1 overflow-auto">
                {profiles.data.items.map((profile) => (
                  <li key={profile.name} className="flex items-center justify-between gap-2 text-sm">
                    <span className="min-w-0 truncate">
                      <span className="font-mono text-text">{profile.name}</span>
                      {profile.name === suggestion ? (
                        <span className="ml-2 rounded bg-accent/20 px-1 text-xs text-accent-text">suggested</span>
                      ) : null}
                      {profile.builtin ? <span className="ml-2 text-xs text-muted">builtin</span> : null}
                    </span>
                    <Button
                      disabled={loadExisting.isPending}
                      onClick={() => {
                        loadExisting.mutate(profile.name)
                      }}
                    >
                      Use
                    </Button>
                  </li>
                ))}
              </ul>
            ) : null}
            <Button
              variant="primary"
              onClick={() => {
                setStep(3)
              }}
            >
              Start blank
            </Button>
          </section>
        ) : null}

        {step === 3 ? (
          <section className="space-y-4">
            <div className="grid gap-3 sm:grid-cols-3">
              <label className="flex flex-col gap-1 text-sm">
                <span className="text-muted">Timestamp path</span>
                <input
                  value={draft.timestampPath}
                  aria-label="Timestamp path"
                  list="mw-paths"
                  onChange={(event) => {
                    updateDraft({ timestampPath: event.target.value })
                    setPreview(null)
                  }}
                  className="rounded-[var(--radius-control)] border border-border bg-surface-2 px-2 py-1 font-mono text-xs text-text"
                />
              </label>
              <label className="flex flex-col gap-1 text-sm">
                <span className="text-muted">Timestamp format</span>
                <select
                  value={draft.timestampFormat}
                  onChange={(event) => {
                    updateDraft({ timestampFormat: event.target.value })
                    setPreview(null)
                  }}
                  className="rounded-[var(--radius-control)] border border-border bg-surface-2 px-2 py-1 text-text"
                >
                  {TIMESTAMP_FORMATS.map((format) => (
                    <option key={format} value={format}>
                      {format}
                    </option>
                  ))}
                </select>
              </label>
              <label className="flex flex-col gap-1 text-sm">
                <span className="text-muted">Timezone</span>
                <input
                  value={draft.timezone}
                  aria-label="Timezone"
                  onChange={(event) => {
                    updateDraft({ timezone: event.target.value })
                    setPreview(null)
                  }}
                  placeholder="UTC"
                  className="rounded-[var(--radius-control)] border border-border bg-surface-2 px-2 py-1 font-mono text-xs text-text"
                />
              </label>
            </div>

            <datalist id="mw-paths">
              {paths.map((path) => (
                <option key={path} value={path} />
              ))}
            </datalist>

            <label className="flex flex-col gap-1 text-sm">
              <span className="text-muted">applies_when keys (one per line)</span>
              <textarea
                rows={3}
                value={appliesText}
                aria-label="applies_when keys"
                onChange={(event) => {
                  setAppliesText(event.target.value)
                  updateDraft({
                    appliesWhen: event.target.value
                      .split(/\r?\n/)
                      .map((line) => line.trim())
                      .filter((line) => line !== ''),
                  })
                  setPreview(null)
                }}
                className="w-full rounded-[var(--radius-control)] border border-border bg-surface-2 p-2 font-mono text-xs text-text"
              />
            </label>

            <fieldset className="space-y-2">
              <legend className="text-sm text-muted">Fields</legend>
              <div className="grid gap-2 sm:grid-cols-2">
                {NORMALIZED_FIELDS.map((field) => (
                  <label key={field.name} className="flex items-center gap-2 text-sm">
                    <span className="w-40 shrink-0 text-muted">{field.label}</span>
                    <input
                      value={draft.fields[field.name] ?? ''}
                      aria-label={`${field.label} path`}
                      list="mw-paths"
                      onChange={(event) => {
                        setField(field.name, event.target.value)
                        setPreview(null)
                      }}
                      className="w-full rounded-[var(--radius-control)] border border-border bg-surface-2 px-2 py-1 font-mono text-xs text-text"
                    />
                  </label>
                ))}
              </div>
            </fieldset>

            <label className="flex flex-col gap-1 text-sm">
              <span className="text-muted">Default category</span>
              <input
                value={draft.defaultCategory}
                aria-label="Default category"
                onChange={(event) => {
                  updateDraft({ defaultCategory: event.target.value })
                  setPreview(null)
                }}
                placeholder="process"
                className="rounded-[var(--radius-control)] border border-border bg-surface-2 px-2 py-1 font-mono text-xs text-text"
              />
            </label>

            <fieldset className="space-y-2">
              <legend className="flex items-center gap-2 text-sm text-muted">
                Category rules
                <Button onClick={addRule}>
                  <Plus aria-hidden="true" size={14} /> Add
                </Button>
              </legend>
              {draft.categoryRules.map((rule, index) => (
                <div key={index} className="flex items-center gap-2 text-sm">
                  <input
                    value={rule.field}
                    aria-label={`Rule ${index + 1} field`}
                    list="mw-paths"
                    placeholder="field path"
                    onChange={(event) => {
                      setRule(index, { field: event.target.value })
                      setPreview(null)
                    }}
                    className="w-1/3 rounded-[var(--radius-control)] border border-border bg-surface-2 px-2 py-1 font-mono text-xs text-text"
                  />
                  <input
                    value={rule.value}
                    aria-label={`Rule ${index + 1} value`}
                    placeholder="equals"
                    onChange={(event) => {
                      setRule(index, { value: event.target.value })
                      setPreview(null)
                    }}
                    className="w-1/4 rounded-[var(--radius-control)] border border-border bg-surface-2 px-2 py-1 font-mono text-xs text-text"
                  />
                  <input
                    value={rule.lsCategory}
                    aria-label={`Rule ${index + 1} category`}
                    placeholder="category"
                    onChange={(event) => {
                      setRule(index, { lsCategory: event.target.value })
                      setPreview(null)
                    }}
                    className="w-1/4 rounded-[var(--radius-control)] border border-border bg-surface-2 px-2 py-1 font-mono text-xs text-text"
                  />
                  <Button
                    variant="danger"
                    aria-label={`Remove rule ${index + 1}`}
                    onClick={() => {
                      removeRule(index)
                      setPreview(null)
                    }}
                  >
                    <Trash2 aria-hidden="true" size={14} />
                  </Button>
                </div>
              ))}
            </fieldset>
          </section>
        ) : null}

        {step === 4 ? (
          <section className="space-y-3">
            <div className="flex items-center gap-2">
              <Button
                variant="primary"
                disabled={previewRun.isPending}
                onClick={() => {
                  previewRun.mutate()
                }}
              >
                Run preview
              </Button>
              <span className="text-sm text-muted">Up to 20 normalized rows.</span>
            </div>
            {previewRun.isError ? (
              <ErrorPanel title="Preview failed" message="The profile was rejected or the sample could not be parsed." />
            ) : null}
            {preview !== null ? (
              <>
                <p className="text-sm text-muted">
                  {preview.row_count} rows · {preview.error_count} errors
                </p>
                <div className="overflow-auto">
                  <table className="w-full text-left text-xs">
                    <thead>
                      <tr className="text-muted">
                        {PREVIEW_COLUMNS.map((column) => (
                          <th key={column} className="py-1 pr-3">
                            {column}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {preview.rows.map((row, index) => (
                        <tr key={index} className="border-t border-border">
                          {PREVIEW_COLUMNS.map((column) => (
                            <td key={column} className="py-1 pr-3 font-mono text-text">
                              {cell(row, column)}
                            </td>
                          ))}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {preview.errors.length > 0 ? (
                  <ul className="space-y-1 text-xs text-sev-medium-text">
                    {preview.errors.map((error) => (
                      <li key={error.record_ref}>
                        {error.record_ref}: {error.reason}
                      </li>
                    ))}
                  </ul>
                ) : null}
              </>
            ) : null}
          </section>
        ) : null}

        {step === 5 ? (
          <section className="space-y-3">
            <p className="text-sm text-muted">
              Save <span className="font-mono text-text">{draft.name}</span>
              {source !== null ? (
                <>
                  {' '}
                  and re-parse <span className="text-text">{source.filename}</span> as{' '}
                  <span className="font-mono text-text">{logType}</span>.
                </>
              ) : (
                '.'
              )}
            </p>
            {save.isError ? (
              <ErrorPanel title="Could not save" message="The profile was rejected. Check the name and fields." />
            ) : null}
            <Button
              variant="primary"
              disabled={save.isPending}
              onClick={() => {
                save.mutate()
              }}
            >
              Save profile
            </Button>
          </section>
        ) : null}

        <div className="flex items-center justify-between border-t border-border pt-3">
          <Button
            disabled={step === 1}
            onClick={() => {
              setStep((current) => Math.max(1, current - 1))
            }}
          >
            Back
          </Button>
          {step < 5 ? (
            <Button
              variant="primary"
              disabled={(step === 1 && (sample.trim() === '' || !nameValid)) || (step === 3 && !timestampValid)}
              onClick={() => {
                setStep((current) => Math.min(5, current + 1))
              }}
            >
              Next
            </Button>
          ) : null}
        </div>
      </div>
    </div>
  )
}
