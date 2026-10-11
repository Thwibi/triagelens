import type { ReactElement } from 'react'
import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useMutation, useQueryClient } from '@tanstack/react-query'

import { createCase, deleteCase, patchCase } from '../../api/endpoints'
import { useCasesQuery } from '../../api/hooks'
import { queryKeys } from '../../api/queryKeys'
import type { Case } from '../../api/types'
import { formatSince } from '../../lib/format'
import { Button } from '../../ui/Button'
import { EmptyState } from '../../ui/EmptyState'
import { ErrorPanel } from '../../ui/ErrorPanel'
import { SkeletonRows } from '../../ui/Skeleton'

function NewCaseForm({ onDone }: { readonly onDone: (created: Case | null) => void }): ReactElement {
  const queryClient = useQueryClient()
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [timezone, setTimezone] = useState(() => Intl.DateTimeFormat().resolvedOptions().timeZone)
  const create = useMutation({
    mutationFn: () =>
      createCase({
        name: name.trim(),
        ...(description.trim() !== '' ? { description: description.trim() } : {}),
        default_timezone: timezone.trim() === '' ? 'UTC' : timezone.trim(),
      }),
    onSuccess: (created) => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.cases() })
      onDone(created)
    },
  })

  const valid = name.trim().length > 0

  return (
    <form
      className="space-y-3 rounded-[var(--radius-card)] border border-border bg-surface p-4"
      onSubmit={(event) => {
        event.preventDefault()
        if (valid) {
          create.mutate()
        }
      }}
    >
      <div className="grid gap-3 sm:grid-cols-2">
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-muted">Name</span>
          <input
            required
            autoFocus
            value={name}
            onChange={(event) => {
              setName(event.target.value)
            }}
            className="rounded-[var(--radius-control)] border border-border bg-surface-2 px-2 py-1 text-text"
          />
        </label>
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-muted">Default timezone</span>
          <input
            value={timezone}
            onChange={(event) => {
              setTimezone(event.target.value)
            }}
            className="rounded-[var(--radius-control)] border border-border bg-surface-2 px-2 py-1 font-mono text-text"
          />
        </label>
      </div>
      <label className="flex flex-col gap-1 text-sm">
        <span className="text-muted">Description</span>
        <textarea
          rows={2}
          value={description}
          onChange={(event) => {
            setDescription(event.target.value)
          }}
          className="rounded-[var(--radius-control)] border border-border bg-surface-2 px-2 py-1 text-text"
        />
      </label>
      {create.isError ? <p className="text-sm text-sev-critical">Could not create the case.</p> : null}
      <div className="flex gap-2">
        <Button type="submit" variant="primary" disabled={!valid || create.isPending}>
          Create case
        </Button>
        <Button
          onClick={() => {
            onDone(null)
          }}
        >
          Cancel
        </Button>
      </div>
    </form>
  )
}

function RenameForm({ target, onDone }: { readonly target: Case; readonly onDone: () => void }): ReactElement {
  const queryClient = useQueryClient()
  const [name, setName] = useState(target.name)
  const rename = useMutation({
    mutationFn: () => patchCase(target.id, { name: name.trim() }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.cases() })
      onDone()
    },
  })
  return (
    <form
      className="flex items-center gap-2"
      onSubmit={(event) => {
        event.preventDefault()
        if (name.trim().length > 0) {
          rename.mutate()
        }
      }}
    >
      <input
        autoFocus
        value={name}
        onChange={(event) => {
          setName(event.target.value)
        }}
        aria-label="New case name"
        className="rounded-[var(--radius-control)] border border-border bg-surface-2 px-2 py-1 text-sm text-text"
      />
      <Button type="submit" variant="primary" disabled={name.trim().length === 0 || rename.isPending}>
        Save
      </Button>
      <Button onClick={onDone}>Cancel</Button>
    </form>
  )
}

function DeleteDialog({ target, onClose }: { readonly target: Case; readonly onClose: () => void }): ReactElement {
  const queryClient = useQueryClient()
  const [typed, setTyped] = useState('')
  const remove = useMutation({
    mutationFn: () => deleteCase(target.id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.cases() })
      onClose()
    },
  })
  return (
    <div role="dialog" aria-modal="true" aria-label="Delete case" className="fixed inset-0 z-30 grid place-items-center bg-black/50 p-4">
      <div className="w-full max-w-md space-y-3 rounded-[var(--radius-card)] border border-border bg-surface p-4">
        <h2 className="text-base font-medium text-text">Delete “{target.name}”</h2>
        <p className="text-sm text-muted">
          This removes the case and everything under it. Type the case name to confirm.
        </p>
        <input
          autoFocus
          value={typed}
          onChange={(event) => {
            setTyped(event.target.value)
          }}
          aria-label="Case name confirmation"
          className="w-full rounded-[var(--radius-control)] border border-border bg-surface-2 px-2 py-1 text-sm text-text"
        />
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="danger"
            disabled={typed !== target.name || remove.isPending}
            onClick={() => {
              remove.mutate()
            }}
          >
            Delete case
          </Button>
        </div>
      </div>
    </div>
  )
}

function CaseCard({ item }: { readonly item: Case }): ReactElement {
  const navigate = useNavigate()
  const [mode, setMode] = useState<'view' | 'rename'>('view')
  const [confirming, setConfirming] = useState(false)

  return (
    <li className="flex flex-col gap-3 rounded-[var(--radius-card)] border border-border bg-surface p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          {mode === 'rename' ? (
            <RenameForm
              target={item}
              onDone={() => {
                setMode('view')
              }}
            />
          ) : (
            <>
              <h2 className="truncate text-base font-medium text-text">{item.name}</h2>
              {item.description !== null && item.description !== '' ? (
                <p className="truncate text-sm text-muted">{item.description}</p>
              ) : null}
            </>
          )}
        </div>
        <span className="shrink-0 text-xs text-muted">Updated {formatSince(Date.parse(item.updated_at))}</span>
      </div>

      <dl className="grid grid-cols-4 gap-2 text-center">
        {(
          [
            ['Sources', item.counts.sources],
            ['Events', item.counts.events],
            ['Alerts', item.counts.alerts],
            ['IOCs', item.counts.iocs],
          ] as const
        ).map(([label, value]) => (
          <div key={label} className="rounded bg-surface-2 px-2 py-1">
            <dt className="text-xs text-muted">{label}</dt>
            <dd className="font-mono text-sm text-text">{value.toLocaleString()}</dd>
          </div>
        ))}
      </dl>

      <div className="flex flex-wrap gap-2">
        <Button
          variant="primary"
          onClick={() => {
            void navigate(`/cases/${encodeURIComponent(item.id)}`)
          }}
        >
          Open
        </Button>
        <Button
          onClick={() => {
            setMode('rename')
          }}
        >
          Rename
        </Button>
        <Button
          variant="danger"
          onClick={() => {
            setConfirming(true)
          }}
        >
          Delete
        </Button>
      </div>

      {confirming ? (
        <DeleteDialog
          target={item}
          onClose={() => {
            setConfirming(false)
          }}
        />
      ) : null}
    </li>
  )
}

/** Cases home (spec 07 section 3.1). */
export function CasesPage(): ReactElement {
  const cases = useCasesQuery()
  const navigate = useNavigate()
  const [creating, setCreating] = useState(false)

  return (
    <section aria-labelledby="cases-heading" className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 id="cases-heading" className="text-xl font-semibold text-text">
          Cases
        </h1>
        {creating ? null : (
          <Button
            variant="primary"
            onClick={() => {
              setCreating(true)
            }}
          >
            New case
          </Button>
        )}
      </div>

      {creating ? (
        <NewCaseForm
          onDone={(created) => {
            setCreating(false)
            if (created !== null) {
              void navigate(`/cases/${encodeURIComponent(created.id)}`)
            }
          }}
        />
      ) : null}

      {cases.isPending ? <SkeletonRows rows={3} /> : null}
      {cases.isError ? (
        <ErrorPanel
          title="Cannot load cases"
          message="The local API did not return the case list."
          onRetry={() => {
            void cases.refetch()
          }}
        />
      ) : null}

      {cases.data !== undefined ? (
        cases.data.items.length === 0 ? (
          <EmptyState
            title="Create your first case"
            detail="A case groups the sources, events and alerts for one investigation. Drag files in once it exists."
            action={
              <Button
                variant="primary"
                onClick={() => {
                  setCreating(true)
                }}
              >
                New case
              </Button>
            }
          />
        ) : (
          <ul className="grid gap-3 md:grid-cols-2">
            {cases.data.items.map((item) => (
              <CaseCard key={item.id} item={item} />
            ))}
          </ul>
        )
      ) : null}
    </section>
  )
}
