import { useEffect, useRef, useState } from 'react'
import type { ReactElement } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { X } from 'lucide-react'

import {
  createRule,
  deleteRule,
  replaceRule,
  setRuleEnabled,
  testRule,
  validateRule,
} from '../../api/endpoints'
import { useRuleQuery } from '../../api/hooks'
import { invalidateRules } from '../../api/invalidate'
import type { RuleTestResult, RuleValidateResult } from '../../api/types'
import { useCaseId } from '../../app/caseRoute'
import { formatTimestamp } from '../../lib/format'
import { Button } from '../../ui/Button'
import { CodeBlock } from '../../ui/CodeBlock'
import { CodeEditor } from '../../ui/CodeEditor'
import { ErrorPanel } from '../../ui/ErrorPanel'
import { SkeletonRows } from '../../ui/Skeleton'
import { useToast } from '../../ui/ToastProvider'
import { healthOf, kindLabel, logsourceSummary, ruleTechniques, toAlertLevel } from './ruleFormat'
import { SeverityBadge } from '../../ui/Badge'

/** A minimal custom-rule skeleton offered when creating from scratch. */
const NEW_RULE_TEMPLATE = `title: New custom rule
id: new-custom-rule
status: experimental
description: Describe what this rule detects.
level: medium
logsource:
  product: windows
detection:
  selection:
    event_id: 1
  condition: selection
`

/** Rewrite the first top-level `id:` line so a copy no longer collides. */
function withCopiedId(yaml: string): string {
  return yaml.replace(/^id:\s*(\S+)\s*$/m, (_match, id: string) => `id: ${id}-copy`)
}

function Field({ label, value }: { readonly label: string; readonly value: string }): ReactElement {
  return (
    <div className="flex justify-between gap-2">
      <dt className="text-muted">{label}</dt>
      <dd className="truncate font-mono text-text">{value}</dd>
    </div>
  )
}

/**
 * The rule detail/editor drawer (spec 07 section 3.10).
 *
 * In create mode (`ruleId` null) it starts from a template; otherwise it loads
 * the stored YAML. Only custom rules may be saved in place or deleted; built-in
 * and Sigma rules offer **Duplicate to custom** instead.
 */
export function RuleDrawer({ ruleId, onClose }: { readonly ruleId: string | null; readonly onClose: () => void }): ReactElement {
  const caseId = useCaseId()
  const queryClient = useQueryClient()
  const { push } = useToast()
  const rule = useRuleQuery(ruleId)
  const panel = useRef<HTMLDivElement | null>(null)

  const isCreate = ruleId === null
  const [yaml, setYaml] = useState(isCreate ? NEW_RULE_TEMPLATE : '')
  const [editing, setEditing] = useState(isCreate)
  const [validation, setValidation] = useState<RuleValidateResult | null>(null)
  const [test, setTest] = useState<RuleTestResult | null>(null)

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

  useEffect(() => {
    if (rule.data !== undefined) {
      setYaml(rule.data.yaml)
    }
  }, [rule.data])

  const detail = rule.data
  const canEditInPlace = isCreate || detail?.kind === 'custom'

  const validate = useMutation({
    mutationFn: (text: string) => validateRule(text),
    onSuccess: (result) => { setValidation(result) },
  })

  const runTest = useMutation({
    mutationFn: (text: string) => {
      if (caseId === null) {
        throw new Error('A case is required to test a rule.')
      }
      return testRule({ yaml: text, case_id: caseId, limit: 20 })
    },
    onSuccess: (result) => { setTest(result) },
  })

  const save = useMutation({
    mutationFn: async (text: string): Promise<void> => {
      if (ruleId === null) {
        await createRule(text)
      } else {
        await replaceRule(ruleId, text)
      }
    },
    onSuccess: () => {
      invalidateRules(queryClient, ruleId ?? undefined)
      push('success', isCreate ? 'Rule created' : 'Rule saved')
      setEditing(isCreate)
      setValidation(null)
    },
    onError: (error) => {
      push('error', error instanceof Error ? error.message : 'Save failed')
    },
  })

  const duplicate = useMutation({
    mutationFn: (text: string) => createRule(withCopiedId(text)),
    onSuccess: () => {
      invalidateRules(queryClient)
      push('success', 'Rule duplicated to custom')
    },
    onError: (error) => {
      push('error', error instanceof Error ? error.message : 'Duplicate failed')
    },
  })

  const toggle = useMutation({
    mutationFn: (enabled: boolean) => {
      if (ruleId === null) {
        throw new Error('A rule id is required.')
      }
      return setRuleEnabled(ruleId, enabled)
    },
    onSuccess: (_data, enabled) => {
      invalidateRules(queryClient, ruleId ?? undefined)
      push('success', enabled ? 'Rule enabled' : 'Rule disabled')
    },
  })

  const remove = useMutation({
    mutationFn: () => {
      if (ruleId === null) {
        throw new Error('A rule id is required.')
      }
      return deleteRule(ruleId)
    },
    onSuccess: () => {
      invalidateRules(queryClient)
      push('success', 'Rule deleted')
      onClose()
    },
    onError: (error) => {
      push('error', error instanceof Error ? error.message : 'Delete failed')
    },
  })

  const problems = validation?.problems ?? []
  const health = detail !== undefined ? healthOf(detail) : null
  const level = detail !== undefined ? toAlertLevel(detail.level) : null

  return (
    <aside
      ref={panel}
      role="dialog"
      aria-modal="true"
      aria-label={isCreate ? 'New rule' : 'Rule detail'}
      tabIndex={-1}
      className="fixed inset-y-0 right-0 z-30 flex w-[46rem] max-w-full flex-col border-l border-border bg-surface shadow-xl"
    >
      <div className="flex items-center justify-between border-b border-border px-4 py-2">
        <h2 className="truncate text-sm font-medium text-text">
          {isCreate ? 'New custom rule' : detail?.title ?? 'Rule'}
        </h2>
        <Button variant="ghost" aria-label="Close rule" onClick={onClose}>
          <X aria-hidden="true" size={16} />
        </Button>
      </div>

      <div className="flex-1 space-y-3 overflow-auto p-4">
        {rule.isPending && !isCreate ? <SkeletonRows rows={6} /> : null}
        {rule.isError ? (
          <ErrorPanel title="Cannot load rule" message="The rule may have been removed." onRetry={() => { void rule.refetch() }} />
        ) : null}

        {detail !== undefined ? (
          <>
            <div className="flex items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                {level !== null ? <SeverityBadge level={level} /> : <span className="text-sm text-text">{detail.level}</span>}
                <span className="rounded bg-surface-2 px-1.5 py-0.5 text-xs text-muted">{kindLabel(detail.kind)}</span>
                <span className="text-xs text-muted">{detail.rule_type}</span>
              </div>
              {health !== null ? <span className="text-xs text-muted">{health.label}</span> : null}
            </div>
            <dl className="grid grid-cols-2 gap-x-4 gap-y-0.5 text-xs">
              <Field label="Status" value={detail.status} />
              <Field label="Logsource" value={logsourceSummary(detail)} />
              <Field label="File" value={detail.file_path} />
              <Field label="SHA-256" value={detail.sha256.slice(0, 16)} />
              <Field label="Updated" value={formatTimestamp(Date.parse(detail.updated_at))} />
              <Field label="Techniques" value={ruleTechniques(detail).join(', ') || '—'} />
            </dl>
            {detail.compile_error !== null ? (
              <ErrorPanel title="Compile error" message={detail.compile_error} />
            ) : null}
            <label className="flex items-center gap-2 text-sm text-text">
              <input
                type="checkbox"
                checked={detail.enabled}
                disabled={toggle.isPending}
                onChange={(event) => { toggle.mutate(event.target.checked) }}
              />
              Enabled
            </label>
          </>
        ) : null}

        <div className="space-y-2 border-t border-border pt-3">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-medium uppercase tracking-wide text-muted">YAML</h3>
            <Button variant="ghost" onClick={() => { setEditing((value) => !value) }} disabled={!canEditInPlace}>
              {editing ? 'View' : 'Edit'}
            </Button>
          </div>
          {editing ? (
            <CodeEditor value={yaml} onChange={setYaml} language="yaml" ariaLabel="Rule YAML editor" />
          ) : (
            <CodeBlock value={yaml} language="yaml" wrap ariaLabel="Rule YAML" />
          )}
          <div className="flex flex-wrap gap-2">
            <Button
              disabled={validate.isPending}
              onClick={() => { validate.mutate(yaml) }}
            >
              {validate.isPending ? 'Validating…' : 'Validate'}
            </Button>
            <Button
              disabled={runTest.isPending || caseId === null}
              onClick={() => { runTest.mutate(yaml) }}
            >
              {runTest.isPending ? 'Testing…' : 'Test on case'}
            </Button>
            <Button
              variant="primary"
              disabled={!canEditInPlace || save.isPending}
              onClick={() => { save.mutate(yaml) }}
            >
              {isCreate ? 'Create' : 'Save'}
            </Button>
            {!isCreate && detail?.kind !== 'custom' ? (
              <Button disabled={duplicate.isPending} onClick={() => { duplicate.mutate(yaml) }}>
                Duplicate to custom
              </Button>
            ) : null}
            {!isCreate && detail?.kind === 'custom' ? (
              <Button
                variant="danger"
                disabled={remove.isPending}
                onClick={() => { remove.mutate() }}
              >
                Delete
              </Button>
            ) : null}
          </div>
        </div>

        {validation !== null ? (
          <section className="space-y-1 border-t border-border pt-3">
            <h3 className="text-xs font-medium uppercase tracking-wide text-muted">
              {validation.valid ? 'Valid' : 'Validation problems'}
            </h3>
            {problems.length === 0 ? (
              <p className="text-sm text-muted">No problems found.</p>
            ) : (
              <ul className="space-y-1">
                {problems.map((problem) => (
                  <li key={`${problem.where}:${problem.error}`} className="text-xs">
                    <span className="font-mono text-muted">{problem.where}</span>: {problem.error}
                  </li>
                ))}
              </ul>
            )}
          </section>
        ) : null}

        {test !== null ? (
          <section className="space-y-1 border-t border-border pt-3">
            <h3 className="text-xs font-medium uppercase tracking-wide text-muted">
              Test: {test.total_matches} match{test.total_matches === 1 ? '' : 'es'}
              {test.executed ? '' : ' (timed out)'}
            </h3>
            {test.items.length === 0 ? (
              <p className="text-sm text-muted">No sample events to show.</p>
            ) : (
              <ul className="space-y-0.5">
                {test.items.map((item) => (
                  <li key={item.id} className="truncate text-xs">
                    <span className="font-mono text-muted">{formatTimestamp(item.ts_ms)}</span>{' '}
                    <span className="text-text">{item.message ?? item.event_action ?? item.log_type ?? 'event'}</span>
                  </li>
                ))}
              </ul>
            )}
          </section>
        ) : null}
      </div>
    </aside>
  )
}
