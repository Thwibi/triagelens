import { useEffect, useRef } from 'react'
import type { ReactElement } from 'react'
import { EditorView } from '@codemirror/view'
import { EditorState } from '@codemirror/state'
import type { Extension } from '@codemirror/state'
import { basicSetup } from 'codemirror'
import { yaml } from '@codemirror/lang-yaml'

/**
 * An editable code view (spec 07 section 3.10).
 *
 * The editor owns its document between external updates: an internal keystroke
 * fires `onChange` without re-creating the view (so the cursor never resets),
 * and an external `value` change is dispatched as a replace.
 */
export interface CodeEditorProps {
  readonly value: string
  readonly onChange: (value: string) => void
  readonly ariaLabel: string
  readonly language?: 'yaml' | 'plain'
}

export function CodeEditor({ value, onChange, ariaLabel, language }: CodeEditorProps): ReactElement {
  const host = useRef<HTMLDivElement | null>(null)
  const viewRef = useRef<EditorView | null>(null)
  const valueRef = useRef(value)
  const onChangeRef = useRef(onChange)

  valueRef.current = value
  onChangeRef.current = onChange

  useEffect(() => {
    const parent = host.current
    if (parent === null) {
      return undefined
    }
    const extensions: Extension[] = [
      basicSetup,
      EditorView.updateListener.of((update) => {
        if (update.docChanged) {
          onChangeRef.current(update.state.doc.toString())
        }
      }),
    ]
    if (language === 'yaml') {
      extensions.push(yaml())
    }
    const view = new EditorView({
      state: EditorState.create({ doc: valueRef.current, extensions }),
      parent,
    })
    viewRef.current = view
    return () => {
      view.destroy()
      viewRef.current = null
    }
  }, [language])

  useEffect(() => {
    const view = viewRef.current
    if (view !== null && view.state.doc.toString() !== value) {
      view.dispatch({ changes: { from: 0, to: view.state.doc.length, insert: value } })
    }
  }, [value])

  return (
    <div
      ref={host}
      role="group"
      aria-label={ariaLabel}
      className="max-h-96 min-h-48 overflow-auto rounded border border-border bg-surface-2 text-xs"
    />
  )
}
