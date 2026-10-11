import { useEffect, useRef } from 'react'
import type { ReactElement } from 'react'
import { EditorState } from '@codemirror/state'
import type { Extension } from '@codemirror/state'
import { EditorView, lineNumbers } from '@codemirror/view'
import { yaml } from '@codemirror/lang-yaml'

/**
 * A read-only code view (spec 07 sections 3.4 and 3.7).
 *
 * Rendered as a live CodeMirror so log-derived text is laid out by the editor's
 * own text nodes; nothing here writes HTML, so untrusted content cannot become
 * markup.
 */
export interface CodeBlockProps {
  readonly value: string
  readonly ariaLabel: string
  readonly language?: 'yaml' | 'plain'
  readonly wrap?: boolean
}

function extensionsFor(options: {
  readonly language?: 'yaml' | 'plain' | undefined
  readonly wrap?: boolean | undefined
}): Extension[] {
  const list: Extension[] = [
    lineNumbers(),
    EditorState.readOnly.of(true),
    EditorView.editable.of(false),
  ]
  if (options.language === 'yaml') {
    list.push(yaml())
  }
  if (options.wrap ?? false) {
    list.push(EditorView.lineWrapping)
  }
  return list
}

export function CodeBlock({ value, ariaLabel, language, wrap }: CodeBlockProps): ReactElement {
  const host = useRef<HTMLDivElement | null>(null)

  useEffect(() => {
    const parent = host.current
    if (parent === null) {
      return undefined
    }
    const view = new EditorView({
      state: EditorState.create({ doc: value, extensions: extensionsFor({ language, wrap }) }),
      parent,
    })
    return () => {
      view.destroy()
    }
    // Rebuilt when the value or options change: these views are small and
    // read-only, so a fresh editor is simpler than imperative reconfiguration.
  }, [value, language, wrap])

  return (
    <div
      ref={host}
      role="group"
      aria-label={ariaLabel}
      className="max-h-96 overflow-auto rounded border border-border text-xs"
    />
  )
}
