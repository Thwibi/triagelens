import type { ReactElement } from 'react'
import { Copy } from 'lucide-react'

import { useToast } from './ToastProvider'
import { Button } from './Button'

/** Copy any log-derived string to the clipboard, with a toast outcome. */
export function CopyButton({ value, label }: { readonly value: string; readonly label?: string }): ReactElement {
  const { push } = useToast()
  return (
    <Button
      variant="ghost"
      aria-label={label ?? `Copy ${value}`}
      onClick={() => {
        void (async () => {
          try {
            await navigator.clipboard.writeText(value)
            push('success', 'Copied to clipboard')
          } catch {
            push('error', 'Clipboard is unavailable')
          }
        })()
      }}
    >
      <Copy aria-hidden="true" size={14} />
    </Button>
  )
}
