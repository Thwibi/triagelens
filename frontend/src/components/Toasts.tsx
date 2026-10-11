import type { ReactElement } from 'react'
import { X } from 'lucide-react'

import { useToast } from '../ui/ToastProvider'

const TONE_CLASS: Readonly<Record<'info' | 'success' | 'error', string>> = {
  info: 'border-border bg-surface-2 text-text',
  success: 'border-accent/50 bg-accent/10 text-text',
  error: 'border-sev-critical/50 bg-sev-critical/10 text-text',
}

/** Corner live region for background outcomes and failures. */
export function Toasts(): ReactElement {
  const { toasts, dismiss } = useToast()
  return (
    <div aria-live="polite" aria-atomic="false" className="pointer-events-none fixed bottom-4 right-4 z-30 flex w-80 flex-col gap-2">
      {toasts.map((toast) => (
        <div
          key={toast.id}
          role={toast.tone === 'error' ? 'alert' : 'status'}
          className={`pointer-events-auto flex items-start gap-2 rounded-[var(--radius-card)] border p-3 text-sm shadow-lg ${TONE_CLASS[toast.tone]}`}
        >
          <span className="flex-1">{toast.message}</span>
          <button
            type="button"
            aria-label="Dismiss"
            onClick={() => {
              dismiss(toast.id)
            }}
            className="text-muted hover:text-text"
          >
            <X aria-hidden="true" size={14} />
          </button>
        </div>
      ))}
    </div>
  )
}
