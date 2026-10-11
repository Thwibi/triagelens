import { createContext, useCallback, useContext, useMemo, useRef, useState } from 'react'
import type { ReactElement, ReactNode } from 'react'

/** A transient notification shown in the corner live region. */
export interface Toast {
  readonly id: number
  readonly tone: 'info' | 'success' | 'error'
  readonly message: string
}

export interface ToastContextValue {
  readonly toasts: readonly Toast[]
  readonly push: (tone: Toast['tone'], message: string) => void
  readonly dismiss: (id: number) => void
}

const ToastContext = createContext<ToastContextValue | null>(null)

/** How long a toast stays before it removes itself. */
export const TOAST_TTL_MS = 6_000

export function ToastProvider({ children }: { readonly children: ReactNode }): ReactElement {
  const [toasts, setToasts] = useState<readonly Toast[]>([])
  const nextId = useRef(1)

  const dismiss = useCallback((id: number): void => {
    setToasts((current) => current.filter((toast) => toast.id !== id))
  }, [])

  const push = useCallback(
    (tone: Toast['tone'], message: string): void => {
      const id = nextId.current
      nextId.current += 1
      setToasts((current) => [...current, { id, tone, message }])
      setTimeout(() => {
        dismiss(id)
      }, TOAST_TTL_MS)
    },
    [dismiss],
  )

  const value = useMemo<ToastContextValue>(() => ({ toasts, push, dismiss }), [dismiss, push, toasts])

  return <ToastContext.Provider value={value}>{children}</ToastContext.Provider>
}

export function useToast(): ToastContextValue {
  const value = useContext(ToastContext)
  if (value === null) {
    throw new Error('useToast must be used inside a ToastProvider')
  }
  return value
}
