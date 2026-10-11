import type { ButtonHTMLAttributes, ReactElement } from 'react'

export type ButtonVariant = 'primary' | 'default' | 'danger' | 'ghost'

const VARIANT_CLASS: Readonly<Record<ButtonVariant, string>> = {
  primary: 'border-transparent bg-accent text-black hover:opacity-90',
  default: 'border-border bg-surface-2 text-text hover:bg-surface',
  danger: 'border-sev-critical/60 text-sev-critical hover:bg-sev-critical/10',
  ghost: 'border-transparent text-muted hover:bg-surface-2 hover:text-text',
}

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  readonly variant?: ButtonVariant
}

/** A small themed button; all buttons share one focus and disabled treatment. */
export function Button({ variant = 'default', className = '', type = 'button', ...rest }: ButtonProps): ReactElement {
  return (
    <button
      type={type}
      className={`inline-flex items-center gap-1.5 rounded-[var(--radius-control)] border px-3 py-1.5 text-sm transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${VARIANT_CLASS[variant]} ${className}`}
      {...rest}
    />
  )
}
