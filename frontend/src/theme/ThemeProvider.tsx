import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'
import type { ReactElement, ReactNode } from 'react'

/** The two themes the app ships; "system" is resolved once at load. */
export type Theme = 'dark' | 'light'

/** Where the explicit choice is persisted (spec 07 section 1). */
export const THEME_STORAGE_KEY = 'triagelens.theme'

export interface ThemeContextValue {
  readonly theme: Theme
  readonly setTheme: (theme: Theme) => void
  readonly toggleTheme: () => void
}

const ThemeContext = createContext<ThemeContextValue | null>(null)

function readStoredTheme(): Theme | null {
  try {
    const value = window.localStorage.getItem(THEME_STORAGE_KEY)
    return value === 'dark' || value === 'light' ? value : null
  } catch {
    // Private-mode or disabled storage: fall through to the OS preference.
    return null
  }
}

/**
 * Resolve the first-paint theme.
 *
 * A stored choice always wins; otherwise the OS preference decides, so a user
 * who has never touched the toggle still gets their system theme.
 */
export function resolveInitialTheme(): Theme {
  const stored = readStoredTheme()
  if (stored !== null) {
    return stored
  }
  if (typeof window.matchMedia === 'function' && window.matchMedia('(prefers-color-scheme: light)').matches) {
    return 'light'
  }
  return 'dark'
}

/** Apply a theme to the document root so CSS variables switch. */
export function applyTheme(theme: Theme): void {
  document.documentElement.dataset['theme'] = theme
}

export function ThemeProvider({ children }: { readonly children: ReactNode }): ReactElement {
  const [theme, setThemeState] = useState<Theme>(resolveInitialTheme)

  useEffect(() => {
    applyTheme(theme)
  }, [theme])

  const setTheme = useCallback((next: Theme): void => {
    setThemeState(next)
    try {
      window.localStorage.setItem(THEME_STORAGE_KEY, next)
    } catch {
      // A failed write must not stop the theme from applying this session.
    }
  }, [])

  const toggleTheme = useCallback((): void => {
    setTheme(theme === 'dark' ? 'light' : 'dark')
  }, [setTheme, theme])

  const value = useMemo<ThemeContextValue>(() => ({ theme, setTheme, toggleTheme }), [setTheme, theme, toggleTheme])

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
}

export function useTheme(): ThemeContextValue {
  const value = useContext(ThemeContext)
  if (value === null) {
    throw new Error('useTheme must be used inside a ThemeProvider')
  }
  return value
}
