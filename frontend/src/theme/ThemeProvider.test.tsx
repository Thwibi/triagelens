import { fireEvent, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'
import type { ReactElement } from 'react'

import { ThemeProvider, THEME_STORAGE_KEY, applyTheme, resolveInitialTheme, useTheme } from './ThemeProvider'

function Harness(): ReactElement {
  const { theme, toggleTheme } = useTheme()
  return (
    <button type="button" onClick={toggleTheme}>
      {theme}
    </button>
  )
}

afterEach(() => {
  window.localStorage.clear()
})

describe('resolveInitialTheme', () => {
  it('prefers an explicit stored choice', () => {
    window.localStorage.setItem(THEME_STORAGE_KEY, 'light')
    expect(resolveInitialTheme()).toBe('light')
  })

  it('ignores a junk stored value', () => {
    window.localStorage.setItem(THEME_STORAGE_KEY, 'sepia')
    expect(resolveInitialTheme()).toBe('dark')
  })

  it('defaults to dark when the OS does not prefer light', () => {
    expect(resolveInitialTheme()).toBe('dark')
  })
})

describe('applyTheme', () => {
  it('writes the theme onto the document element', () => {
    applyTheme('light')
    expect(document.documentElement.dataset['theme']).toBe('light')
    applyTheme('dark')
    expect(document.documentElement.dataset['theme']).toBe('dark')
  })
})

describe('ThemeProvider', () => {
  it('exposes the current theme and persists a toggle', () => {
    render(
      <ThemeProvider>
        <Harness />
      </ThemeProvider>,
    )
    const toggle = screen.getByRole('button')
    expect(toggle).toHaveTextContent('dark')

    fireEvent.click(toggle)

    expect(toggle).toHaveTextContent('light')
    expect(window.localStorage.getItem(THEME_STORAGE_KEY)).toBe('light')
    expect(document.documentElement.dataset['theme']).toBe('light')
  })
})
