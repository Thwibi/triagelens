import '@testing-library/jest-dom/vitest'

import { afterEach, vi } from 'vitest'
import { cleanup } from '@testing-library/react'

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

/**
 * jsdom does not implement `matchMedia`.
 *
 * Only the fields the UI reads are implemented; anything else keeps the default
 * behaviour of never matching.
 */
function stubMatchMedia(): void {
  if ('matchMedia' in window) {
    return
  }
  Object.defineProperty(window, 'matchMedia', {
    writable: true,
    value: (media: string): MediaQueryList => {
      const list: MediaQueryList = {
        matches: false,
        media,
        onchange: null,
        addListener: () => undefined,
        removeListener: () => undefined,
        addEventListener: () => undefined,
        removeEventListener: () => undefined,
        dispatchEvent: () => false,
      }
      return list
    },
  })
}

stubMatchMedia()