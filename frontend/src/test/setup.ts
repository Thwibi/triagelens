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

/**
 * jsdom does not implement `ResizeObserver`.
 *
 * CodeMirror and the virtualized table observe element resizes; a no-op stub is
 * enough because the tests drive sizing with explicit mocks where it matters.
 */
function stubResizeObserver(): void {
  if ('ResizeObserver' in globalThis) {
    return
  }
  class ResizeObserverStub {
    observe(): void {
      return undefined
    }
    unobserve(): void {
      return undefined
    }
    disconnect(): void {
      return undefined
    }
  }
  Object.defineProperty(globalThis, 'ResizeObserver', {
    writable: true,
    value: ResizeObserverStub,
  })
}

stubResizeObserver()
