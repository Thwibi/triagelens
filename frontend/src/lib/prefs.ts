/**
 * Small `localStorage` helpers for UI preferences (spec 07 section 4).
 *
 * Every access is guarded: private-mode or disabled storage must degrade to the
 * in-memory default rather than throw, so a preference read can never crash a
 * screen.
 */

/** Read a JSON preference, returning `fallback` for absent or corrupt values. */
export function loadPref<T>(key: string, fallback: T): T {
  try {
    const raw = window.localStorage.getItem(key)
    if (raw === null) {
      return fallback
    }
    return JSON.parse(raw) as T
  } catch {
    return fallback
  }
}

/** Persist a JSON preference, silently ignoring storage failures. */
export function savePref(key: string, value: unknown): void {
  try {
    window.localStorage.setItem(key, JSON.stringify(value))
  } catch {
    // Storage full or unavailable: the preference simply does not persist.
  }
}
