/** Presentation helpers. Pure functions, no React, no DOM. */

const BYTE_UNITS = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'] as const

/**
 * Render a byte count with a binary unit.
 *
 * Negative input is clamped to zero so a corrupt backend value cannot produce
 * something like `-1 B`.
 */
export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) {
    return '0 B'
  }
  let value = bytes
  let unit = 0
  while (value >= 1024 && unit < BYTE_UNITS.length - 1) {
    value /= 1024
    unit += 1
  }
  const decimals = unit === 0 ? 0 : value < 10 ? 2 : 1
  return `${value.toFixed(decimals)} ${BYTE_UNITS[unit]}`
}

/**
 * Shorten a hex digest for display while keeping both ends recognisable.
 *
 * An empty digest means the bundle has not been built yet, which is a real
 * state, so it is rendered as an explicit placeholder rather than hidden.
 */
export function formatHash(hash: string): string {
  if (hash.length === 0) {
    return 'not built'
  }
  if (hash.length <= 16) {
    return hash
  }
  return `${hash.slice(0, 8)}…${hash.slice(-8)}`
}

/** Render the bundled ATT&CK version, or a clear "absent" state. */
export function formatAttackVersion(version: string): string {
  return version.length === 0 ? 'bundle not installed' : version
}

/** Human-readable duration for the check-up interval. */
export function formatSeconds(seconds: number): string {
  return seconds < 60 ? `${seconds}s` : `${Math.round(seconds / 60)}m`
}

/**
 * Guard against values that would blow up the UI layout.
 *
 * Long hashes, paths and user-controlled strings are truncated before they
 * reach the DOM.
 */
export function truncate(value: string, max: number): string {
  if (max <= 1) {
    return value.slice(0, Math.max(max, 0))
  }
  return value.length <= max ? value : `${value.slice(0, max - 1)}…`
}