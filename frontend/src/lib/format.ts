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

/** Thousands-separated integer, with a sane fallback for non-finite input. */
export function formatNumber(value: number): string {
  return Number.isFinite(value) ? value.toLocaleString() : '0'
}

/** Render an epoch-millisecond timestamp in the viewer's local timezone. */
export function formatTimestamp(ms: number | null): string {
  if (ms === null || !Number.isFinite(ms)) {
    return '—'
  }
  return new Date(ms).toLocaleString()
}

/** Compact "how long ago", used for freshness hints and job rows. */
export function formatSince(epochMs: number | null, now: number = Date.now()): string {
  if (epochMs === null || !Number.isFinite(epochMs)) {
    return '—'
  }
  const seconds = Math.max(0, Math.round((now - epochMs) / 1000))
  if (seconds < 60) {
    return `${seconds}s ago`
  }
  const minutes = Math.round(seconds / 60)
  if (minutes < 60) {
    return `${minutes}m ago`
  }
  const hours = Math.round(minutes / 60)
  if (hours < 24) {
    return `${hours}h ago`
  }
  return `${Math.round(hours / 24)}d ago`
}

/** A fraction in `[0, 1]` as a whole-number percentage. */
export function formatPercent(fraction: number): string {
  if (!Number.isFinite(fraction)) {
    return '0%'
  }
  return `${Math.round(Math.min(Math.max(fraction, 0), 1) * 100)}%`
}

/**
 * Make an indicator safe to paste into a chat or ticket (spec 07 sections 3.6
 * and 4).
 *
 * Dots in hostnames, IPs and paths become `[.]` and a leading `http`/`https`
 * scheme becomes `hxxp`, which stops most linkifiers from turning a malicious
 * value into a live link. Hashes and other dot-free values are unchanged.
 */
export function defang(value: string): string {
  return value
    .replace(/^http(s?):\/\//i, (_match, secure: string) => (secure.length > 0 ? 'hxxps[://]' : 'hxxp[://]'))
    .replace(/\./g, '[.]')
    .replace(/@/g, '[at]')
}
