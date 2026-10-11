/**
 * Pure helpers for the Timeline screen (spec 07 section 3.8).
 *
 * The chart, the brush range and the "notable items in range" lists are all
 * derived from the bucket payloads; keeping this math out of the component
 * makes it unit-testable without a chart renderer.
 */
import type { TimelineBucket } from '../../api/types'

/** A chart row: the bucket time plus one number per log type. */
export interface TimelinePoint {
  readonly t_ms: number
  readonly count: number
  readonly alert_count: number
  [series: string]: number
}

/** Chart keys that are not log-type series and must never be treated as one. */
const RESERVED = new Set(['t_ms', 'count', 'alert_count'])

/** Stable palette for stacked log-type series. */
const PALETTE: readonly string[] = [
  '#4f9cf9',
  '#f59e0b',
  '#10b981',
  '#ef4444',
  '#8b5cf6',
  '#14b8a6',
  '#ec4899',
  '#84cc16',
  '#f97316',
  '#06b6d4',
]

/** Every log type present across the buckets, sorted for a stable legend. */
export function seriesKeys(buckets: readonly TimelineBucket[]): string[] {
  const keys = new Set<string>()
  for (const bucket of buckets) {
    for (const key of Object.keys(bucket.by_log_type)) {
      if (!RESERVED.has(key)) {
        keys.add(key)
      }
    }
  }
  return [...keys].sort((a, b) => a.localeCompare(b))
}

/** Reshape buckets into recharts-friendly rows. */
export function toChartData(buckets: readonly TimelineBucket[]): TimelinePoint[] {
  return buckets.map((bucket) => {
    const point: TimelinePoint = {
      t_ms: bucket.t_ms,
      count: bucket.count,
      alert_count: bucket.alert_count,
    }
    for (const [key, value] of Object.entries(bucket.by_log_type)) {
      if (!RESERVED.has(key)) {
        point[key] = value
      }
    }
    return point
  })
}

/** The time span covered by the buckets, or `null` when there are none. */
export function extentMs(buckets: readonly TimelineBucket[]): { readonly min: number; readonly max: number } | null {
  if (buckets.length === 0) {
    return null
  }
  let min = buckets[0]?.t_ms ?? 0
  let max = min
  for (const bucket of buckets) {
    min = Math.min(min, bucket.t_ms)
    max = Math.max(max, bucket.t_ms)
  }
  return { min, max }
}

/**
 * Zoom the current range by `factor` about its centre (factor < 1 zooms in),
 * clamped to the full extent.
 */
export function zoomRange(
  from: number | null,
  to: number | null,
  extent: { readonly min: number; readonly max: number },
  factor: number,
): { readonly from: number; readonly to: number } {
  const baseFrom = from ?? extent.min
  const baseTo = to ?? extent.max
  const center = (baseFrom + baseTo) / 2
  const half = ((baseTo - baseFrom) / 2) * factor
  return {
    from: Math.max(extent.min, Math.round(center - half)),
    to: Math.min(extent.max, Math.round(center + half)),
  }
}

/** Keep the items whose timestamp falls within `[from, to]` (open ends allowed). */
export function filterByRange<T>(
  items: readonly T[],
  getMs: (item: T) => number | null,
  from: number | null,
  to: number | null,
): T[] {
  return items.filter((item) => {
    const ms = getMs(item)
    if (ms === null) {
      return false
    }
    if (from !== null && ms < from) {
      return false
    }
    if (to !== null && ms > to) {
      return false
    }
    return true
  })
}

/** Colour for the n-th log-type series, cycling the palette. */
export function logTypeColor(index: number): string {
  return PALETTE[index % PALETTE.length] ?? PALETTE[0] ?? '#4f9cf9'
}
