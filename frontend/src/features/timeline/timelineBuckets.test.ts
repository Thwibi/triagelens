import { describe, expect, it } from 'vitest'

import type { TimelineBucket } from '../../api/types'
import { extentMs, filterByRange, logTypeColor, seriesKeys, toChartData, zoomRange } from './timelineBuckets'

const BUCKETS: readonly TimelineBucket[] = [
  { t_ms: 1_000, count: 3, by_log_type: { windows: 2, sysmon: 1 }, alert_count: 0 },
  { t_ms: 2_000, count: 5, by_log_type: { windows: 5 }, alert_count: 2 },
]

describe('timelineBuckets', () => {
  it('collects sorted, de-duplicated log-type keys', () => {
    expect(seriesKeys(BUCKETS)).toEqual(['sysmon', 'windows'])
  })

  it('reshapes buckets into chart rows with one key per log type', () => {
    expect(toChartData(BUCKETS)).toEqual([
      { t_ms: 1_000, count: 3, alert_count: 0, windows: 2, sysmon: 1 },
      { t_ms: 2_000, count: 5, alert_count: 2, windows: 5 },
    ])
  })

  it('computes the covered time extent', () => {
    expect(extentMs(BUCKETS)).toEqual({ min: 1_000, max: 2_000 })
    expect(extentMs([])).toBeNull()
  })

  it('zooms about the centre and clamps to the extent', () => {
    expect(zoomRange(null, null, { min: 0, max: 1000 }, 0.5)).toEqual({ from: 250, to: 750 })
    expect(zoomRange(null, null, { min: 0, max: 1000 }, 4)).toEqual({ from: 0, to: 1000 })
  })

  it('filters items into an inclusive, open-ended range', () => {
    const items = [{ ms: 1 }, { ms: 5 }, { ms: 9 }, { ms: null }]
    expect(filterByRange(items, (item) => item.ms, 2, 8)).toEqual([{ ms: 5 }])
    expect(filterByRange(items, (item) => item.ms, null, null)).toEqual([{ ms: 1 }, { ms: 5 }, { ms: 9 }])
  })

  it('cycles the palette', () => {
    expect(logTypeColor(0)).toBe(logTypeColor(10))
    expect(logTypeColor(0)).not.toBe(logTypeColor(1))
  })
})
