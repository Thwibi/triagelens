/**
 * Safe text highlighting for log content (spec 07 section 3.7).
 *
 * Splits a string into literal segments, marking the ranges that match one of
 * the provided needles. It never interprets the content as markup or a regular
 * expression, so a malicious log line cannot inject HTML; callers render the
 * segments as text nodes only.
 */

/** One slice of the source text, flagged when it matches a needle. */
export interface HighlightSegment {
  readonly text: string
  readonly match: boolean
}

interface Range {
  readonly start: number
  readonly end: number
}

function rangesFor(text: string, needle: string): Range[] {
  if (needle.length === 0) {
    return []
  }
  const lowerText = text.toLowerCase()
  const lowerNeedle = needle.toLowerCase()
  const ranges: Range[] = []
  let index = lowerText.indexOf(lowerNeedle)
  while (index !== -1) {
    ranges.push({ start: index, end: index + needle.length })
    index = lowerText.indexOf(lowerNeedle, index + needle.length)
  }
  return ranges
}

/** Merge overlapping or touching ranges into a minimal ordered set. */
function mergeRanges(ranges: readonly Range[]): Range[] {
  const sorted = [...ranges].sort((a, b) => a.start - b.start || a.end - b.end)
  const merged: Range[] = []
  for (const range of sorted) {
    const last = merged[merged.length - 1]
    if (last !== undefined && range.start <= last.end) {
      if (range.end > last.end) {
        merged[merged.length - 1] = { start: last.start, end: range.end }
      }
    } else {
      merged.push(range)
    }
  }
  return merged
}

/**
 * Split `text` into segments, flagging every occurrence of any needle.
 *
 * Needles shorter than two characters are ignored: single characters would
 * light up almost every line and drown the signal an analyst is looking for.
 */
export function highlightSegments(text: string, needles: readonly string[]): HighlightSegment[] {
  const ranges = mergeRanges(
    needles.filter((needle) => needle.length >= 2).flatMap((needle) => rangesFor(text, needle)),
  )
  if (ranges.length === 0) {
    return text.length === 0 ? [] : [{ text, match: false }]
  }
  const segments: HighlightSegment[] = []
  let cursor = 0
  for (const range of ranges) {
    if (range.start > cursor) {
      segments.push({ text: text.slice(cursor, range.start), match: false })
    }
    segments.push({ text: text.slice(range.start, range.end), match: true })
    cursor = range.end
  }
  if (cursor < text.length) {
    segments.push({ text: text.slice(cursor), match: false })
  }
  return segments
}
