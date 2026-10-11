/**
 * Event table column definitions and preference persistence (spec 07 section 3.7).
 *
 * The default column set mirrors the spec; the analyst can add or remove columns
 * and the choice is remembered in `localStorage`.
 */

/** One selectable table column. */
export interface EventColumnDef {
  readonly id: string
  readonly label: string
  readonly default: boolean
  /** CSS grid track width for this column. */
  readonly width: string
}

/** Every column, in display order. */
export const EVENT_COLUMNS: readonly EventColumnDef[] = [
  { id: 'time', label: 'Time', default: true, width: '11rem' },
  { id: 'host', label: 'Host', default: true, width: '9rem' },
  { id: 'log_type', label: 'Log type', default: true, width: '8rem' },
  { id: 'event', label: 'Event', default: true, width: '7rem' },
  { id: 'user', label: 'User', default: true, width: '8rem' },
  { id: 'net', label: 'Src → Dst', default: true, width: '12rem' },
  { id: 'summary', label: 'Summary', default: true, width: 'minmax(16rem,1fr)' },
  { id: 'channel', label: 'Channel', default: false, width: '8rem' },
  { id: 'level', label: 'Level', default: false, width: '6rem' },
  { id: 'source', label: 'Source', default: false, width: '8rem' },
  { id: 'process', label: 'Process', default: false, width: '14rem' },
  { id: 'file', label: 'File', default: false, width: '14rem' },
  { id: 'url', label: 'URL', default: false, width: '14rem' },
]

/** The ids shown by default (spec 07 section 3.7). */
export const DEFAULT_EVENT_COLUMNS: readonly string[] = EVENT_COLUMNS.filter((column) => column.default).map(
  (column) => column.id,
)

/** `localStorage` key for the persisted column choice. */
export const EVENT_COLUMNS_STORAGE_KEY = 'triagelens.events.columns'

const COLUMN_IDS = EVENT_COLUMNS.map((column) => column.id)

/**
 * Coerce a persisted value into a valid, non-empty, ordered column id list.
 *
 * Unknown ids (from an older build) are dropped and an empty or malformed value
 * falls back to the defaults, so a stale preference can never hide every column.
 */
export function sanitizeColumns(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [...DEFAULT_EVENT_COLUMNS]
  }
  const chosen = COLUMN_IDS.filter((id) => (value as readonly unknown[]).includes(id))
  return chosen.length === 0 ? [...DEFAULT_EVENT_COLUMNS] : chosen
}

/** The grid template for a set of visible columns (order follows `EVENT_COLUMNS`). */
export function gridTemplateFor(columnIds: readonly string[]): string {
  return EVENT_COLUMNS.filter((column) => columnIds.includes(column.id))
    .map((column) => column.width)
    .join(' ')
}
