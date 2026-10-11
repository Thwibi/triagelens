/**
 * Pure helpers that shape the two MITRE payloads into one render model
 * (spec 07 section 3.5).
 *
 * The case matrix lists only fired techniques; the static matrix lists every
 * technique but carries no counts. Both are folded into the same `MatrixColumn`
 * tree here so the view has one shape and the "Fired only" / "Full matrix"
 * toggle is just a choice of source plus a count lookup.
 */
import type { AlertLevel, CaseMitreMatrix, MitreStaticMatrix } from '../../api/types'

export type MitreMode = 'fired' | 'full'

export interface MatrixCell {
  readonly count: number
  readonly level: AlertLevel | null
  readonly alertIds: readonly string[]
}

export interface MatrixNode {
  readonly id: string
  readonly name: string
  readonly cell: MatrixCell
  readonly sub: readonly MatrixNode[]
}

export interface MatrixColumn {
  readonly shortname: string
  readonly name: string
  readonly nodes: readonly MatrixNode[]
}

const LEVELS: readonly string[] = ['critical', 'high', 'medium', 'low', 'informational']

/** Coerce a backend `max_level` (which may be `""`) to a known level or null. */
export function normalizeLevel(value: string | null | undefined): AlertLevel | null {
  if (value === null || value === undefined || !LEVELS.includes(value)) {
    return null
  }
  return value as AlertLevel
}

const EMPTY_CELL: MatrixCell = { count: 0, level: null, alertIds: [] }

/** Flatten every technique (parents and subs) of a case matrix into a lookup. */
export function caseCountMap(matrix: CaseMitreMatrix): Map<string, MatrixCell> {
  const map = new Map<string, MatrixCell>()
  const walk = (node: CaseMitreMatrix['tactics'][number]['techniques'][number]): void => {
    map.set(node.id, {
      count: node.alert_count,
      level: normalizeLevel(node.max_level),
      alertIds: node.alert_ids,
    })
    for (const child of node.subtechniques) {
      walk(child)
    }
  }
  for (const tactic of matrix.tactics) {
    for (const technique of tactic.techniques) {
      walk(technique)
    }
  }
  return map
}

/** The columns to render for the current mode. */
export function matrixColumns(
  mode: MitreMode,
  caseMatrix: CaseMitreMatrix,
  staticMatrix: MitreStaticMatrix | null,
): readonly MatrixColumn[] {
  if (mode === 'fired') {
    return caseMatrix.tactics.map((tactic) => ({
      shortname: tactic.shortname,
      name: tactic.name,
      nodes: tactic.techniques.map((node) => ({
        id: node.id,
        name: node.name,
        cell: { count: node.alert_count, level: normalizeLevel(node.max_level), alertIds: node.alert_ids },
        sub: node.subtechniques.map((child) => ({
          id: child.id,
          name: child.name,
          cell: { count: child.alert_count, level: normalizeLevel(child.max_level), alertIds: child.alert_ids },
          sub: [],
        })),
      })),
    }))
  }
  const counts = caseCountMap(caseMatrix)
  const source = staticMatrix ?? { attack_version: caseMatrix.attack_version, tactics: [] }
  return source.tactics.map((tactic) => ({
    shortname: tactic.shortname,
    name: tactic.name,
    nodes: tactic.techniques.map((node) => ({
      id: node.id,
      name: node.name,
      cell: counts.get(node.id) ?? EMPTY_CELL,
      sub: node.subtechniques.map((child) => ({
        id: child.id,
        name: child.name,
        cell: counts.get(child.id) ?? EMPTY_CELL,
        sub: [],
      })),
    })),
  }))
}

/**
 * Fill fraction for a cell: 0 when empty, else 0.25–1.0 scaled to the busiest
 * cell so a single alert is still visible.
 */
export function intensity(count: number, maxCount: number): number {
  if (count <= 0) {
    return 0
  }
  return 0.25 + 0.75 * (count / Math.max(1, maxCount))
}

/** The highest cell count anywhere in the columns. */
export function maxCellCount(columns: readonly MatrixColumn[]): number {
  let max = 0
  for (const column of columns) {
    for (const node of column.nodes) {
      max = Math.max(max, node.cell.count)
      for (const child of node.sub) {
        max = Math.max(max, child.cell.count)
      }
    }
  }
  return max
}

export interface MatrixExportCell {
  readonly column: string
  readonly id: string
  readonly name: string
  readonly count: number
}

/** A flat list of fired cells in column order, used by the SVG snapshot. */
export function firedCells(columns: readonly MatrixColumn[]): readonly MatrixExportCell[] {
  const cells: MatrixExportCell[] = []
  for (const column of columns) {
    for (const node of column.nodes) {
      if (node.cell.count > 0) {
        cells.push({ column: column.shortname, id: node.id, name: node.name, count: node.cell.count })
      }
      for (const child of node.sub) {
        if (child.cell.count > 0) {
          cells.push({ column: column.shortname, id: child.id, name: child.name, count: child.cell.count })
        }
      }
    }
  }
  return cells
}

function escapeXml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;')
}

export interface SvgOptions {
  readonly title: string
  readonly attackVersion: string
  readonly mode: MitreMode
}

const COLUMN_WIDTH = 210
const CELL_HEIGHT = 34
const HEADER_HEIGHT = 96

/** The pixel size the SVG snapshot will occupy for these columns. */
export function matrixSvgSize(columns: readonly MatrixColumn[]): { readonly width: number; readonly height: number } {
  const fired = firedCells(columns)
  const byColumn = new Map<string, number>()
  for (const cell of fired) {
    byColumn.set(cell.column, (byColumn.get(cell.column) ?? 0) + 1)
  }
  const maxRows = Math.max(1, ...[...byColumn.values()])
  return { width: columns.length * COLUMN_WIDTH + 20, height: HEADER_HEIGHT + maxRows * CELL_HEIGHT + 20 }
}

/**
 * A self-contained SVG snapshot of the fired techniques, one column per tactic.
 *
 * Building a string (rather than a React tree) keeps the PNG export honest: the
 * same pure data drives the on-screen matrix and the exported image.
 */
export function matrixSvg(columns: readonly MatrixColumn[], options: SvgOptions): string {
  const fired = firedCells(columns)
  const byColumn = new Map<string, MatrixExportCell[]>()
  for (const cell of fired) {
    const list = byColumn.get(cell.column) ?? []
    list.push(cell)
    byColumn.set(cell.column, list)
  }
  const { width, height } = matrixSvgSize(columns)
  const parts: string[] = []
  parts.push(`<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">`)
  parts.push('<rect width="100%" height="100%" fill="#15171c"/>')
  parts.push(`<text x="10" y="26" fill="#e6e6e6" font-family="sans-serif" font-size="16">${escapeXml(options.title)}</text>`)
  parts.push(`<text x="10" y="46" fill="#8b8f96" font-family="sans-serif" font-size="11">ATT&amp;CK ${escapeXml(options.attackVersion)} · ${options.mode === 'fired' ? 'fired only' : 'full matrix'}</text>`)
  columns.forEach((column, index) => {
    const x = 10 + index * COLUMN_WIDTH
    parts.push(`<text x="${x + 4}" y="${HEADER_HEIGHT - 12}" fill="#8b8f96" font-family="sans-serif" font-size="11">${escapeXml(column.name)}</text>`)
    const list = byColumn.get(column.shortname) ?? []
    list.forEach((cell, row) => {
      const y = HEADER_HEIGHT + row * CELL_HEIGHT
      const opacity = Math.min(1, 0.25 + cell.count / 10)
      parts.push(`<rect x="${x}" y="${y}" width="${COLUMN_WIDTH - 12}" height="${CELL_HEIGHT - 6}" rx="4" fill="#4c8bf5" fill-opacity="${opacity.toFixed(2)}"/>`)
      parts.push(`<text x="${x + 6}" y="${y + 19}" fill="#0b0c0f" font-family="monospace" font-size="12">${escapeXml(cell.id)} ${escapeXml(cell.name)} (${cell.count})</text>`)
    })
  })
  parts.push('</svg>')
  return parts.join('')
}
