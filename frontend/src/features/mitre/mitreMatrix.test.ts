import { describe, expect, it } from 'vitest'

import type { CaseMitreMatrix, MitreStaticMatrix } from '../../api/types'
import {
  caseCountMap,
  firedCells,
  intensity,
  matrixColumns,
  matrixSvg,
  matrixSvgSize,
  maxCellCount,
  normalizeLevel,
} from './mitreMatrix'

const CASE_MATRIX: CaseMitreMatrix = {
  attack_version: 'v16.1',
  unmapped_alert_count: 2,
  tactics: [
    {
      shortname: 'execution',
      name: 'Execution',
      techniques: [
        {
          id: 'T1059',
          name: 'Command and Scripting Interpreter',
          alert_count: 3,
          max_level: 'high',
          alert_ids: ['a1', 'a2', 'a3'],
          subtechniques: [
            {
              id: 'T1059.001',
              name: 'PowerShell',
              alert_count: 1,
              max_level: 'critical',
              alert_ids: ['a1'],
              subtechniques: [],
            },
          ],
        },
      ],
    },
    {
      shortname: 'persistence',
      name: 'Persistence',
      techniques: [],
    },
  ],
}

const STATIC_MATRIX: MitreStaticMatrix = {
  attack_version: 'v16.1',
  tactics: [
    {
      shortname: 'execution',
      name: 'Execution',
      techniques: [
        {
          id: 'T1059',
          name: 'Command and Scripting Interpreter',
          subtechniques: [
            { id: 'T1059.001', name: 'PowerShell', subtechniques: [] },
            { id: 'T1059.003', name: 'Windows Command Shell', subtechniques: [] },
          ],
        },
        { id: 'T1204', name: 'User Execution', subtechniques: [] },
      ],
    },
    {
      shortname: 'persistence',
      name: 'Persistence',
      techniques: [{ id: 'T1547', name: 'Boot or Logon Autostart', subtechniques: [] }],
    },
  ],
}

describe('normalizeLevel', () => {
  it('keeps known levels and turns the empty string into null', () => {
    expect(normalizeLevel('critical')).toBe('critical')
    expect(normalizeLevel('informational')).toBe('informational')
    expect(normalizeLevel('')).toBeNull()
    expect(normalizeLevel(null)).toBeNull()
    expect(normalizeLevel('nonsense')).toBeNull()
  })
})

describe('caseCountMap', () => {
  it('flattens parents and sub-techniques', () => {
    const map = caseCountMap(CASE_MATRIX)
    expect(map.get('T1059')?.count).toBe(3)
    expect(map.get('T1059')?.level).toBe('high')
    expect(map.get('T1059.001')?.count).toBe(1)
    expect(map.get('T1059.001')?.level).toBe('critical')
  })
})

describe('matrixColumns', () => {
  it('renders only fired techniques in fired mode', () => {
    const columns = matrixColumns('fired', CASE_MATRIX, null)
    expect(columns).toHaveLength(2)
    expect(columns[0]?.nodes.map((node) => node.id)).toEqual(['T1059'])
    expect(columns[1]?.nodes).toEqual([])
  })

  it('renders the whole reference matrix with case counts overlaid in full mode', () => {
    const columns = matrixColumns('full', CASE_MATRIX, STATIC_MATRIX)
    const execution = columns[0]
    expect(execution?.nodes.map((node) => node.id)).toEqual(['T1059', 'T1204'])
    expect(execution?.nodes[0]?.cell.count).toBe(3)
    expect(execution?.nodes[0]?.sub.map((node) => node.id)).toEqual(['T1059.001', 'T1059.003'])
    expect(execution?.nodes[0]?.sub[0]?.cell.count).toBe(1)
    expect(execution?.nodes[0]?.sub[1]?.cell.count).toBe(0)
    expect(execution?.nodes[1]?.cell.count).toBe(0)
  })

  it('falls back to an empty matrix when the static payload is missing', () => {
    expect(matrixColumns('full', CASE_MATRIX, null)).toEqual([])
  })
})

describe('intensity and maxCellCount', () => {
  it('is zero for empty cells and scales up with the busiest cell', () => {
    expect(intensity(0, 10)).toBe(0)
    expect(intensity(10, 10)).toBeCloseTo(1)
    expect(intensity(5, 10)).toBeCloseTo(0.625)
  })

  it('finds the loudest cell across parents and children', () => {
    expect(maxCellCount(matrixColumns('fired', CASE_MATRIX, null))).toBe(3)
    expect(maxCellCount(matrixColumns('full', CASE_MATRIX, STATIC_MATRIX))).toBe(3)
  })
})

describe('firedCells', () => {
  it('lists only cells with a count', () => {
    const cells = firedCells(matrixColumns('full', CASE_MATRIX, STATIC_MATRIX))
    expect(cells.map((cell) => cell.id)).toEqual(['T1059', 'T1059.001'])
  })
})

describe('matrixSvg', () => {
  it('embeds the fired techniques and the version', () => {
    const columns = matrixColumns('fired', CASE_MATRIX, null)
    const svg = matrixSvg(columns, { title: 'ATT&CK coverage', attackVersion: 'v16.1', mode: 'fired' })
    expect(svg.startsWith('<svg')).toBe(true)
    expect(svg).toContain('T1059')
    expect(svg).toContain('v16.1')
  })

  it('computes a size that fits every column', () => {
    const columns = matrixColumns('full', CASE_MATRIX, STATIC_MATRIX)
    const size = matrixSvgSize(columns)
    expect(size.width).toBeGreaterThan(0)
    expect(size.height).toBeGreaterThan(0)
  })
})
