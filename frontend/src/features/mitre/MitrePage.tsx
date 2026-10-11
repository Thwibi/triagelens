import { useMemo, useState } from 'react'
import type { CSSProperties, ReactElement } from 'react'
import { Link } from 'react-router-dom'
import { ChevronRight, Download, ImageDown } from 'lucide-react'

import { getMitreNavigatorLayer } from '../../api/endpoints'
import { useCaseMitreQuery, useMitreStaticQuery } from '../../api/hooks'
import type { AlertLevel } from '../../api/types'
import { useCaseId } from '../../app/caseRoute'
import { caseNavPath } from '../../app/navigation'
import { formatNumber, formatAttackVersion } from '../../lib/format'
import { Button } from '../../ui/Button'
import { EmptyState } from '../../ui/EmptyState'
import { ErrorPanel } from '../../ui/ErrorPanel'
import { Skeleton } from '../../ui/Skeleton'
import { useToast } from '../../ui/ToastProvider'
import {
  intensity,
  matrixColumns,
  matrixSvg,
  matrixSvgSize,
  maxCellCount,
} from './mitreMatrix'
import type { MatrixColumn, MatrixNode, MitreMode } from './mitreMatrix'

const LEVEL_BORDER: Readonly<Record<AlertLevel, string>> = {
  critical: 'var(--sev-critical)',
  high: 'var(--sev-high)',
  medium: 'var(--sev-medium)',
  low: 'var(--sev-low)',
  informational: 'var(--sev-info)',
}

/** The deep link from a technique cell to the filtered alerts list. */
function alertsHref(caseId: string, techniqueId: string): string {
  return `${caseNavPath(caseId, 'alerts')}?technique=${encodeURIComponent(techniqueId)}`
}

function rasterizeSvg(svg: string, width: number, height: number): Promise<Blob> {
  return new Promise<Blob>((resolve, reject) => {
    const image = new Image()
    image.onload = () => {
      const canvas = document.createElement('canvas')
      canvas.width = width
      canvas.height = height
      const context = canvas.getContext('2d')
      if (context === null) {
        reject(new Error('canvas is unavailable'))
        return
      }
      context.drawImage(image, 0, 0)
      canvas.toBlob((blob) => {
        if (blob === null) {
          reject(new Error('PNG encoding failed'))
        } else {
          resolve(blob)
        }
      }, 'image/png')
    }
    image.onerror = () => { reject(new Error('SVG could not be rendered')) }
    image.src = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`
  })
}

function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()
  URL.revokeObjectURL(url)
}

function TechniqueCell({
  caseId,
  node,
  maxCount,
  parentExpanded,
  onToggle,
}: {
  readonly caseId: string
  readonly node: MatrixNode
  readonly maxCount: number
  readonly parentExpanded: boolean
  readonly onToggle: (id: string) => void
}): ReactElement {
  const fill = intensity(node.cell.count, maxCount)
  const style: CSSProperties = {
    backgroundColor: fill === 0 ? 'transparent' : `color-mix(in srgb, var(--accent) ${Math.round(fill * 100)}%, transparent)`,
    borderColor: node.cell.level !== null ? LEVEL_BORDER[node.cell.level] : 'var(--border)',
  }
  const hasSubs = node.sub.length > 0
  return (
    <li className="rounded border" style={style}>
      <div className="flex items-center gap-1 px-1 py-0.5">
        {hasSubs ? (
          <button
            type="button"
            aria-expanded={parentExpanded}
            aria-label={parentExpanded ? `Collapse ${node.id}` : `Expand ${node.id}`}
            className="text-muted hover:text-text"
            onClick={() => { onToggle(node.id) }}
          >
            <ChevronRight aria-hidden="true" size={12} className={parentExpanded ? 'rotate-90 transition-transform' : 'transition-transform'} />
          </button>
        ) : (
          <span aria-hidden="true" className="w-3" />
        )}
        <Link
          to={alertsHref(caseId, node.id)}
          title={`${node.id} ${node.name} — ${formatNumber(node.cell.count)} alerts`}
          className="min-w-0 flex-1 truncate text-left text-xs hover:underline"
        >
          <span className="font-mono text-muted">{node.id}</span> <span className="text-text">{node.name}</span>
        </Link>
        {node.cell.count > 0 ? <span className="font-mono text-xs text-text">{node.cell.count}</span> : null}
      </div>
      {hasSubs && parentExpanded ? (
        <ul className="space-y-0.5 border-t border-border/60 px-1 py-0.5">
          {node.sub.map((child) => (
            <li key={child.id} className="flex items-center gap-1 pl-3">
              <Link
                to={alertsHref(caseId, child.id)}
                title={`${child.id} ${child.name} — ${formatNumber(child.cell.count)} alerts`}
                className="min-w-0 flex-1 truncate text-xs hover:underline"
              >
                <span className="font-mono text-muted">{child.id}</span> <span className="text-text">{child.name}</span>
              </Link>
              {child.cell.count > 0 ? <span className="font-mono text-xs text-text">{child.cell.count}</span> : null}
            </li>
          ))}
        </ul>
      ) : null}
    </li>
  )
}

function MatrixView({
  caseId,
  columns,
  expanded,
  onToggle,
}: {
  readonly caseId: string
  readonly columns: readonly MatrixColumn[]
  readonly expanded: ReadonlySet<string>
  readonly onToggle: (id: string) => void
}): ReactElement {
  const maxCount = maxCellCount(columns)
  return (
    <div className="overflow-auto rounded-[var(--radius-card)] border border-border bg-surface p-2" aria-label="ATT&CK matrix">
      <div className="flex gap-2">
        {columns.map((column) => (
          <section key={column.shortname} aria-label={column.name} className="w-52 shrink-0">
            <h2 className="mb-1 truncate text-xs font-medium uppercase tracking-wide text-muted" title={column.name}>
              {column.name}
            </h2>
            {column.nodes.length === 0 ? (
              <p className="rounded border border-dashed border-border px-1 py-2 text-center text-[10px] text-muted">no techniques</p>
            ) : (
              <ul className="space-y-0.5">
                {column.nodes.map((node) => (
                  <TechniqueCell
                    key={node.id}
                    caseId={caseId}
                    node={node}
                    maxCount={maxCount}
                    parentExpanded={expanded.has(node.id)}
                    onToggle={onToggle}
                  />
                ))}
              </ul>
            )}
          </section>
        ))}
      </div>
    </div>
  )
}

/** ATT&CK coverage matrix with exports (spec 07 section 3.5). */
export function MitrePage(): ReactElement {
  const caseId = useCaseId()
  const { push } = useToast()
  const [mode, setMode] = useState<MitreMode>('fired')
  const [expanded, setExpanded] = useState<ReadonlySet<string>>(() => new Set())
  const [busy, setBusy] = useState<'navigator' | 'png' | null>(null)

  const caseMatrix = useCaseMitreQuery(caseId)
  const staticMatrix = useMitreStaticQuery(mode === 'full')

  const columns = useMemo(
    () => matrixColumns(mode, caseMatrix.data ?? { attack_version: '', tactics: [], unmapped_alert_count: 0 }, staticMatrix.data ?? null),
    [mode, caseMatrix.data, staticMatrix.data],
  )

  const onToggle = (id: string): void => {
    setExpanded((current) => {
      const next = new Set(current)
      if (next.has(id)) {
        next.delete(id)
      } else {
        next.add(id)
      }
      return next
    })
  }

  const exportNavigator = async (): Promise<void> => {
    if (caseId === null) {
      return
    }
    setBusy('navigator')
    try {
      const layer = await getMitreNavigatorLayer(caseId)
      downloadBlob(new Blob([JSON.stringify(layer, null, 2)], { type: 'application/json' }), `${caseId}-attack-navigator.json`)
      push('success', 'Navigator layer exported')
    } catch {
      push('error', 'Could not export the Navigator layer')
    } finally {
      setBusy(null)
    }
  }

  const exportPng = async (): Promise<void> => {
    if (caseId === null) {
      return
    }
    setBusy('png')
    try {
      const attackVersion = caseMatrix.data?.attack_version ?? ''
      const svg = matrixSvg(columns, { title: 'ATT&CK coverage', attackVersion, mode })
      const { width, height } = matrixSvgSize(columns)
      const blob = await rasterizeSvg(svg, width, height)
      downloadBlob(blob, `${caseId}-attack.png`)
      push('success', 'Matrix image exported')
    } catch {
      push('error', 'Could not export the matrix image')
    } finally {
      setBusy(null)
    }
  }

  if (caseId === null) {
    return <ErrorPanel message="No case is selected." />
  }
  if (caseMatrix.isError) {
    return (
      <ErrorPanel
        title="Cannot load the ATT&CK matrix"
        message="The case may have no detection run yet."
        onRetry={() => { void caseMatrix.refetch() }}
      />
    )
  }
  if (caseMatrix.isPending) {
    return <Skeleton className="h-96 w-full" />
  }

  const firedTotal = caseMatrix.data.tactics.reduce(
    (sum, tactic) => sum + tactic.techniques.reduce((inner, technique) => inner + technique.alert_count, 0),
    0,
  )
  const unmapped = caseMatrix.data.unmapped_alert_count

  return (
    <section aria-labelledby="mitre-heading" className="flex h-full flex-col gap-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <h1 id="mitre-heading" className="text-xl font-semibold text-text">
            ATT&CK Coverage
          </h1>
          <span className="rounded bg-surface-2 px-2 py-0.5 text-xs text-muted">
            {formatAttackVersion(caseMatrix.data.attack_version)}
          </span>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <div role="group" aria-label="Matrix mode" className="inline-flex overflow-hidden rounded-[var(--radius-control)] border border-border">
            <button
              type="button"
              aria-pressed={mode === 'fired'}
              className={`px-3 py-1.5 text-sm ${mode === 'fired' ? 'bg-accent text-black' : 'bg-surface-2 text-text hover:bg-surface'}`}
              onClick={() => { setMode('fired') }}
            >
              Fired only
            </button>
            <button
              type="button"
              aria-pressed={mode === 'full'}
              className={`px-3 py-1.5 text-sm ${mode === 'full' ? 'bg-accent text-black' : 'bg-surface-2 text-text hover:bg-surface'}`}
              onClick={() => { setMode('full') }}
            >
              Full matrix
            </button>
          </div>
          <Button disabled={busy !== null} onClick={() => { void exportNavigator() }}>
            <Download aria-hidden="true" size={14} /> Navigator JSON
          </Button>
          <Button disabled={busy !== null || columns.length === 0} onClick={() => { void exportPng() }}>
            <ImageDown aria-hidden="true" size={14} /> PNG
          </Button>
        </div>
      </div>

      {unmapped > 0 ? (
        <p className="text-xs text-sev-medium">
          {formatNumber(unmapped)} alert{unmapped === 1 ? '' : 's'} have no ATT&CK technique and are not shown on the matrix.
        </p>
      ) : null}

      {mode === 'full' && staticMatrix.isPending ? <Skeleton className="h-96 w-full" /> : null}
      {mode === 'full' && staticMatrix.isError ? (
        <ErrorPanel
          title="Cannot load the reference matrix"
          message="The bundled ATT&CK catalogue may be missing."
          onRetry={() => { void staticMatrix.refetch() }}
        />
      ) : null}
      {mode === 'full' && staticMatrix.isSuccess ? (
        <MatrixView caseId={caseId} columns={columns} expanded={expanded} onToggle={onToggle} />
      ) : null}

      {mode === 'fired' && firedTotal === 0 ? (
        <EmptyState
          title="No ATT&CK mappings yet"
          detail="Run detection after ingesting sources to populate the matrix."
          action={<Link to={caseNavPath(caseId, 'sources')}><Button variant="primary">Go to Sources</Button></Link>}
        />
      ) : null}
      {mode === 'fired' && firedTotal > 0 ? (
        <MatrixView caseId={caseId} columns={columns} expanded={expanded} onToggle={onToggle} />
      ) : null}

      <p className="text-xs text-muted">
        Box colour scales with alert count; the border shows the loudest severity. Click a technique to open the filtered alerts list.
      </p>
    </section>
  )
}
