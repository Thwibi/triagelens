import type { ReactElement } from 'react'
import { Link } from 'react-router-dom'

import { useEntitiesQuery } from '../../api/hooks'
import type { Entity } from '../../api/types'
import { useCaseId } from '../../app/caseRoute'
import { caseNavPath } from '../../app/navigation'
import { formatNumber } from '../../lib/format'
import { EmptyState } from '../../ui/EmptyState'
import { ErrorPanel } from '../../ui/ErrorPanel'
import { SkeletonRows } from '../../ui/Skeleton'

function EntityTable({
  title,
  kind,
  query,
  caseId,
}: {
  readonly title: string
  readonly kind: 'host' | 'user'
  readonly query: readonly Entity[]
  readonly caseId: string
}): ReactElement {
  const filterKey = kind === 'host' ? 'host' : 'user_name'
  return (
    <div className="space-y-2">
      <h2 className="text-sm font-medium text-text">{title}</h2>
      {query.length === 0 ? (
        <p className="text-sm text-muted">No {kind === 'host' ? 'hosts' : 'users'} recorded.</p>
      ) : (
        <table className="w-full border-collapse text-sm">
          <thead>
            <tr className="border-b border-border text-left text-xs uppercase tracking-wide text-muted">
              <th scope="col" className="py-1 pr-2">
                {kind === 'host' ? 'Host' : 'User'}
              </th>
              <th scope="col" className="py-1 pr-2 text-right">
                Events
              </th>
              <th scope="col" className="py-1 text-right">
                Alerts
              </th>
            </tr>
          </thead>
          <tbody>
            {query.map((entity) => (
              <tr key={entity.name} className="border-b border-border/60">
                <td className="py-1 pr-2">
                  <Link
                    to={`${caseNavPath(caseId, 'events')}?${filterKey}=${encodeURIComponent(entity.name)}`}
                    className="font-mono text-accent hover:underline"
                  >
                    {entity.name}
                  </Link>
                </td>
                <td className="py-1 pr-2 text-right font-mono text-text">{formatNumber(entity.event_count)}</td>
                <td className="py-1 text-right font-mono text-text">{formatNumber(entity.alert_count)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}

/** Entities screen (spec 07 section 3.9). */
export function EntitiesPage(): ReactElement {
  const caseId = useCaseId()
  const entities = useEntitiesQuery(caseId)

  if (caseId === null) {
    return <ErrorPanel message="No case is selected." />
  }
  if (entities.isError) {
    return (
      <ErrorPanel title="Cannot load entities" message="The entities query failed." onRetry={() => { void entities.refetch() }} />
    )
  }

  const all = entities.data ?? []
  const hosts = all.filter((entity) => entity.kind === 'host')
  const users = all.filter((entity) => entity.kind === 'user')

  return (
    <section aria-labelledby="entities-heading" className="space-y-4">
      <h1 id="entities-heading" className="text-xl font-semibold text-text">
        Entities
      </h1>
      {entities.isPending ? (
        <SkeletonRows rows={8} />
      ) : all.length === 0 ? (
        <EmptyState title="No entities yet" detail="Import a log source to populate hosts and users." />
      ) : (
        <>
          <div className="grid gap-6 lg:grid-cols-2">
            <EntityTable title="Hosts" kind="host" query={hosts} caseId={caseId} />
            <EntityTable title="Users" kind="user" query={users} caseId={caseId} />
          </div>
          <p className="text-xs text-muted">
            Counts only: first/last seen and per-entity ATT&CK techniques are not exposed by the entities API, and the
            API currently reports zero alerts per entity.
          </p>
        </>
      )}
    </section>
  )
}
