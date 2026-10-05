import { useApi } from '../hooks/useApi'
import { api } from '../lib/api'
import { Empty, ErrorNote, Mono, Panel, Spinner } from '../components/ui'
import { stamp } from '../lib/format'

export function Audit() {
  const { data, error, loading, reload } = useApi(() => api.audit(), [], 15_000)

  if (error) return <ErrorNote message={error} onRetry={reload} />
  if (loading && !data) return <Spinner />

  const items = data?.items ?? []
  return (
    <div className="space-y-4">
      <p className="text-sm leading-relaxed text-slate-400">
        Toute action qui modifie un état est enregistrée avec son auteur. Sans cela, un triage n’est
        pas vérifiable : on ne peut pas savoir qui a classé quoi en faux positif, ni pourquoi un
        incident a été fermé.
      </p>
      <Panel pad={false} title={`${items.length} entrée(s)`}>
        {items.length === 0 ? <Empty title="Journal vide" /> : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[760px]">
              <thead className="border-b border-ink-800">
                <tr>
                  <th className="th">Horodatage</th><th className="th">Auteur</th>
                  <th className="th">Action</th><th className="th">Cible</th><th className="th">Détail</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-ink-800">
                {items.map((row) => (
                  <tr key={row.id} className="hover:bg-ink-850/60">
                    <td className="td text-xs text-slate-500">{stamp(row.ts)}</td>
                    <td className="td text-slate-200">{row.actor}</td>
                    <td className="td"><Mono className="text-accent">{row.action}</Mono></td>
                    <td className="td text-slate-400">{row.target || '—'}</td>
                    <td className="td max-w-[380px] truncate text-xs text-slate-600"
                        title={JSON.stringify(row.detail)}>
                      {Object.keys(row.detail ?? {}).length ? JSON.stringify(row.detail) : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  )
}
