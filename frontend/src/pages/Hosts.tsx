import { useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { ArrowLeft, Network, Search, ShieldCheck } from 'lucide-react'
import { useApi } from '../hooks/useApi'
import { api } from '../lib/api'
import { RankedBars } from '../components/charts'
import {
  Criticality, Empty, ErrorNote, Mono, Panel, SeverityTag, Spinner, StatTile, StatusTag,
} from '../components/ui'
import { ago, bytes, num, score as fmtScore, stamp } from '../lib/format'

export function Hosts() {
  const [search, setSearch] = useState('')
  const { data, error, loading, reload } = useApi(() => api.hosts(search || undefined), [search], 20_000)

  if (error) return <ErrorNote message={error} onRetry={reload} />

  const items = data?.items ?? []
  return (
    <div className="space-y-4">
      <div className="panel panel-pad">
        <label htmlFor="hq" className="label-xs mb-1.5 block">Rechercher un hôte</label>
        <div className="relative max-w-md">
          <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-slate-600" aria-hidden />
          <input id="hq" className="input pl-8" placeholder="adresse IP ou nom d’actif"
                 value={search} onChange={(e) => setSearch(e.target.value)} />
        </div>
      </div>

      <Panel pad={false} title={`${num(data?.total ?? 0)} hôte(s) observé(s)`}>
        {loading && !items.length ? <Spinner /> : items.length === 0 ? (
          <Empty title="Aucun hôte observé" icon={Network}
                 hint="Les hôtes apparaissent dès que du trafic est analysé." />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[920px]">
              <thead className="border-b border-ink-800">
                <tr>
                  <th className="th">Adresse</th><th className="th">Actif</th><th className="th">Criticité</th>
                  <th className="th">Flux émis</th><th className="th">Flux reçus</th>
                  <th className="th">Sortant</th><th className="th">Entrant</th>
                  <th className="th">Alertes</th><th className="th">Seuil</th><th className="th">Vu</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-ink-800">
                {items.map((h) => (
                  <tr key={h.ip} className="hover:bg-ink-850/60">
                    <td className="td"><Link to={`/hosts/${h.ip}`} className="link"><Mono>{h.ip}</Mono></Link></td>
                    <td className="td text-slate-300">{h.asset_name || '—'}</td>
                    <td className="td"><Criticality value={h.criticality} /></td>
                    <td className="td tabular-nums text-slate-400">{num(h.flows_out)}</td>
                    <td className="td tabular-nums text-slate-400">{num(h.flows_in)}</td>
                    <td className="td tabular-nums text-slate-400">{bytes(h.bytes_out)}</td>
                    <td className="td tabular-nums text-slate-400">{bytes(h.bytes_in)}</td>
                    <td className="td tabular-nums">
                      <span className={h.alerts > 0 ? 'text-red-300' : 'text-slate-500'}>{num(h.alerts)}</span>
                    </td>
                    <td className="td tabular-nums">
                      <span className="text-slate-300">{fmtScore(h.threshold)}</span>
                      {h.calibrated && (
                        <ShieldCheck className="ml-1.5 inline h-3.5 w-3.5 text-emerald-500"
                                     aria-label="seuil calibré sur cet hôte" />
                      )}
                    </td>
                    <td className="td text-xs text-slate-500">{ago(h.last_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
      <p className="text-[11px] text-slate-600">
        <ShieldCheck className="mr-1 inline h-3 w-3 text-emerald-500" aria-hidden />
        indique un hôte dont le seuil est calibré sur son propre comportement. Les autres utilisent
        le plancher global jusqu’à avoir assez d’historique.
      </p>
    </div>
  )
}

export function HostDetailPage() {
  const { ip } = useParams<{ ip: string }>()
  const navigate = useNavigate()
  const { data, error, loading, reload } = useApi(() => api.host(ip ?? ''), [ip])

  if (error) return <ErrorNote message={error} onRetry={reload} />
  if (loading && !data) return <Spinner />
  if (!data) return null

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-3">
        <button onClick={() => navigate(-1)} className="btn-ghost">
          <ArrowLeft className="h-4 w-4" aria-hidden /> Retour
        </button>
        <h2 className="font-mono text-lg font-semibold text-slate-50">{data.ip}</h2>
        <span className="text-sm text-slate-400">{data.asset_name}</span>
        <Criticality value={data.criticality} />
      </div>

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-6">
        <StatTile label="Flux émis" value={num(data.flows_out)} />
        <StatTile label="Flux reçus" value={num(data.flows_in)} />
        <StatTile label="Octets sortants" value={bytes(data.bytes_out)} />
        <StatTile label="Octets entrants" value={bytes(data.bytes_in)} />
        <StatTile label="Alertes" value={num(data.alerts)} accent="var(--series-2)" />
        <StatTile label="Seuil de l’hôte" value={fmtScore(data.threshold)}
                  hint={data.calibrated ? 'calibré sur son historique' : 'plancher global'} />
      </div>

      <div className="grid gap-5 xl:grid-cols-[1fr_340px]">
        <Panel pad={false} title={`Incidents impliquant cet hôte (${data.incidents.length})`}>
          {data.incidents.length === 0 ? <Empty title="Aucun incident" /> : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[760px]">
                <thead className="border-b border-ink-800">
                  <tr>
                    <th className="th">Gravité</th><th className="th">Famille</th><th className="th">Rôle</th>
                    <th className="th">Pair</th><th className="th">Volume</th><th className="th">Statut</th>
                    <th className="th">Vu</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-ink-800">
                  {data.incidents.map((inc) => (
                    <tr key={inc.id} className="hover:bg-ink-850/60">
                      <td className="td"><SeverityTag severity={inc.severity} /></td>
                      <td className="td">
                        <Link to={`/incidents/${inc.id}`} className="link">{inc.family_title}</Link>
                      </td>
                      <td className="td text-xs">
                        {inc.src === data.ip
                          ? <span className="text-amber-300">source</span>
                          : <span className="text-sky-300">cible</span>}
                      </td>
                      <td className="td"><Mono className="text-slate-400">
                        {inc.src === data.ip ? inc.dst : inc.src}
                      </Mono></td>
                      <td className="td tabular-nums text-slate-400">{num(inc.occurrences)}</td>
                      <td className="td"><StatusTag status={inc.status} /></td>
                      <td className="td text-xs text-slate-500">{ago(inc.last_seen)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>

        <div className="space-y-5">
          <Panel title="Profil">
            <dl className="space-y-2.5 text-sm">
              <div className="flex justify-between gap-3">
                <dt className="text-slate-500">Première observation</dt>
                <dd className="text-xs text-slate-300">{stamp(data.first_seen)}</dd>
              </div>
              <div className="flex justify-between gap-3">
                <dt className="text-slate-500">Dernière observation</dt>
                <dd className="text-xs text-slate-300">{stamp(data.last_seen)}</dd>
              </div>
              <div className="flex justify-between gap-3">
                <dt className="text-slate-500">Score moyen</dt>
                <dd className="tabular-nums text-slate-300">{fmtScore(data.score_mean)}</dd>
              </div>
            </dl>
          </Panel>
          <Panel title="Familles le concernant">
            <RankedBars
              rows={Object.entries(
                data.incidents.reduce<Record<string, number>>((acc, i) => {
                  acc[i.family_title] = (acc[i.family_title] ?? 0) + i.occurrences
                  return acc
                }, {}),
              ).sort((a, b) => b[1] - a[1]).map(([label, value]) => ({ label, value }))}
              emptyLabel="aucune attaque associée" />
          </Panel>
        </div>
      </div>
    </div>
  )
}
