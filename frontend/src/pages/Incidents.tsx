import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { CheckCheck, Filter, RotateCw, Search, X } from 'lucide-react'
import { useApi } from '../hooks/useApi'
import { api, type IncidentQuery, type Session } from '../lib/api'
import { Criticality, Empty, ErrorNote, Mono, Panel, SeverityTag, Spinner, StatusTag, Toast, VerdictTag } from '../components/ui'
import { ago, num, score as fmtScore, SEVERITY_ORDER, STATUS_LABEL } from '../lib/format'
import type { Incident } from '../lib/types'

const FAMILIES = ['PORT_SCAN', 'NET_SCAN', 'DOS_FLOOD', 'SSH_BRUTEFORCE', 'WEB_BRUTEFORCE',
  'SLOWLORIS', 'DNS_TUNNEL', 'EXFILTRATION', 'C2_BEACON', 'UNKNOWN', 'BENIGN']
const PAGE = 50

export function Incidents({ session }: { session: Session }) {
  const [filters, setFilters] = useState<IncidentQuery>({ open_only: true, sort: 'priority' })
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(0)
  const [selected, setSelected] = useState<Set<number>>(new Set())
  const [toast, setToast] = useState<{ message: string; tone: 'ok' | 'error' } | null>(null)
  const [busy, setBusy] = useState(false)

  const query = useMemo<IncidentQuery>(
    () => ({ ...filters, q: search || undefined, limit: PAGE, offset: page * PAGE }),
    [filters, search, page],
  )
  const { data, error, loading, reload } = useApi(() => api.incidents(query), [JSON.stringify(query)], 20_000)
  const canTriage = session.role !== 'viewer'

  const setFilter = <K extends keyof IncidentQuery>(key: K, value: IncidentQuery[K]) => {
    setPage(0)
    setFilters((f) => ({ ...f, [key]: value || undefined }))
  }

  const toggle = (id: number) => setSelected((prev) => {
    const next = new Set(prev)
    next.has(id) ? next.delete(id) : next.add(id)
    return next
  })

  const bulk = async (payload: { status?: string; verdict?: string }) => {
    if (!selected.size) return
    setBusy(true)
    try {
      const result = await api.bulkIncidents({ ids: [...selected], ...payload })
      setToast({ message: `${result.updated} incident(s) mis à jour`, tone: 'ok' })
      setSelected(new Set())
      reload()
    } catch (exc) {
      setToast({ message: (exc as Error).message, tone: 'error' })
    } finally {
      setBusy(false)
      window.setTimeout(() => setToast(null), 3200)
    }
  }

  const items: Incident[] = data?.items ?? []
  const total = data?.total ?? 0
  const pages = Math.ceil(total / PAGE)

  return (
    <div className="space-y-4">
      {/* filters: one row above the table */}
      <div className="panel panel-pad">
        <div className="flex flex-wrap items-end gap-3">
          <div className="min-w-[220px] flex-1">
            <label htmlFor="q" className="label-xs mb-1.5 block">Recherche</label>
            <div className="relative">
              <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-slate-600" aria-hidden />
              <input id="q" className="input pl-8" placeholder="IP, famille, actif, technique MITRE…"
                     value={search} onChange={(e) => { setPage(0); setSearch(e.target.value) }} />
              {search && (
                <button className="absolute right-2 top-2.5 text-slate-600 hover:text-slate-300"
                        onClick={() => setSearch('')} aria-label="Effacer la recherche">
                  <X className="h-4 w-4" />
                </button>
              )}
            </div>
          </div>
          <div>
            <label htmlFor="sev" className="label-xs mb-1.5 block">Gravité</label>
            <select id="sev" className="input w-[140px]" value={filters.severity ?? ''}
                    onChange={(e) => setFilter('severity', e.target.value)}>
              <option value="">Toutes</option>
              {SEVERITY_ORDER.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </div>
          <div>
            <label htmlFor="fam" className="label-xs mb-1.5 block">Famille</label>
            <select id="fam" className="input w-[170px]" value={filters.family ?? ''}
                    onChange={(e) => setFilter('family', e.target.value)}>
              <option value="">Toutes</option>
              {FAMILIES.map((f) => <option key={f} value={f}>{f}</option>)}
            </select>
          </div>
          <div>
            <label htmlFor="st" className="label-xs mb-1.5 block">Statut</label>
            <select id="st" className="input w-[160px]" value={filters.status ?? ''}
                    onChange={(e) => { setFilter('status', e.target.value); setFilter('open_only', false) }}>
              <option value="">Tous</option>
              {Object.entries(STATUS_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
          </div>
          <div>
            <label htmlFor="sort" className="label-xs mb-1.5 block">Tri</label>
            <select id="sort" className="input w-[160px]" value={filters.sort ?? 'priority'}
                    onChange={(e) => setFilter('sort', e.target.value)}>
              <option value="priority">Priorité</option>
              <option value="last_seen">Plus récent</option>
              <option value="occurrences">Volume</option>
              <option value="score_max">Score</option>
            </select>
          </div>
          <label className="inline-flex cursor-pointer items-center gap-2 pb-2.5 text-sm text-slate-400">
            <input type="checkbox" className="accent-accent" checked={!!filters.open_only}
                   onChange={(e) => { setFilter('open_only', e.target.checked); setFilter('status', undefined) }} />
            Ouverts uniquement
          </label>
          <button className="btn-ghost mb-0.5" onClick={reload} disabled={loading}>
            <RotateCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} aria-hidden /> Actualiser
          </button>
        </div>
      </div>

      {selected.size > 0 && canTriage && (
        <div className="panel panel-pad flex flex-wrap items-center gap-3 border-accent/30 bg-accent/5">
          <span className="inline-flex items-center gap-2 text-sm text-accent">
            <CheckCheck className="h-4 w-4" aria-hidden /> {selected.size} sélectionné(s)
          </span>
          <button className="btn-ghost" disabled={busy} onClick={() => bulk({ status: 'ACK' })}>Prendre en compte</button>
          <button className="btn-ghost" disabled={busy} onClick={() => bulk({ status: 'INVESTIGATING' })}>En analyse</button>
          <button className="btn-danger" disabled={busy} onClick={() => bulk({ verdict: 'TP' })}>Vrai positif</button>
          <button className="btn-ghost" disabled={busy} onClick={() => bulk({ verdict: 'FP' })}>Faux positif</button>
          <button className="btn-ghost ml-auto" onClick={() => setSelected(new Set())}>Désélectionner</button>
        </div>
      )}

      {error ? <ErrorNote message={error} onRetry={reload} /> : (
        <Panel pad={false}
               title={`${num(total)} incident${total === 1 ? '' : 's'}`}
               action={pages > 1 ? (
                 <span className="flex items-center gap-2 text-xs text-slate-500">
                   <button className="btn-ghost px-2 py-1" disabled={page === 0}
                           onClick={() => setPage((p) => p - 1)}>←</button>
                   page {page + 1} / {pages}
                   <button className="btn-ghost px-2 py-1" disabled={page + 1 >= pages}
                           onClick={() => setPage((p) => p + 1)}>→</button>
                 </span>
               ) : null}>
          {loading && !items.length ? <Spinner /> : items.length === 0 ? (
            <Empty title="Aucun incident ne correspond" icon={Filter}
                   hint="Élargissez les filtres, ou démarrez une source pour générer du trafic." />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[1040px]">
                <thead className="border-b border-ink-800">
                  <tr>
                    {canTriage && <th className="th w-9">
                      <input type="checkbox" className="accent-accent" aria-label="Tout sélectionner"
                             checked={selected.size > 0 && selected.size === items.length}
                             onChange={(e) => setSelected(e.target.checked ? new Set(items.map((i) => i.id)) : new Set())} />
                    </th>}
                    <th className="th">Prio</th>
                    <th className="th">Gravité</th>
                    <th className="th">Famille</th>
                    <th className="th">Source → Cible</th>
                    <th className="th">Actif</th>
                    <th className="th">Volume</th>
                    <th className="th">Score</th>
                    <th className="th">Statut</th>
                    <th className="th">Vu</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-ink-800">
                  {items.map((inc) => (
                    <tr key={inc.id} className="group hover:bg-ink-850/60">
                      {canTriage && (
                        <td className="td">
                          <input type="checkbox" className="accent-accent" checked={selected.has(inc.id)}
                                 onChange={() => toggle(inc.id)} aria-label={`Sélectionner l'incident ${inc.id}`} />
                        </td>
                      )}
                      <td className="td">
                        <span className="inline-flex h-6 min-w-[28px] items-center justify-center rounded
                                         bg-ink-800 px-1 text-xs font-semibold tabular-nums text-slate-300">
                          {inc.priority}
                        </span>
                      </td>
                      <td className="td"><SeverityTag severity={inc.severity} /></td>
                      <td className="td">
                        <Link to={`/incidents/${inc.id}`} className="font-medium text-slate-100 hover:text-accent">
                          {inc.family_title}
                        </Link>
                        {inc.mitre_technique !== '-' && (
                          <span className="ml-1.5 font-mono text-[10px] text-slate-600">{inc.mitre_technique}</span>
                        )}
                      </td>
                      <td className="td text-slate-400">
                        <Mono>{inc.src}</Mono>
                        <span className="mx-1 text-slate-600">→</span>
                        <Mono>{inc.dst}{inc.dport ? `:${inc.dport}` : ''}</Mono>
                      </td>
                      <td className="td">
                        <span className="flex items-center gap-2">
                          <Criticality value={inc.criticality} />
                          <span className="truncate text-xs text-slate-400">{inc.asset_name}</span>
                        </span>
                      </td>
                      <td className="td tabular-nums text-slate-400">
                        {num(inc.occurrences)}
                        {inc.distinct_dports > 1 && <span className="text-slate-600"> · {inc.distinct_dports} ports</span>}
                        {inc.distinct_peers > 1 && <span className="text-slate-600"> · {inc.distinct_peers} pairs</span>}
                      </td>
                      <td className="td tabular-nums">
                        <span className="text-slate-200">{fmtScore(inc.score_max)}</span>
                        <span className="text-slate-600"> / {fmtScore(inc.threshold)}</span>
                      </td>
                      <td className="td">
                        <span className="flex items-center gap-1.5">
                          <StatusTag status={inc.status} />
                          <VerdictTag verdict={inc.verdict} />
                        </span>
                      </td>
                      <td className="td text-xs text-slate-500">{ago(inc.last_seen)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      )}

      {toast && <Toast message={toast.message} tone={toast.tone} />}
    </div>
  )
}
