import { useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import {
  ArrowLeft, BookOpen, Download, Lightbulb, Microscope, Server, Target,
} from 'lucide-react'
import { useApi } from '../hooks/useApi'
import { api, type Session } from '../lib/api'
import { ContributionBars, RankedBars } from '../components/charts'
import {
  Criticality, Empty, ErrorNote, Mono, Panel, SeverityTag, Spinner, StatTile, StatusTag, Toast, VerdictTag,
} from '../components/ui'
import { bytes, duration, num, pct, score as fmtScore, stamp, SEVERITY_VAR } from '../lib/format'

export function IncidentDetail({ session }: { session: Session }) {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const incidentId = Number(id)
  const { data, error, loading, reload } = useApi(() => api.incident(incidentId, 200), [incidentId])
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(false)
  const [toast, setToast] = useState<{ message: string; tone: 'ok' | 'error' } | null>(null)
  const canTriage = session.role !== 'viewer'

  const act = async (patch: Record<string, string | null>) => {
    setBusy(true)
    try {
      await api.patchIncident(incidentId, patch)
      setToast({ message: 'Incident mis à jour', tone: 'ok' })
      setNote('')
      reload()
    } catch (exc) {
      setToast({ message: (exc as Error).message, tone: 'error' })
    } finally {
      setBusy(false)
      window.setTimeout(() => setToast(null), 3000)
    }
  }

  if (error) return <ErrorNote message={error} onRetry={reload} />
  if (loading && !data) return <Spinner />
  if (!data) return null

  const truthEntries = Object.entries(data.ground_truth)
  const truthTotal = truthEntries.reduce((s, [, v]) => s + v, 0)
  const truthCorrect = truthEntries
    .filter(([k]) => k !== 'BENIGN')
    .reduce((s, [, v]) => s + v, 0)

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-3">
        <button onClick={() => navigate(-1)} className="btn-ghost">
          <ArrowLeft className="h-4 w-4" aria-hidden /> Retour
        </button>
        <SeverityTag severity={data.severity} className="text-sm" />
        <h2 className="text-lg font-semibold text-slate-50">{data.family_title}</h2>
        <StatusTag status={data.status} />
        <VerdictTag verdict={data.verdict} />
        {data.mitre_technique !== '-' && (
          <span className="rounded bg-ink-800 px-2 py-1 font-mono text-[11px] text-slate-400">
            {data.mitre_technique} · {data.mitre_tactic}
          </span>
        )}
        <a className="btn-ghost ml-auto" href={`/api/incidents/${incidentId}/export`}
           download={`aegis-incident-${incidentId}.json`}>
          <Download className="h-3.5 w-3.5" aria-hidden /> Exporter
        </a>
      </div>

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-6">
        <StatTile label="Priorité" value={data.priority} unit="/100" emphasis
                  accent={SEVERITY_VAR[data.severity]} />
        <StatTile label="Score max" value={fmtScore(data.score_max)}
                  hint={`seuil de l’hôte ${fmtScore(data.threshold)}`} />
        <StatTile label="Alertes fusionnées" value={num(data.occurrences)}
                  hint={`${num(data.total_packets)} paquets`} />
        <StatTile label="Volume" value={bytes(data.total_bytes)}
                  hint={`${data.distinct_dports} port(s) · ${data.distinct_peers} pair(s)`} />
        <StatTile label="Confiance du classifieur" value={pct(data.confidence, 0)}
                  hint={data.family === 'UNKNOWN' ? 'sous le seuil de nommage' : 'famille nommée'} />
        <StatTile label="Durée" value={duration(
          data.first_seen && data.last_seen
            ? (new Date(data.last_seen).getTime() - new Date(data.first_seen).getTime()) / 1000 : 0)}
                  hint={stamp(data.first_seen)} />
      </div>

      <div className="grid gap-5 xl:grid-cols-[1fr_380px]">
        <div className="space-y-5">
          <Panel title={<span className="inline-flex items-center gap-2">
            <Microscope className="h-4 w-4 text-accent" aria-hidden /> Pourquoi cette alerte
          </span>}>
            <p className="mb-4 text-xs leading-relaxed text-slate-500">
              Attribution par occlusion : chaque feature est remplacée tour à tour par sa valeur
              médiane sur le trafic normal, et le flux est réévalué. La chute du score mesure la
              part de l’anomalie imputable à cette feature.
            </p>
            <ContributionBars contributions={data.contributions} />
          </Panel>

          <Panel title="Alertes de l’incident" pad={false}
                 action={<span className="text-xs text-slate-500">
                   les {Math.min(data.alerts.length, 200)} plus fortes
                 </span>}>
            {data.alerts.length === 0 ? <Empty title="Aucune alerte stockée" /> : (
              <div className="max-h-[420px] overflow-auto">
                <table className="w-full min-w-[760px]">
                  <thead className="sticky top-0 border-b border-ink-800 bg-ink-900">
                    <tr>
                      <th className="th">Horodatage</th><th className="th">Source</th><th className="th">Cible</th>
                      <th className="th">Score</th><th className="th">Paquets</th><th className="th">Octets</th>
                      <th className="th">Durée</th>
                      {truthTotal > 0 && <th className="th">Vérité terrain</th>}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-ink-800">
                    {data.alerts.map((a) => (
                      <tr key={a.id} className="hover:bg-ink-850/60">
                        <td className="td text-xs text-slate-500">{stamp(a.ts)}</td>
                        <td className="td"><Mono className="text-slate-300">{a.src}:{a.sport}</Mono></td>
                        <td className="td"><Mono className="text-slate-300">{a.dst}:{a.dport}</Mono>
                          <span className="ml-1 text-[10px] uppercase text-slate-600">{a.proto}</span></td>
                        <td className="td tabular-nums text-slate-200">{fmtScore(a.score)}</td>
                        <td className="td tabular-nums text-slate-400">{num(a.packets)}</td>
                        <td className="td tabular-nums text-slate-400">{bytes(a.bytes)}</td>
                        <td className="td tabular-nums text-slate-400">{duration(a.duration)}</td>
                        {truthTotal > 0 && (
                          <td className="td text-xs">
                            <span className={a.truth && a.truth !== 'BENIGN' ? 'text-emerald-400' : 'text-slate-500'}>
                              {a.truth ?? '—'}
                            </span>
                          </td>
                        )}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>

          <div className="grid gap-5 sm:grid-cols-2">
            <Panel title="Ports visés">
              <RankedBars rows={data.ports.map((p) => ({ label: `port ${p.port}`, value: p.count }))}
                          emptyLabel="aucun port enregistré" height={200} />
            </Panel>
            <Panel title="Pairs impliqués">
              <RankedBars rows={data.peers.map((p) => ({ label: p.ip, value: p.count }))}
                          emptyLabel="aucun pair enregistré" height={200} />
            </Panel>
          </div>
        </div>

        <div className="space-y-5">
          <Panel title={<span className="inline-flex items-center gap-2">
            <BookOpen className="h-4 w-4 text-accent" aria-hidden /> Ce que c’est
          </span>}>
            <p className="text-sm leading-relaxed text-slate-300">{data.guidance.description}</p>
            <div className="mt-4 rounded-lg border border-accent/20 bg-accent/5 p-3">
              <p className="mb-1.5 inline-flex items-center gap-1.5 text-xs font-semibold text-accent">
                <Lightbulb className="h-3.5 w-3.5" aria-hidden /> Marche à suivre
              </p>
              <p className="text-sm leading-relaxed text-slate-300">{data.guidance.triage}</p>
            </div>
          </Panel>

          <Panel title="Contexte">
            <dl className="space-y-2.5 text-sm">
              <div className="flex items-start justify-between gap-3">
                <dt className="inline-flex items-center gap-1.5 text-slate-500">
                  <Target className="h-3.5 w-3.5" aria-hidden /> Source
                </dt>
                <dd><Link to={`/hosts/${data.src}`} className="link"><Mono>{data.src}</Mono></Link></dd>
              </div>
              <div className="flex items-start justify-between gap-3">
                <dt className="inline-flex items-center gap-1.5 text-slate-500">
                  <Server className="h-3.5 w-3.5" aria-hidden /> Cible
                </dt>
                <dd className="text-right">
                  <Link to={`/hosts/${data.dst}`} className="link"><Mono>{data.dst}</Mono></Link>
                  <p className="text-xs text-slate-500">{data.asset_name}</p>
                </dd>
              </div>
              <div className="flex items-center justify-between gap-3">
                <dt className="text-slate-500">Criticité de l’actif</dt>
                <dd><Criticality value={data.criticality} /></dd>
              </div>
              <div className="flex items-center justify-between gap-3">
                <dt className="text-slate-500">Première occurrence</dt>
                <dd className="text-xs text-slate-300">{stamp(data.first_seen)}</dd>
              </div>
              <div className="flex items-center justify-between gap-3">
                <dt className="text-slate-500">Dernière occurrence</dt>
                <dd className="text-xs text-slate-300">{stamp(data.last_seen)}</dd>
              </div>
              {data.assignee && (
                <div className="flex items-center justify-between gap-3">
                  <dt className="text-slate-500">Assigné à</dt>
                  <dd className="text-slate-200">{data.assignee}</dd>
                </div>
              )}
            </dl>

            {truthTotal > 0 && (
              <div className="mt-4 border-t border-ink-800 pt-3">
                <p className="label-xs mb-2">Vérité terrain (source de laboratoire)</p>
                <p className="text-sm text-slate-300">
                  {truthCorrect === truthTotal
                    ? <span className="text-emerald-400">
                        {num(truthTotal)} alerte(s), toutes réellement malveillantes.
                      </span>
                    : <>
                        {num(truthCorrect)} / {num(truthTotal)} alertes correspondent à une vraie attaque
                        {' '}({pct(truthCorrect / truthTotal, 0)}).
                      </>}
                </p>
                <ul className="mt-2 space-y-1 text-xs text-slate-500">
                  {truthEntries.map(([label, count]) => (
                    <li key={label} className="flex justify-between gap-3">
                      <span>{label}</span><span className="tabular-nums">{num(count)}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </Panel>

          {canTriage ? (
            <Panel title="Triage">
              <div className="flex flex-wrap gap-2">
                <button className="btn-ghost" disabled={busy} onClick={() => act({ status: 'ACK' })}>
                  Prendre en compte
                </button>
                <button className="btn-ghost" disabled={busy} onClick={() => act({ status: 'INVESTIGATING' })}>
                  En analyse
                </button>
                <button className="btn-ghost" disabled={busy}
                        onClick={() => act({ assignee: session.username })}>
                  M’assigner
                </button>
              </div>
              <p className="label-xs mt-4 mb-2">Conclusion</p>
              <div className="flex flex-wrap gap-2">
                <button className="btn-danger" disabled={busy} onClick={() => act({ verdict: 'TP' })}>
                  Vrai positif
                </button>
                <button className="btn-ghost" disabled={busy} onClick={() => act({ verdict: 'FP' })}>
                  Faux positif
                </button>
                <button className="btn-ghost" disabled={busy} onClick={() => act({ verdict: 'BENIGN' })}>
                  Trafic légitime
                </button>
              </div>
              <p className="mt-2 text-[11px] leading-relaxed text-slate-600">
                Conclure ferme l’incident et enregistre le jugement. Les faux positifs déclarés
                constituent le signal de ré-entraînement : c’est ce qui fait progresser le modèle
                au lieu de le laisser figé.
              </p>

              <label htmlFor="note" className="label-xs mb-1.5 mt-4 block">Note d’analyse</label>
              <textarea id="note" className="input min-h-[80px]" value={note}
                        onChange={(e) => setNote(e.target.value)}
                        placeholder="Ce que vous avez vérifié, et ce que vous en concluez…" />
              <button className="btn-primary mt-2 w-full justify-center" disabled={busy || !note.trim()}
                      onClick={() => act({ note })}>
                Ajouter la note
              </button>
              {data.note && (
                <pre className="mt-4 max-h-48 overflow-auto whitespace-pre-wrap rounded-lg border
                                border-ink-800 bg-ink-950 p-3 text-xs leading-relaxed text-slate-400">
                  {data.note}
                </pre>
              )}
            </Panel>
          ) : (
            <Panel title="Triage">
              <p className="text-sm text-slate-500">
                Votre rôle (<span className="text-slate-400">lecteur</span>) permet la consultation
                mais pas la modification. Un compte analyste est requis pour trier.
              </p>
            </Panel>
          )}
        </div>
      </div>

      {toast && <Toast message={toast.message} tone={toast.tone} />}
    </div>
  )
}
