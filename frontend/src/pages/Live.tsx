import { Link } from 'react-router-dom'
import { Activity, Boxes, Filter, Gauge, Layers, ShieldOff, Zap } from 'lucide-react'
import type { ConnectionState } from '../hooks/useStream'
import { ActivityChart, ScoreChart } from '../components/charts'
import { Empty, ErrorNote, Mono, Panel, SeverityTag, StatTile, StatusTag } from '../components/ui'
import { bytes, clock, num, score as fmtScore } from '../lib/format'
import type { Incident, PipelineStatus, TickEvent } from '../lib/types'

export function Live({ points, feed, status, connection, lastEvent }: {
  points: TickEvent[]
  feed: Incident[]
  status: PipelineStatus | null
  connection: ConnectionState
  lastEvent: string | null
}) {
  const latest = points.length ? points[points.length - 1] : null
  const stats = latest?.stats ?? status?.stats ?? null
  const source = latest?.source ?? status?.source ?? null
  const running = status?.running ?? false

  if (connection === 'unauthorised') {
    return <ErrorNote message="Le flux temps réel a refusé le jeton. Reconnectez-vous." />
  }

  return (
    <div className="space-y-5">
      {!running && !points.length && (
        <div className="panel panel-pad border-amber-500/30 bg-amber-500/5">
          <div className="flex items-start gap-3">
            <ShieldOff className="mt-0.5 h-5 w-5 shrink-0 text-amber-400" aria-hidden />
            <div>
              <p className="text-sm font-medium text-amber-200">Aucune source active</p>
              <p className="mt-1 text-sm text-slate-400">
                Le moteur est prêt mais rien ne l’alimente. Allez dans{' '}
                <Link to="/replay" className="link">Sources &amp; rejeu</Link> pour démarrer le réseau
                de laboratoire, rejouer un PCAP ou capturer une interface réelle.
              </p>
            </div>
          </div>
        </div>
      )}

      {status?.error && <ErrorNote message={status.error} />}
      {lastEvent === 'finished' && (
        <p className="text-xs text-slate-500">La source a atteint sa fin — les flux restants ont été vidés.</p>
      )}

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-3 xl:grid-cols-6">
        <StatTile label="Paquets analysés" value={num(stats?.packets ?? 0)} icon={Activity}
                  hint={source ? `source : ${source.name}` : undefined} />
        <StatTile label="Flux reconstruits" value={num(stats?.flows ?? 0)} icon={Layers}
                  hint={`${num(latest?.active_flows ?? status?.active_flows ?? 0)} en cours`} />
        <StatTile label="Alertes levées" value={num(stats?.alerts ?? 0)} icon={Zap}
                  accent="var(--series-2)"
                  hint={stats ? `${num(stats.alerts_per_hour)} / heure` : undefined} />
        <StatTile label="Supprimées par l’étage B" value={num(stats?.suppressed ?? 0)} icon={Filter}
                  hint="anomalies reconnues comme normales" />
        <StatTile label="Incidents ouverts" value={num(latest?.open_incidents ?? status?.open_incidents ?? 0)}
                  icon={Boxes} hint={`${num(status?.alerts_merged ?? 0)} alertes fusionnées`} />
        <StatTile label="Score max observé" value={fmtScore(stats?.score_max ?? 0)} icon={Gauge}
                  hint={`moyenne ${fmtScore(stats?.score_mean ?? 0)}`} />
      </div>

      <Panel title="Score d’anomalie — temps réel"
             action={source?.kind === 'lab' && source.attacks
               ? <span className="text-xs text-slate-500">
                   {source.attacks.length} attaques programmées · t+{num(source.simulated_seconds ?? 0)} s
                 </span>
               : source?.kind === 'pcap'
                 ? <span className="text-xs text-slate-500">
                     rejeu ×{source.speed} · {num(source.capture_seconds ?? 0)} s de capture
                   </span>
                 : null}>
        {points.length ? <ScoreChart data={points} height={280} />
          : <Empty title="En attente de données" hint="Le graphique se remplit dès le premier tick." />}
      </Panel>

      <div className="grid gap-5 xl:grid-cols-[1fr_440px]">
        <Panel title="Débit analysé">
          {points.length ? <ActivityChart data={points} height={200} /> : <Empty title="Aucun flux" />}
        </Panel>

        <Panel title="Journal des incidents (direct)" pad={false}
               action={<Link to="/incidents" className="link text-xs">Tout voir →</Link>}>
          <div className="max-h-[420px] overflow-y-auto">
            {feed.length === 0 ? (
              <Empty title="Aucune anomalie pour le moment"
                     hint="Les incidents corrélés apparaissent ici au fil de leur détection." />
            ) : (
              <ul className="divide-y divide-ink-800">
                {feed.map((incident) => (
                  <li key={incident.id}
                      className={`px-4 py-3 transition-colors hover:bg-ink-850/60 ${
                        incident.is_new ? 'animate-fade-in' : ''}`}>
                    <div className="flex items-start justify-between gap-3">
                      <SeverityTag severity={incident.severity} />
                      <span className="shrink-0 text-[11px] tabular-nums text-slate-500">
                        {clock(incident.last_seen)}
                      </span>
                    </div>
                    <Link to={`/incidents/${incident.id}`}
                          className="mt-1 block text-sm font-medium text-slate-100 hover:text-accent">
                      {incident.family_title}
                      {incident.occurrences > 1 && (
                        <span className="ml-1.5 rounded bg-ink-800 px-1.5 py-0.5 text-[11px]
                                         font-normal tabular-nums text-slate-400">
                          ×{num(incident.occurrences)}
                        </span>
                      )}
                    </Link>
                    <p className="mt-1 text-xs text-slate-500">
                      <Mono>{incident.src}</Mono> → <Mono>{incident.dst}</Mono>
                      {incident.dport ? <Mono>:{incident.dport}</Mono> : null}
                      {incident.asset_name && <span className="text-slate-600"> · {incident.asset_name}</span>}
                    </p>
                    <div className="mt-1.5 flex items-center gap-2 text-[11px] text-slate-500">
                      <StatusTag status={incident.status} />
                      <span className="tabular-nums">
                        score {fmtScore(incident.score_max)} / seuil {fmtScore(incident.threshold)}
                      </span>
                      {incident.mitre_technique !== '-' && (
                        <span className="rounded bg-ink-800 px-1.5 py-0.5 font-mono text-[10px] text-slate-400">
                          {incident.mitre_technique}
                        </span>
                      )}
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </Panel>
      </div>

      {source && (
        <p className="text-[11px] text-slate-600">
          Source : <span className="text-slate-500">{source.name}</span> ({source.kind}) ·
          {' '}{num(source.packets)} paquets émis
          {source.dropped !== undefined && source.dropped > 0 && (
            <span className="text-amber-500"> · {num(source.dropped)} paquets perdus (file de capture saturée)</span>
          )}
          {' · '}écrit en base : {num(status?.written.incidents ?? 0)} incidents,
          {' '}{num(status?.written.alerts ?? 0)} alertes
          {(status?.written.alerts_dropped ?? 0) > 0 &&
            ` (${num(status?.written.alerts_dropped ?? 0)} alertes non stockées : plafond par incident atteint)`}
          {' · '}{bytes(stats?.bytes ?? 0)} analysés
        </p>
      )}
    </div>
  )
}
