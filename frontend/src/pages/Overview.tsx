import { Link } from 'react-router-dom'
import {
  Activity, AlertTriangle, CheckCircle2, Clock, Gauge, ShieldAlert, Target, TrendingUp,
} from 'lucide-react'
import { useApi } from '../hooks/useApi'
import { api } from '../lib/api'
import { ActivityChart, HourlyBars, RankedBars, ScoreChart, TableView } from '../components/charts'
import { Criticality, Empty, ErrorNote, Mono, Panel, SeverityTag, Spinner, StatTile } from '../components/ui'
import { bytes, duration, num, pct, SEVERITY_ORDER, SEVERITY_VAR } from '../lib/format'
import type { Overview as OverviewData } from '../lib/types'

const FAMILY_LABEL: Record<string, string> = {
  PORT_SCAN: 'Balayage de ports', NET_SCAN: 'Balayage réseau', DOS_FLOOD: 'Déni de service',
  SSH_BRUTEFORCE: 'Force brute SSH', WEB_BRUTEFORCE: 'Force brute web', SLOWLORIS: 'Slowloris',
  DNS_TUNNEL: 'Tunnel DNS', EXFILTRATION: 'Exfiltration', C2_BEACON: 'Balise C2',
  UNKNOWN: 'Anomalie non classée', BENIGN: 'Classé légitime',
}

export function Overview() {
  const { data, error, loading, reload } = useApi<OverviewData>(() => api.overview(24), [], 15_000)

  if (error) return <ErrorNote message={error} onRetry={reload} />
  if (loading && !data) return <Spinner />
  if (!data) return null

  const open = SEVERITY_ORDER.reduce((sum, s) => sum + (data.open_by_severity[s] ?? 0), 0)
  const critical = data.open_by_severity.CRITICAL ?? 0
  const families = Object.entries(data.by_family)
    .sort((a, b) => b[1] - a[1])
    .map(([key, value]) => ({ label: FAMILY_LABEL[key] ?? key, value }))

  return (
    <div className="space-y-5">
      {/* severity breakdown: icon + label, never colour alone */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 xl:grid-cols-6">
        <StatTile label="Incidents ouverts" value={num(open)} emphasis icon={ShieldAlert}
                  accent={critical > 0 ? SEVERITY_VAR.CRITICAL : SEVERITY_VAR.LOW}
                  hint={critical > 0 ? `dont ${num(critical)} critique${critical > 1 ? 's' : ''}` : 'rien de critique'} />
        {SEVERITY_ORDER.map((sev) => (
          <div key={sev} className="panel panel-pad relative overflow-hidden">
            <div className="absolute left-0 top-0 bottom-0 w-[3px]" style={{ background: SEVERITY_VAR[sev] }} aria-hidden />
            <SeverityTag severity={sev} />
            <p className="mt-2 text-2xl font-semibold tabular-nums text-slate-50">
              {num(data.open_by_severity[sev] ?? 0)}
            </p>
          </div>
        ))}
        <StatTile label="Alertes corrélées (24 h)" value={num(data.alerts_total)} icon={Activity}
                  hint={`${num(data.incidents_total)} incidents · ratio ${
                    data.incidents_total ? (data.alerts_total / data.incidents_total).toFixed(0) : '—'}:1`} />
      </div>

      <div className="grid gap-5 xl:grid-cols-3">
        <Panel className="xl:col-span-2" title="Score d’anomalie et seuil adaptatif (24 h)">
          {data.buckets.length
            ? <ScoreChart data={data.buckets} />
            : <Empty title="Aucune donnée sur la période"
                     hint="Démarrez une source depuis « Sources & rejeu » pour alimenter le moteur." />}
        </Panel>

        <Panel title="Qualité de la détection">
          <dl className="space-y-3.5 text-sm">
            <div className="flex items-baseline justify-between gap-3">
              <dt className="text-slate-400">Incidents clos (24 h)</dt>
              <dd className="tabular-nums text-slate-100">{num(data.closed_total)}</dd>
            </div>
            <div className="flex items-baseline justify-between gap-3">
              <dt className="text-slate-400">Délai moyen de clôture</dt>
              <dd className="tabular-nums text-slate-100">
                {data.mean_time_to_close_minutes !== null
                  ? duration(data.mean_time_to_close_minutes * 60) : '—'}
              </dd>
            </div>
            <div className="flex items-baseline justify-between gap-3">
              <dt className="inline-flex items-center gap-1.5 text-slate-400">
                <AlertTriangle className="h-3.5 w-3.5" style={{ color: SEVERITY_VAR.CRITICAL }} aria-hidden />
                Vrais positifs confirmés
              </dt>
              <dd className="tabular-nums text-slate-100">{num(data.feedback.true_positive)}</dd>
            </div>
            <div className="flex items-baseline justify-between gap-3">
              <dt className="inline-flex items-center gap-1.5 text-slate-400">
                <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" aria-hidden />
                Faux positifs déclarés
              </dt>
              <dd className="tabular-nums text-slate-100">{num(data.feedback.false_positive)}</dd>
            </div>
            <div className="border-t border-ink-800 pt-3.5 flex items-baseline justify-between gap-3">
              <dt className="inline-flex items-center gap-1.5 font-medium text-slate-300">
                <Gauge className="h-4 w-4 text-accent" aria-hidden /> Précision observée
              </dt>
              <dd className="text-lg font-semibold tabular-nums text-slate-50">
                {data.feedback.precision_observed !== null ? pct(data.feedback.precision_observed) : '—'}
              </dd>
            </div>
          </dl>
          <p className="mt-4 text-[11px] leading-relaxed text-slate-600">
            Mesurée sur les incidents que les analystes ont réellement jugés, pas sur le jeu de test.
            C’est la seule précision qui décrit ce déploiement-ci — et chaque faux positif déclaré
            devient un exemple d’entraînement.
          </p>
        </Panel>
      </div>

      <div className="grid gap-5 xl:grid-cols-3">
        <Panel title="Débit analysé et alertes">
          {data.buckets.length ? <ActivityChart data={data.buckets} /> : <Empty title="Aucun flux analysé" />}
        </Panel>
        <Panel title="Incidents par heure">
          <HourlyBars rows={data.hourly} />
        </Panel>
        <Panel title="Familles d’attaque détectées">
          <RankedBars rows={families} emptyLabel="aucune famille détectée sur la période" />
          {families.length > 0 && (
            <TableView caption="Familles d’attaque détectées sur 24 heures"
                       head={['Famille', 'Incidents']}
                       rows={families.map((f) => [f.label, num(f.value)])} />
          )}
        </Panel>
      </div>

      <div className="grid gap-5 lg:grid-cols-2">
        <Panel title="Sources les plus actives"
               action={<Link to="/incidents" className="link text-xs">Tous les incidents →</Link>}>
          {data.top_sources.length === 0 ? <Empty title="Aucune source à signaler" icon={Target} /> : (
            <table className="w-full">
              <thead><tr>
                <th className="th">Adresse</th><th className="th">Incidents</th>
                <th className="th">Alertes</th><th className="th">Pire gravité</th>
              </tr></thead>
              <tbody className="divide-y divide-ink-800">
                {data.top_sources.map((s) => (
                  <tr key={s.ip} className="hover:bg-ink-850/60">
                    <td className="td"><Link to={`/hosts/${s.ip}`} className="link"><Mono>{s.ip}</Mono></Link></td>
                    <td className="td tabular-nums text-slate-300">{num(s.incidents)}</td>
                    <td className="td tabular-nums text-slate-300">{num(s.alerts)}</td>
                    <td className="td">
                      <SeverityTag severity={['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'][s.max_severity] ?? 'LOW'} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>

        <Panel title="Cibles les plus visées">
          {data.top_targets.length === 0 ? <Empty title="Aucune cible à signaler" icon={Target} /> : (
            <table className="w-full">
              <thead><tr>
                <th className="th">Adresse</th><th className="th">Actif</th>
                <th className="th">Criticité</th><th className="th">Incidents</th>
              </tr></thead>
              <tbody className="divide-y divide-ink-800">
                {data.top_targets.map((t) => (
                  <tr key={t.ip} className="hover:bg-ink-850/60">
                    <td className="td"><Link to={`/hosts/${t.ip}`} className="link"><Mono>{t.ip}</Mono></Link></td>
                    <td className="td text-slate-300">{t.asset || '—'}</td>
                    <td className="td"><Criticality value={t.criticality} /></td>
                    <td className="td tabular-nums text-slate-300">{num(t.incidents)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>
      </div>

      <p className="flex items-center gap-1.5 text-[11px] text-slate-600">
        <Clock className="h-3 w-3" aria-hidden />
        Fenêtre : {data.window_hours} h · actualisation automatique toutes les 15 s ·
        volume total analysé {bytes(data.buckets.reduce((s, b) => s + b.bytes, 0))}
        <TrendingUp className="ml-1 h-3 w-3" aria-hidden />
      </p>
    </div>
  )
}
