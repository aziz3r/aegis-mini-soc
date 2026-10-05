import { Cpu, GitCompare, Info, Timer, TrendingDown } from 'lucide-react'
import { useApi } from '../hooks/useApi'
import { api } from '../lib/api'
import { RankedBars } from '../components/charts'
import { Empty, ErrorNote, Mono, Panel, Spinner, StatTile } from '../components/ui'
import { duration, num, pct, score as fmtScore, stamp } from '../lib/format'

export function Model() {
  const model = useApi(() => api.model(), [])
  const thresholds = useApi(() => api.thresholds(), [], 10_000)

  if (model.error) return <ErrorNote message={model.error} onRetry={model.reload} />
  if (model.loading && !model.data) return <Spinner />
  if (!model.data) return null

  const m = model.data
  const metrics = m.metrics ?? {}
  const stealth = metrics.stealth ?? {}
  const report = metrics.classifier_report ?? {}
  const confusion = metrics.confusion
  const raised = (thresholds.data?.items ?? []).filter((t) => t.raised)

  if (!metrics.recall) {
    return (
      <Empty title="Aucune métrique enregistrée pour ce modèle"
             icon={Cpu}
             hint={<>Lancez <Mono>aegis bench</Mono> pour évaluer le modèle sauvegardé et remplir cette page.</>} />
    )
  }

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-6">
        <StatTile label="Rappel (bruyant)" value={pct(metrics.recall)} emphasis
                  hint={`précision ${pct(metrics.precision)}`} />
        <StatTile label="Rappel (furtif)" value={pct(stealth.recall ?? 0)} emphasis
                  accent="var(--sev-medium)" hint={`précision ${pct(stealth.precision ?? 0)}`} />
        <StatTile label="PR-AUC" value={fmtScore(metrics.pr_auc ?? 0, 4)}
                  hint={`ROC-AUC ${fmtScore(metrics.roc_auc ?? 0, 4)}`} />
        <StatTile label="macro-F1 des familles" value={fmtScore(metrics.classifier_macro_f1 ?? 0, 4)}
                  hint={`${m.classes.length} classes`} />
        <StatTile label="Faux positifs" value={num(metrics.benign_incidents_per_hour ?? 0)} unit="incidents/h"
                  icon={TrendingDown}
                  hint={`${num(metrics.benign_alerts_per_hour ?? 0)} alertes/h avant corrélation`} />
        <StatTile label="Latence médiane" value={duration(metrics.latency_p50 ?? 0)} icon={Timer}
                  hint={`p95 ${duration(metrics.latency_p95 ?? 0)}`} />
      </div>

      <div className="panel panel-pad border-sky-500/25 bg-sky-500/5">
        <div className="flex items-start gap-3">
          <Info className="mt-0.5 h-5 w-5 shrink-0 text-sky-400" aria-hidden />
          <div className="space-y-1.5 text-sm leading-relaxed text-slate-300">
            <p>
              <strong className="text-slate-100">Comment lire ces chiffres.</strong> Les deux colonnes
              « bruyant » et « furtif » sont les mêmes attaques, la seconde ralentie d’un facteur 15 à 60
              avec rotation des sources et gigue sur les balises. Les chiffres bruyants disent que la
              chaîne fonctionne ; les chiffres furtifs disent où elle cesse de fonctionner.
            </p>
            <p className="text-slate-400">
              Le trafic d’évaluation est <strong>synthétique</strong> : la chaîne de détection est réelle
              et c’est la même qui tourne en production, mais un vrai réseau est plus désordonné.
              Attendez-vous à davantage de faux positifs qu’ici — et utilisez le rejeu d’un PCAP réel
              comme véritable épreuve.
            </p>
          </div>
        </div>
      </div>

      <div className="grid gap-5 xl:grid-cols-2">
        <Panel title="Rappel par famille d’attaque">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="border-b border-ink-800">
                <tr>
                  <th className="th">Famille</th><th className="th">Bruyant</th>
                  <th className="th">Furtif</th><th className="th">Latence</th><th className="th">n</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-ink-800">
                {Object.entries(metrics.family_recall ?? {}).map(([family, recall]) => {
                  const sr = (stealth.family_recall ?? {})[family] ?? 0
                  return (
                    <tr key={family} className="hover:bg-ink-850/60">
                      <td className="td">
                        <span className="text-slate-200">{m.families[family]?.title ?? family}</span>
                        <span className="ml-1.5 font-mono text-[10px] text-slate-600">
                          {m.families[family]?.technique}
                        </span>
                      </td>
                      <td className="td tabular-nums">
                        <span className={recall >= 0.95 ? 'text-emerald-300' : recall >= 0.8 ? 'text-amber-300' : 'text-red-300'}>
                          {pct(recall)}
                        </span>
                      </td>
                      <td className="td tabular-nums">
                        <span className={sr >= 0.95 ? 'text-emerald-300' : sr >= 0.8 ? 'text-amber-300' : 'text-red-300'}>
                          {pct(sr)}
                        </span>
                      </td>
                      <td className="td tabular-nums text-slate-400">
                        {duration((metrics.latency_by_family ?? {})[family] ?? 0)}
                      </td>
                      <td className="td tabular-nums text-slate-500">
                        {num((metrics.family_support ?? {})[family] ?? 0)}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </Panel>

        <Panel title="Nommage de la famille (étage B)">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="border-b border-ink-800">
                <tr>
                  <th className="th">Famille</th><th className="th">Précision</th>
                  <th className="th">Rappel</th><th className="th">F1</th><th className="th">n</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-ink-800">
                {Object.entries(report).map(([family, r]) => (
                  <tr key={family} className="hover:bg-ink-850/60">
                    <td className="td text-slate-200">{m.families[family]?.title ?? family}</td>
                    <td className="td tabular-nums text-slate-300">{r.precision.toFixed(3)}</td>
                    <td className="td tabular-nums text-slate-300">{r.recall.toFixed(3)}</td>
                    <td className="td tabular-nums text-slate-300">{r.f1.toFixed(3)}</td>
                    <td className="td tabular-nums text-slate-500">{num(r.support)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      </div>

      {confusion && (
        <Panel title={<span className="inline-flex items-center gap-2">
          <GitCompare className="h-4 w-4 text-accent" aria-hidden /> Matrice de confusion du classifieur
        </span>}>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[760px] text-xs">
              <thead>
                <tr>
                  <th className="th">vérité \ prédit</th>
                  {confusion.labels.map((l) => (
                    <th key={l} className="th text-center">{l.slice(0, 10)}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-ink-800">
                {confusion.matrix.map((row, i) => {
                  const total = row.reduce((s, v) => s + v, 0) || 1
                  return (
                    <tr key={i}>
                      <td className="td font-medium text-slate-300">{confusion.labels[i]}</td>
                      {row.map((value, j) => (
                        <td key={j} className="td text-center tabular-nums"
                            style={{
                              // single hue, lightness carries magnitude
                              background: value ? `rgba(57,135,229,${0.08 + 0.52 * (value / total)})` : undefined,
                              color: value ? '#e2e8f0' : '#475569',
                            }}>
                          {value || '·'}
                        </td>
                      ))}
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
          <p className="mt-3 text-[11px] text-slate-600">
            La diagonale est le cas correct. Hors diagonale : une famille confondue avec une autre.
            Les colonnes <Mono>UNKNOWN</Mono> et <Mono>BENIGN</Mono> comptent les flux d’attaque que le
            classifieur n’a pas su nommer — l’étage A les a quand même signalés.
          </p>
        </Panel>
      )}

      <div className="grid gap-5 xl:grid-cols-2">
        <Panel title="Seuils adaptatifs par hôte"
               action={<span className="text-xs text-slate-500">
                 plancher {fmtScore(thresholds.data?.base ?? 0.98)}
               </span>}>
          {(thresholds.data?.items ?? []).length === 0 ? (
            <Empty title="Aucun hôte profilé"
                   hint="Les seuils par hôte se construisent à mesure que le moteur observe du trafic." />
          ) : (
            <>
              <p className="mb-3 text-xs leading-relaxed text-slate-500">
                {raised.length} hôte(s) sur {thresholds.data?.items.length} ont relevé leur propre seuil
                au-dessus du plancher : leur trafic normal est légitimement inhabituel, et c’est exactement
                ce que l’adaptation évite de signaler en boucle.
              </p>
              <div className="max-h-[320px] overflow-auto">
                <table className="w-full">
                  <thead className="sticky top-0 bg-ink-900">
                    <tr>
                      <th className="th">Hôte</th><th className="th">Échantillons</th>
                      <th className="th">Médiane</th><th className="th">p99</th><th className="th">Seuil</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-ink-800">
                    {thresholds.data?.items.map((t) => (
                      <tr key={t.host} className="hover:bg-ink-850/60">
                        <td className="td"><Mono className="text-slate-300">{t.host}</Mono></td>
                        <td className="td tabular-nums text-slate-500">{num(t.samples)}</td>
                        <td className="td tabular-nums text-slate-400">{fmtScore(t.median)}</td>
                        <td className="td tabular-nums text-slate-400">{fmtScore(t.p99)}</td>
                        <td className="td tabular-nums">
                          <span className={t.raised ? 'text-amber-300' : 'text-slate-300'}>
                            {fmtScore(t.threshold)}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </Panel>

        <div className="space-y-5">
          <Panel title="Modèle et protocole">
            <dl className="space-y-2.5 text-sm">
              <div className="flex justify-between gap-3">
                <dt className="text-slate-500">Entraîné le</dt>
                <dd className="text-xs text-slate-300">{stamp(m.trained_at)}</dd>
              </div>
              <div className="flex justify-between gap-3">
                <dt className="text-slate-500">Flux bénins (étage A)</dt>
                <dd className="tabular-nums text-slate-300">{num(m.train_flows_benign)}</dd>
              </div>
              <div className="flex justify-between gap-3">
                <dt className="text-slate-500">Flux étiquetés (étage B)</dt>
                <dd className="tabular-nums text-slate-300">{num(m.train_flows_labelled)}</dd>
              </div>
              <div className="flex justify-between gap-3">
                <dt className="text-slate-500">Captures d’entraînement</dt>
                <dd className="font-mono text-xs text-slate-400">[{m.train_seeds.join(', ')}]</dd>
              </div>
              <div className="flex justify-between gap-3">
                <dt className="text-slate-500">Captures de test</dt>
                <dd className="font-mono text-xs text-slate-400">[{m.test_seeds.join(', ')}]</dd>
              </div>
              <div className="flex justify-between gap-3">
                <dt className="text-slate-500">Features</dt>
                <dd className="tabular-nums text-slate-300">{m.feature_count}</dd>
              </div>
              <div className="flex justify-between gap-3">
                <dt className="text-slate-500">Débit mesuré</dt>
                <dd className="tabular-nums text-slate-300">
                  {num(metrics.throughput_pkts_per_sec ?? 0)} paquets/s
                </dd>
              </div>
            </dl>
            <p className="mt-3 border-t border-ink-800 pt-3 text-[11px] leading-relaxed text-slate-600">
              Les seeds d’entraînement et de test sont <strong>disjoints</strong> : la séparation se fait
              par capture, jamais par ligne. Des flux issus de la même rafale d’attaque sont très
              corrélés ; un découpage aléatoire produirait des scores illusoires.
            </p>
          </Panel>

          <Panel title="Point de fonctionnement">
            <RankedBars
              rows={Object.entries(m.operating_point).map(([label, value]) => ({ label, value }))}
              valueFormat={(v) => (v < 1 ? v.toFixed(4) : String(v))} />
          </Panel>
        </div>
      </div>
    </div>
  )
}
