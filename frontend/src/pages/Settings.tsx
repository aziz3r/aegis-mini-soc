import { useEffect, useState } from 'react'
import { Plus, Save, Trash2 } from 'lucide-react'
import { useApi } from '../hooks/useApi'
import { api } from '../lib/api'
import { Criticality, ErrorNote, Panel, Spinner, Toast } from '../components/ui'
import type { AssetEntry } from '../lib/types'

const FIELD_HELP: Record<string, string> = {
  base_threshold: "Plancher global et valeur à froid. Le score étant un percentile du trafic normal, 0,98 signifie « alerter au-delà de ce qui est plus inhabituel que 98 % du trafic connu ».",
  min_threshold: "Borne basse absolue de l'adaptation par hôte.",
  max_threshold: "Borne haute : limite jusqu'où un hôte peut relever son propre seuil, pour qu'une attaque lente ne puisse pas le rendre insensible.",
  host_quantile: "Budget de faux positifs par hôte. 0,99 = alerter sur le 1 % de flux les plus inhabituels de cet hôte.",
  dedup_window: "Fenêtre de regroupement des alertes en incident, en secondes.",
  supervised_min_confidence: "En dessous de cette confiance, l'étage B refuse de nommer une famille et renvoie « inconnu ».",
}

const EDITABLE = ['base_threshold', 'min_threshold', 'max_threshold', 'host_quantile',
  'dedup_window', 'supervised_min_confidence'] as const

export function Settings() {
  const { data, error, loading, reload } = useApi(() => api.settings(), [])
  const [detection, setDetection] = useState<Record<string, number>>({})
  const [assets, setAssets] = useState<AssetEntry[]>([])
  const [busy, setBusy] = useState(false)
  const [toast, setToast] = useState<{ message: string; tone: 'ok' | 'error' } | null>(null)

  useEffect(() => {
    if (!data) return
    setDetection(Object.fromEntries(EDITABLE.map((k) => [k, data.detection[k] ?? 0])))
    setAssets(data.assets)
  }, [data])

  const flash = (message: string, tone: 'ok' | 'error' = 'ok') => {
    setToast({ message, tone })
    window.setTimeout(() => setToast(null), 3600)
  }

  const saveDetection = async () => {
    setBusy(true)
    try { await api.putDetection(detection); flash('Réglages de détection enregistrés'); reload() }
    catch (exc) { flash((exc as Error).message, 'error') }
    finally { setBusy(false) }
  }

  const saveAssets = async () => {
    setBusy(true)
    try {
      const result = await api.putAssets(assets.filter((a) => a.cidr.trim() && a.name.trim()))
      flash(`${result.count} actif(s) enregistré(s)`)
      reload()
    } catch (exc) { flash((exc as Error).message, 'error') }
    finally { setBusy(false) }
  }

  if (error) return <ErrorNote message={error} onRetry={reload} />
  if (loading && !data) return <Spinner />

  return (
    <div className="space-y-5">
      <Panel title="Détection" action={
        <button className="btn-primary" onClick={saveDetection} disabled={busy}>
          <Save className="h-3.5 w-3.5" aria-hidden /> Enregistrer
        </button>
      }>
        <div className="grid gap-5 lg:grid-cols-2">
          {EDITABLE.map((key) => (
            <div key={key}>
              <label htmlFor={key} className="label-xs mb-1.5 block">{key}</label>
              <input id={key} className="input" type="number"
                     step={key === 'dedup_window' ? 5 : 0.001}
                     value={detection[key] ?? 0}
                     onChange={(e) => setDetection((d) => ({ ...d, [key]: Number(e.target.value) }))} />
              <p className="mt-1.5 text-[11px] leading-relaxed text-slate-600">{FIELD_HELP[key]}</p>
            </div>
          ))}
        </div>
        <p className="mt-4 border-t border-ink-800 pt-3 text-[11px] leading-relaxed text-slate-600">
          Contrainte vérifiée côté serveur : min ≤ plancher ≤ max. Les valeurs prennent effet
          immédiatement sur le moteur en cours et sont persistées — elles ne nécessitent pas de
          ré-entraînement, puisqu’elles ne touchent que le point de fonctionnement.
        </p>
      </Panel>

      <Panel title="Inventaire des actifs" action={
        <div className="flex gap-2">
          <button className="btn-ghost"
                  onClick={() => setAssets((a) => [...a, { cidr: '', name: '', criticality: 3, tags: [] }])}>
            <Plus className="h-3.5 w-3.5" aria-hidden /> Ajouter
          </button>
          <button className="btn-primary" onClick={saveAssets} disabled={busy}>
            <Save className="h-3.5 w-3.5" aria-hidden /> Enregistrer
          </button>
        </div>
      }>
        <p className="mb-4 text-sm leading-relaxed text-slate-400">
          La criticité transforme un score en priorité : un balayage de ports sur l’imprimante et le
          même balayage sur le serveur de base de données produisent le même score d’anomalie, et ne
          doivent pas produire la même gravité. La recherche se fait par préfixe le plus long, donc
          un <code className="text-slate-500">/32</code> l’emporte sur un <code className="text-slate-500">/24</code>.
        </p>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[720px]">
            <thead className="border-b border-ink-800">
              <tr>
                <th className="th">Préfixe (CIDR)</th><th className="th">Nom</th>
                <th className="th w-[200px]">Criticité</th><th className="th">Étiquettes</th><th className="th w-10" />
              </tr>
            </thead>
            <tbody className="divide-y divide-ink-800">
              {assets.map((asset, index) => (
                <tr key={index}>
                  <td className="td">
                    <input className="input font-mono text-xs" value={asset.cidr}
                           placeholder="192.168.1.0/24"
                           onChange={(e) => setAssets((a) => a.map((x, i) =>
                             i === index ? { ...x, cidr: e.target.value } : x))} />
                  </td>
                  <td className="td">
                    <input className="input" value={asset.name} placeholder="Serveur web"
                           onChange={(e) => setAssets((a) => a.map((x, i) =>
                             i === index ? { ...x, name: e.target.value } : x))} />
                  </td>
                  <td className="td">
                    <div className="flex items-center gap-2">
                      <input type="range" min={1} max={5} value={asset.criticality} className="accent-accent"
                             aria-label={`Criticité de ${asset.name || asset.cidr}`}
                             onChange={(e) => setAssets((a) => a.map((x, i) =>
                               i === index ? { ...x, criticality: Number(e.target.value) } : x))} />
                      <Criticality value={asset.criticality} />
                    </div>
                  </td>
                  <td className="td">
                    <input className="input text-xs" value={asset.tags.join(', ')} placeholder="web, production"
                           onChange={(e) => setAssets((a) => a.map((x, i) =>
                             i === index
                               ? { ...x, tags: e.target.value.split(',').map((t) => t.trim()).filter(Boolean) }
                               : x))} />
                  </td>
                  <td className="td">
                    <button className="text-slate-600 hover:text-red-400"
                            aria-label="Supprimer cet actif"
                            onClick={() => setAssets((a) => a.filter((_, i) => i !== index))}>
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>

      {toast && <Toast message={toast.message} tone={toast.tone} />}
    </div>
  )
}
