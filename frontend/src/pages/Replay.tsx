import { useRef, useState } from 'react'
import {
  CirclePlay, FileUp, FlaskConical, Radio, Square, Upload, Wifi,
} from 'lucide-react'
import { useApi } from '../hooks/useApi'
import { api } from '../lib/api'
import { Empty, ErrorNote, Mono, Panel, Spinner, StatTile, Toast } from '../components/ui'
import { bytes, num, stamp } from '../lib/format'

type Tab = 'lab' | 'pcap' | 'live'

export function Replay() {
  const status = useApi(() => api.pipeline(), [], 3000)
  const pcaps = useApi(() => api.pcaps(), [])
  const [tab, setTab] = useState<Tab>('lab')
  const [busy, setBusy] = useState(false)
  const [toast, setToast] = useState<{ message: string; tone: 'ok' | 'error' } | null>(null)
  const fileInput = useRef<HTMLInputElement>(null)

  // lab
  const [speed, setSpeed] = useState(1)
  const [density, setDensity] = useState(1)
  const [stealth, setStealth] = useState(0.25)
  const [seed, setSeed] = useState('')
  // pcap
  const [pcapFile, setPcapFile] = useState('')
  const [pcapSpeed, setPcapSpeed] = useState(10)
  // live
  const [iface, setIface] = useState('en0')
  const [bpf, setBpf] = useState('ip')

  const flash = (message: string, tone: 'ok' | 'error' = 'ok') => {
    setToast({ message, tone })
    window.setTimeout(() => setToast(null), 3600)
  }

  const start = async () => {
    setBusy(true)
    try {
      const body =
        tab === 'lab'
          ? { source: 'lab', duration: 86400, speed, density, stealth_ratio: stealth,
              ...(seed.trim() ? { seed: Number(seed) } : {}) }
          : tab === 'pcap'
            ? { source: 'pcap', file: pcapFile, speed: pcapSpeed }
            : { source: 'live', iface, bpf }
      await api.startPipeline(body)
      flash('Source démarrée')
      status.reload()
    } catch (exc) {
      flash((exc as Error).message, 'error')
    } finally { setBusy(false) }
  }

  const stop = async () => {
    setBusy(true)
    try { await api.stopPipeline(); flash('Source arrêtée'); status.reload() }
    catch (exc) { flash((exc as Error).message, 'error') }
    finally { setBusy(false) }
  }

  const upload = async (file: File) => {
    setBusy(true)
    try {
      const result = await api.uploadPcap(file)
      flash(`${result.name} envoyé (${bytes(result.size)})`)
      pcaps.reload()
      setPcapFile(result.name)
    } catch (exc) { flash((exc as Error).message, 'error') }
    finally { setBusy(false) }
  }

  if (status.error) return <ErrorNote message={status.error} onRetry={status.reload} />
  if (status.loading && !status.data) return <Spinner />

  const s = status.data
  const running = s?.running ?? false
  const source = s?.source

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <StatTile label="État du moteur" value={running ? 'En marche' : 'Arrêté'}
                  accent={running ? 'var(--ok)' : 'var(--sev-low)'}
                  hint={s?.started_at ? `depuis ${stamp(s.started_at)}` : undefined} />
        <StatTile label="Paquets" value={num(s?.stats.packets ?? 0)}
                  hint={`${num(s?.active_flows ?? 0)} flux en cours`} />
        <StatTile label="Alertes" value={num(s?.stats.alerts ?? 0)}
                  hint={`${num(s?.stats.suppressed ?? 0)} supprimées par l’étage B`} />
        <StatTile label="Incidents" value={num(s?.incidents_opened ?? 0)}
                  hint={`${num(s?.alerts_merged ?? 0)} alertes fusionnées`} />
      </div>

      {s?.error && <ErrorNote message={s.error} />}

      {running && source && (
        <Panel title="Source active" action={
          <button className="btn-danger" onClick={stop} disabled={busy}>
            <Square className="h-3.5 w-3.5" aria-hidden /> Arrêter
          </button>
        }>
          <dl className="grid gap-3 text-sm sm:grid-cols-2 lg:grid-cols-4">
            <div><dt className="label-xs">Type</dt><dd className="mt-1 text-slate-200">{source.kind}</dd></div>
            <div><dt className="label-xs">Nom</dt><dd className="mt-1"><Mono className="text-slate-200">{source.name}</Mono></dd></div>
            <div><dt className="label-xs">Paquets émis</dt>
              <dd className="mt-1 tabular-nums text-slate-200">{num(source.packets)}</dd></div>
            <div><dt className="label-xs">Progression</dt>
              <dd className="mt-1 tabular-nums text-slate-200">
                {source.progress !== null ? `${(source.progress * 100).toFixed(1)} %` : '—'}
              </dd></div>
          </dl>
          {source.progress !== null && (
            <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-ink-800">
              <div className="h-full rounded-r-[4px] bg-accent transition-all"
                   style={{ width: `${Math.min(source.progress * 100, 100)}%` }} />
            </div>
          )}
          {source.attacks && source.attacks.length > 0 && (
            <div className="mt-4">
              <p className="label-xs mb-2">Attaques programmées ({source.attacks.length})</p>
              <div className="max-h-44 overflow-auto rounded-lg border border-ink-800">
                <table className="w-full text-xs">
                  <thead className="sticky top-0 bg-ink-850">
                    <tr><th className="th">Famille</th><th className="th">Début</th>
                        <th className="th">Durée</th><th className="th">Intensité</th><th className="th">Mode</th></tr>
                  </thead>
                  <tbody className="divide-y divide-ink-800">
                    {source.attacks.map((a, i) => (
                      <tr key={i}>
                        <td className="td text-slate-300">{a.family}</td>
                        <td className="td tabular-nums text-slate-500">t+{a.start.toFixed(0)} s</td>
                        <td className="td tabular-nums text-slate-500">{a.duration.toFixed(0)} s</td>
                        <td className="td tabular-nums text-slate-500">×{a.intensity.toFixed(2)}</td>
                        <td className="td">
                          {a.stealth
                            ? <span className="text-amber-300">furtif</span>
                            : <span className="text-slate-500">bruyant</span>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <p className="mt-2 text-[11px] text-slate-600">
                Le plan est connu à l’avance : c’est la vérité terrain qui permet de vérifier que
                ce que le tableau de bord affiche correspond à ce qui s’est réellement passé.
              </p>
            </div>
          )}
        </Panel>
      )}

      <Panel title="Démarrer une source">
        <div className="mb-4 flex flex-wrap gap-2" role="tablist">
          {([
            ['lab', 'Réseau de laboratoire', FlaskConical],
            ['pcap', 'Rejeu de PCAP', FileUp],
            ['live', 'Capture réelle', Wifi],
          ] as const).map(([key, label, Icon]) => (
            <button key={key} role="tab" aria-selected={tab === key}
                    onClick={() => setTab(key)}
                    className={tab === key ? 'btn-primary' : 'btn-ghost'}>
              <Icon className="h-4 w-4" aria-hidden /> {label}
            </button>
          ))}
        </div>

        {tab === 'lab' && (
          <div className="space-y-4">
            <p className="text-sm leading-relaxed text-slate-400">
              Génère un réseau d’entreprise synthétique — navigation web, DNS, SSH, SMB, streaming —
              dans lequel sont planifiées les neuf familles d’attaque, avec leur vérité terrain.
              C’est la démonstration reproductible : même graine, même scénario.
            </p>
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
              <div>
                <label htmlFor="sp" className="label-xs mb-1.5 block">Vitesse ×{speed}</label>
                <input id="sp" type="range" min={1} max={60} step={1} value={speed} className="w-full accent-accent"
                       onChange={(e) => setSpeed(Number(e.target.value))} />
                <p className="mt-1 text-[11px] text-slate-600">
                  ×1 = temps réel · ×60 = une heure simulée par minute
                </p>
              </div>
              <div>
                <label htmlFor="de" className="label-xs mb-1.5 block">Densité d’attaques ×{density}</label>
                <input id="de" type="range" min={0.2} max={4} step={0.2} value={density} className="w-full accent-accent"
                       onChange={(e) => setDensity(Number(e.target.value))} />
              </div>
              <div>
                <label htmlFor="st" className="label-xs mb-1.5 block">
                  Part d’attaques furtives {(stealth * 100).toFixed(0)} %
                </label>
                <input id="st" type="range" min={0} max={1} step={0.05} value={stealth} className="w-full accent-accent"
                       onChange={(e) => setStealth(Number(e.target.value))} />
                <p className="mt-1 text-[11px] text-slate-600">lentes, discrètes, bien plus dures à détecter</p>
              </div>
              <div>
                <label htmlFor="sd" className="label-xs mb-1.5 block">Graine (optionnel)</label>
                <input id="sd" className="input" placeholder="aléatoire" value={seed}
                       onChange={(e) => setSeed(e.target.value.replace(/\D/g, ''))} />
              </div>
            </div>
          </div>
        )}

        {tab === 'pcap' && (
          <div className="space-y-4">
            <p className="text-sm leading-relaxed text-slate-400">
              Rejoue une capture réelle. Les horodatages de la capture sont conservés pour
              l’assemblage des flux, donc un rejeu accéléré produit exactement les mêmes flux que
              la capture d’origine. <strong className="text-slate-300">C’est la vraie épreuve</strong> du
              détecteur : du trafic qu’aucun générateur n’a produit.
            </p>
            <div className="grid gap-4 sm:grid-cols-[1fr_200px]">
              <div>
                <label htmlFor="pf" className="label-xs mb-1.5 block">Fichier</label>
                {pcaps.data && pcaps.data.items.length > 0 ? (
                  <select id="pf" className="input" value={pcapFile} onChange={(e) => setPcapFile(e.target.value)}>
                    <option value="">— choisir —</option>
                    {pcaps.data.items.map((p) => (
                      <option key={p.name} value={p.name}>{p.name} ({bytes(p.size)})</option>
                    ))}
                  </select>
                ) : (
                  <p className="rounded-lg border border-ink-700 bg-ink-950 px-3 py-2 text-sm text-slate-500">
                    Aucun fichier dans <Mono>{pcaps.data?.directory ?? 'data/pcaps'}</Mono>
                  </p>
                )}
              </div>
              <div>
                <label htmlFor="ps" className="label-xs mb-1.5 block">
                  Vitesse {pcapSpeed === 0 ? '(maximale)' : `×${pcapSpeed}`}
                </label>
                <input id="ps" type="range" min={0} max={120} step={1} value={pcapSpeed} className="w-full accent-accent"
                       onChange={(e) => setPcapSpeed(Number(e.target.value))} />
              </div>
            </div>
            <div className="flex items-center gap-3">
              <input ref={fileInput} type="file" accept=".pcap,.pcapng,.cap" className="hidden"
                     onChange={(e) => { const f = e.target.files?.[0]; if (f) void upload(f) }} />
              <button className="btn-ghost" onClick={() => fileInput.current?.click()} disabled={busy}>
                <Upload className="h-3.5 w-3.5" aria-hidden /> Envoyer un PCAP
              </button>
              {pcaps.data && <span className="text-xs text-slate-600">
                dossier : <Mono>{pcaps.data.directory}</Mono>
              </span>}
            </div>
          </div>
        )}

        {tab === 'live' && (
          <div className="space-y-4">
            <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-3">
              <p className="text-sm leading-relaxed text-amber-200">
                La capture réelle exige les privilèges root, donc l’API doit avoir été lancée avec
                ces privilèges. Ne capturez que sur un réseau dont vous êtes responsable.
              </p>
            </div>
            <div className="grid gap-4 sm:grid-cols-2">
              <div>
                <label htmlFor="if" className="label-xs mb-1.5 block">Interface</label>
                <input id="if" className="input" value={iface} onChange={(e) => setIface(e.target.value)}
                       placeholder="en0, eth0, lo0…" />
              </div>
              <div>
                <label htmlFor="bp" className="label-xs mb-1.5 block">Filtre BPF</label>
                <input id="bp" className="input" value={bpf} onChange={(e) => setBpf(e.target.value)}
                       placeholder="ip, tcp port 80, not arp…" />
              </div>
            </div>
          </div>
        )}

        <div className="mt-5 flex items-center gap-3 border-t border-ink-800 pt-4">
          <button className="btn-primary" onClick={start}
                  disabled={busy || (tab === 'pcap' && !pcapFile) || (tab === 'live' && !iface.trim())}>
            {running ? <Radio className="h-4 w-4" aria-hidden /> : <CirclePlay className="h-4 w-4" aria-hidden />}
            {running ? 'Remplacer la source active' : 'Démarrer'}
          </button>
          {running && (
            <button className="btn-ghost" onClick={stop} disabled={busy}>
              <Square className="h-3.5 w-3.5" aria-hidden /> Arrêter
            </button>
          )}
          <span className="text-xs text-slate-600">
            Démarrer une source réinitialise l’état du moteur (flux en cours et références par hôte).
          </span>
        </div>
      </Panel>

      {!running && !source && <Empty title="Aucune source n’a encore été démarrée" icon={CirclePlay} />}
      {toast && <Toast message={toast.message} tone={toast.tone} />}
    </div>
  )
}
