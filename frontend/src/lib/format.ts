/** Formatting helpers. French locale, because the UI is French. */

const NF = new Intl.NumberFormat('fr-FR')

export const num = (v: number | null | undefined): string =>
  v === null || v === undefined || Number.isNaN(v) ? '—' : NF.format(Math.round(v))

export const pct = (v: number | null | undefined, digits = 1): string =>
  v === null || v === undefined || Number.isNaN(v) ? '—' : `${(v * 100).toFixed(digits)} %`

export const score = (v: number | null | undefined, digits = 3): string =>
  v === null || v === undefined || Number.isNaN(v) ? '—' : v.toFixed(digits)

export function bytes(v: number | null | undefined): string {
  if (v === null || v === undefined || Number.isNaN(v)) return '—'
  if (v < 1024) return `${v} o`
  const units = ['Kio', 'Mio', 'Gio', 'Tio']
  let value = v / 1024
  let i = 0
  while (value >= 1024 && i < units.length - 1) { value /= 1024; i += 1 }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${units[i]}`
}

export function duration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined || Number.isNaN(seconds)) return '—'
  if (seconds < 1) return `${(seconds * 1000).toFixed(0)} ms`
  if (seconds < 60) return `${seconds.toFixed(seconds < 10 ? 1 : 0)} s`
  // round to whole seconds *first*: rounding the remainder alone renders 119.6 s
  // as "1 min 60 s"
  const total = Math.round(seconds)
  const m = Math.floor(total / 60)
  if (m < 60) return `${m} min ${total % 60} s`
  const h = Math.floor(m / 60)
  return `${h} h ${m % 60} min`
}

export const clock = (iso: string | null | undefined): string =>
  !iso ? '—' : new Date(iso).toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit', second: '2-digit' })

export const stamp = (iso: string | null | undefined): string =>
  !iso ? '—' : new Date(iso).toLocaleString('fr-FR', {
    day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit',
  })

export function ago(iso: string | null | undefined): string {
  if (!iso) return '—'
  const delta = (Date.now() - new Date(iso).getTime()) / 1000
  if (delta < 10) return "à l'instant"
  if (delta < 60) return `il y a ${Math.floor(delta)} s`
  if (delta < 3600) return `il y a ${Math.floor(delta / 60)} min`
  if (delta < 86400) return `il y a ${Math.floor(delta / 3600)} h`
  return `il y a ${Math.floor(delta / 86400)} j`
}

export const SEVERITY_LABEL: Record<string, string> = {
  CRITICAL: 'Critique', HIGH: 'Élevée', MEDIUM: 'Moyenne', LOW: 'Faible', INFO: 'Info',
}

export const STATUS_LABEL: Record<string, string> = {
  NEW: 'Nouveau', ACK: 'Pris en compte', INVESTIGATING: 'En analyse', CLOSED: 'Clos',
}

export const VERDICT_LABEL: Record<string, string> = {
  TP: 'Vrai positif', FP: 'Faux positif', BENIGN: 'Trafic légitime',
}

export const SEVERITY_VAR: Record<string, string> = {
  CRITICAL: 'var(--sev-critical)', HIGH: 'var(--sev-high)',
  MEDIUM: 'var(--sev-medium)', LOW: 'var(--sev-low)', INFO: 'var(--sev-low)',
}

export const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const
