/** Shared presentational pieces. */
import type { ReactNode } from 'react'
import {
  AlertTriangle, CheckCircle2, CircleAlert, Info, Loader2, ShieldAlert, Inbox,
} from 'lucide-react'
import { SEVERITY_LABEL, SEVERITY_VAR, STATUS_LABEL, VERDICT_LABEL } from '../lib/format'

export function Panel({ title, action, children, className = '', pad = true }: {
  title?: ReactNode; action?: ReactNode; children: ReactNode; className?: string; pad?: boolean
}) {
  return (
    <section className={`panel ${className}`}>
      {(title || action) && (
        <header className="flex items-center justify-between gap-3 px-4 sm:px-5 pt-4 pb-3 border-b border-ink-800">
          <h2 className="text-sm font-semibold text-slate-100">{title}</h2>
          {action}
        </header>
      )}
      <div className={pad ? 'panel-pad' : ''}>{children}</div>
    </section>
  )
}

/** Severity is status, not a series: it always carries an icon AND a text label.
 *  Red, orange and yellow are hue neighbours - colour alone would be unreadable
 *  for a colourblind operator, and ambiguous for everyone in a hurry. */
export function SeverityTag({ severity, className = '' }: { severity: string; className?: string }) {
  const Icon = severity === 'CRITICAL' ? ShieldAlert
    : severity === 'HIGH' ? AlertTriangle
    : severity === 'MEDIUM' ? CircleAlert : Info
  const color = SEVERITY_VAR[severity] ?? 'var(--sev-low)'
  return (
    <span className={`inline-flex items-center gap-1.5 text-xs font-semibold ${className}`} style={{ color }}>
      <Icon className="w-3.5 h-3.5 shrink-0" aria-hidden />
      {SEVERITY_LABEL[severity] ?? severity}
    </span>
  )
}

export function StatusTag({ status }: { status: string }) {
  const tone = status === 'NEW' ? 'bg-sky-500/15 text-sky-300 border-sky-500/30'
    : status === 'ACK' ? 'bg-violet-500/15 text-violet-300 border-violet-500/30'
    : status === 'INVESTIGATING' ? 'bg-amber-500/15 text-amber-300 border-amber-500/30'
    : 'bg-slate-600/20 text-slate-400 border-slate-600/40'
  return (
    <span className={`inline-flex items-center rounded-md border px-1.5 py-0.5 text-[11px] font-medium ${tone}`}>
      {STATUS_LABEL[status] ?? status}
    </span>
  )
}

export function VerdictTag({ verdict }: { verdict: string | null }) {
  if (!verdict) return null
  const tone = verdict === 'TP' ? 'text-red-300 border-red-500/40 bg-red-500/10'
    : verdict === 'FP' ? 'text-emerald-300 border-emerald-500/40 bg-emerald-500/10'
    : 'text-slate-300 border-slate-500/40 bg-slate-500/10'
  return (
    <span className={`inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[11px] font-medium ${tone}`}>
      {verdict === 'FP' ? <CheckCircle2 className="w-3 h-3" aria-hidden /> : null}
      {VERDICT_LABEL[verdict] ?? verdict}
    </span>
  )
}

/** A hero number. Not a chart: one value's job is to be read, not compared. */
export function StatTile({ label, value, unit, hint, accent, icon: Icon, emphasis = false }: {
  label: string; value: ReactNode; unit?: string; hint?: ReactNode
  accent?: string; icon?: typeof Info; emphasis?: boolean
}) {
  return (
    <div className="panel panel-pad relative overflow-hidden">
      {accent && <div className="absolute left-0 top-0 bottom-0 w-[3px]" style={{ background: accent }} aria-hidden />}
      <div className="flex items-start justify-between gap-2">
        <p className="label-xs">{label}</p>
        {Icon && <Icon className="w-4 h-4 text-slate-600 shrink-0" aria-hidden />}
      </div>
      <p className={`mt-2 font-semibold tabular-nums ${emphasis ? 'text-3xl' : 'text-2xl'} text-slate-50`}>
        {value}
        {unit && <span className="ml-1 text-sm font-normal text-slate-500">{unit}</span>}
      </p>
      {hint && <p className="mt-1 text-xs text-slate-500">{hint}</p>}
    </div>
  )
}

export function Spinner({ label = 'chargement…' }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-2 py-10 text-sm text-slate-500">
      <Loader2 className="w-4 h-4 animate-spin" aria-hidden /> {label}
    </div>
  )
}

export function ErrorNote({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div role="alert" className="panel panel-pad border-red-500/30 bg-red-500/5">
      <div className="flex items-start gap-3">
        <AlertTriangle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" aria-hidden />
        <div className="min-w-0 flex-1">
          <p className="text-sm font-medium text-red-200">Une erreur est survenue</p>
          <p className="mt-1 text-sm text-slate-400 break-words">{message}</p>
        </div>
        {onRetry && <button className="btn-ghost shrink-0" onClick={onRetry}>Réessayer</button>}
      </div>
    </div>
  )
}

export function Empty({ title, hint, icon: Icon = Inbox }: { title: string; hint?: ReactNode; icon?: typeof Inbox }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-14 text-center">
      <Icon className="w-8 h-8 text-slate-700" aria-hidden />
      <p className="text-sm font-medium text-slate-400">{title}</p>
      {hint && <p className="max-w-md text-xs text-slate-600">{hint}</p>}
    </div>
  )
}

export function Mono({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <span className={`font-mono text-[12.5px] ${className}`}>{children}</span>
}

/** Criticality 1..5 as filled squares: a magnitude, so it reads as a ramp and
 *  never needs a legend. */
export function Criticality({ value }: { value: number }) {
  return (
    <span className="inline-flex items-center gap-0.5" title={`Criticité ${value}/5`}
          aria-label={`Criticité ${value} sur 5`}>
      {[1, 2, 3, 4, 5].map((i) => (
        <span key={i} className="w-1.5 h-3 rounded-sm"
              style={{ background: i <= value ? 'var(--series-1)' : '#1f3153' }} aria-hidden />
      ))}
    </span>
  )
}

export function Toast({ message, tone = 'ok' }: { message: string; tone?: 'ok' | 'error' }) {
  return (
    <div role="status"
         className={`fixed bottom-5 right-5 z-50 animate-fade-in rounded-lg border px-4 py-3 text-sm shadow-xl
          ${tone === 'ok' ? 'bg-emerald-500/10 border-emerald-500/40 text-emerald-200'
                          : 'bg-red-500/10 border-red-500/40 text-red-200'}`}>
      {message}
    </div>
  )
}
