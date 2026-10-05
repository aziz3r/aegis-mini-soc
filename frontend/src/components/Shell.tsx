/** Application frame: navigation, live connection indicator, session menu. */
import { useState } from 'react'
import { NavLink, useLocation } from 'react-router-dom'
import {
  Activity, ClipboardList, Cpu, Gauge, LayoutDashboard, LogOut, Menu, Network,
  PlayCircle, Settings as SettingsIcon, ShieldAlert, Wifi, WifiOff, X,
} from 'lucide-react'
import type { ReactNode } from 'react'
import type { Session } from '../lib/api'
import type { ConnectionState } from '../hooks/useStream'
import { num } from '../lib/format'

interface NavItem { to: string; label: string; icon: typeof Gauge; role?: 'analyst' | 'admin' }

const NAV: NavItem[] = [
  { to: '/', label: "Vue d'ensemble", icon: LayoutDashboard },
  { to: '/live', label: 'Flux temps réel', icon: Activity },
  { to: '/incidents', label: 'Incidents', icon: ShieldAlert },
  { to: '/hosts', label: 'Hôtes', icon: Network },
  { to: '/model', label: 'Modèle', icon: Cpu },
  { to: '/replay', label: 'Sources & rejeu', icon: PlayCircle, role: 'admin' },
  { to: '/settings', label: 'Réglages', icon: SettingsIcon, role: 'admin' },
  { to: '/audit', label: 'Journal d’audit', icon: ClipboardList, role: 'admin' },
]

const RANK = { viewer: 0, analyst: 1, admin: 2 } as const

function ConnectionBadge({ state, openIncidents, onRetry }: {
  state: ConnectionState; openIncidents: number | null; onRetry: () => void
}) {
  const live = state === 'open'
  return (
    <div className="flex items-center gap-3">
      {openIncidents !== null && (
        <span className="hidden sm:inline text-xs text-slate-500">
          {num(openIncidents)} incident{openIncidents === 1 ? '' : 's'} ouvert{openIncidents === 1 ? '' : 's'}
        </span>
      )}
      <button
        onClick={onRetry}
        className={`inline-flex items-center gap-2 rounded-lg border px-2.5 py-1.5 text-xs font-medium transition-colors
          ${live ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
                 : 'border-ink-700 bg-ink-850 text-slate-400 hover:text-slate-200'}`}
        title={live ? 'Flux temps réel connecté' : 'Cliquez pour reconnecter'}
      >
        {live ? <Wifi className="w-3.5 h-3.5" aria-hidden /> : <WifiOff className="w-3.5 h-3.5" aria-hidden />}
        {state === 'open' ? 'EN DIRECT'
          : state === 'connecting' ? 'CONNEXION…'
          : state === 'unauthorised' ? 'NON AUTORISÉ' : 'HORS LIGNE'}
      </button>
    </div>
  )
}

export function Shell({ session, connection, openIncidents, onLogout, onRetryStream, children }: {
  session: Session
  connection: ConnectionState
  openIncidents: number | null
  onLogout: () => void
  onRetryStream: () => void
  children: ReactNode
}) {
  const [open, setOpen] = useState(false)
  const location = useLocation()
  const items = NAV.filter((i) => !i.role || RANK[session.role] >= RANK[i.role])

  return (
    <div className="min-h-screen lg:grid lg:grid-cols-[232px_1fr]">
      {/* skip link: keyboard users should not have to tab the whole nav */}
      <a href="#contenu" className="sr-only focus:not-sr-only focus:absolute focus:z-50 focus:m-3
        focus:rounded focus:bg-accent focus:px-3 focus:py-2 focus:text-ink-950">
        Aller au contenu
      </a>

      <aside className={`fixed inset-y-0 left-0 z-40 w-[232px] border-r border-ink-800 bg-ink-900
        transition-transform lg:static lg:translate-x-0
        ${open ? 'translate-x-0' : '-translate-x-full'}`}>
        <div className="flex h-14 items-center gap-2.5 border-b border-ink-800 px-4">
          <ShieldAlert className="h-6 w-6 text-accent shrink-0" aria-hidden />
          <div className="min-w-0">
            <p className="text-sm font-bold tracking-wide text-white">AEGIS</p>
            <p className="truncate text-[10px] uppercase tracking-wider text-slate-500">Mini-SOC</p>
          </div>
          <button className="ml-auto lg:hidden text-slate-500 hover:text-white" onClick={() => setOpen(false)}
                  aria-label="Fermer le menu">
            <X className="h-5 w-5" />
          </button>
        </div>

        <nav className="p-2.5" aria-label="Navigation principale">
          <ul className="space-y-0.5">
            {items.map(({ to, label, icon: Icon }) => (
              <li key={to}>
                <NavLink
                  to={to}
                  end={to === '/'}
                  onClick={() => setOpen(false)}
                  className={({ isActive }) =>
                    `flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-sm transition-colors
                     ${isActive || (to !== '/' && location.pathname.startsWith(to))
                        ? 'bg-accent/10 text-accent font-medium'
                        : 'text-slate-400 hover:bg-ink-800 hover:text-slate-100'}`}
                >
                  <Icon className="h-4 w-4 shrink-0" aria-hidden />
                  {label}
                </NavLink>
              </li>
            ))}
          </ul>
        </nav>

        <div className="absolute bottom-0 left-0 right-0 border-t border-ink-800 p-3">
          <p className="truncate text-sm text-slate-300">{session.username}</p>
          <p className="text-[11px] uppercase tracking-wider text-slate-600">{session.role}</p>
          <button onClick={onLogout} className="btn-ghost mt-2.5 w-full justify-center">
            <LogOut className="h-3.5 w-3.5" aria-hidden /> Se déconnecter
          </button>
        </div>
      </aside>

      {open && <div className="fixed inset-0 z-30 bg-black/60 lg:hidden" onClick={() => setOpen(false)} aria-hidden />}

      <div className="flex min-h-screen min-w-0 flex-col">
        <header className="sticky top-0 z-20 flex h-14 items-center gap-3 border-b border-ink-800
                           bg-ink-950/85 px-4 backdrop-blur">
          <button className="lg:hidden text-slate-400 hover:text-white" onClick={() => setOpen(true)}
                  aria-label="Ouvrir le menu">
            <Menu className="h-5 w-5" />
          </button>
          <h1 className="truncate text-sm font-medium text-slate-300">
            {items.find((i) => i.to === location.pathname)?.label
              ?? (location.pathname.startsWith('/incidents/') ? 'Détail de l’incident'
                : location.pathname.startsWith('/hosts/') ? 'Détail de l’hôte' : 'AEGIS')}
          </h1>
          <div className="ml-auto">
            <ConnectionBadge state={connection} openIncidents={openIncidents} onRetry={onRetryStream} />
          </div>
        </header>

        <main id="contenu" className="min-w-0 flex-1 p-4 sm:p-6">{children}</main>
      </div>
    </div>
  )
}
