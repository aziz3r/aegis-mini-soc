import { useCallback, useEffect, useState } from 'react'
import { Navigate, Route, Routes } from 'react-router-dom'
import { Shell } from './components/Shell'
import { useStream } from './hooks/useStream'
import { loadSession, logout as clearSession, setUnauthorizedHandler, type Session } from './lib/api'
import { Audit } from './pages/Audit'
import { HostDetailPage, Hosts } from './pages/Hosts'
import { IncidentDetail } from './pages/IncidentDetail'
import { Incidents } from './pages/Incidents'
import { Live } from './pages/Live'
import { Login } from './pages/Login'
import { Model } from './pages/Model'
import { Overview } from './pages/Overview'
import { Replay } from './pages/Replay'
import { Settings } from './pages/Settings'

function AdminOnly({ session, children }: { session: Session; children: React.ReactNode }) {
  if (session.role !== 'admin') {
    return (
      <div className="panel panel-pad">
        <p className="text-sm text-slate-300">Cette page demande le rôle administrateur.</p>
        <p className="mt-1 text-xs text-slate-500">Votre rôle actuel : {session.role}.</p>
      </div>
    )
  }
  return <>{children}</>
}

export default function App() {
  const [session, setSession] = useState<Session | null>(() => loadSession())

  // A 401 from anywhere drops the session exactly once, rather than each caller
  // inventing its own handling.
  useEffect(() => { setUnauthorizedHandler(() => setSession(null)) }, [])

  const stream = useStream(session !== null)
  const handleLogout = useCallback(() => { clearSession(); setSession(null) }, [])

  if (!session) return <Login onSuccess={setSession} />

  const openIncidents = stream.points.length
    ? (stream.points[stream.points.length - 1]?.open_incidents ?? null)
    : (stream.status?.open_incidents ?? null)

  return (
    <Shell session={session} connection={stream.connection} openIncidents={openIncidents}
           onLogout={handleLogout} onRetryStream={stream.reconnect}>
      <Routes>
        <Route path="/" element={<Overview />} />
        <Route path="/live" element={
          <Live points={stream.points} feed={stream.feed} status={stream.status}
                connection={stream.connection} lastEvent={stream.lastEvent} />} />
        <Route path="/incidents" element={<Incidents session={session} />} />
        <Route path="/incidents/:id" element={<IncidentDetail session={session} />} />
        <Route path="/hosts" element={<Hosts />} />
        <Route path="/hosts/:ip" element={<HostDetailPage />} />
        <Route path="/model" element={<Model />} />
        <Route path="/replay" element={<AdminOnly session={session}><Replay /></AdminOnly>} />
        <Route path="/settings" element={<AdminOnly session={session}><Settings /></AdminOnly>} />
        <Route path="/audit" element={<AdminOnly session={session}><Audit /></AdminOnly>} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Shell>
  )
}
