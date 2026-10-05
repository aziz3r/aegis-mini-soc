import { useState } from 'react'
import { ShieldAlert, Loader2 } from 'lucide-react'
import { ApiError, login, type Session } from '../lib/api'

export function Login({ onSuccess }: { onSuccess: (s: Session) => void }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    setBusy(true)
    setError(null)
    try {
      onSuccess(await login(username.trim(), password))
    } catch (exc) {
      setError(exc instanceof ApiError ? exc.message : 'connexion impossible — l’API répond-elle ?')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <div className="w-full max-w-sm">
        <div className="mb-6 flex items-center gap-3">
          <ShieldAlert className="h-9 w-9 text-accent" aria-hidden />
          <div>
            <p className="text-xl font-bold tracking-wide text-white">AEGIS <span className="text-accent">Mini-SOC</span></p>
            <p className="text-xs text-slate-500">Détection d’intrusion réseau par apprentissage</p>
          </div>
        </div>

        <form onSubmit={submit} className="panel panel-pad space-y-4">
          <div>
            <label htmlFor="u" className="label-xs mb-1.5 block">Identifiant</label>
            <input id="u" className="input" autoComplete="username" autoFocus required
                   value={username} onChange={(e) => setUsername(e.target.value)} />
          </div>
          <div>
            <label htmlFor="p" className="label-xs mb-1.5 block">Mot de passe</label>
            <input id="p" type="password" className="input" autoComplete="current-password" required
                   value={password} onChange={(e) => setPassword(e.target.value)} />
          </div>
          {error && <p role="alert" className="text-sm text-red-300">{error}</p>}
          <button type="submit" className="btn-primary w-full justify-center" disabled={busy}>
            {busy && <Loader2 className="h-4 w-4 animate-spin" aria-hidden />}
            Se connecter
          </button>
          <p className="text-[11px] leading-relaxed text-slate-600">
            Les comptes et leurs mots de passe sont affichés par <code className="text-slate-500">aegis init</code>.
            Trois rôles : <span className="text-slate-500">lecteur</span> (lecture seule),
            {' '}<span className="text-slate-500">analyste</span> (triage),
            {' '}<span className="text-slate-500">admin</span> (réglages et sources).
          </p>
        </form>
      </div>
    </div>
  )
}
