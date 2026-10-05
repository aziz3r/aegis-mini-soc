/** Typed API client.
 *
 *  One place that knows about the token, the base URL and error shapes. Every
 *  call goes through `request`, so a 401 anywhere logs the session out exactly
 *  once instead of each caller inventing its own handling.
 */
import type {
  AuditRow, HostDetail, HostRow, Incident, IncidentDetail, ModelInfo, Overview,
  PcapEntry, PipelineStatus, Role, SettingsPayload, ThresholdRow,
} from './types'

const TOKEN_KEY = 'aegis.token'
const USER_KEY = 'aegis.user'

export interface Session { token: string; username: string; role: Role }

export class ApiError extends Error {
  constructor(public statusCode: number, message: string) {
    super(message)
    this.name = 'ApiError'
  }
}

let onUnauthorized: (() => void) | null = null
export const setUnauthorizedHandler = (fn: () => void): void => { onUnauthorized = fn }

export function loadSession(): Session | null {
  try {
    const token = localStorage.getItem(TOKEN_KEY)
    const raw = localStorage.getItem(USER_KEY)
    if (!token || !raw) return null
    const { username, role } = JSON.parse(raw) as { username: string; role: Role }
    return { token, username, role }
  } catch {
    return null   // private browsing, cleared storage: behave as logged out
  }
}

function storeSession(session: Session | null): void {
  try {
    if (session) {
      localStorage.setItem(TOKEN_KEY, session.token)
      localStorage.setItem(USER_KEY, JSON.stringify({ username: session.username, role: session.role }))
    } else {
      localStorage.removeItem(TOKEN_KEY)
      localStorage.removeItem(USER_KEY)
    }
  } catch { /* storage unavailable: the session simply does not survive a reload */ }
}

export const logout = (): void => storeSession(null)

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const session = loadSession()
  const headers = new Headers(init.headers)
  if (session) headers.set('Authorization', `Bearer ${session.token}`)
  if (init.body && !(init.body instanceof FormData)) headers.set('Content-Type', 'application/json')

  const response = await fetch(`/api${path}`, { ...init, headers })
  if (response.status === 401) {
    logout()
    onUnauthorized?.()
    throw new ApiError(401, 'session expirée — reconnectez-vous')
  }
  if (!response.ok) {
    let detail = `erreur ${response.status}`
    try {
      const body = await response.json()
      if (typeof body?.detail === 'string') detail = body.detail
      else if (Array.isArray(body?.detail)) detail = body.detail.map((d: { msg: string }) => d.msg).join(', ')
    } catch { /* non-JSON error body */ }
    throw new ApiError(response.status, detail)
  }
  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
}

export async function login(username: string, password: string): Promise<Session> {
  const body = new FormData()
  body.set('username', username)
  body.set('password', password)
  const data = await request<{ access_token: string; username: string; role: Role }>(
    '/auth/token', { method: 'POST', body },
  )
  const session: Session = { token: data.access_token, username: data.username, role: data.role }
  storeSession(session)
  return session
}

const qs = (params: Record<string, string | number | boolean | undefined | null>): string => {
  const sp = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') sp.set(k, String(v))
  }
  const s = sp.toString()
  return s ? `?${s}` : ''
}

export interface IncidentQuery {
  status?: string; severity?: string; family?: string; src?: string; dst?: string
  q?: string; open_only?: boolean; hours?: number; sort?: string; limit?: number; offset?: number
  [key: string]: string | number | boolean | undefined
}

export const api = {
  health: () => request<{ status: string; model_loaded: boolean; model_error: string | null }>('/health'),
  me: () => request<{ username: string; role: Role }>('/auth/me'),
  overview: (hours = 24) => request<Overview>(`/overview${qs({ hours })}`),
  incidents: (query: IncidentQuery = {}) =>
    request<{ total: number; limit: number; offset: number; items: Incident[] }>(`/incidents${qs(query)}`),
  incident: (id: number, alerts = 100) => request<IncidentDetail>(`/incidents/${id}${qs({ alerts })}`),
  patchIncident: (id: number, patch: Record<string, string | null>) =>
    request<Incident>(`/incidents/${id}`, { method: 'PATCH', body: JSON.stringify(patch) }),
  bulkIncidents: (payload: { ids: number[]; status?: string; verdict?: string; assignee?: string }) =>
    request<{ updated: number }>('/incidents/bulk', { method: 'POST', body: JSON.stringify(payload) }),
  hosts: (q?: string) => request<{ total: number; items: HostRow[] }>(`/hosts${qs({ q, limit: 200 })}`),
  host: (ip: string) => request<HostDetail>(`/hosts/${encodeURIComponent(ip)}`),
  model: () => request<ModelInfo>('/model'),
  thresholds: () => request<{ base: number; items: ThresholdRow[] }>('/model/thresholds'),
  pipeline: () => request<PipelineStatus>('/pipeline'),
  startPipeline: (body: Record<string, unknown>) =>
    request<PipelineStatus>('/pipeline/start', { method: 'POST', body: JSON.stringify(body) }),
  stopPipeline: () => request<PipelineStatus>('/pipeline/stop', { method: 'POST' }),
  pcaps: () => request<{ directory: string; items: PcapEntry[] }>('/pcaps'),
  uploadPcap: (file: File) => {
    const body = new FormData()
    body.set('file', file)
    return request<{ name: string; size: number }>('/pcaps', { method: 'POST', body })
  },
  settings: () => request<SettingsPayload>('/settings'),
  putDetection: (body: Record<string, number>) =>
    request<Record<string, number>>('/settings/detection', { method: 'PUT', body: JSON.stringify(body) }),
  putAssets: (entries: SettingsPayload['assets']) =>
    request<{ count: number }>('/settings/assets', { method: 'PUT', body: JSON.stringify({ entries }) }),
  audit: () => request<{ items: AuditRow[] }>('/audit'),
}
