/** Live WebSocket stream with automatic reconnection.
 *
 *  The chart buffer lives in a ref and is published on a timer rather than on
 *  every frame: during a flood the backend emits a tick a second but incident
 *  payloads arrive in bursts, and re-rendering per message would make the page
 *  stutter exactly when the operator needs it most.
 */
import { useCallback, useEffect, useRef, useState } from 'react'
import type { Incident, PipelineStatus, StreamEvent, TickEvent } from '../lib/types'
import { loadSession } from '../lib/api'

const MAX_POINTS = 180
const MAX_FEED = 60
const RECONNECT_BASE_MS = 800
const RECONNECT_MAX_MS = 15_000

export type ConnectionState = 'connecting' | 'open' | 'closed' | 'unauthorised'

export interface StreamState {
  connection: ConnectionState
  points: TickEvent[]
  feed: Incident[]
  status: PipelineStatus | null
  lastEvent: string | null
  reconnect: () => void
}

export function useStream(enabled = true): StreamState {
  const [connection, setConnection] = useState<ConnectionState>('connecting')
  const [points, setPoints] = useState<TickEvent[]>([])
  const [feed, setFeed] = useState<Incident[]>([])
  const [status, setStatus] = useState<PipelineStatus | null>(null)
  const [lastEvent, setLastEvent] = useState<string | null>(null)

  const socketRef = useRef<WebSocket | null>(null)
  const pointsRef = useRef<TickEvent[]>([])
  const feedRef = useRef<Incident[]>([])
  const dirtyRef = useRef(false)
  const attemptRef = useRef(0)
  const timerRef = useRef<number | null>(null)
  const [nonce, setNonce] = useState(0)

  const reconnect = useCallback(() => {
    attemptRef.current = 0
    setNonce((n) => n + 1)
  }, [])

  // publish buffered frames at a steady 4 Hz, whatever the inbound rate
  useEffect(() => {
    const id = window.setInterval(() => {
      if (!dirtyRef.current) return
      dirtyRef.current = false
      setPoints([...pointsRef.current])
      setFeed([...feedRef.current])
    }, 250)
    return () => window.clearInterval(id)
  }, [])

  useEffect(() => {
    if (!enabled) return
    const session = loadSession()
    if (!session) { setConnection('unauthorised'); return }

    const scheme = window.location.protocol === 'https:' ? 'wss' : 'ws'
    const url = `${scheme}://${window.location.host}/api/stream?token=${encodeURIComponent(session.token)}`
    setConnection('connecting')
    const socket = new WebSocket(url)
    socketRef.current = socket

    const absorbTick = (tick: TickEvent) => {
      pointsRef.current = [...pointsRef.current, tick].slice(-MAX_POINTS)
      if (tick.incidents?.length) {
        const byId = new Map(feedRef.current.map((i) => [i.id, i]))
        for (const incident of tick.incidents) byId.set(incident.id, incident)
        feedRef.current = [...byId.values()]
          .sort((a, b) => (b.last_seen ?? '').localeCompare(a.last_seen ?? ''))
          .slice(0, MAX_FEED)
      }
      dirtyRef.current = true
    }

    socket.onopen = () => { attemptRef.current = 0; setConnection('open') }
    socket.onmessage = (event) => {
      let frame: StreamEvent
      try { frame = JSON.parse(event.data as string) as StreamEvent } catch { return }
      if (frame.type === 'hello') {
        pointsRef.current = frame.history.slice(-MAX_POINTS)
        dirtyRef.current = true
        setStatus(frame.status)
      } else if (frame.type === 'tick') {
        absorbTick(frame)
      } else if (frame.type === 'pipeline') {
        setLastEvent(frame.state === 'error' ? `erreur du pipeline : ${frame.error ?? ''}` : frame.state)
        if (frame.state === 'started') { pointsRef.current = []; feedRef.current = []; dirtyRef.current = true }
      }
    }
    socket.onclose = (event) => {
      socketRef.current = null
      if (event.code === 4401) { setConnection('unauthorised'); return }
      setConnection('closed')
      // exponential backoff with a ceiling: a backend restart must not turn into
      // a reconnect storm from every open tab
      const delay = Math.min(RECONNECT_BASE_MS * 2 ** attemptRef.current, RECONNECT_MAX_MS)
      attemptRef.current += 1
      timerRef.current = window.setTimeout(() => setNonce((n) => n + 1), delay)
    }
    socket.onerror = () => { /* onclose always follows; handled there */ }

    return () => {
      if (timerRef.current) window.clearTimeout(timerRef.current)
      socket.onclose = null
      socket.close()
      socketRef.current = null
    }
  }, [enabled, nonce])

  return { connection, points, feed, status, lastEvent, reconnect }
}
