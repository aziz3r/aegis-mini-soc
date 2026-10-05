/** Small data-fetching hook: load, reload, poll, and surface errors as text. */
import { useCallback, useEffect, useRef, useState } from 'react'
import { ApiError } from '../lib/api'

export interface Resource<T> {
  data: T | null
  error: string | null
  loading: boolean
  reload: () => void
}

export function useApi<T>(fetcher: () => Promise<T>, deps: unknown[] = [],
                          pollMs = 0): Resource<T> {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [nonce, setNonce] = useState(0)
  const alive = useRef(true)
  const fetcherRef = useRef(fetcher)
  fetcherRef.current = fetcher

  const reload = useCallback(() => setNonce((n) => n + 1), [])

  useEffect(() => {
    alive.current = true
    let cancelled = false
    const run = async (first: boolean) => {
      if (first) setLoading(true)
      try {
        const result = await fetcherRef.current()
        if (!cancelled && alive.current) { setData(result); setError(null) }
      } catch (exc) {
        if (!cancelled && alive.current) {
          setError(exc instanceof ApiError ? exc.message : (exc as Error).message ?? 'erreur inconnue')
        }
      } finally {
        if (!cancelled && alive.current) setLoading(false)
      }
    }
    void run(true)
    const id = pollMs > 0 ? window.setInterval(() => void run(false), pollMs) : null
    return () => {
      cancelled = true
      alive.current = false
      if (id) window.clearInterval(id)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, nonce, pollMs])

  return { data, error, loading, reload }
}
