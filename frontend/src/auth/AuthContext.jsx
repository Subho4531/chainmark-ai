import { createContext, useCallback, useContext, useEffect, useState } from 'react'

const AuthContext = createContext(null)

async function requestJson(url, options = {}) {
  const res = await fetch(url, {
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
    ...options,
  })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) {
    const err = new Error(data.error || `Request failed (${res.status})`)
    err.status = res.status
    throw err
  }
  return data
}

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [org, setOrg] = useState(null)
  const [billing, setBilling] = useState(null)
  const [loading, setLoading] = useState(true)

  const refresh = useCallback(async () => {
    try {
      const data = await requestJson('/api/auth/me')
      setUser(data.user || null)
      setOrg(data.org || null)
      setBilling(data.billing || null)
      return data
    } catch {
      setUser(null)
      setOrg(null)
      setBilling(null)
      return null
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    let cancelled = false
    requestJson('/api/auth/me')
      .then((data) => {
        if (cancelled) return
        setUser(data.user || null)
        setOrg(data.org || null)
        setBilling(data.billing || null)
      })
      .catch(() => {
        if (cancelled) return
        setUser(null)
        setOrg(null)
        setBilling(null)
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [])

  const login = useCallback(
    async ({ email, password }) => {
      const data = await requestJson('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email, password }),
      })
      setUser(data.user)
      setOrg(data.org)
      await refresh()
      return data
    },
    [refresh],
  )

  const signup = useCallback(
    async ({ email, password, name, workspaceName }) => {
      const data = await requestJson('/api/auth/signup', {
        method: 'POST',
        body: JSON.stringify({ email, password, name, workspaceName }),
      })
      setUser(data.user)
      setOrg(data.org)
      await refresh()
      return data
    },
    [refresh],
  )

  const logout = useCallback(async () => {
    try {
      await requestJson('/api/auth/logout', { method: 'POST' })
    } finally {
      setUser(null)
      setOrg(null)
      setBilling(null)
    }
  }, [])

  return (
    <AuthContext.Provider value={{ user, org, billing, loading, login, signup, logout, refresh }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) {
    throw new Error('useAuth must be used inside AuthProvider')
  }
  return ctx
}
