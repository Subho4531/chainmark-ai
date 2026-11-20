import { useEffect, useState } from 'react'

/**
 * Minimal client-side routing state: no dependency, no layout thrash.
 * Path state is shared so every Link and the app root stay in sync.
 */

const subscribers = new Set()

function readPath() {
  return window.location.pathname.replace(/\/+$/, '') || '/'
}

export function navigate(to) {
  if (to === readPath()) return
  window.history.pushState({}, '', to)
  subscribers.forEach((subscriber) => subscriber())
  window.scrollTo({ top: 0, behavior: 'auto' })
}

export function usePath() {
  const [path, setPath] = useState(readPath)

  useEffect(() => {
    const update = () => setPath(readPath())
    subscribers.add(update)
    window.addEventListener('popstate', update)
    return () => {
      subscribers.delete(update)
      window.removeEventListener('popstate', update)
    }
  }, [])

  return path
}
