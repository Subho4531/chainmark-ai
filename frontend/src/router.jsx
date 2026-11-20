import { useCallback } from 'react'
import { navigate } from './routerState'

export function Link({ to, children, className, onClick, ...rest }) {
  const handleClick = useCallback(
    (event) => {
      onClick?.(event)
      if (event.defaultPrevented) return
      if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return
      if (event.button !== 0) return
      if (!to.startsWith('/')) return
      event.preventDefault()
      navigate(to)
    },
    [onClick, to],
  )

  return (
    <a href={to} className={className} onClick={handleClick} {...rest}>
      {children}
    </a>
  )
}
