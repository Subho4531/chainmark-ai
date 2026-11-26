import { useEffect, useState } from 'react'
import {
  BookOpen,
  KeyRound,
  LayoutGrid,
  LogOut,
  Menu,
  Plus,
  Search,
  Terminal,
  X,
} from 'lucide-react'
import { Link } from '../router'
import { usePath, navigate } from '../routerState'
import { useAuth } from '../auth/AuthContext'
import { markSrc, markSrcSet } from '../logo'
import Overview from './Overview'
import Playground from './Playground'
import ApiKeys from './ApiKeys'
import Docs from './Docs'
import './dashboard.css'

const NAV = [
  { label: 'Dashboard', to: '/dashboard', icon: LayoutGrid },
  { label: 'Playground', to: '/playground', icon: Terminal },
  { label: 'API keys', to: '/api-keys', icon: KeyRound },
  { label: 'Docs', to: '/docs', icon: BookOpen },
]

const PAGES = {
  '/dashboard': Overview,
  '/playground': Playground,
  '/api-keys': ApiKeys,
  '/docs': Docs,
}

function normalize(path) {
  if (path.startsWith('/dashboard/')) {
    return `/${path.slice('/dashboard/'.length)}`
  }
  return path
}

function initialsFor(name, email) {
  const src = (name || email || 'CM').trim()
  const parts = src.split(/\s+/)
  if (parts.length >= 2) {
    return `${parts[0][0]}${parts[1][0]}`.toUpperCase()
  }
  return src.slice(0, 2).toUpperCase()
}

export default function DashboardLayout() {
  const path = usePath()
  const route = normalize(path)
  const Page = PAGES[route] ?? Overview
  const [navOpen, setNavOpen] = useState(false)
  const [menuOpen, setMenuOpen] = useState(false)
  const { user, org, billing, logout } = useAuth()

  useEffect(() => {
    const onKey = (event) => {
      if (event.key === 'Escape') {
        setNavOpen(false)
        setMenuOpen(false)
      }
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [])

  const handleLogout = async () => {
    setMenuOpen(false)
    await logout()
    navigate('/login')
  }

  return (
    <div className="dash">
      <header className="dash-top">
        <Link className="dash-brand" to="/dashboard" aria-label="Chainmark AI dashboard">
          <img
            className="dash-brand-mark"
            src={markSrc(26)}
            srcSet={markSrcSet(26)}
            sizes="26px"
            alt=""
            width="26"
            height="26"
            decoding="async"
          />
          <span className="dash-brand-word">
            CHAINMARK
            <em>AI</em>
          </span>
        </Link>

        <nav id="dash-nav" className={`dash-nav ${navOpen ? 'is-open' : ''}`} aria-label="Dashboard">
          {NAV.map((item) => {
            const Icon = item.icon
            const isActive = item.to === route
            return (
              <Link
                key={item.to}
                to={item.to}
                className={`dash-nav-item ${isActive ? 'is-active' : ''}`}
                aria-current={isActive ? 'page' : undefined}
                onClick={() => setNavOpen(false)}
              >
                <Icon size={15} strokeWidth={1.6} />
                <span>{item.label}</span>
              </Link>
            )
          })}
        </nav>

        <div className="dash-top-actions">
          <label className="dash-search">
            <Search size={14} />
            <input type="search" placeholder="Search sessions, tokens" aria-label="Search sessions and tokens" />
            <kbd>/</kbd>
          </label>

          <span className="dash-chain-chip" title="Cloud audit events stored for this workspace">
            <span className="dash-chain-key">cloud</span>
            <span className="dash-chain-value">{billing?.eventsStored ?? 0} events</span>
          </span>

          <Link className="dash-btn dash-btn-primary dash-cta" to="/playground">
            <Plus size={15} />
            New session
          </Link>

          <div className="dash-user-wrap">
            <button
              type="button"
              className="dash-user"
              aria-label={`Account: ${user?.email || 'operator'}`}
              aria-expanded={menuOpen}
              onClick={() => setMenuOpen((open) => !open)}
            >
              <span className="dash-avatar">{initialsFor(user?.name, user?.email)}</span>
              <span className="dash-user-text">
                <strong>{user?.email || 'operator'}</strong>
                <span>{org?.slug || 'workspace'} · cloud</span>
              </span>
            </button>
            {menuOpen ? (
              <div className="dash-user-menu" role="menu">
                <div className="dash-user-menu-meta">
                  <strong>{org?.name}</strong>
                  <span>
                    {org?.role} · {billing?.sessionsCount ?? 0} sessions
                  </span>
                </div>
                <button type="button" className="dash-user-logout" onClick={handleLogout}>
                  <LogOut size={14} />
                  Sign out
                </button>
              </div>
            ) : null}
          </div>

          <button
            type="button"
            className="dash-menu"
            aria-label={navOpen ? 'Close navigation' : 'Open navigation'}
            aria-expanded={navOpen}
            aria-controls="dash-nav"
            onClick={() => setNavOpen((open) => !open)}
          >
            {navOpen ? <X size={18} /> : <Menu size={18} />}
          </button>
        </div>
      </header>

      <main className="dash-main">
        <Page />
      </main>

      <footer className="dash-foot">
        <span>© 2026 Chainmark AI</span>
        <span>Evidence you can verify offline</span>
      </footer>
    </div>
  )
}
