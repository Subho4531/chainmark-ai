import { useEffect, useState } from 'react'
import {
  BookOpen,
  KeyRound,
  LayoutGrid,
  Menu,
  Plus,
  Search,
  Terminal,
  X,
} from 'lucide-react'
import { Link } from '../router'
import { usePath } from '../routerState'
import Overview from './Overview'
import Playground from './Playground'
import ApiKeys from './ApiKeys'
import Docs from './Docs'
import './dashboard.css'

const NAV = [
  { label: 'Dashboard', to: '/dashboard', icon: LayoutGrid, meta: '01' },
  { label: 'Playground', to: '/playground', icon: Terminal, meta: '02' },
  { label: 'API keys', to: '/api-keys', icon: KeyRound, meta: '03' },
  { label: 'Docs', to: '/docs', icon: BookOpen, meta: '04' },
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

export default function DashboardLayout() {
  const path = usePath()
  const route = normalize(path)
  const Page = PAGES[route] ?? Overview
  const active = NAV.find((item) => item.to === route) ?? NAV[0]
  const [navOpen, setNavOpen] = useState(false)

  useEffect(() => {
    const onKey = (event) => {
      if (event.key === 'Escape') setNavOpen(false)
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [])

  return (
    <div className="dash">
      <aside className={`dash-side ${navOpen ? 'is-open' : ''}`}>
        <div className="dash-side-head">
          <Link className="dash-brand" to="/dashboard" aria-label="Chainmark AI dashboard">
            <span className="dash-brand-badge">
              <img
                src="/logo/mark-26.png"
                srcSet="/logo/mark-26.png 1x, /logo/mark-52.png 2x"
                alt=""
                width="26"
                height="26"
                decoding="async"
              />
            </span>
            <span className="dash-brand-word">CHAINMARK AI</span>
          </Link>
          <button
            type="button"
            className="dash-side-close"
            aria-label="Close navigation"
            onClick={() => setNavOpen(false)}
          >
            <X size={16} />
          </button>
        </div>

        <div className="dash-workspace">
          <span className="dash-workspace-label">Workspace</span>
          <span className="dash-workspace-name">acme · production</span>
          <span className="dash-workspace-id">ws_8f21c</span>
        </div>

        <nav className="dash-nav" aria-label="Dashboard">
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
                <Icon size={16} strokeWidth={1.6} />
                <span>{item.label}</span>
                <span className="dash-nav-meta">{item.meta}</span>
              </Link>
            )
          })}
        </nav>

        <div className="dash-side-foot">
          <div className="dash-chain">
            <span className="dash-chain-label">Evidence chain</span>
            <span className="dash-chain-state">VERIFIED · seq 4182</span>
            <span className="dash-chain-meta">last check 2m ago · ECDSA P-256</span>
          </div>
          <div className="dash-user">
            <span className="dash-avatar">SB</span>
            <span className="dash-user-text">
              <strong>subho@acme.dev</strong>
              <span>Team · 12 seats</span>
            </span>
          </div>
        </div>
      </aside>

      {navOpen ? <button type="button" className="dash-scrim" aria-label="Close navigation" onClick={() => setNavOpen(false)} /> : null}

      <div className="dash-body">
        <header className="dash-top">
          <button
            type="button"
            className="dash-menu"
            aria-label="Open navigation"
            aria-expanded={navOpen}
            onClick={() => setNavOpen(true)}
          >
            <Menu size={18} />
          </button>

          <div className="dash-crumb">
            <span className="dash-crumb-root">chainmark</span>
            <span className="dash-crumb-sep">/</span>
            <span className="dash-crumb-page">{active.label.toLowerCase()}</span>
          </div>

          <div className="dash-top-actions">
            <label className="dash-search">
              <Search size={14} />
              <input type="search" placeholder="Search sessions, tokens" aria-label="Search sessions and tokens" />
              <kbd>/</kbd>
            </label>
            <Link className="dash-btn dash-btn-ghost" to="/docs">
              SDK docs
            </Link>
            <Link className="dash-btn dash-btn-primary" to="/playground">
              <Plus size={15} />
              New session
            </Link>
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
    </div>
  )
}
