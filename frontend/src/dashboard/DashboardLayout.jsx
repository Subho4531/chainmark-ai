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

export default function DashboardLayout() {
  const path = usePath()
  const route = normalize(path)
  const Page = PAGES[route] ?? Overview
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

          <span className="dash-chain-chip" title="Evidence chain verified against the sealed ledgers">
            <span className="dash-chain-key">chain</span>
            <span className="dash-chain-value">verified · 4182</span>
          </span>

          <Link className="dash-btn dash-btn-primary dash-cta" to="/playground">
            <Plus size={15} />
            New session
          </Link>

          <button type="button" className="dash-user" aria-label="Account: subho@acme.dev">
            <span className="dash-avatar">SB</span>
            <span className="dash-user-text">
              <strong>subho@acme.dev</strong>
              <span>acme · production</span>
            </span>
          </button>

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
