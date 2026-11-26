import { useState } from 'react'
import { Link } from '../router'
import { navigate } from '../routerState'
import { markSrc, markSrcSet } from '../logo'
import { useAuth } from './AuthContext'
import './auth.css'

export default function AuthPage({ mode = 'login', redirectTo = '/dashboard' }) {
  const isSignup = mode === 'signup'
  const { login, signup } = useAuth()

  const [email, setEmail] = useState('')
  const [name, setName] = useState('')
  const [workspaceName, setWorkspaceName] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)

  const handleSubmit = async (event) => {
    event.preventDefault()
    setError('')
    setSubmitting(true)
    try {
      if (isSignup) {
        await signup({ email, password, name, workspaceName })
      } else {
        await login({ email, password })
      }
      navigate(redirectTo === '/login' || redirectTo === '/signup' ? '/dashboard' : redirectTo)
    } catch (err) {
      setError(err.message || 'Authentication failed')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="auth-shell">
      <header className="auth-header">
        <Link className="auth-brand" to="/" aria-label="Chainmark AI home">
          <img
            src={markSrc(26)}
            srcSet={markSrcSet(26)}
            sizes="26px"
            alt=""
            width="26"
            height="26"
            decoding="async"
          />
          <span className="auth-brand-word">
            CHAINMARK
            <em>AI</em>
          </span>
        </Link>
        <Link className="auth-back" to="/">
          ← Back to site
        </Link>
      </header>

      <main className="auth-main">
        <div className="auth-grid">
          <section className="auth-aside">
            <p className="auth-eyebrow">Managed Cloud · Option 2</p>
            <h1>Keep plaintext inside your host. Sync signed proofs to the cloud.</h1>
            <p>
              Run the Chainmark Rust proxy container beside your agents so raw PII and AES-256-GCM
              vault keys never leave your network. Authenticate with a scoped workspace token to
              persist Merkle audit chains and export verification packs.
            </p>
            <div className="auth-topology">
              <div className="auth-topology-row">
                <span>Local Rust Docker proxy</span>
                <code>AES-256-GCM vault + detectors</code>
              </div>
              <div className="auth-topology-row">
                <span>Website API token</span>
                <code>Authorization: Bearer cm_live_…</code>
              </div>
              <div className="auth-topology-row">
                <span>Cloud audit storage</span>
                <code>SHA-256 digests + ECDSA receipts</code>
              </div>
            </div>
          </section>

          <section className="auth-card" aria-label={isSignup ? 'Create workspace account' : 'Log in'}>
            <div className="auth-card-head">
              <h2>{isSignup ? 'Create cloud account' : 'Sign in to workspace'}</h2>
              <span className="auth-card-meta">PostgreSQL · ECDSA</span>
            </div>

            <form className="auth-form" onSubmit={handleSubmit}>
              {isSignup ? (
                <>
                  <label className="auth-field">
                    <span>Your name</span>
                    <input
                      type="text"
                      required
                      autoComplete="name"
                      placeholder="Subho"
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                    />
                  </label>
                  <label className="auth-field">
                    <span>Workspace name</span>
                    <input
                      type="text"
                      required
                      placeholder="Acme Security"
                      value={workspaceName}
                      onChange={(e) => setWorkspaceName(e.target.value)}
                    />
                  </label>
                </>
              ) : null}

              <label className="auth-field">
                <span>Work email</span>
                <input
                  type="email"
                  required
                  autoComplete="email"
                  placeholder="operator@company.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                />
              </label>

              <label className="auth-field">
                <span>Password</span>
                <input
                  type="password"
                  required
                  minLength={8}
                  autoComplete={isSignup ? 'new-password' : 'current-password'}
                  placeholder={isSignup ? 'Minimum 8 characters' : '••••••••'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
              </label>

              {error ? (
                <p className="auth-error" role="alert">
                  {error}
                </p>
              ) : null}

              <button type="submit" className="auth-submit" disabled={submitting}>
                {submitting
                  ? isSignup
                    ? 'Provisioning workspace…'
                    : 'Signing in…'
                  : isSignup
                    ? 'Create account & workspace'
                    : 'Log in'}
              </button>
            </form>

            <div className="auth-switch">
              <span>{isSignup ? 'Already have a workspace?' : 'Need a cloud workspace?'}</span>
              <Link to={isSignup ? '/login' : '/signup'}>
                {isSignup ? 'Log in →' : 'Sign up →'}
              </Link>
            </div>
          </section>
        </div>
      </main>

      <footer className="auth-foot">
        <span>Chainmark AI Cloud Control Plane</span>
        <span>Zero plaintext egress · Offline verifiable</span>
      </footer>
    </div>
  )
}
