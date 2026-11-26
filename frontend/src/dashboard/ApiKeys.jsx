import { useEffect, useState } from 'react'
import { Check, Copy, KeyRound, Plus, RotateCw, ShieldCheck, Trash2 } from 'lucide-react'

const SCOPES = [
  { id: 'intercept', label: 'intercept', note: 'Stream zero-plaintext Merkle telemetry from a local Docker proxy to the cloud.' },
  { id: 'vault', label: 'vault', note: 'Authorize local session token map inspection.' },
  { id: 'verify', label: 'verify', note: 'Verify sealed ledgers and download signed receipts.' },
  { id: 'admin', label: 'admin', note: 'Create, rotate and revoke keys for this workspace.' },
]

function formatRelative(iso) {
  if (!iso) return 'never'
  const diffSec = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000))
  if (diffSec < 60) return 'just now'
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)} min ago`
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)} hr ago`
  return `${Math.floor(diffSec / 86400)} days ago`
}

function formatDate(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleDateString('en-GB', {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
  })
}

export default function ApiKeys() {
  const [keys, setKeys] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [creating, setCreating] = useState(false)
  const [name, setName] = useState('')
  const [scopes, setScopes] = useState(['intercept'])
  const [revealed, setRevealed] = useState(null)
  const [copied, setCopied] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    let cancelled = false
    fetch('/api/keys', { credentials: 'include' })
      .then(async (res) => {
        const data = await res.json().catch(() => ({}))
        if (!res.ok) throw new Error(data.error || 'Failed to load API keys')
        return data
      })
      .then((data) => {
        if (!cancelled) setKeys(data.keys || [])
      })
      .catch((err) => {
        if (!cancelled) setError(err.message)
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [])

  const toggleScope = (id) => {
    setScopes((current) =>
      current.includes(id) ? current.filter((scope) => scope !== id) : [...current, id],
    )
  }

  const createKey = async (event) => {
    event.preventDefault()
    setBusy(true)
    setError('')
    try {
      const res = await fetch('/api/keys', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: name.trim() || 'agent-runtime',
          scopes: scopes.length ? scopes : ['intercept'],
        }),
      })
      const data = await res.json().catch(() => ({}))
      if (!res.ok) throw new Error(data.error || 'Failed to create API key')
      setKeys((current) => [data.key, ...current])
      setRevealed({ id: data.key.id, name: data.key.name, secret: data.secret })
      setName('')
      setScopes(['intercept'])
      setCreating(false)
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  const copy = async (value, marker) => {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(marker)
      window.setTimeout(() => setCopied(''), 1800)
    } catch {
      setCopied('')
    }
  }

  const revoke = async (id) => {
    setError('')
    try {
      const res = await fetch(`/api/keys/${encodeURIComponent(id)}`, {
        method: 'DELETE',
        credentials: 'include',
      })
      const data = await res.json().catch(() => ({}))
      if (!res.ok) throw new Error(data.error || 'Failed to revoke key')
      setKeys((current) =>
        current.map((key) => (key.id === id ? { ...key, status: 'revoked' } : key)),
      )
      if (revealed?.id === id) setRevealed(null)
    } catch (err) {
      setError(err.message)
    }
  }

  const rotate = async (id) => {
    setError('')
    try {
      const res = await fetch(`/api/keys/${encodeURIComponent(id)}/rotate`, {
        method: 'POST',
        credentials: 'include',
      })
      const data = await res.json().catch(() => ({}))
      if (!res.ok) throw new Error(data.error || 'Failed to rotate key')
      setKeys((current) =>
        current.map((key) => (key.id === id ? data.key : key)),
      )
      setRevealed({ id, name: data.key.name, secret: data.secret })
    } catch (err) {
      setError(err.message)
    }
  }

  return (
    <div className="keys">
      <header className="dash-page-head">
        <div>
          <p className="dash-eyebrow">Workspace access</p>
          <h1 className="dash-title">API keys</h1>
          <p className="dash-lede">
            Mint a workspace token for your local Docker proxy container. Chainmark stores only an
            HMAC-SHA256 digest and prefix—never the secret itself.
          </p>
        </div>
        <button
          type="button"
          className="dash-btn dash-btn-primary"
          onClick={() => setCreating((open) => !open)}
          aria-expanded={creating}
        >
          <Plus size={15} />
          Create key
        </button>
      </header>

      <p className="keys-note">
        <ShieldCheck size={15} />
        Secrets are shown once at creation or rotation. Configure your local Docker container with{' '}
        <code>CHAINMARK_API_TOKEN</code> to stream zero-plaintext audit logs here.
      </p>

      {error ? (
        <p className="ov-error" role="alert">
          {error}
        </p>
      ) : null}

      {creating ? (
        <form className="dash-panel keys-form" onSubmit={createKey}>
          <div className="dash-panel-head">
            <h2>New key</h2>
            <span className="dash-panel-meta">scoped to this workspace</span>
          </div>
          <label className="keys-field">
            <span>Name</span>
            <input
              type="text"
              value={name}
              placeholder="docker-proxy-prod"
              onChange={(event) => setName(event.target.value)}
            />
          </label>
          <fieldset className="keys-scopes">
            <legend>Scopes</legend>
            {SCOPES.map((scope) => (
              <label key={scope.id} className={scopes.includes(scope.id) ? 'is-on' : ''}>
                <input
                  type="checkbox"
                  checked={scopes.includes(scope.id)}
                  onChange={() => toggleScope(scope.id)}
                />
                <span className="keys-scope-name">{scope.label}</span>
                <span className="keys-scope-note">{scope.note}</span>
              </label>
            ))}
          </fieldset>
          <div className="keys-form-actions">
            <button type="submit" className="dash-btn dash-btn-primary" disabled={busy}>
              {busy ? 'Generating…' : 'Generate key'}
            </button>
            <button type="button" className="dash-btn dash-btn-ghost" onClick={() => setCreating(false)}>
              Cancel
            </button>
          </div>
        </form>
      ) : null}

      {revealed ? (
        <div className="keys-reveal" role="status">
          <div>
            <p className="keys-reveal-label">New secret · {revealed.name} (save now, shown once)</p>
            <code>{revealed.secret}</code>
          </div>
          <button
            type="button"
            className="dash-btn dash-btn-primary"
            onClick={() => copy(revealed.secret, 'reveal')}
          >
            {copied === 'reveal' ? <Check size={15} /> : <Copy size={15} />}
            {copied === 'reveal' ? 'Copied' : 'Copy secret'}
          </button>
        </div>
      ) : null}

      <section className="dash-panel keys-table" aria-label="Issued keys">
        <div className="dash-panel-head">
          <h2>Issued keys</h2>
          <span className="dash-panel-meta">
            {keys.filter((key) => key.status === 'active').length} active
          </span>
        </div>
        <div className="keys-scroll">
          <table>
            <thead>
              <tr>
                <th scope="col">Name</th>
                <th scope="col">Key</th>
                <th scope="col">Scopes</th>
                <th scope="col">Created</th>
                <th scope="col">Last used</th>
                <th scope="col">Status</th>
                <th scope="col"><span className="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={7} className="keys-dim">
                    Loading workspace keys…
                  </td>
                </tr>
              ) : keys.length === 0 ? (
                <tr>
                  <td colSpan={7} className="keys-dim">
                    No API keys yet. Click “Create key” above to mint your first container token.
                  </td>
                </tr>
              ) : (
                keys.map((key) => (
                  <tr key={key.id} className={key.status === 'revoked' ? 'is-revoked' : ''}>
                    <td className="keys-name">
                      <KeyRound size={14} />
                      {key.name}
                    </td>
                    <td className="keys-mono">{key.prefix}…</td>
                    <td className="keys-scope-cell">
                      {(key.scopes || []).map((scope) => (
                        <span key={scope}>{scope}</span>
                      ))}
                    </td>
                    <td className="keys-dim">{formatDate(key.createdAt)}</td>
                    <td className="keys-dim">{formatRelative(key.lastUsedAt)}</td>
                    <td>
                      <span className={`keys-state ${key.status === 'revoked' ? 'is-off' : ''}`}>
                        {key.status === 'revoked' ? 'Revoked' : 'Active'}
                      </span>
                    </td>
                    <td>
                      <div className="keys-actions">
                        <button
                          type="button"
                          aria-label={`Copy ${key.name} prefix`}
                          onClick={() => copy(`${key.prefix}…`, key.id)}
                        >
                          {copied === key.id ? <Check size={14} /> : <Copy size={14} />}
                        </button>
                        <button
                          type="button"
                          aria-label={`Rotate ${key.name}`}
                          disabled={key.status === 'revoked'}
                          onClick={() => rotate(key.id)}
                        >
                          <RotateCw size={14} />
                        </button>
                        <button
                          type="button"
                          aria-label={`Revoke ${key.name}`}
                          disabled={key.status === 'revoked'}
                          onClick={() => revoke(key.id)}
                        >
                          <Trash2 size={14} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>

      <div className="keys-grid">
        <article className="dash-panel">
          <div className="dash-panel-head">
            <h2>Connect local proxy container</h2>
            <span className="dash-panel-meta">zero-plaintext telemetry</span>
          </div>
          <pre className="keys-code">{`docker run -p 8000:8000 \\
  -e CHAINMARK_CLOUD_URL=${typeof window !== 'undefined' ? window.location.origin : 'http://localhost:5174'} \\
  -e CHAINMARK_API_TOKEN=${revealed?.secret || 'cm_live_…'} \\
  chainmark-proxy:latest`}</pre>
          <p className="keys-hint">
            Plaintext secrets stay inside your local AES-256-GCM vault. Only SHA-256 digests,
            Merkle events, and ECDSA receipts are sent to the Cloud API.
          </p>
        </article>

        <article className="dash-panel">
          <div className="dash-panel-head">
            <h2>Scopes</h2>
            <span className="dash-panel-meta">least privilege</span>
          </div>
          <ul className="keys-scope-list">
            {SCOPES.map((scope) => (
              <li key={scope.id}>
                <code>{scope.label}</code>
                <span>{scope.note}</span>
              </li>
            ))}
          </ul>
        </article>
      </div>
    </div>
  )
}
