import { useState } from 'react'
import { Check, Copy, KeyRound, Plus, RotateCw, ShieldCheck, Trash2 } from 'lucide-react'

const SCOPES = [
  { id: 'intercept', label: 'intercept', note: 'Route /v1/chat/completions and :generateContent through the gateway.' },
  { id: 'vault', label: 'vault', note: 'Open the token map for a session you own.' },
  { id: 'verify', label: 'verify', note: 'Run the offline verifier against sealed ledgers.' },
  { id: 'admin', label: 'admin', note: 'Create, rotate and revoke keys for this workspace.' },
]

const INITIAL_KEYS = [
  {
    id: 'k_runtime',
    name: 'agent-runtime',
    prefix: 'cm_live_7f2a',
    scopes: ['intercept', 'vault'],
    created: '14 Sep 2026',
    lastUsed: '2 min ago',
    status: 'active',
  },
  {
    id: 'k_ci',
    name: 'ci-evidence-check',
    prefix: 'cm_live_2b88',
    scopes: ['verify'],
    created: '02 Oct 2026',
    lastUsed: '1 hr ago',
    status: 'active',
  },
  {
    id: 'k_console',
    name: 'retired-console',
    prefix: 'cm_live_c3e1',
    scopes: ['intercept'],
    created: '08 Jun 2026',
    lastUsed: '41 days ago',
    status: 'revoked',
  },
]

function makeSecret() {
  if (typeof crypto === 'undefined' || !crypto.getRandomValues) {
    return 'cm_live_00000000000000000000000000000000'
  }
  const bytes = new Uint8Array(16)
  crypto.getRandomValues(bytes)
  return `cm_live_${Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')}`
}

export default function ApiKeys() {
  const [keys, setKeys] = useState(INITIAL_KEYS)
  const [creating, setCreating] = useState(false)
  const [name, setName] = useState('')
  const [scopes, setScopes] = useState(['intercept'])
  const [revealed, setRevealed] = useState(null)
  const [copied, setCopied] = useState('')

  const toggleScope = (id) => {
    setScopes((current) =>
      current.includes(id) ? current.filter((scope) => scope !== id) : [...current, id],
    )
  }

  const createKey = (event) => {
    event.preventDefault()
    const secret = makeSecret()
    const id = `k_${Date.now().toString(36)}`
    setKeys((current) => [
      {
        id,
        name: name.trim() || 'untitled-key',
        prefix: secret.slice(0, 12),
        scopes: scopes.length ? scopes : ['intercept'],
        created: 'just now',
        lastUsed: 'never',
        status: 'active',
      },
      ...current,
    ])
    setRevealed({ id, name: name.trim() || 'untitled-key', secret })
    setName('')
    setScopes(['intercept'])
    setCreating(false)
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

  const revoke = (id) => {
    setKeys((current) =>
      current.map((key) => (key.id === id ? { ...key, status: 'revoked' } : key)),
    )
    if (revealed?.id === id) setRevealed(null)
  }

  const rotate = (id) => {
    const secret = makeSecret()
    setKeys((current) =>
      current.map((key) =>
        key.id === id
          ? { ...key, prefix: secret.slice(0, 12), lastUsed: 'never', status: 'active' }
          : key,
      ),
    )
    const target = keys.find((key) => key.id === id)
    setRevealed({ id, name: target?.name ?? 'key', secret })
  }

  return (
    <div className="keys">
      <header className="dash-page-head">
        <div>
          <p className="dash-eyebrow">Workspace access</p>
          <h1 className="dash-title">API keys</h1>
          <p className="dash-lede">
            One key per workload. Scope it down to what the agent actually does, then rotate on a
            schedule you can prove to an auditor.
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
        Secrets are shown once. Chainmark stores only an HMAC of the key and the prefix you see here.
      </p>

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
              placeholder="agent-runtime-staging"
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
            <button type="submit" className="dash-btn dash-btn-primary">
              Generate key
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
            <p className="keys-reveal-label">New secret · {revealed.name}</p>
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
          <span className="dash-panel-meta">{keys.filter((key) => key.status === 'active').length} active</span>
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
              {keys.map((key) => (
                <tr key={key.id} className={key.status === 'revoked' ? 'is-revoked' : ''}>
                  <td className="keys-name">
                    <KeyRound size={14} />
                    {key.name}
                  </td>
                  <td className="keys-mono">{key.prefix}…</td>
                  <td className="keys-scope-cell">
                    {key.scopes.map((scope) => (
                      <span key={scope}>{scope}</span>
                    ))}
                  </td>
                  <td className="keys-dim">{key.created}</td>
                  <td className="keys-dim">{key.lastUsed}</td>
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
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <div className="keys-grid">
        <article className="dash-panel">
          <div className="dash-panel-head">
            <h2>Using a key</h2>
            <span className="dash-panel-meta">same SDK, one header</span>
          </div>
          <pre className="keys-code">{`curl http://localhost:8000/v1/chat/completions \\
  -H "Authorization: Bearer cm_live_…" \\
  -H "X-Chainmark-Session-Id: agent-7f2c" \\
  -d '{"model":"gpt-4o-mini","messages":[...]}'`}</pre>
          <p className="keys-hint">
            The session header is what binds the tokens and the evidence entries together. Keep one id
            for the whole agent run.
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
