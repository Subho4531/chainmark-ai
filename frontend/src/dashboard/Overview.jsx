import { useEffect, useMemo, useState } from 'react'
import { ArrowUpRight, Check, Copy, Download, ShieldCheck } from 'lucide-react'
import { Link } from '../router'
import { useAuth } from '../auth/AuthContext'

const RANGES = [
  { id: '24h', label: '24h' },
  { id: '7d', label: '7d' },
  { id: '30d', label: '30d' },
]

function trendPath(values) {
  const safe = values && values.length >= 2 ? values : [0, 0]
  const max = Math.max(...safe, 1)
  return safe
    .map((value, index) => {
      const x = (index / (safe.length - 1)) * 100
      const y = 92 - (value / max) * 78
      return `${index === 0 ? 'M' : 'L'}${x.toFixed(1)},${y.toFixed(1)}`
    })
    .join(' ')
}

function formatBytes(bytes) {
  if (!bytes) return '0 B'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
}

function formatRelative(iso) {
  if (!iso) return '—'
  const diffSec = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000))
  if (diffSec < 60) return `${diffSec}s ago`
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)} min ago`
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)} hr ago`
  return `${Math.floor(diffSec / 86400)}d ago`
}

function Spark({ points, accent }) {
  const safe = points && points.length >= 2 ? points : [0, 0]
  const max = Math.max(...safe)
  const min = Math.min(...safe)
  const span = max - min || 1
  const d = safe
    .map((point, index) => `${(index / (safe.length - 1)) * 100},${28 - ((point - min) / span) * 24}`)
    .join(' ')

  return (
    <svg className="ov-spark" viewBox="0 0 100 28" preserveAspectRatio="none" aria-hidden="true">
      <polyline
        points={d}
        fill="none"
        stroke={accent ? '#ff571a' : '#5a564f'}
        strokeWidth="1.4"
        vectorEffect="non-scaling-stroke"
      />
    </svg>
  )
}

export default function Overview() {
  const { org } = useAuth()
  const [range, setRange] = useState('24h')
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [copied, setCopied] = useState(false)
  const [verifyMap, setVerifyMap] = useState({})

  useEffect(() => {
    let cancelled = false
    fetch(`/api/analytics/overview?range=${encodeURIComponent(range)}`, {
      credentials: 'include',
    })
      .then(async (res) => {
        const payload = await res.json().catch(() => ({}))
        if (!res.ok) throw new Error(payload.error || 'Failed to load analytics')
        return payload
      })
      .then((payload) => {
        if (!cancelled) {
          setError('')
          setData(payload)
        }
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
  }, [range])

  const series = useMemo(() => data?.series || [], [data?.series])
  const line = useMemo(() => trendPath(series), [series])
  const area = `${line} L100,100 L0,100 Z`
  const summary = data?.summary || {
    totalSessions: 0,
    eventsInWindow: 0,
    totalEventsStored: 0,
    tokensRedacted: 0,
    blockedCalls: 0,
    estimatedAuditBytes: 0,
    packsStored: 0,
  }

  const headSessionId = data?.chainHead?.sessionId || 'agent-session'
  const verifyCmd = `curl -O ${typeof window !== 'undefined' ? window.location.origin : ''}/api/analytics/sessions/${headSessionId}/export`

  const copyCmd = async () => {
    try {
      await navigator.clipboard.writeText(verifyCmd)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1800)
    } catch {
      setCopied(false)
    }
  }

  const verifySession = async (sessionId) => {
    try {
      const res = await fetch(
        `/api/analytics/sessions/${encodeURIComponent(sessionId)}/verify`,
        { credentials: 'include' },
      )
      const result = await res.json().catch(() => ({}))
      if (!res.ok) throw new Error(result.error || 'Verification failed')
      setVerifyMap((prev) => ({
        ...prev,
        [sessionId]: result.valid ? 'VERIFIED' : 'INVALID',
      }))
    } catch {
      setVerifyMap((prev) => ({ ...prev, [sessionId]: 'ERROR' }))
    }
  }

  const statsCards = [
    {
      label: 'Sessions sealed',
      value: summary.totalSessions.toLocaleString(),
      delta: org?.slug || 'cloud',
      note: 'PostgreSQL org ledger',
      spark: series,
      accent: true,
    },
    {
      label: 'Merkle events',
      value: summary.eventsInWindow.toLocaleString(),
      delta: `${summary.totalEventsStored} total`,
      note: `in ${range} window`,
      spark: series,
    },
    {
      label: 'Tokens redacted',
      value: summary.tokensRedacted.toLocaleString(),
      delta: `${summary.blockedCalls} blocked`,
      note: '0 plaintext uploaded',
      spark: series,
    },
    {
      label: 'Audit storage metered',
      value: formatBytes(summary.estimatedAuditBytes),
      delta: `${summary.packsStored} zip packs`,
      note: 'Option 2 cloud retention',
      spark: series,
    },
  ]

  return (
    <div className="ov">
      <header className="dash-page-head">
        <div>
          <p className="dash-eyebrow">Cloud control plane · {org?.name}</p>
          <h1 className="dash-title">Overview</h1>
          <p className="dash-lede">
            Live zero-plaintext telemetry ingested from your Docker proxy containers. Plaintext
            prompts stay inside your local AES-256-GCM vault.
          </p>
        </div>
        <div className="dash-segment" role="group" aria-label="Time range">
          {RANGES.map((item) => (
            <button
              key={item.id}
              type="button"
              className={range === item.id ? 'is-active' : ''}
              aria-pressed={range === item.id}
              onClick={() => setRange(item.id)}
            >
              {item.label}
            </button>
          ))}
        </div>
      </header>

      {error ? (
        <p className="ov-error" role="alert">
          {error}
        </p>
      ) : null}

      {!loading && summary.totalSessions === 0 ? (
        <section className="ov-panel ov-empty" aria-label="Onboarding">
          <div className="ov-panel-head">
            <h2>No telemetry received for {org?.name} yet</h2>
            <span className="ov-panel-meta">0 events metered</span>
          </div>
          <p className="ov-empty-copy">
            Mint a workspace API key (`cm_live_…`) and pass it to your local Rust Docker proxy
            container via <code>CHAINMARK_API_TOKEN</code> to start streaming signed Merkle events.
          </p>
          <div className="ov-empty-actions">
            <Link className="dash-btn dash-btn-primary" to="/api-keys">
              Create workspace API key
            </Link>
            <Link className="dash-btn dash-btn-ghost" to="/playground">
              Open local playground
            </Link>
          </div>
        </section>
      ) : null}

      <section className="ov-stats" aria-label="Key metrics">
        {statsCards.map((stat) => (
          <article className="ov-stat" key={stat.label}>
            <p className="ov-stat-label">{stat.label}</p>
            <p className={`ov-stat-value ${stat.accent ? 'is-accent' : ''}`}>{stat.value}</p>
            <Spark points={stat.spark} accent={stat.accent} />
            <p className="ov-stat-foot">
              <span className="ov-delta">{stat.delta}</span>
              <span>{stat.note}</span>
            </p>
          </article>
        ))}
      </section>

      <section className="ov-grid" aria-label="Traffic">
        <article className="ov-panel ov-trend">
          <div className="ov-panel-head">
            <h2>Ingested audit events</h2>
            <span className="ov-panel-meta">{range} buckets</span>
          </div>
          <div className="ov-chart">
            <svg viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">
              <defs>
                <linearGradient id="ov-area" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#ff571a" stopOpacity="0.22" />
                  <stop offset="100%" stopColor="#ff571a" stopOpacity="0" />
                </linearGradient>
              </defs>
              {[0, 25, 50, 75, 100].map((y) => (
                <line
                  key={y}
                  x1="0"
                  y1={y}
                  x2="100"
                  y2={y}
                  stroke="#171717"
                  strokeWidth="1"
                  vectorEffect="non-scaling-stroke"
                />
              ))}
              <path d={area} fill="url(#ov-area)" />
              <path d={line} fill="none" stroke="#ff571a" strokeWidth="1.6" vectorEffect="non-scaling-stroke" />
            </svg>
          </div>
          <div className="ov-axis">
            <span>Start ({range})</span>
            <span>Midpoint</span>
            <span>Now</span>
          </div>
        </article>

        <article className="ov-panel ov-mix">
          <div className="ov-panel-head">
            <h2>Detector mix</h2>
            <span className="ov-panel-meta">{summary.tokensRedacted} tokens</span>
          </div>
          {(data?.detectors || []).length === 0 ? (
            <p className="ov-empty-copy">No entities flagged in this window.</p>
          ) : (
            <ul className="ov-bars">
              {data.detectors.map((detector) => (
                <li key={detector.name}>
                  <span className="ov-bar-name">{detector.name}</span>
                  <span className="ov-bar-track">
                    <span className="ov-bar-fill" style={{ width: `${detector.share}%` }} />
                  </span>
                  <span className="ov-bar-count">{detector.count.toLocaleString()}</span>
                </li>
              ))}
            </ul>
          )}
        </article>
      </section>

      <section className="ov-grid is-split" aria-label="Sessions">
        <article className="ov-panel ov-table">
          <div className="ov-panel-head">
            <h2>Recent sessions</h2>
            <Link className="ov-link" to="/api-keys">
              Manage API keys
              <ArrowUpRight size={13} />
            </Link>
          </div>
          <div className="ov-table-scroll">
            <table>
              <thead>
                <tr>
                  <th scope="col">Session</th>
                  <th scope="col">Events</th>
                  <th scope="col">Merkle root</th>
                  <th scope="col">Integrity</th>
                  <th scope="col">Seen</th>
                  <th scope="col">Receipt</th>
                </tr>
              </thead>
              <tbody>
                {(data?.sessions || []).length === 0 ? (
                  <tr>
                    <td colSpan={6} className="ov-dim">
                      No sessions recorded yet.
                    </td>
                  </tr>
                ) : (
                  data.sessions.map((session) => {
                    const verifyLabel = verifyMap[session.sessionId] || session.status
                    return (
                      <tr key={session.sessionId}>
                        <td className="ov-mono">{session.sessionId}</td>
                        <td>{session.totalEvents}</td>
                        <td className="ov-mono ov-dim">{session.merkleRoot.slice(0, 12)}…</td>
                        <td>
                          <button
                            type="button"
                            className="ov-chip ov-chip-btn"
                            onClick={() => verifySession(session.sessionId)}
                            title="Run cryptographic chain verification"
                          >
                            <ShieldCheck size={11} />
                            {verifyLabel}
                          </button>
                        </td>
                        <td className="ov-dim">{formatRelative(session.lastActive)}</td>
                        <td>
                          <a
                            className="ov-download"
                            href={`/api/analytics/sessions/${encodeURIComponent(session.sessionId)}/export`}
                          >
                            <Download size={13} />
                            .zip
                          </a>
                        </td>
                      </tr>
                    )
                  })
                )}
              </tbody>
            </table>
          </div>
        </article>

        <div className="ov-stack">
          <article className="ov-panel ov-chain">
            <div className="ov-panel-head">
              <h2>Latest chain head</h2>
              <span className="ov-panel-meta">
                {data?.chainHead ? `${data.chainHead.totalEvents} events` : 'awaiting telemetry'}
              </span>
            </div>
            <dl className="ov-kv">
              <div>
                <dt>Session</dt>
                <dd className="ov-mono">{data?.chainHead?.sessionId || '—'}</dd>
              </div>
              <div>
                <dt>Merkle root</dt>
                <dd className="ov-mono">
                  {data?.chainHead ? `${data.chainHead.merkleRoot.slice(0, 16)}…` : '—'}
                </dd>
              </div>
              <div>
                <dt>Signature</dt>
                <dd className="ov-mono">
                  {data?.chainHead?.signatureValid ? 'ecdsa-p256 · present' : 'unsigned / pending'}
                </dd>
              </div>
            </dl>
            <div className="ov-cmd">
              <code>{verifyCmd}</code>
              <button type="button" onClick={copyCmd} aria-label="Copy export command">
                {copied ? <Check size={13} /> : <Copy size={13} />}
              </button>
            </div>
          </article>

          <article className="ov-panel">
            <div className="ov-panel-head">
              <h2>Latest events</h2>
              <span className="ov-panel-meta">digest log</span>
            </div>
            <ul className="ov-events">
              {(data?.latestEvents || []).length === 0 ? (
                <li>
                  <span className="ov-dim">No audit events recorded in this window.</span>
                </li>
              ) : (
                data.latestEvents.map((event) => (
                  <li key={event.id}>
                    <span className="ov-mono ov-dim">#{event.sequence}</span>
                    <span className={event.policyAction.includes('BLOCK') ? 'is-warm' : ''}>
                      {event.eventType} · {event.sessionId} ({event.tokenCount} tokens ·{' '}
                      {event.inputDigest.slice(0, 8)}…)
                    </span>
                  </li>
                ))
              )}
            </ul>
          </article>
        </div>
      </section>
    </div>
  )
}
