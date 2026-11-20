import { useMemo, useState } from 'react'
import { ArrowUpRight, Check, Copy } from 'lucide-react'
import { Link } from '../router'

const RANGES = [
  { id: '24h', label: '24 hours' },
  { id: '7d', label: '7 days' },
  { id: '30d', label: '30 days' },
]

const SERIES = {
  '24h': [18, 16, 14, 12, 11, 10, 13, 19, 27, 34, 31, 36, 43, 47, 44, 40, 38, 35, 33, 30, 27, 24, 22, 20],
  '7d': [34, 29, 41, 48, 52, 44, 39, 46, 58, 63, 61, 55, 49, 44],
  '30d': [22, 26, 31, 28, 34, 39, 36, 42, 48, 45, 51, 57, 54, 60, 66, 62, 58, 63, 69, 72],
}

const STATS = [
  {
    label: 'Requests intercepted',
    value: '128,412',
    delta: '+18.2%',
    note: 'across 41 agent sessions',
    spark: [30, 32, 31, 36, 38, 35, 41, 44, 43, 48, 52, 50, 56, 59],
    accent: false,
  },
  {
    label: 'Entities tokenized',
    value: '9,847',
    delta: '+6.4%',
    note: '1.9 per intercepted call',
    spark: [20, 22, 21, 24, 23, 27, 26, 29, 28, 32, 31, 33, 35, 36],
    accent: false,
  },
  {
    label: 'Plaintext egress',
    value: '0',
    delta: 'none detected',
    note: 'verified against 41 ledgers',
    spark: [4, 4, 3, 3, 2, 2, 2, 1, 1, 1, 1, 0, 0, 0],
    accent: true,
  },
  {
    label: 'Chain entries sealed',
    value: '4,182',
    delta: 'continuous',
    note: 'seq 0000 → 4181, no gaps',
    spark: [12, 16, 21, 25, 30, 34, 38, 41, 45, 49, 53, 57, 60, 64],
    accent: false,
  },
]

const DETECTORS = [
  { name: 'email', count: 4128, share: 42 },
  { name: 'card · luhn', count: 2914, share: 30 },
  { name: 'iban · mod-97', count: 1206, share: 12 },
  { name: 'phone', count: 894, share: 9 },
  { name: 'api key', count: 512, share: 5 },
  { name: 'national id', count: 193, share: 2 },
]

const SESSIONS = [
  { id: 'agent-7f2c', requests: 42, tokens: 41, when: '2 min ago', window: '11:42 — 11:58' },
  { id: 'agent-91ab', requests: 18, tokens: 12, when: '14 min ago', window: '11:31 — 11:44' },
  { id: 'agent-4d07', requests: 96, tokens: 130, when: '31 min ago', window: '11:02 — 11:27' },
  { id: 'agent-c3e1', requests: 7, tokens: 3, when: '1 hr ago', window: '10:48 — 10:52' },
  { id: 'agent-2b88', requests: 63, tokens: 58, when: '2 hrs ago', window: '09:58 — 10:21' },
]

const EVENTS = [
  { time: '11:58', text: 'Session agent-7f2c sealed · 42 entries', tone: 'warm' },
  { time: '11:44', text: 'Card family match rejected by Luhn at hop 3', tone: '' },
  { time: '11:27', text: 'Taint rule escalated · IBAN re-checked on reply', tone: '' },
  { time: '10:52', text: 'Key rotated · vault re-wrapped, 0 re-encryption errors', tone: '' },
  { time: '09:58', text: 'Verifier replay · 41 ledgers, 0 divergences', tone: 'warm' },
]

const VERIFY_CMD = 'uv run chainmark-verify --session agent-7f2c'

function trendPath(values) {
  const max = Math.max(...values)
  const min = Math.min(...values)
  const span = max - min || 1
  return values
    .map((value, index) => {
      const x = (index / (values.length - 1)) * 100
      const y = 100 - ((value - min) / span) * 84 - 8
      return `${index === 0 ? 'M' : 'L'}${x.toFixed(2)},${y.toFixed(2)}`
    })
    .join(' ')
}

function Spark({ points, accent }) {
  const max = Math.max(...points)
  const min = Math.min(...points)
  const span = max - min || 1
  const d = points
    .map((point, index) => `${(index / (points.length - 1)) * 100},${28 - ((point - min) / span) * 24}`)
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
  const [range, setRange] = useState('24h')
  const [copied, setCopied] = useState(false)
  const series = SERIES[range]
  const line = useMemo(() => trendPath(series), [series])
  const area = `${line} L100,100 L0,100 Z`

  const copyCmd = async () => {
    try {
      await navigator.clipboard.writeText(VERIFY_CMD)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1800)
    } catch {
      setCopied(false)
    }
  }

  return (
    <div className="ov">
      <header className="dash-page-head">
        <div>
          <p className="dash-eyebrow">Control plane</p>
          <h1 className="dash-title">Overview</h1>
          <p className="dash-lede">
            Every agent call through the gateway, scanned and sealed. The numbers below come from the
            local evidence chain, not from a billing meter.
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

      <section className="ov-stats" aria-label="Key metrics">
        {STATS.map((stat) => (
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
            <h2>Intercepted throughput</h2>
            <span className="ov-panel-meta">calls / hour</span>
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
                <line key={y} x1="0" y1={y} x2="100" y2={y} stroke="#171717" strokeWidth="1" vectorEffect="non-scaling-stroke" />
              ))}
              <path d={area} fill="url(#ov-area)" />
              <path d={line} fill="none" stroke="#ff571a" strokeWidth="1.6" vectorEffect="non-scaling-stroke" />
            </svg>
          </div>
          <div className="ov-axis">
            <span>00:00</span>
            <span>06:00</span>
            <span>12:00</span>
            <span>18:00</span>
            <span>23:59</span>
          </div>
        </article>

        <article className="ov-panel ov-mix">
          <div className="ov-panel-head">
            <h2>Detector mix</h2>
            <span className="ov-panel-meta">9,847 tokens</span>
          </div>
          <ul className="ov-bars">
            {DETECTORS.map((detector) => (
              <li key={detector.name}>
                <span className="ov-bar-name">{detector.name}</span>
                <span className="ov-bar-track">
                  <span className="ov-bar-fill" style={{ width: `${detector.share}%` }} />
                </span>
                <span className="ov-bar-count">{detector.count.toLocaleString()}</span>
              </li>
            ))}
          </ul>
        </article>
      </section>

      <section className="ov-grid is-split" aria-label="Sessions">
        <article className="ov-panel ov-table">
          <div className="ov-panel-head">
            <h2>Recent sessions</h2>
            <Link className="ov-link" to="/playground">
              Open playground
              <ArrowUpRight size={13} />
            </Link>
          </div>
          <div className="ov-table-scroll">
            <table>
              <thead>
                <tr>
                  <th scope="col">Session</th>
                  <th scope="col">Requests</th>
                  <th scope="col">Tokens</th>
                  <th scope="col">Window</th>
                  <th scope="col">Chain</th>
                  <th scope="col">Seen</th>
                </tr>
              </thead>
              <tbody>
                {SESSIONS.map((session) => (
                  <tr key={session.id}>
                    <td className="ov-mono">{session.id}</td>
                    <td>{session.requests}</td>
                    <td>{session.tokens}</td>
                    <td className="ov-mono ov-dim">{session.window}</td>
                    <td>
                      <span className="ov-chip">VERIFIED</span>
                    </td>
                    <td className="ov-dim">{session.when}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </article>

        <div className="ov-stack">
          <article className="ov-panel ov-chain">
            <div className="ov-panel-head">
              <h2>Chain integrity</h2>
              <span className="ov-panel-meta">seq 0000 → 4181</span>
            </div>
            <dl className="ov-kv">
              <div>
                <dt>Digest</dt>
                <dd className="ov-mono">sha256:9c1f…4ab2</dd>
              </div>
              <div>
                <dt>Signature</dt>
                <dd className="ov-mono">ecdsa-p256 · valid</dd>
              </div>
              <div>
                <dt>Vault</dt>
                <dd className="ov-mono">41 tokens · 0 plaintext</dd>
              </div>
            </dl>
            <div className="ov-cmd">
              <code>{VERIFY_CMD}</code>
              <button type="button" onClick={copyCmd} aria-label="Copy verify command">
                {copied ? <Check size={13} /> : <Copy size={13} />}
              </button>
            </div>
          </article>

          <article className="ov-panel">
            <div className="ov-panel-head">
              <h2>Latest events</h2>
              <span className="ov-panel-meta">chain log</span>
            </div>
            <ul className="ov-events">
              {EVENTS.map((event) => (
                <li key={event.time + event.text}>
                  <span className="ov-mono ov-dim">{event.time}</span>
                  <span className={event.tone === 'warm' ? 'is-warm' : ''}>{event.text}</span>
                </li>
              ))}
            </ul>
          </article>
        </div>
      </section>
    </div>
  )
}
