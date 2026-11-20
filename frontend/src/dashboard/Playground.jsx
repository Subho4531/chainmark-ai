import { useMemo, useState } from 'react'
import { Check, Copy, ShieldCheck } from 'lucide-react'
import { SAMPLES, scan } from './detectors'

const TABS = [
  { id: 'payload', label: 'Sanitized payload' },
  { id: 'tokens', label: 'Token map' },
  { id: 'chain', label: 'Chain entry' },
]

export default function Playground() {
  const [text, setText] = useState(SAMPLES[0].text)
  const [tab, setTab] = useState('payload')
  const [copied, setCopied] = useState(false)

  const result = useMemo(() => scan(text), [text])

  const copyPayload = async () => {
    try {
      await navigator.clipboard.writeText(result.sanitized)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1800)
    } catch {
      setCopied(false)
    }
  }

  const entry = `{
  "seq": 4182,
  "session": "agent-playground",
  "route": "/v1/chat/completions",
  "model": "gpt-4o-mini",
  "detections": ${result.entities.length},
  "input_digest": "sha256:${result.inputDigest}…",
  "sanitized_digest": "sha256:${result.sanitizedDigest}…",
  "signature": "ecdsa-p256",
  "prev": "sha256:9c1f4ab2…"
}`

  return (
    <div className="pg">
      <header className="dash-page-head">
        <div>
          <p className="dash-eyebrow">Local sandbox</p>
          <h1 className="dash-title">Playground</h1>
          <p className="dash-lede">
            Paste an outbound payload and watch the detector, vault and evidence layers run. The same
            rules as the gateway, executed in this tab — nothing is sent anywhere.
          </p>
        </div>
        <span className="dash-badge">
          <ShieldCheck size={14} />
          runs in your browser
        </span>
      </header>

      <div className="pg-grid">
        <section className="dash-panel pg-editor" aria-label="Payload input">
          <div className="dash-panel-head">
            <h2>Outbound payload</h2>
            <div className="pg-samples">
              {SAMPLES.map((sample) => (
                <button
                  key={sample.id}
                  type="button"
                  className={text === sample.text ? 'is-active' : ''}
                  onClick={() => setText(sample.text)}
                >
                  {sample.label}
                </button>
              ))}
            </div>
          </div>

          <textarea
            className="pg-input"
            value={text}
            spellCheck="false"
            aria-label="Payload to scan"
            onChange={(event) => setText(event.target.value)}
          />

          <div className="dash-panel-foot">
            <span className="pg-foot-meta">
              {text.length} chars · {result.entities.length} matches
            </span>
            <button type="button" className="dash-btn dash-btn-ghost" onClick={() => setText('')}>
              Clear
            </button>
          </div>
        </section>

        <section className="dash-panel pg-result" aria-label="Scan result">
          <div className="dash-panel-head">
            <h2>Result</h2>
            <span className="pg-safe">
              <span className="pg-safe-dot" aria-hidden="true" />
              0 plaintext leaves the perimeter
            </span>
          </div>

          <div className="pg-tabs" role="tablist" aria-label="Result views">
            {TABS.map((item) => (
              <button
                key={item.id}
                type="button"
                role="tab"
                aria-selected={tab === item.id}
                className={tab === item.id ? 'is-active' : ''}
                onClick={() => setTab(item.id)}
              >
                {item.label}
              </button>
            ))}
          </div>

          {tab === 'payload' ? (
            <div className="pg-payload">
              <pre>
                {result.parts.map((part, index) =>
                  part.type === 'token' ? (
                    <mark key={index} className="pg-token">
                      {part.value}
                    </mark>
                  ) : (
                    <span key={index}>{part.value}</span>
                  ),
                )}
              </pre>
              <button type="button" className="pg-copy" onClick={copyPayload} aria-label="Copy sanitized payload">
                {copied ? <Check size={13} /> : <Copy size={13} />}
                {copied ? 'Copied' : 'Copy'}
              </button>
            </div>
          ) : null}

          {tab === 'tokens' ? (
            result.entities.length ? (
              <div className="pg-tokenlist">
                <table>
                  <thead>
                    <tr>
                      <th scope="col">Type</th>
                      <th scope="col">Matched value</th>
                      <th scope="col">Token</th>
                      <th scope="col">Check</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.entities.map((entity) => (
                      <tr key={`${entity.start}-${entity.kind}`}>
                        <td>{entity.label}</td>
                        <td className="pg-mono">{entity.value}</td>
                        <td className="pg-mono pg-token-cell">{entity.token}</td>
                        <td className="pg-muted">{entity.note}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <p className="pg-empty">No sensitive values matched. Try the invoice or support sample.</p>
            )
          ) : null}

          {tab === 'chain' ? (
            <div className="pg-payload">
              <pre className="pg-json">{entry}</pre>
            </div>
          ) : null}
        </section>
      </div>

      <ol className="pg-steps" aria-label="What the gateway did">
        <li>
          <span className="pg-step-n">01</span>
          <h3>Detect</h3>
          <p>
            Pattern families run first, then checksums (Luhn, mod-97) discard look-alikes. Ambiguity
            fails closed: the call stops before the model sees anything.
          </p>
        </li>
        <li>
          <span className="pg-step-n">02</span>
          <h3>Tokenize</h3>
          <p>
            Each match becomes an HMAC-derived token, stable inside the session and opaque outside it.
            The vault keeps the AES-256-GCM ciphertext, never the plaintext.
          </p>
        </li>
        <li>
          <span className="pg-step-n">03</span>
          <h3>Seal</h3>
          <p>
            The digest of the sanitized payload joins the hash chain, signed with ECDSA P-256, so the
            entry can be replayed offline later.
          </p>
        </li>
      </ol>
    </div>
  )
}
