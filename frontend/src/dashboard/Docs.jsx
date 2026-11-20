import { ArrowUpRight } from 'lucide-react'
import { Link } from '../router'

const SECTIONS = [
  { id: 'quickstart', label: 'Quickstart' },
  { id: 'endpoints', label: 'Gateway endpoints' },
  { id: 'auth', label: 'Authentication' },
  { id: 'detectors', label: 'Detectors & checksums' },
  { id: 'evidence', label: 'Evidence & verification' },
  { id: 'errors', label: 'Error codes' },
  { id: 'selfhost', label: 'Self-hosting' },
]

const ENDPOINTS = [
  { method: 'POST', path: '/v1/chat/completions', use: 'OpenAI wire format', protocol: 'OpenAI' },
  { method: 'POST', path: '/v1beta/models/{model}:generateContent', use: 'Gemini wire format', protocol: 'Gemini' },
  { method: 'GET', path: '/healthz', use: 'Liveness probe, never touches the chain', protocol: 'Ops' },
  { method: 'POST', path: '/v1/tokens/{token}', use: 'Detokenize a value inside your own process', protocol: 'Vault' },
]

const DETECTOR_TABLE = [
  { family: 'Email', shapes: 'local@domain.tld', check: 'pattern family' },
  { family: 'Card number', shapes: '4242 4242 4242 4242', check: 'Luhn checksum' },
  { family: 'IBAN', shapes: 'DE89 3704 0044 0532 0130 00', check: 'mod-97 checksum' },
  { family: 'National ID', shapes: '412-88-9014', check: 'pattern family' },
  { family: 'API key', shapes: 'sk-live-8f2a91cd44', check: 'entropy + prefix' },
  { family: 'Phone', shapes: '+1 415 555 0142', check: 'E.164 shape' },
]

const ERRORS = [
  {
    code: 40001,
    title: 'DETECTOR_AMBIGUOUS',
    text: 'A value could not be classified confidently. The call stops before the model sees it — fail closed.',
  },
  {
    code: 40002,
    title: 'SESSION_TAINTED',
    text: 'A later hop in the session re-matched a classified value. Re-run with a clean session id.',
  },
  {
    code: 40007,
    title: 'VAULT_UNAVAILABLE',
    text: 'The vault could not be reached. No plaintext is forwarded when the vault is down.',
  },
  {
    code: 40009,
    title: 'CHAIN_SEQUENCE_GAP',
    text: 'The evidence chain found a missing sequence number. Treat the run as unverified.',
  },
]

export default function Docs() {
  return (
    <div className="docs">
      <header className="dash-page-head">
        <div>
          <p className="dash-eyebrow">Reference</p>
          <h1 className="dash-title">Docs</h1>
          <p className="dash-lede">
            Wire the gateway, understand the detectors, and verify the evidence chain offline. Full
            specifications live in the repository.
          </p>
        </div>
        <a className="dash-btn dash-btn-ghost" href="https://github.com/Subho4531/chainmark-ai#readme" target="_blank" rel="noreferrer">
          GitHub readme
          <ArrowUpRight size={14} />
        </a>
      </header>

      <div className="docs-body">
        <aside className="docs-toc" aria-label="On this page">
          <span className="docs-toc-label">On this page</span>
          <nav>
            {SECTIONS.map((section) => (
              <a key={section.id} href={`#${section.id}`}>
                {section.label}
              </a>
            ))}
          </nav>
        </aside>

        <div className="docs-prose">
          <section id="quickstart" className="docs-section">
            <h2>Quickstart</h2>
            <p>
              Point your model clients at the gateway. No SDK required — the proxy stays transparent
              to the OpenAI and Gemini wire formats.
            </p>
            <div className="docs-cards">
              <article>
                <span>01 · Point</span>
                <pre>{`OPENAI_BASE_URL=http://localhost:8000/v1
GEMINI_BASE_URL=http://localhost:8000
X-Chainmark-Session-Id: agent-<id>`}</pre>
              </article>
              <article>
                <span>02 · Run</span>
                <pre>{`uv run python scripts/run_local.py`}</pre>
              </article>
              <article>
                <span>03 · Verify</span>
                <pre>{`uv run chainmark-verify \\
  --session agent-<id>`}</pre>
              </article>
            </div>
            <p className="docs-tip">
              Keep one session id for the whole agent run. It is the join key between tokens and
              their evidence entries.
            </p>
          </section>

          <section id="endpoints" className="docs-section">
            <h2>Gateway endpoints</h2>
            <div className="docs-table">
              <table>
                <thead>
                  <tr>
                    <th scope="col">Method</th>
                    <th scope="col">Path</th>
                    <th scope="col">Use</th>
                    <th scope="col">Protocol</th>
                  </tr>
                </thead>
                <tbody>
                  {ENDPOINTS.map((endpoint) => (
                    <tr key={endpoint.path}>
                      <td><code className="docs-method">{endpoint.method}</code></td>
                      <td><code>{endpoint.path}</code></td>
                      <td>{endpoint.use}</td>
                      <td className="docs-dim">{endpoint.protocol}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          <section id="auth" className="docs-section">
            <h2>Authentication</h2>
            <p>
              Requests carry a bearer key from the <Link to="/api-keys">API keys</Link> page. The key is
              hashed at rest; the gateway rejects calls it cannot attribute to a workspace.
            </p>
            <pre className="docs-code">{`Authorization: Bearer cm_live_…
X-Chainmark-Session-Id: agent-7f2c`}</pre>
            <p className="docs-tip">Keys are rotated through the dashboard and take effect immediately.</p>
          </section>

          <section id="detectors" className="docs-section">
            <h2>Detectors &amp; checksums</h2>
            <p>
              Detection is deterministic — regex families for shape, checksums for veracity. A
              look-alike that fails its checksum is dropped, not forwarded.
            </p>
            <div className="docs-table">
              <table>
                <thead>
                  <tr>
                    <th scope="col">Family</th>
                    <th scope="col">Shapes</th>
                    <th scope="col">Check</th>
                  </tr>
                </thead>
                <tbody>
                  {DETECTOR_TABLE.map((detector) => (
                    <tr key={detector.family}>
                      <td>{detector.family}</td>
                      <td><code>{detector.shapes}</code></td>
                      <td className="docs-dim">{detector.check}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          <section id="evidence" className="docs-section">
            <h2>Evidence &amp; verification</h2>
            <p>
              Every request is chained: strictly monotonic sequence numbers, SHA-256 digests, a Merkle
              DAG per entry, and an ECDSA P-256 signature over the block.
            </p>
            <pre className="docs-code">{`chain   seq 0000..0041      continuous
digest  sha256 per entry    match
sig     ecdsa p-256         valid
vault   41 tokens           0 plaintext
result  VERIFIED  ·  exit 0`}</pre>
            <p className="docs-tip">
              Verification is offline. No account, no network call, and no phone-home.
            </p>
          </section>

          <section id="errors" className="docs-section">
            <h2>Error codes</h2>
            <ul className="docs-errors">
              {ERRORS.map((error) => (
                <li key={error.code}>
                  <code>{error.code}</code>
                  <strong>{error.title}</strong>
                  <span>{error.text}</span>
                </li>
              ))}
            </ul>
          </section>

          <section id="selfhost" className="docs-section">
            <h2>Self-hosting</h2>
            <p>The whole pipeline runs on your own machine or cluster.</p>
            <pre className="docs-code">{`uv sync
uv run python scripts/run_local.py

# tests, in the repo root
uv run pytest`}</pre>
          </section>
        </div>
      </div>
    </div>
  )
}