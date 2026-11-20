import { useCallback, useEffect, useRef, useState } from 'react'
import FlowField from './FlowField'
import HeroSeam from './HeroSeam'
import ScanFlow from './ScanFlow'
import './landing.css'

const REPO_URL = 'https://github.com/Subho4531/chainmark-ai'
const ISSUES_URL = `${REPO_URL}/issues/new`
const BRACKET_WORDS = ['security', 'evidence', 'privacy', 'compliance']

const SETUP_PROMPT = `Wire Chainmark into this project.

1. Point every model client at the gateway:
   OPENAI_BASE_URL=http://localhost:8000/v1
   GEMINI_BASE_URL=http://localhost:8000
   X-Chainmark-Session-Id: agent-<your-session-id>

2. Start the gateway:
   uv run python scripts/run_local.py

3. After the run, verify the sealed evidence chain:
   uv run chainmark-verify --session agent-<your-session-id>

Keep one session id for the whole agent run. Never send raw prompts or
tool output to a host outside the gateway.`

const VERIFY_LOG = [
  { text: '$ uv run chainmark-verify --session agent-7f2c', tone: 'dim' },
  { text: 'open    ledger/session-7f2c.jsonl', tone: '' },
  { text: 'chain   seq 0000..0041      continuous', tone: '' },
  { text: 'digest  sha256 per entry    match', tone: '' },
  { text: 'sig     ecdsa p-256         valid', tone: '' },
  { text: 'vault   41 tokens           0 plaintext', tone: '' },
  { text: 'result  VERIFIED  ·  exit 0', tone: 'ok' },
]

const PILLARS = [
  {
    index: '01',
    name: 'Detector',
    claim: 'Deterministic, not probabilistic.',
    points: [
      'Pattern families for cards, IBANs, emails, keys and national IDs.',
      'Verhoeff and Luhn checksums drop look-alikes before anything moves.',
      'Sliding-window session taint re-checks every later hop.',
      'Ambiguity fails closed — the call stops before the model sees it.',
    ],
    tags: ['verhoeff', 'luhn', 'session taint'],
  },
  {
    index: '02',
    name: 'Vault',
    claim: 'Reversible, never in the clear.',
    points: [
      'AES-256-GCM per value with a fresh 12-byte IV from os.urandom(12).',
      'HMAC-derived tokens stay stable inside a session, opaque outside it.',
      'Streaming detokenization restores values only in your own process.',
      'Keys never leave the vault and nothing is written to disk in plaintext.',
    ],
    tags: ['aes-256-gcm', 'hmac', 'streaming'],
  },
  {
    index: '03',
    name: 'Evidence',
    claim: 'Sealed per decision.',
    points: [
      'Strictly monotonic sequence numbers, 0 → n, with no gaps.',
      'SHA-256 chaining with a Merkle DAG digest per entry.',
      'ECDSA P-256 signatures over every sealed block.',
      'An offline verifier replays the chain: no account, no phone-home.',
    ],
    tags: ['sha-256', 'merkle dag', 'ecdsa p-256'],
  },
]

const CHECKS = [
  {
    title: 'Sequence continuity',
    body: 'Every entry is bound to the one before it, so deletions and reordering are visible.',
  },
  {
    title: 'Digest agreement',
    body: 'The sanitized payload is re-hashed and compared against the recorded digest.',
  },
  {
    title: 'Signature validity',
    body: 'Each block verifies against the session key using ECDSA P-256 over SHA-256.',
  },
]

const TIERS = [
  {
    name: 'Open source',
    price: '$0',
    suffix: 'self-hosted',
    line: 'Run the whole pipeline on your own machine or cluster.',
    features: [
      'Full detector, vault and evidence core',
      'Interceptor for the OpenAI and Gemini wire',
      'Offline verifier CLI',
      'Community support',
    ],
    cta: 'Star on GitHub',
    href: REPO_URL,
  },
  {
    name: 'Team',
    price: 'Usage based',
    suffix: 'managed',
    line: 'A hosted gateway with policy and evidence retention.',
    features: [
      'Hosted interceptor with per-workspace policy',
      'Evidence retention, export and bundles',
      'SSO and role-based access',
      'Priority support',
    ],
    cta: 'Talk to us',
    action: 'chat',
    featured: true,
  },
  {
    name: 'Enterprise',
    price: 'Custom',
    suffix: 'your perimeter',
    line: 'Deployed inside your network, on keys you control.',
    features: [
      'VPC or on-prem deployment',
      'HSM-backed vault keys',
      'Custom detectors and taint rules',
      'Audit support and SLA',
    ],
    cta: 'Talk to us',
    action: 'chat',
  },
]

const RESOURCES = [
  {
    title: 'Docs',
    body: 'Wire the gateway, run the verifier, read the threat model.',
    href: `${REPO_URL}#readme`,
    external: true,
  },
  {
    title: 'Specifications',
    body: 'Detector, vault and evidence specs, written to be implemented.',
    href: `${REPO_URL}/tree/main/docs/specs`,
    external: true,
  },
  {
    title: 'Testbench',
    body: 'Exercise detectors and inspect sealed sessions live.',
    href: '/testbench',
    external: false,
  },
  {
    title: 'GitHub',
    body: 'Source, issues and release notes.',
    href: REPO_URL,
    external: true,
  },
]

async function writeClipboard(text) {
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text)
      return true
    }
  } catch {
    // fall through to the legacy path
  }
  try {
    const area = document.createElement('textarea')
    area.value = text
    area.setAttribute('readonly', '')
    area.style.position = 'fixed'
    area.style.top = '-9999px'
    document.body.appendChild(area)
    area.select()
    const ok = document.execCommand('copy')
    document.body.removeChild(area)
    return ok
  } catch {
    return false
  }
}

function GithubMark(props) {
  return (
    <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true" {...props}>
      <path d="M12 .5C5.73.5.5 5.73.5 12c0 5.08 3.29 9.39 7.86 10.91.58.11.79-.25.79-.55v-2.1c-3.2.7-3.88-1.36-3.88-1.36-.52-1.33-1.28-1.68-1.28-1.68-1.05-.72.08-.71.08-.71 1.16.08 1.77 1.19 1.77 1.19 1.03 1.77 2.7 1.26 3.36.96.1-.75.4-1.26.73-1.55-2.55-.29-5.24-1.28-5.24-5.69 0-1.26.45-2.29 1.19-3.1-.12-.29-.52-1.46.11-3.05 0 0 .97-.31 3.18 1.18a11.1 11.1 0 0 1 5.8 0c2.2-1.49 3.17-1.18 3.17-1.18.63 1.59.23 2.76.11 3.05.74.81 1.19 1.84 1.19 3.1 0 4.42-2.69 5.39-5.25 5.68.41.36.78 1.06.78 2.14v3.17c0 .3.21.67.8.55A11.51 11.51 0 0 0 23.5 12C23.5 5.73 18.27.5 12 .5Z" />
    </svg>
  )
}

function CopyIcon(props) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" {...props}>
      <rect x="9" y="9" width="11" height="11" rx="1.5" />
      <path d="M5 15H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v1" />
    </svg>
  )
}

function CheckIcon(props) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" {...props}>
      <path d="m20 6-11 11-5-5" />
    </svg>
  )
}

function ChevronIcon(props) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" {...props}>
      <path d="m6 9 6 6 6-6" />
    </svg>
  )
}

function ArrowUpRight(props) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" {...props}>
      <path d="M7 17 17 7M8 7h9v9" />
    </svg>
  )
}

function ChatIcon(props) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" {...props}>
      <path d="M21 14.5a2 2 0 0 1-2 2H8l-4.5 3.5v-14a2 2 0 0 1 2-2h13.5a2 2 0 0 1 2 2Z" />
    </svg>
  )
}

function CloseIcon(props) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" aria-hidden="true" {...props}>
      <path d="M6 6l12 12M18 6 6 18" />
    </svg>
  )
}

function MenuIcon(props) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" aria-hidden="true" {...props}>
      <path d="M3.5 7h17M3.5 12h17M3.5 17h17" />
    </svg>
  )
}

export default function Landing() {
  const [menuOpen, setMenuOpen] = useState(false)
  const [promptOpen, setPromptOpen] = useState(false)
  const [copied, setCopied] = useState(false)
  const [chatOpen, setChatOpen] = useState(false)
  const [chatCopied, setChatCopied] = useState(false)
  const [audience, setAudience] = useState('human')
  const [wordIndex, setWordIndex] = useState(0)

  const copyTimer = useRef(0)
  const chatTimer = useRef(0)
  const promptBarRef = useRef(null)
  const chatPanelRef = useRef(null)
  const bubbleRef = useRef(null)

  useEffect(() => {
    const onKey = (event) => {
      if (event.key !== 'Escape') return
      setMenuOpen(false)
      setChatOpen(false)
    }
    const onPointerDown = (event) => {
      if (!chatOpen) return
      const panel = chatPanelRef.current
      const bubble = bubbleRef.current
      if (panel && panel.contains(event.target)) return
      if (bubble && bubble.contains(event.target)) return
      setChatOpen(false)
    }
    document.addEventListener('keydown', onKey)
    document.addEventListener('pointerdown', onPointerDown)
    return () => {
      document.removeEventListener('keydown', onKey)
      document.removeEventListener('pointerdown', onPointerDown)
      window.clearTimeout(copyTimer.current)
      window.clearTimeout(chatTimer.current)
    }
  }, [chatOpen])

  // Section reveals: motion only, content is visible without JS.
  useEffect(() => {
    if (typeof IntersectionObserver === 'undefined') return
    const nodes = Array.from(document.querySelectorAll('.landing [data-reveal]'))
    if (!nodes.length) return
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (!entry.isIntersecting) return
          entry.target.classList.add('is-in')
          observer.unobserve(entry.target)
        })
      },
      { rootMargin: '0px 0px -10% 0px', threshold: 0.1 },
    )
    nodes.forEach((node) => observer.observe(node))
    return () => observer.disconnect()
  }, [])

  // The bracketed word cycles; static (first word) when motion is reduced.
  useEffect(() => {
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return
    const id = window.setInterval(() => {
      setWordIndex((index) => (index + 1) % BRACKET_WORDS.length)
    }, 3600)
    return () => window.clearInterval(id)
  }, [])

  const copyPrompt = useCallback(async () => {
    await writeClipboard(SETUP_PROMPT)
    setCopied(true)
    window.clearTimeout(copyTimer.current)
    copyTimer.current = window.setTimeout(() => setCopied(false), 2200)
  }, [])

  const copyPromptFromChat = useCallback(async () => {
    await writeClipboard(SETUP_PROMPT)
    setChatCopied(true)
    window.clearTimeout(chatTimer.current)
    chatTimer.current = window.setTimeout(() => setChatCopied(false), 2200)
  }, [])

  const startBuilding = useCallback(() => {
    setPromptOpen(true)
    window.requestAnimationFrame(() => {
      promptBarRef.current?.scrollIntoView({ block: 'nearest' })
      promptBarRef.current?.querySelector('.prompt-main')?.focus({ preventScroll: true })
    })
  }, [])

  const openChat = useCallback(() => {
    setChatOpen((open) => !open)
  }, [])

  return (
    <div className="landing" id="top">
      <header className={`landing-header ${menuOpen ? 'menu-open' : ''}`}>
        <a className="brand" href="#top" aria-label="Chainmark AI home">
          <span className="brand-badge">
            <img
              className="brand-mark"
              src="/logo/mark-32.png"
              srcSet="/logo/mark-27.png 27w, /logo/mark-32.png 32w, /logo/mark-54.png 54w, /logo/mark-64.png 64w"
              sizes="(max-width: 900px) 27px, 32px"
              alt=""
              width="32"
              height="32"
              decoding="async"
            />
          </span>
          <span className="brand-word">
            <span className="brand-name">CHAINMARK</span>
            <span className="brand-ai">AI</span>
          </span>
        </a>

        <nav className="nav-links" aria-label="Primary">
          <a href="#architecture">Architecture</a>
          <a href="#evals">Evals</a>
          <a href="#pricing">Pricing</a>
          <a className="nav-resources" href="#resources">
            Resources
            <ChevronIcon className="nav-chevron" />
          </a>
          <a className="nav-docs" href={`${REPO_URL}#readme`} target="_blank" rel="noreferrer">
            Docs
            <ArrowUpRight className="nav-arrow" />
          </a>
        </nav>

        <div className="nav-actions">
          <a
            className="nav-github"
            href={REPO_URL}
            target="_blank"
            rel="noreferrer"
            aria-label="Chainmark AI on GitHub"
          >
            <GithubMark className="nav-github-icon" />
          </a>
          <a className="login" href="/dashboard">Log in</a>
          <a className="signup" href="/dashboard">Sign up</a>
          <button
            type="button"
            className="menu-button"
            aria-label={menuOpen ? 'Close menu' : 'Open menu'}
            aria-expanded={menuOpen}
            aria-controls="mobile-menu"
            onClick={() => setMenuOpen((open) => !open)}
          >
            {menuOpen ? <CloseIcon /> : <MenuIcon />}
          </button>
        </div>

        <div id="mobile-menu" className={`mobile-menu ${menuOpen ? 'open' : ''}`} inert={menuOpen ? undefined : true}>
          <div className="mobile-menu-inner">
            <a href="#architecture" onClick={() => setMenuOpen(false)}>
              <span>Architecture</span>
              <span className="mobile-index">01</span>
            </a>
            <a href="#evals" onClick={() => setMenuOpen(false)}>
              <span>Evals</span>
              <span className="mobile-index">02</span>
            </a>
            <a href="#pricing" onClick={() => setMenuOpen(false)}>
              <span>Pricing</span>
              <span className="mobile-index">03</span>
            </a>
            <a href="#resources" onClick={() => setMenuOpen(false)}>
              <span>Resources</span>
              <span className="mobile-index">04</span>
            </a>
            <a href={`${REPO_URL}#readme`} target="_blank" rel="noreferrer" onClick={() => setMenuOpen(false)}>
              <span>Docs</span>
              <ArrowUpRight className="mobile-arrow" />
            </a>
            <div className="mobile-menu-foot">
              <a className="login" href="/dashboard">Log in</a>
              <a className="signup" href="/dashboard">Sign up</a>
            </div>
          </div>
        </div>
      </header>

      <main>
        <section className="hero" aria-labelledby="hero-title">
          <div className="shell">
            <div className="hero-copy">
              <p className="eyebrow">Security infrastructure · agent egress</p>
              <h1 id="hero-title" className="hero-title" aria-label="Security infrastructure for AI agents">
                <span className="line line-one" aria-hidden="true">
                  <span className="swap" key={BRACKET_WORDS[wordIndex]}>
                    <span className="bracket bracket-open" />
                    <span className="slot">
                      {BRACKET_WORDS.map((word) => (
                        <span className="slot-word" key={word}>
                          {word}
                        </span>
                      ))}
                      <span className="slot-live accent">{BRACKET_WORDS[wordIndex]}</span>
                    </span>
                    <span className="bracket bracket-close" />
                  </span>
                  <span className="rest">infrastructure</span>
                </span>
                <span className="line line-two" aria-hidden="true">
                  for AI agents
                </span>
              </h1>

              <p className="hero-lede">
                Chainmark sits between your agents and every foundation model. It intercepts
                egress, swaps sensitive values for reversible tokens, and seals each decision
                into a signed evidence chain you can verify offline.
              </p>

              <div className="hero-actions">
                <div className="cta-row">
                  <button type="button" className="btn btn-primary" onClick={startBuilding}>
                    Start building
                  </button>
                  <button type="button" className="btn btn-light" onClick={openChat}>
                    Talk to us
                  </button>
                </div>

                <div className="prompt" ref={promptBarRef}>
                  <div className={`prompt-bar ${promptOpen ? 'is-open' : ''}`}>
                    <button
                      type="button"
                      className="prompt-main"
                      onClick={copyPrompt}
                      aria-label="Copy setup prompt for your agent"
                    >
                      {copied ? (
                        <span className="prompt-text">
                          <strong>Copied</strong>
                          <span>to clipboard</span>
                        </span>
                      ) : (
                        <span className="prompt-text">
                          <strong>Copy setup prompt</strong>
                          <span>for your agent</span>
                        </span>
                      )}
                      <span className="prompt-copy-icon" aria-hidden="true">
                        {copied ? <CheckIcon /> : <CopyIcon />}
                      </span>
                    </button>
                    <span className="prompt-divider" aria-hidden="true" />
                    <button
                      type="button"
                      className="prompt-toggle"
                      aria-expanded={promptOpen}
                      aria-controls="setup-panel"
                      onClick={() => setPromptOpen((open) => !open)}
                    >
                      <span className="sr-only">{promptOpen ? 'Hide setup prompt' : 'Show setup prompt'}</span>
                      <ChevronIcon className="prompt-chevron" />
                    </button>
                  </div>

                  <div id="setup-panel" className={`prompt-panel ${promptOpen ? 'open' : ''}`}>
                    <div className="prompt-panel-clip">
                      <div className="prompt-panel-body">
                        <div className="prompt-panel-head">
                          <span className="panel-label">agent setup</span>
                          <span className="panel-meta">localhost:8000</span>
                        </div>
                        <pre>
                          <code>{SETUP_PROMPT}</code>
                        </pre>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div className="hero-aside">
              <HeroSeam />
            </div>

          </div>
        </section>

        <section id="request-path" className="section" aria-labelledby="path-title">
          <div className="shell">
            <div className="section-head" data-reveal>
              <div className="section-head-main">
                <p className="eyebrow">01 — Request path</p>
                <h2 id="path-title" className="section-title">
                  Every call leaves through Chainmark.
                </h2>
              </div>
              <p className="section-lede">
                Your agent keeps its SDK. Requests to <code>/v1/chat/completions</code> and
                <code>:generateContent</code> are routed through the interceptor, scanned,
                tokenized and chained — so the model only ever reads tokens, and your data stays
                behind the seam.
              </p>
            </div>

            <div className="flow-card" data-reveal>
              <FlowField />
            </div>

            <ul className="flow-legend" data-reveal>
              <li className="chip"><b>01</b> Agent SDK · unchanged</li>
              <li className="chip"><b>02</b> Interrupt · ASGI proxy</li>
              <li className="chip"><b>03</b> Detect · checksum + taint</li>
              <li className="chip"><b>04</b> Vault · HMAC tokens</li>
              <li className="chip"><b>05</b> Evidence · hash chain</li>
            </ul>

            <p className="flow-note">
              Session taint: once a value is classified, every later hop in the same session is
              re-checked before it leaves.
            </p>
          </div>
        </section>

        <section className="trusted" aria-label="Trusted by teams and agents">
          <p className="trusted-title" aria-live="polite">
            <span key={audience} className="trusted-swap">
              {audience === 'human'
                ? 'Trusted by teams building world-class agents'
                : 'Trusted by agents running world-class operations'}
            </span>
          </p>
          <div className="trusted-switch" role="group" aria-label="Audience">
            <span className={`switch-thumb ${audience}`} aria-hidden="true" />
            <button
              type="button"
              className={audience === 'human' ? 'is-active' : ''}
              aria-pressed={audience === 'human'}
              onClick={() => setAudience('human')}
            >
              Human
            </button>
            <button
              type="button"
              className={audience === 'ai' ? 'is-active' : ''}
              aria-pressed={audience === 'ai'}
              onClick={() => setAudience('ai')}
            >
              AI
            </button>
          </div>
        </section>

        <section id="execution" className="section" aria-labelledby="scan-title">
          <div className="shell">
            <div className="section-head" data-reveal>
              <div className="section-head-main">
                <p className="eyebrow">02 — Execution</p>
                <h2 id="scan-title" className="section-title">
                  Scan. Tokenize. Seal. Restore.
                </h2>
              </div>
              <p className="section-lede">
                One request, end to end. Detectors read the outbound payload, checksum-verified
                matches become opaque tokens, and the response is detokenized only inside your own
                process — with a hash-chained receipt for every step.
              </p>
            </div>

            <div data-reveal>
              <ScanFlow />
            </div>
          </div>
        </section>

        <section id="architecture" className="section" aria-labelledby="arch-title">
          <div className="shell">
            <div className="section-head" data-reveal>
              <div className="section-head-main">
                <p className="eyebrow">03 — Architecture</p>
                <h2 id="arch-title" className="section-title">
                  Three components, one seam.
                </h2>
              </div>
              <p className="section-lede">
                Detection, reversible tokenization and evidence live in separate modules with one
                contract between them. Each is small enough to audit, and each fails loudly rather
                than silently.
              </p>
            </div>

            <div className="pillars" data-reveal>
              {PILLARS.map((pillar) => (
                <article className="pillar" key={pillar.name}>
                  <div className="pillar-head">
                    <span className="pillar-index">{pillar.index}</span>
                    <h3>{pillar.name}</h3>
                  </div>
                  <p className="pillar-line">{pillar.claim}</p>
                  <ul className="pillar-list">
                    {pillar.points.map((point) => (
                      <li key={point}>{point}</li>
                    ))}
                  </ul>
                  <p className="pillar-tags">
                    {pillar.tags.map((tag) => (
                      <span key={tag}>{tag}</span>
                    ))}
                  </p>
                </article>
              ))}
            </div>
          </div>
        </section>

        <section id="evals" className="section" aria-labelledby="evals-title">
          <div className="shell">
            <div className="section-head" data-reveal>
              <div className="section-head-main">
                <p className="eyebrow">04 — Evals &amp; verification</p>
                <h2 id="evals-title" className="section-title">
                  Proof you can run yourself.
                </h2>
              </div>
              <p className="section-lede">
                Chainmark is judged on what the verifier can prove offline: no plaintext egress, no
                sequence gaps, no signature drift. The checks are deterministic, so the same
                session always returns the same answer.
              </p>
            </div>

            <div className="verify" data-reveal>
              <div className="verify-list">
                <h3 className="verify-h">What the verifier proves</h3>
                <ul className="checklist">
                  {CHECKS.map((check) => (
                    <li key={check.title}>
                      <b>{check.title}</b>
                      <span>{check.body}</span>
                    </li>
                  ))}
                </ul>
                <p className="verify-note">
                  No account, no network call, no trust in us required.
                </p>
              </div>

              <div className="verify-term">
                <div className="term-head">
                  <span>chainmark-verify</span>
                  <span>offline · local</span>
                </div>
                <pre>
                  {VERIFY_LOG.map((line) => (
                    <span key={line.text} className={`term-line ${line.tone}`}>
                      {line.text}
                      {'\n'}
                    </span>
                  ))}
                </pre>
              </div>
            </div>
          </div>
        </section>

        <section id="pricing" className="section" aria-labelledby="pricing-title">
          <div className="shell">
            <div className="section-head" data-reveal>
              <div className="section-head-main">
                <p className="eyebrow">05 — Pricing</p>
                <h2 id="pricing-title" className="section-title">
                  Start free, scale inward.
                </h2>
              </div>
              <p className="section-lede">
                The core is open source and stays that way. Hosted and in-perimeter deployments add
                policy, retention and key management for teams that need them.
              </p>
            </div>

            <div className="tiers" data-reveal>
              {TIERS.map((tier) => (
                <article className={`tier ${tier.featured ? 'is-featured' : ''}`} key={tier.name}>
                  <p className="tier-name">{tier.name}</p>
                  <p className="tier-price">
                    {tier.price}
                    <span>{tier.suffix}</span>
                  </p>
                  <p className="tier-line">{tier.line}</p>
                  <ul className="tier-list">
                    {tier.features.map((feature) => (
                      <li key={feature}>{feature}</li>
                    ))}
                  </ul>
                  {tier.action === 'chat' ? (
                    <button type="button" className="btn btn-ghost" onClick={openChat}>
                      {tier.cta}
                    </button>
                  ) : (
                    <a className="btn btn-ghost" href={tier.href} target="_blank" rel="noreferrer">
                      {tier.cta}
                    </a>
                  )}
                </article>
              ))}
            </div>
          </div>
        </section>

        <section id="resources" className="section" aria-labelledby="resources-title">
          <div className="shell">
            <div className="section-head" data-reveal>
              <div className="section-head-main">
                <p className="eyebrow">06 — Resources</p>
                <h2 id="resources-title" className="section-title">
                  Read it, run it, verify it.
                </h2>
              </div>
              <p className="section-lede">
                Everything needed to wire the gateway and check the evidence is in the repository.
                Specifications are written to be implemented, not admired.
              </p>
            </div>

            <div className="resource-grid" data-reveal>
              {RESOURCES.map((item) => (
                <a
                  className="resource"
                  key={item.title}
                  href={item.href}
                  target={item.external ? '_blank' : undefined}
                  rel={item.external ? 'noreferrer' : undefined}
                >
                  <span className="resource-top">
                    <span className="resource-title">{item.title}</span>
                    <ArrowUpRight />
                  </span>
                  <p>{item.body}</p>
                </a>
              ))}
            </div>
          </div>
        </section>

        <section className="cta-band" aria-labelledby="cta-title">
          <div className="shell">
            <div className="cta-inner" data-reveal>
              <div>
                <p className="eyebrow">Get started</p>
                <h2 id="cta-title" className="cta-title">
                  Put a seam between your agents and the models.
                </h2>
                <p className="cta-sub">
                  Self-host the gateway in minutes. No SDK on the client, no plaintext on the wire.
                </p>
              </div>
              <div className="cta-actions">
                <button type="button" className="btn btn-primary" onClick={startBuilding}>
                  Start building
                </button>
                <button type="button" className="btn btn-ghost" onClick={openChat}>
                  Talk to us
                </button>
              </div>
            </div>
          </div>
        </section>
      </main>

      <footer className="site-foot">
        <div className="shell foot-inner">
          <div className="foot-brand">
            <a className="brand" href="#top" aria-label="Chainmark AI home">
              <img
                className="brand-mark"
                src="/logo/mark-30.png"
                srcSet="/logo/mark-28.png 28w, /logo/mark-30.png 30w, /logo/mark-56.png 56w, /logo/mark-60.png 60w"
                sizes="(max-width: 900px) 28px, 30px"
                alt=""
                width="30"
                height="30"
                loading="lazy"
              />
              <span className="brand-word">CHAINMARK AI</span>
            </a>
            <p>Security infrastructure for autonomous AI agents.</p>
          </div>

          <nav className="foot-col" aria-label="Product">
            <h4>Product</h4>
            <a href="#request-path">Request path</a>
            <a href="#architecture">Architecture</a>
            <a href="#evals">Evals</a>
            <a href="#pricing">Pricing</a>
          </nav>

          <nav className="foot-col" aria-label="Resources">
            <h4>Resources</h4>
            <a href={`${REPO_URL}#readme`} target="_blank" rel="noreferrer">Docs</a>
            <a href={`${REPO_URL}/tree/main/docs/specs`} target="_blank" rel="noreferrer">Specifications</a>
            <a href="/testbench">Testbench</a>
            <a href={REPO_URL} target="_blank" rel="noreferrer">GitHub</a>
          </nav>

          <div className="foot-col">
            <h4>Contact</h4>
            <a href={ISSUES_URL} target="_blank" rel="noreferrer">Open an issue</a>
            <button type="button" className="foot-link" onClick={openChat}>
              Talk to us
            </button>
          </div>
        </div>

        <div className="shell foot-meta">
          <span>© 2026 Chainmark AI</span>
          <span>Evidence you can verify offline.</span>
        </div>
      </footer>

      <div className={`chat-panel ${chatOpen ? 'open' : ''}`} role="dialog" aria-modal="false" aria-label="Talk to Chainmark" ref={chatPanelRef} inert={chatOpen ? undefined : true}>
        <div className="chat-head">
          <span className="chat-eyebrow">chainmark support</span>
          <button type="button" className="chat-close" aria-label="Close conversation" onClick={() => setChatOpen(false)}>
            <CloseIcon />
          </button>
        </div>
        <p className="chat-title">Talk to us</p>
        <p className="chat-body">
          Tell us what your agents touch. We will map the data path and show you the evidence trail behind every call.
        </p>
        <a className="chat-primary" href={ISSUES_URL} target="_blank" rel="noreferrer">
          Open a GitHub issue
          <ArrowUpRight />
        </a>
        <button type="button" className="chat-secondary" onClick={copyPromptFromChat}>
          {chatCopied ? 'Copied to clipboard' : 'Copy setup prompt'}
          {chatCopied ? <CheckIcon /> : <CopyIcon />}
        </button>
        <p className="chat-foot">Evidence you can verify offline.</p>
      </div>

      <button
        type="button"
        className={`chat-bubble ${chatOpen ? 'is-open' : ''}`}
        aria-label={chatOpen ? 'Close support panel' : 'Talk to us'}
        aria-expanded={chatOpen}
        onClick={openChat}
        ref={bubbleRef}
      >
        <span className="chat-bubble-icon">{chatOpen ? <CloseIcon /> : <ChatIcon />}</span>
      </button>
    </div>
  )
}
