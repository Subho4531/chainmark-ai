import { markSrc, markSrcSet } from './logo'

const STAGES = [
  { n: '01', title: 'Prompt', note: 'agent egress' },
  { n: '02', title: 'Scan', note: 'detector + checksum' },
  { n: '03', title: 'Tokenize', note: 'hmac vault' },
  { n: '04', title: 'Model', note: 'tokens only' },
  { n: '05', title: 'Seal', note: 'hash chain' },
]

/**
 * A single request, animated end to end. Decorative motion only: the same
 * information is readable in the copy around it, so nothing depends on the
 * animation to make sense.
 */
export default function ScanFlow() {
  return (
    <div className="scan">
      <div className="scan-grid">
        <article className="scan-card">
          <header className="scan-card-head">
            <span className="scan-card-title">agent · outbound</span>
            <span className="scan-card-meta">raw</span>
          </header>
          <div className="scan-body">
            <p className="scan-line">
              <span className="scan-key">to</span>
              <mark className="scan-hit">billing@acme-corp.com</mark>
            </p>
            <p className="scan-line">
              <span className="scan-key">card</span>
              <mark className="scan-hit">4242 4242 4242 4242</mark>
            </p>
            <p className="scan-line">
              <span className="scan-key">remit</span>
              <mark className="scan-hit">DE89 3704 0044 0532 0130 00</mark>
            </p>
            <p className="scan-line">
              <span className="scan-key">task</span>
              <span className="scan-plain">summarise the invoice and reply</span>
            </p>
            <span className="scan-sweep" aria-hidden="true" />
          </div>
          <footer className="scan-card-foot">3 matches · 1 line passed clean</footer>
        </article>

        <div className="scan-hub">
          <span className="scan-hub-label">outbound</span>
          <div className="scan-hub-node">
            <img
              src={markSrc(38)}
              srcSet={markSrcSet(24, 38)}
              sizes="(max-width: 900px) 24px, 38px"
              alt=""
              width="38"
              height="38"
              decoding="async"
            />
          </div>
          <span className="scan-hub-word">CHAINMARK</span>
          <span className="scan-hub-sub">detect → tokenize → seal</span>
          <span className="scan-hub-label is-back">inbound · detokenize</span>
        </div>

        <article className="scan-card is-after">
          <header className="scan-card-head">
            <span className="scan-card-title">model · inbound</span>
            <span className="scan-card-meta">sealed</span>
          </header>
          <div className="scan-body">
            <p className="scan-line">
              <span className="scan-key">to</span>
              <span className="scan-token">cm_mail_7f2a</span>
            </p>
            <p className="scan-line">
              <span className="scan-key">card</span>
              <span className="scan-token">cm_pan_91c4</span>
            </p>
            <p className="scan-line">
              <span className="scan-key">remit</span>
              <span className="scan-token">cm_iban_3d88</span>
            </p>
            <p className="scan-line">
              <span className="scan-key">task</span>
              <span className="scan-plain">summarise the invoice and reply</span>
            </p>
          </div>
          <footer className="scan-card-foot">0 plaintext leaves the perimeter</footer>
        </article>
      </div>

      <ol className="scan-rail">
        {STAGES.map((stage) => (
          <li key={stage.n}>
            <span className="scan-stage-n">{stage.n}</span>
            <span className="scan-stage-t">{stage.title}</span>
            <span className="scan-stage-d">{stage.note}</span>
          </li>
        ))}
      </ol>
    </div>
  )
}
