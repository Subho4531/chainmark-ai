const OUT = ['-0.2s', '-2s', '-3.8s', '-5.6s']
const BACK = ['-1s', '-3.4s', '-5.8s']

/**
 * Hero graphic: the seam Chainmark sits on, between the agent and the model.
 *
 * Payloads leave the agent as outlined rectangles, reach the top edge of the
 * seam and vanish into it; tokens fade out of the bottom edge and land on the
 * model. Replies run the same path in reverse and come back restored. The lanes
 * break at the band on purpose, so nothing ever crosses the labels.
 *
 * Decorative only: the copy beside it carries the meaning.
 */
export default function HeroSeam() {
  return (
    <div className="seam">
      <svg
        className="seam-svg"
        viewBox="0 0 520 700"
        fill="none"
        preserveAspectRatio="xMidYMid meet"
        aria-hidden="true"
        focusable="false"
      >
        <defs>
          <linearGradient id="hs-sweep" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#ff571a" stopOpacity="0" />
            <stop offset="50%" stopColor="#ff571a" stopOpacity="0.7" />
            <stop offset="100%" stopColor="#ff571a" stopOpacity="0" />
          </linearGradient>
        </defs>

        {/* Agent ------------------------------------------------------------ */}
        <rect className="seam-card" x="104" y="32" width="312" height="96" rx="3" />
        <circle className="seam-node" cx="132" cy="62" r="3.5" />
        <text className="seam-name" x="148" y="67">
          AGENT
        </text>
        <text className="seam-sub" x="132" y="96">
          runtime · outbound payload
        </text>
        <g className="seam-bars">
          <rect x="132" y="108" width="52" height="3" rx="1.5" />
          <rect x="190" y="108" width="28" height="3" rx="1.5" />
          <rect x="224" y="108" width="40" height="3" rx="1.5" />
        </g>

        {/* Rails, broken at the seam ---------------------------------------- */}
        <path className="seam-rail" d="M196 128v164" />
        <path className="seam-rail" d="M196 404v168" />
        <path className="seam-rail is-return" d="M324 572v-168" />
        <path className="seam-rail is-return" d="M324 292v-164" />
        <path className="seam-arrow" d="M190 566l6 9 6-9" />
        <path className="seam-arrow" d="M318 134l6-9 6 9" />

        <text className="seam-lane" x="212" y="196">
          RAW
        </text>
        <text className="seam-lane" x="212" y="512">
          TOKENS
        </text>
        <text className="seam-lane is-end" x="308" y="196">
          RAW
        </text>
        <text className="seam-lane is-end" x="308" y="512">
          TOKENS
        </text>

        {/* The seam ---------------------------------------------------------- */}
        <rect className="seam-band" x="28" y="292" width="464" height="112" rx="3" />
        <rect className="seam-sweep" x="28" y="294" width="464" height="2" fill="url(#hs-sweep)" />

        <text className="seam-tag" x="48" y="316">
          SECURE SEAM
        </text>
        <text className="seam-tag is-end" x="472" y="316">
          ECDSA P-256
        </text>
        <image href="/logo/mark-96.png" x="44" y="326" width="30" height="30" />
        <text className="seam-brand" x="84" y="347">
          CHAINMARK
        </text>
        <text className="seam-sub" x="84" y="365">
          detect → tokenize → seal
        </text>
        <g className="seam-stages">
          <text x="300" y="338">
            <tspan className="seam-stage-n">01</tspan> detect
          </text>
          <text x="300" y="358">
            <tspan className="seam-stage-n">02</tspan> tokenize
          </text>
          <text x="300" y="378">
            <tspan className="seam-stage-n">03</tspan> seal
          </text>
        </g>

        {/* Ports either side of the seam -------------------------------------- */}
        <circle className="seam-port" cx="196" cy="292" r="2.4" />
        <circle className="seam-port" cx="196" cy="404" r="2.4" />
        <circle className="seam-port is-return" cx="324" cy="292" r="2.4" />
        <circle className="seam-port is-return" cx="324" cy="404" r="2.4" />

        {/* Foundation model -------------------------------------------------- */}
        <rect className="seam-card" x="104" y="572" width="312" height="96" rx="3" />
        <circle className="seam-node is-hollow" cx="132" cy="602" r="3.5" />
        <text className="seam-name" x="148" y="607">
          FOUNDATION MODEL
        </text>
        <text className="seam-sub" x="132" y="636">
          reads tokens · never plaintext
        </text>
        <g className="seam-bars">
          <rect x="132" y="648" width="34" height="3" rx="1.5" />
          <rect x="172" y="648" width="18" height="3" rx="1.5" />
        </g>

        {/* Outbound: outlined while raw, filled once it clears the seam. */}
        {OUT.map((delay) => (
          <g key={`out-${delay}`}>
            <rect
              className="seam-pkt seam-down-raw"
              x="182"
              y="140"
              width="28"
              height="13"
              rx="2"
              style={{ animationDelay: delay }}
            />
            <rect
              className="seam-pkt seam-down-tok"
              x="186"
              y="142"
              width="20"
              height="9"
              rx="1.5"
              style={{ animationDelay: delay }}
            />
          </g>
        ))}

        {/* Replies: tokens on the way down, restored on the way back up. */}
        {BACK.map((delay) => (
          <g key={`back-${delay}`}>
            <rect
              className="seam-pkt seam-up-tok"
              x="314"
              y="556"
              width="20"
              height="9"
              rx="1.5"
              style={{ animationDelay: delay }}
            />
            <rect
              className="seam-pkt seam-up-raw"
              x="310"
              y="554"
              width="28"
              height="13"
              rx="2"
              style={{ animationDelay: delay }}
            />
          </g>
        ))}
      </svg>

      <p className="seam-cap">every hop crosses the seam</p>
    </div>
  )
}
