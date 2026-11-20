const ORANGE = '#ff571a'

const NODES = [
  { id: 'llm', x: 46, y: 230, r: 28, label: 'LLM', icon: 'globe' },
  { id: 'chainmark', x: 212, y: 230, r: 40, label: 'CHAINMARK', brand: true },
  { id: 'agent', x: 378, y: 230, r: 28, label: 'Agent', icon: 'robot' },
  { id: 'user1', x: 700, y: 60, r: 28, label: 'User 1', icon: 'user' },
  { id: 'user2', x: 700, y: 160, r: 28, label: 'User 2', icon: 'user' },
  { id: 'table', x: 700, y: 260, r: 28, label: 'User Dataverse Table', icon: 'database' },
  { id: 'topic1', x: 700, y: 360, r: 28, label: 'Agent Topic', icon: 'topic' },
  { id: 'topic2', x: 700, y: 460, r: 28, label: 'Agent Topic', icon: 'topic' },
  { id: 'action', x: 700, y: 560, r: 28, label: 'Agent Action', icon: 'action' },
  { id: 'flow', x: 1010, y: 260, r: 28, label: 'Flow', icon: 'flow' },
  { id: 'topic3', x: 1010, y: 460, r: 28, label: 'Agent Topic', icon: 'topic' },
  { id: 'user3', x: 1010, y: 590, r: 28, label: 'User 3', icon: 'user' },
  { id: 'connector', x: 1010, y: 675, r: 28, label: 'Connector', icon: 'connector' },
  { id: 'connection', x: 1010, y: 770, r: 28, label: 'Connection', icon: 'connection' },
]

const EDGES = [
  {
    id: 'via',
    d: 'M 74 230 L 172 230',
    delay: 0,
    duration: 4.4,
    label: { text: 'via', x: 123, y: 217, rotate: 0 },
  },
  {
    id: 'by',
    d: 'M 252 230 L 350 230',
    delay: 1.5,
    duration: 4.2,
    label: { text: 'by', x: 301, y: 217, rotate: 0 },
  },
  {
    id: 'created',
    d: 'M 406 230 C 500 230, 500 60, 672 60',
    delay: 0.6,
    duration: 5.6,
    label: { text: 'created by, owned by', x: 512, y: 101, rotate: -47 },
  },
  {
    id: 'editable',
    d: 'M 406 230 C 510 230, 510 160, 672 160',
    delay: 2.2,
    duration: 4.8,
    label: { text: 'editable by', x: 528, y: 165, rotate: -24 },
  },
  {
    id: 'stores',
    d: 'M 406 230 C 515 230, 525 260, 672 260',
    delay: 3.1,
    duration: 5.1,
    label: { text: 'stores to', x: 551, y: 229, rotate: 11 },
  },
  {
    id: 'contains-a',
    d: 'M 406 230 C 515 230, 525 360, 672 360',
    delay: 1.1,
    duration: 5.4,
    label: { text: 'contains', x: 560, y: 297, rotate: 40 },
  },
  {
    id: 'contains-b',
    d: 'M 406 230 C 515 230, 525 460, 672 460',
    delay: 3.6,
    duration: 5.9,
    label: { text: 'contains', x: 563, y: 366, rotate: 56 },
  },
  {
    id: 'contains-c',
    d: 'M 406 230 C 515 230, 525 560, 672 560',
    delay: 0.2,
    duration: 6.2,
    label: { text: 'contains', x: 564, y: 433, rotate: 65 },
  },
  {
    id: 'used-by',
    d: 'M 728 260 L 982 260',
    delay: 2.7,
    duration: 4.6,
    label: { text: 'used by', x: 855, y: 247, rotate: 0 },
  },
  {
    id: 'uses-topic',
    d: 'M 728 460 L 982 460',
    delay: 0.9,
    duration: 4.9,
    label: { text: 'uses, used by', x: 855, y: 447, rotate: 0 },
  },
  {
    id: 'last-modified',
    d: 'M 728 560 C 790 560, 810 590, 982 590',
    delay: 4.1,
    duration: 5.2,
    label: { text: 'last modified by', x: 839, y: 562, rotate: 10 },
  },
  {
    id: 'uses-connector',
    d: 'M 728 560 C 790 560, 810 675, 982 675',
    delay: 2.4,
    duration: 5.5,
    label: { text: 'uses', x: 846, y: 620, rotate: 34 },
  },
  {
    id: 'uses-connection',
    d: 'M 728 560 C 790 560, 810 760, 982 760',
    delay: 3.4,
    duration: 6,
    label: { text: 'uses', x: 850, y: 678, rotate: 50 },
  },
]

function Icon({ name }) {
  switch (name) {
    case 'globe':
      return (
        <>
          <circle cx="12" cy="12" r="8.2" />
          <ellipse cx="12" cy="12" rx="3.6" ry="8.2" />
          <path d="M3.8 12h16.4" />
        </>
      )
    case 'robot':
      return (
        <>
          <rect x="4.8" y="8.2" width="14.4" height="11" rx="3.1" />
          <path d="M12 8.2V5.6" />
          <circle cx="12" cy="4.5" r="1.1" />
          <circle cx="9.4" cy="13.4" r="1.15" className="flow-icon-dot" />
          <circle cx="14.6" cy="13.4" r="1.15" className="flow-icon-dot" />
        </>
      )
    case 'user':
      return (
        <>
          <circle cx="12" cy="8.6" r="3.3" />
          <path d="M5.5 19.3c.6-3.4 3.1-5.4 6.5-5.4s5.9 2 6.5 5.4" />
        </>
      )
    case 'database':
      return (
        <>
          <ellipse cx="12" cy="6.6" rx="6.2" ry="2.6" />
          <path d="M5.8 6.6v10.8c0 1.4 2.8 2.6 6.2 2.6s6.2-1.2 6.2-2.6V6.6" />
          <path d="M5.8 12c0 1.4 2.8 2.6 6.2 2.6s6.2-1.2 6.2-2.6" />
        </>
      )
    case 'topic':
      return (
        <>
          <circle cx="12" cy="6.4" r="1.7" />
          <circle cx="6.8" cy="16.4" r="1.7" />
          <circle cx="17.2" cy="16.4" r="1.7" />
          <path d="M10.8 8.1 7.9 14.7M13.2 8.1l2.9 6.6M8.5 16.4h7" opacity=".45" />
        </>
      )
    case 'action':
      return (
        <>
          <circle cx="8" cy="8" r="1.6" className="flow-icon-dot" />
          <circle cx="16" cy="8" r="1.6" className="flow-icon-dot" />
          <circle cx="8" cy="16" r="1.6" className="flow-icon-dot" />
          <circle cx="16" cy="16" r="1.6" className="flow-icon-dot" />
        </>
      )
    case 'flow':
      return (
        <>
          <circle cx="9.2" cy="14.8" r="3.9" />
          <circle cx="14.8" cy="9.2" r="3.9" />
        </>
      )
    case 'connector':
      return (
        <>
          <path d="M9.4 14.6 14.6 9.4" />
          <path d="M8.5 12.7 6.9 14.3a3.1 3.1 0 0 0 4.4 4.4l1.6-1.6" />
          <path d="M15.5 11.3l1.6-1.6a3.1 3.1 0 0 0-4.4-4.4l-1.6 1.6" />
        </>
      )
    case 'connection':
      return (
        <>
          <circle cx="9" cy="15" r="3.2" />
          <circle cx="15" cy="9" r="3.2" />
          <path d="M11.2 12.8 12.8 11.2" />
        </>
      )
    default:
      return null
  }
}

export default function FlowField() {
  return (
    <svg
      className="flow-svg"
      viewBox="0 0 1120 850"
      preserveAspectRatio="xMidYMid meet"
      aria-hidden="true"
      focusable="false"
    >
      <defs>
        <radialGradient id="flow-node-fill" cx="50%" cy="42%" r="65%">
          <stop offset="0%" stopColor="#1a1a1a" />
          <stop offset="100%" stopColor="#060606" />
        </radialGradient>
        <radialGradient id="flow-cm-halo" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor={ORANGE} stopOpacity="0.3" />
          <stop offset="45%" stopColor={ORANGE} stopOpacity="0.1" />
          <stop offset="100%" stopColor={ORANGE} stopOpacity="0" />
        </radialGradient>
        <linearGradient id="flow-edge-warm" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0%" stopColor={ORANGE} stopOpacity="0.6" />
          <stop offset="38%" stopColor={ORANGE} stopOpacity="0" />
        </linearGradient>
      </defs>

      <g className="flow-edge-layer">
        {EDGES.map((edge) => (
          <g key={edge.id}>
            <path className="flow-edge" d={edge.d} />
            <path className="flow-edge-warm" d={edge.d} />
          </g>
        ))}
      </g>

      <g className="flow-pulse-layer">
        {EDGES.map((edge) => (
          <g
            key={edge.id}
            className="flow-pulse-run"
            style={{ '--flow-delay': `${edge.delay}s`, '--flow-duration': `${edge.duration}s` }}
          >
            <path className="flow-pulse-halo" d={edge.d} pathLength="100" />
            <path className="flow-pulse" d={edge.d} pathLength="100" />
          </g>
        ))}
      </g>

      <g className="flow-edge-labels">
        {EDGES.map((edge) => (
          <text
            key={edge.id}
            className="flow-edge-label"
            transform={`translate(${edge.label.x} ${edge.label.y}) rotate(${edge.label.rotate})`}
            textAnchor="middle"
          >
            {edge.label.text}
          </text>
        ))}
      </g>

      <g className="flow-node-layer">
        {NODES.map((node) => (
          <g key={node.id} transform={`translate(${node.x} ${node.y})`} className={node.brand ? 'flow-node is-brand' : 'flow-node'}>
            {node.brand && <circle className="flow-cm-halo" r="76" fill="url(#flow-cm-halo)" />}
            <circle className="flow-node-ring" r={node.r} fill="url(#flow-node-fill)" />
            <circle className="flow-node-inner" r={node.r - 7} />
            {node.brand ? (
              // SVG <image> has no srcset/sizes support, so ship a raster large enough that
              // viewBox scale x device-pixel-ratio (up to ~3x) never upscales the ~50u mark.
              <image
                className="flow-brand-mark"
                href="/logo/mark-192.png"
                x={-node.r * 0.62}
                y={-node.r * 0.62}
                width={node.r * 1.24}
                height={node.r * 1.24}
              />
            ) : (
              <g
                className="flow-icon"
                transform={`translate(${-node.r * 0.6} ${-node.r * 0.6}) scale(${(node.r * 1.2) / 24})`}
              >
                <Icon name={node.icon} />
              </g>
            )}
          </g>
        ))}
      </g>

      <g className="flow-node-labels">
        {NODES.map((node) => (
          <text
            key={node.id}
            className={node.brand ? 'flow-brand-word' : 'flow-node-label'}
            x={node.x}
            y={node.y + node.r + 22}
            textAnchor="middle"
          >
            {node.label}
          </text>
        ))}
      </g>
    </svg>
  )
}
