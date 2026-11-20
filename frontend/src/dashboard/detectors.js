/**
 * Client-side versions of the Chainmark detectors, used by the playground.
 * They mirror the shapes handled by the Python core (checksums included) but
 * run entirely in the browser, so nothing typed here leaves the page.
 */

function luhn(digits) {
  let sum = 0
  let double = false
  for (let index = digits.length - 1; index >= 0; index -= 1) {
    let value = Number(digits[index])
    if (double) {
      value *= 2
      if (value > 9) value -= 9
    }
    sum += value
    double = !double
  }
  return sum % 10 === 0
}

function ibanValid(raw) {
  const compact = raw.replace(/[^A-Za-z0-9]/g, '').toUpperCase()
  if (compact.length < 15 || compact.length > 34) return false
  const rearranged = compact.slice(4) + compact.slice(0, 4)
  const numeric = rearranged.replace(/[A-Z]/g, (letter) => String(letter.charCodeAt(0) - 55))
  let remainder = 0
  for (const char of numeric) {
    remainder = (remainder * 10 + Number(char)) % 97
  }
  return remainder === 1
}

function fnv(value) {
  let hash = 0x811c9dc5
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index)
    hash = Math.imul(hash, 0x01000193) >>> 0
  }
  return hash
}

const RULES = [
  {
    kind: 'mail',
    label: 'Email',
    tone: 'mail',
    pattern: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g,
    note: 'pattern family',
    validate: () => true,
  },
  {
    kind: 'pan',
    label: 'Card number',
    tone: 'pan',
    pattern: /\b(?:\d[ -]?){12,18}\d\b/g,
    note: 'Luhn checksum',
    validate: (match) => {
      const digits = match.replace(/\D/g, '')
      return digits.length >= 13 && digits.length <= 19 && luhn(digits)
    },
  },
  {
    kind: 'iban',
    label: 'IBAN',
    tone: 'iban',
    pattern: /\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){10,30}\b/g,
    note: 'mod-97 checksum',
    validate: ibanValid,
  },
  {
    kind: 'ssn',
    label: 'National ID',
    tone: 'ssn',
    pattern: /\b\d{3}-\d{2}-\d{4}\b/g,
    note: 'pattern family',
    validate: () => true,
  },
  {
    kind: 'key',
    label: 'API key',
    tone: 'key',
    pattern: /\b(?:sk|pk|rk)[-_][A-Za-z0-9][A-Za-z0-9-]{10,}\b/g,
    note: 'entropy + prefix',
    validate: () => true,
  },
  {
    kind: 'tel',
    label: 'Phone',
    tone: 'tel',
    pattern: /\+\d[\d ().-]{7,}\d/g,
    note: 'E.164 shape',
    validate: (match) => match.replace(/\D/g, '').length >= 9,
  },
]

export function tokenFor(kind, value) {
  return `cm_${kind}_${fnv(`${kind}:${value}`).toString(16).slice(0, 4)}`
}

export function digestFor(value) {
  return fnv(value).toString(16).padStart(8, '0')
}

export function scan(text) {
  const candidates = []

  for (const rule of RULES) {
    rule.pattern.lastIndex = 0
    let match = rule.pattern.exec(text)
    while (match) {
      const value = match[0]
      if (rule.validate(value)) {
        candidates.push({
          kind: rule.kind,
          label: rule.label,
          tone: rule.tone,
          note: rule.note,
          value,
          start: match.index,
          end: match.index + value.length,
        })
      }
      match = rule.pattern.exec(text)
    }
  }

  candidates.sort((a, b) => (a.start === b.start ? b.end - a.end : a.start - b.start))

  const entities = []
  let cursor = 0
  for (const candidate of candidates) {
    if (candidate.start < cursor) continue
    entities.push({ ...candidate, token: tokenFor(candidate.kind, candidate.value) })
    cursor = candidate.end
  }

  const parts = []
  let position = 0
  for (const entity of entities) {
    parts.push({ type: 'text', value: text.slice(position, entity.start) })
    parts.push({ type: 'token', value: entity.token, tone: entity.tone })
    position = entity.end
  }
  parts.push({ type: 'text', value: text.slice(position) })

  const sanitized = parts.map((part) => part.value).join('')

  return {
    entities,
    parts,
    sanitized,
    inputDigest: digestFor(text),
    sanitizedDigest: digestFor(sanitized),
  }
}

export const SAMPLES = [
  {
    id: 'invoice',
    label: 'Invoice reply',
    text:
      'Send the remittance for card 4242 4242 4242 4242 to billing@acme-corp.com before Friday. ' +
      'IBAN DE89 3704 0044 0532 0130 00, and call +1 415 555 0142 if it bounces.',
  },
  {
    id: 'support',
    label: 'Support ticket',
    text:
      'Customer with key sk-live-8f2a91cd44 says the SSN 412-88-9014 no longer matches the account, ' +
      'and their card 5555 5555 5555 4444 was declined twice this morning.',
  },
  {
    id: 'clean',
    label: 'Clean prompt',
    text:
      'Summarise the Q3 revenue deck and list the three biggest risks for the board review on Monday.',
  },
]
