'use strict'

const PUBLIC_KEYS = {
  'svp-cert-2026-01': {
    kty: 'EC',
    crv: 'P-256',
    x: 'cmTHcl3WWCu30_n4GUpDb28LlDph2dCWK5kmSRqOnws',
    y: 'gahUUAAsY3h8KUU5__YoADyqENLhRtwksbyWTeC9mpc',
  },
}

const REQUIRED_PAYLOAD_FIELDS = [
  'certificateId',
  'recipientName',
  'institutionName',
  'startDate',
  'endDate',
  'lectureCount',
  'totalCpdCredits',
]

const FIELD_LABELS = {
  certificateId: 'Certificate ID',
  recipientName: 'Recipient',
  institutionName: 'Institution',
  startDate: 'Start date',
  endDate: 'End date',
  lectureCount: 'Lectures attended',
  totalCpdCredits: 'CPD hours',
  issueDate: 'Issue date',
}

const tokenParam = new URLSearchParams(window.location.search).get('token')

const elements = {
  result: document.getElementById('result'),
  statusChip: document.getElementById('status-chip'),
  details: document.getElementById('details'),
  detailsGrid: document.getElementById('details-grid'),
  technicalDetails: document.getElementById('technical-details'),
  technicalList: document.getElementById('technical-list'),
}

class VerificationError extends Error {
  constructor(code, message, state = 'error') {
    super(message)
    this.name = 'VerificationError'
    this.code = code
    this.state = state
  }
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value)
}

function base64UrlToBytes(value) {
  const text = String(value || '').trim()
  if (!text) throw new VerificationError('empty_value', 'A required encoded value is empty.')
  if (/[^A-Za-z0-9_-]/.test(text)) {
    throw new VerificationError('invalid_base64url', 'The encoded value contains invalid characters.')
  }

  const base64 = text.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(text.length / 4) * 4, '=')
  let binary

  try {
    binary = window.atob(base64)
  } catch {
    throw new VerificationError('invalid_base64url', 'The encoded value could not be decoded.')
  }

  return Uint8Array.from(binary, (character) => character.charCodeAt(0))
}

function base64UrlToText(value) {
  return new TextDecoder().decode(base64UrlToBytes(value))
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize)
  if (!isPlainObject(value)) return value

  return Object.keys(value)
    .sort()
    .reduce((next, key) => {
      next[key] = canonicalize(value[key])
      return next
    }, {})
}

function canonicalJson(value) {
  return JSON.stringify(canonicalize(value))
}

function validateDate(value, fieldName) {
  const text = String(value || '')
  if (!/^\d{4}-\d{2}-\d{2}$/.test(text)) {
    throw new VerificationError('invalid_payload', `${FIELD_LABELS[fieldName]} must use YYYY-MM-DD format.`)
  }

  const date = new Date(`${text}T12:00:00Z`)
  if (
    Number.isNaN(date.getTime()) ||
    date.getUTCFullYear() !== Number(text.slice(0, 4)) ||
    date.getUTCMonth() + 1 !== Number(text.slice(5, 7)) ||
    date.getUTCDate() !== Number(text.slice(8, 10))
  ) {
    throw new VerificationError('invalid_payload', `${FIELD_LABELS[fieldName]} is not a valid date.`)
  }
}

function validatePayload(payload) {
  if (!isPlainObject(payload)) {
    throw new VerificationError('invalid_payload', 'The certificate payload is missing or invalid.')
  }

  REQUIRED_PAYLOAD_FIELDS.forEach((field) => {
    if (payload[field] === undefined || payload[field] === null || String(payload[field]).trim() === '') {
      throw new VerificationError('invalid_payload', `${FIELD_LABELS[field]} is missing from the certificate token.`)
    }
  })

  validateDate(payload.startDate, 'startDate')
  validateDate(payload.endDate, 'endDate')
  if (payload.issueDate !== undefined && String(payload.issueDate).trim() !== '') {
    validateDate(payload.issueDate, 'issueDate')
  }

  const lectureCount = Number(payload.lectureCount)
  if (!Number.isInteger(lectureCount) || lectureCount < 0) {
    throw new VerificationError('invalid_payload', 'Lectures attended must be a non-negative whole number.')
  }

  const cpdHours = Number(payload.totalCpdCredits)
  if (!Number.isFinite(cpdHours) || cpdHours < 0) {
    throw new VerificationError('invalid_payload', 'CPD hours must be a non-negative number.')
  }
}

function parseToken(token) {
  if (!token) {
    throw new VerificationError(
      'missing_token',
      'No certificate token was found in the URL.',
      'warning',
    )
  }

  let parsed
  try {
    parsed = JSON.parse(base64UrlToText(token))
  } catch (error) {
    if (error instanceof VerificationError) throw error
    throw new VerificationError('malformed_token', 'The certificate token is not valid JSON.')
  }

  if (!isPlainObject(parsed)) {
    throw new VerificationError('malformed_token', 'The certificate token must be a JSON object.')
  }

  if (parsed.v !== 1) {
    throw new VerificationError('unsupported_version', 'This certificate token version is not supported.')
  }

  if (parsed.alg !== 'ES256') {
    throw new VerificationError('unsupported_algorithm', 'This certificate token algorithm is not supported.')
  }

  if (!parsed.kid || typeof parsed.kid !== 'string') {
    throw new VerificationError('missing_key_id', 'The certificate token is missing a key ID.')
  }

  if (!parsed.sig || typeof parsed.sig !== 'string') {
    throw new VerificationError('missing_signature', 'The certificate token is missing a signature.')
  }

  validatePayload(parsed.payload)
  return parsed
}

function getPublicKey(kid) {
  const publicKey = PUBLIC_KEYS[kid]
  if (!publicKey) {
    throw new VerificationError('unknown_key', 'The verification key for this certificate is not configured.')
  }

  if (
    publicKey.x === 'REPLACE_WITH_PUBLIC_KEY_X' ||
    publicKey.y === 'REPLACE_WITH_PUBLIC_KEY_Y' ||
    !publicKey.x ||
    !publicKey.y
  ) {
    throw new VerificationError(
      'public_key_not_configured',
      'The public verification key has not been configured yet.',
      'warning',
    )
  }

  return publicKey
}

async function verifyCertificateToken(token) {
  const parsed = parseToken(token)
  const publicKey = getPublicKey(parsed.kid)
  const signature = base64UrlToBytes(parsed.sig)

  if (signature.byteLength !== 64) {
    throw new VerificationError(
      'invalid_signature_format',
      'The signature must be a 64-byte ES256 raw signature.',
    )
  }

  const key = await crypto.subtle.importKey(
    'jwk',
    publicKey,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify'],
  )
  const signedData = new TextEncoder().encode(
    canonicalJson({
      v: parsed.v,
      alg: parsed.alg,
      kid: parsed.kid,
      payload: parsed.payload,
    }),
  )
  const verified = await crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    signature,
    signedData,
  )

  if (!verified) {
    throw new VerificationError(
      'signature_mismatch',
      'The QR token signature does not match these certificate details.',
    )
  }

  return parsed
}

function formatDate(value) {
  if (!value) return ''
  return new Intl.DateTimeFormat('en-GB', {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
  }).format(new Date(`${value}T12:00:00Z`))
}

function formatNumber(value) {
  const number = Number(value)
  if (!Number.isFinite(number)) return String(value)
  return Number.isInteger(number) ? String(number) : number.toFixed(1)
}

function displayValue(field, value) {
  if (field === 'startDate' || field === 'endDate' || field === 'issueDate') return formatDate(value)
  if (field === 'totalCpdCredits') return formatNumber(value)
  return String(value)
}

function setStatusChip(state, text) {
  elements.statusChip.dataset.state = state
  elements.statusChip.textContent = text
}

function setResult(state, kicker, title, message) {
  elements.result.dataset.state = state
  elements.result.innerHTML = `
    <div class="status-mark" aria-hidden="true">${statusIconSvg(state)}</div>
    <div class="result-copy">
      <p class="result-kicker">${escapeHtml(kicker)}</p>
      <h1 id="page-title">${escapeHtml(title)}</h1>
      <p>${escapeHtml(message)}</p>
    </div>
  `
}

function statusIconSvg(state) {
  if (state === 'success') {
    return `
      <svg class="status-icon" viewBox="0 0 48 48" focusable="false">
        <circle class="status-ring" cx="24" cy="24" r="21" />
        <path class="status-check" d="M14.5 24.5 21 31l13-15" />
      </svg>
    `
  }

  if (state === 'error' || state === 'warning') {
    return `
      <svg class="status-icon" viewBox="0 0 48 48" focusable="false">
        <circle class="status-ring" cx="24" cy="24" r="21" />
        <path class="status-x" d="M17 17 31 31" />
        <path class="status-x" d="M31 17 17 31" />
      </svg>
    `
  }

  return `
    <svg class="status-icon" viewBox="0 0 48 48" focusable="false">
      <circle class="status-ring" cx="24" cy="24" r="21" />
      <circle class="status-dot" cx="24" cy="24" r="5" />
    </svg>
  `
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;')
}

function renderDetails(payload) {
  const fields = [
    'recipientName',
    'certificateId',
    'institutionName',
    'startDate',
    'endDate',
    'lectureCount',
    'totalCpdCredits',
    'issueDate',
  ].filter((field) => payload[field] !== undefined && payload[field] !== null && String(payload[field]).trim() !== '')

  elements.detailsGrid.innerHTML = fields
    .map(
      (field, index) => `
        <div class="detail-row" style="--row-delay: ${index * 55}ms">
          <span class="detail-label">${escapeHtml(FIELD_LABELS[field] || field)}</span>
          <span class="detail-value">${escapeHtml(displayValue(field, payload[field]))}</span>
        </div>
      `,
    )
    .join('')
  elements.details.hidden = false
}

function renderTechnicalDetails(token, parsed) {
  elements.technicalList.innerHTML = [
    ['Version', parsed.v],
    ['Algorithm', parsed.alg],
    ['Key ID', parsed.kid],
    ['Token length', `${token.length} characters`],
  ]
    .map(([label, value]) => `<dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value)}</dd>`)
    .join('')
  elements.technicalDetails.hidden = false
}

function renderError(error) {
  const state = error.state || 'error'
  setStatusChip(state, state === 'warning' ? 'Setup needed' : 'Invalid')
  setResult(
    state,
    state === 'warning' ? 'Verification unavailable' : 'Verification failed',
    state === 'warning' ? 'Certificate cannot be checked yet' : 'Certificate could not be verified',
    error.message || 'The certificate token could not be verified.',
  )
  elements.details.hidden = true
  elements.technicalDetails.hidden = true
}

async function main() {
  try {
    const parsed = await verifyCertificateToken(tokenParam)
    setStatusChip('success', 'Verified')
    setResult(
      'success',
      'Authentication successful',
      'Valid SVP certificate',
      'This QR token was signed by the configured SVP certificate key.',
    )
    renderDetails(parsed.payload)
    renderTechnicalDetails(tokenParam, parsed)
  } catch (error) {
    renderError(error instanceof VerificationError ? error : new VerificationError('unexpected_error', 'An unexpected verification error occurred.'))
  }
}

main()
