const LOCAL_DEV_API_BASE_URL = 'http://localhost:5000'

/**
 * Normalizes the configured base URL so endpoint paths can always be appended as `/api/...`:
 * trims whitespace, removes trailing slashes, and strips an accidental trailing `/api` segment.
 */
function normalizeBaseUrl(value) {
  if (typeof value !== 'string') return ''
  return value.trim().replace(/\/+$/, '').replace(/\/api$/i, '')
}

// The localhost fallback is only used by the Vite dev server; production builds must set VITE_API_BASE_URL.
export const API_BASE_URL =
  normalizeBaseUrl(import.meta.env.VITE_API_BASE_URL) ||
  (import.meta.env.DEV ? LOCAL_DEV_API_BASE_URL : '')

function buildApiUrl(path) {
  if (!API_BASE_URL) {
    const error = new Error(
      'The ScamShield backend URL is not configured. Set VITE_API_BASE_URL in the hosting environment and redeploy the frontend.',
    )
    error.kind = 'config'
    throw error
  }
  return `${API_BASE_URL}${path}`
}

/**
 * fetch() wrapper that turns browser-level failures into a clear, accurate error.
 * Browsers intentionally report CORS rejections and network failures identically (a TypeError),
 * so both possibilities are described rather than guessed.
 */
async function requestApi(path, options) {
  const url = buildApiUrl(path)

  try {
    return await fetch(url, options)
  } catch (networkError) {
    const error = new Error(
      `Could not reach the ScamShield server at ${API_BASE_URL}. The server may be waking up (please retry in a minute), offline, or blocking this site via CORS.`,
    )
    error.kind = 'network'
    error.cause = networkError
    throw error
  }
}

async function readJson(response) {
  const contentType = response.headers.get('content-type') || ''
  if (!contentType.includes('application/json')) return null
  try {
    return await response.json()
  } catch {
    return null
  }
}

/**
 * Checks backend server health.
 * @returns {Promise<{ status: string, service?: string, uptime?: number, timestamp?: string }>}
 */
export async function checkHealth() {
  const response = await requestApi('/api/health', {
    method: 'GET',
    headers: {
      Accept: 'application/json',
    },
  })

  const data = await readJson(response)

  if (!response.ok || !data) {
    const error = new Error(`Server health check failed with status ${response.status}`)
    error.kind = 'http'
    error.status = response.status
    throw error
  }

  return data
}

/**
 * Sends a message to the backend Gemini AI analysis endpoint.
 * @param {string} message - Untrusted message to analyze
 * @returns {Promise<object>} - Structured scam analysis result
 */
export async function analyzeMessageApi(message) {
  if (typeof message !== 'string' || !message.trim()) {
    throw new Error('Enter a message to analyze.')
  }

  if (message.length > 6000) {
    throw new Error('Messages must be 6000 characters or fewer.')
  }

  const response = await requestApi('/api/analyze', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: JSON.stringify({ message }),
  })

  const data = await readJson(response)

  if (!response.ok) {
    const errorMessage = data?.error || (
      response.status === 404
        ? `The analysis endpoint was not found at ${API_BASE_URL}/api/analyze. Check that VITE_API_BASE_URL points to the ScamShield backend.`
        : `Analysis request failed with status ${response.status}.`
    )
    const error = new Error(errorMessage)
    error.kind = data?.error ? 'backend' : 'http'
    error.status = response.status
    error.data = data
    throw error
  }

  if (!data) {
    const error = new Error(
      `The server at ${API_BASE_URL} did not return JSON. Check that VITE_API_BASE_URL points to the ScamShield backend, not the frontend site.`,
    )
    error.kind = 'http'
    error.status = response.status
    throw error
  }

  // Normalize returned structured fields for client consumption
  return normalizeAnalysisResponse(data)
}

/**
 * Normalizes backend analysis to ensure UI compatibility
 * while preserving structured fields (classification, riskScore, warningSigns, recommendedActions, confidence)
 */
export function normalizeAnalysisResponse(data) {
  if (!data || typeof data !== 'object') {
    throw new Error('Received invalid data from analysis server.')
  }

  const classification = data.classification || (
    data.risk_score >= 70 ? 'likely_scam' : data.risk_score >= 40 ? 'suspicious' : 'likely_safe'
  )

  const riskScore = Number.isInteger(data.riskScore)
    ? data.riskScore
    : Number.isInteger(data.risk_score)
      ? data.risk_score
      : 50

  const summary = typeof data.summary === 'string' ? data.summary : ''
  const warningSigns = Array.isArray(data.warningSigns)
    ? data.warningSigns
    : Array.isArray(data.signals)
      ? data.signals
      : []

  const recommendedActions = Array.isArray(data.recommendedActions)
    ? data.recommendedActions
    : Array.isArray(data.safe_actions)
      ? data.safe_actions
      : []

  const confidence = typeof data.confidence === 'string'
    ? data.confidence
    : typeof data.uncertainty === 'string'
      ? data.uncertainty
      : 'This is an automated risk assessment based on visible patterns, not legal proof.'

  const riskLevel = classification === 'likely_scam'
    ? 'High'
    : classification === 'suspicious'
      ? 'Medium'
      : 'Low'

  return {
    // Standard structured analysis fields
    classification,
    riskScore,
    summary,
    warningSigns,
    recommendedActions,
    confidence,

    // UI backward-compatibility aliases
    risk_level: riskLevel,
    risk_score: riskScore,
    signals: warningSigns,
    safe_actions: recommendedActions,
    uncertainty: confidence,
  }
}
