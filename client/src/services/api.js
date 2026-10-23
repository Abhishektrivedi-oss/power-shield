const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || ''

/**
 * Checks backend server health.
 * @returns {Promise<{ status: string, service?: string, uptime?: number, timestamp?: string }>}
 */
export async function checkHealth() {
  const response = await fetch(`${API_BASE_URL}/api/health`, {
    method: 'GET',
    headers: {
      Accept: 'application/json',
    },
  })

  if (!response.ok) {
    throw new Error(`Server health check failed with status ${response.status}`)
  }

  return response.json()
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

  let response
  try {
    response = await fetch(`${API_BASE_URL}/api/analyze`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify({ message }),
    })
  } catch (networkError) {
    const error = new Error('Could not connect to the ScamShield analysis service. Please check your connection and try again.')
    error.cause = networkError
    throw error
  }

  let data = null
  try {
    data = await response.json()
  } catch {
    // Non-JSON response
  }

  if (!response.ok) {
    const errorMessage = data?.error || `Analysis request failed with status ${response.status}`
    const error = new Error(errorMessage)
    error.status = response.status
    error.data = data
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
