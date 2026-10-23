import { useEffect, useState } from 'react'
import { analyzeMessageApi } from './services/api'
import './App.css'

const examples = [
  {
    id: 'account-alert',
    label: 'Account alert',
    message:
      'ALERT: Your bank account will be locked in 10 minutes. Reply with your password and one-time code to keep access.',
    result: {
      classification: 'likely_scam',
      riskScore: 94,
      risk_level: 'High',
      risk_score: 94,
      summary:
        'The message uses a short deadline and asks for sensitive account credentials.',
      signals: [
        {
          type: 'Urgency',
          evidence: 'Your bank account will be locked in 10 minutes',
        },
        {
          type: 'Credential request',
          evidence: 'Reply with your password and one-time code',
        },
      ],
      warningSigns: [
        {
          type: 'Urgency',
          evidence: 'Your bank account will be locked in 10 minutes',
        },
        {
          type: 'Credential request',
          evidence: 'Reply with your password and one-time code',
        },
      ],
      safe_actions: [
        'Do not reply or share passwords or one-time codes.',
        'Check your account through the official banking app or website.',
        'Contact your bank using the number on your card.',
      ],
      recommendedActions: [
        'Do not reply or share passwords or one-time codes.',
        'Check your account through the official banking app or website.',
        'Contact your bank using the number on your card.',
      ],
      uncertainty: 'This is a scam risk assessment, not proof that the message is fraudulent.',
      confidence: 'High confidence based on typical credential-phishing urgency patterns.',
    },
  },
  {
    id: 'job-offer',
    label: 'Job offer',
    message:
      'Congratulations! You are hired for a remote assistant job paying $900 a day. Send a $75 training fee today to reserve your position.',
    result: {
      classification: 'likely_scam',
      riskScore: 88,
      risk_level: 'High',
      risk_score: 88,
      summary:
        'The unusually high pay and upfront fee are warning signs worth checking carefully.',
      signals: [
        {
          type: 'Unusually high pay',
          evidence: 'paying $900 a day',
        },
        {
          type: 'Upfront payment',
          evidence: 'Send a $75 training fee today',
        },
      ],
      warningSigns: [
        {
          type: 'Unusually high pay',
          evidence: 'paying $900 a day',
        },
        {
          type: 'Upfront payment',
          evidence: 'Send a $75 training fee today',
        },
      ],
      safe_actions: [
        'Do not send money to secure a job or interview.',
        'Look up the employer using contact details from its official website.',
        'Ask for a written offer and verify it with the company directly.',
      ],
      recommendedActions: [
        'Do not send money to secure a job or interview.',
        'Look up the employer using contact details from its official website.',
        'Ask for a written offer and verify it with the company directly.',
      ],
      uncertainty: 'This is a scam risk assessment, not proof that the message is fraudulent.',
      confidence: 'High confidence due to upfront advance-fee employment scam indicators.',
    },
  },
  {
    id: 'club-reminder',
    label: 'Club reminder',
    message:
      'Reminder: The campus photography club meets Thursday at 4 pm in the student center. Bring your camera if you have one.',
    result: {
      classification: 'likely_safe',
      riskScore: 12,
      risk_level: 'Low',
      risk_score: 12,
      summary:
        'This reads like a routine event reminder and does not include an obvious request for money or sensitive information.',
      signals: [],
      warningSigns: [],
      safe_actions: [
        'If you are unsure who sent it, confirm the meeting details with the club through a channel you already trust.',
        'A low score is not proof that a message is safe.',
      ],
      recommendedActions: [
        'If you are unsure who sent it, confirm the meeting details with the club through a channel you already trust.',
        'A low score is not proof that a message is safe.',
      ],
      uncertainty: 'This is a scam risk assessment, not proof that the message is fraudulent.',
      confidence: 'Consistent with routine non-threatening student event communications.',
    },
  },
  {
    id: 'delivery-notice',
    label: 'Delivery notice',
    message:
      'Parcel update: We could not deliver your package. Confirm your address at delivery-check.example to arrange another attempt.',
    result: {
      classification: 'suspicious',
      riskScore: 67,
      risk_level: 'Medium',
      risk_score: 67,
      summary:
        'The message asks you to use an unfamiliar delivery link, which could lead to a request for personal or payment details.',
      signals: [
        {
          type: 'Unverified link',
          evidence: 'Confirm your address at delivery-check.example',
        },
      ],
      warningSigns: [
        {
          type: 'Unverified link',
          evidence: 'Confirm your address at delivery-check.example',
        },
      ],
      safe_actions: [
        'Do not use the link in the message.',
        'Check delivery status in the retailer or carrier app you normally use.',
        'Do not enter payment details to receive an unexpected parcel.',
      ],
      recommendedActions: [
        'Do not use the link in the message.',
        'Check delivery status in the retailer or carrier app you normally use.',
        'Do not enter payment details to receive an unexpected parcel.',
      ],
      uncertainty: 'This is a scam risk assessment, not proof that the message is fraudulent.',
      confidence: 'Moderate confidence as package smishing tactics frequently use link verification.',
    },
  },
]

function formatClassification(classification) {
  switch (classification) {
    case 'likely_scam':
      return 'Likely Scam'
    case 'suspicious':
      return 'Suspicious'
    case 'likely_safe':
      return 'Likely Safe'
    default:
      return classification
  }
}

function buildRiskFactors(message, result) {
  const normalizedMessage = message.toLowerCase()
  const factors = []
  const checks = [
    {
      label: 'Urgency',
      pattern: /(urgent|immediately|today|now|within \d+ minutes?|deadline|expires|locked|final chance|turant|jaldi|abhi)/i,
    },
    {
      label: 'Money request',
      pattern: /(send money|payment|fee|transfer|bank details|wire|cash app|venmo|gift card|upfront payment|paise bhejo|rupaye)/i,
    },
    {
      label: 'Credentials',
      pattern: /(password|pin|otp|one-time code|security code|verify your account|login details|kba)/i,
    },
    {
      label: 'Suspicious link',
      pattern: /(click|tap|open|visit|link|url|domain|confirm your address|delivery-check|example\.|bit\.ly|t\.me)/i,
    },
    {
      label: 'Job scam',
      pattern: /(hired|job offer|remote assistant|training fee|easy money|salary|part-time job|earn daily|telegram job)/i,
    },
    {
      label: 'Impersonation',
      pattern: /(bank|government|official|security|support|account alert|alert:|bijli|electricity|challan|police)/i,
    },
  ]

  checks.forEach((check) => {
    if (check.pattern.test(normalizedMessage)) {
      factors.push({ label: check.label })
    }
  })

  const signals = result?.warningSigns || result?.signals
  if (signals?.length) {
    signals.forEach((signal) => {
      if (!factors.some((factor) => factor.label === signal.type)) {
        factors.push({ label: signal.type })
      }
    })
  }

  if (factors.length === 0) {
    return [{ label: 'Low-pressure content' }]
  }

  return factors.slice(0, 5)
}

function formatDate(timestamp) {
  return new Date(timestamp).toLocaleString([], {
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  })
}

function createSummaryText(result) {
  const signs = result.warningSigns || result.signals || []
  const actions = result.recommendedActions || result.safe_actions || []
  const score = result.riskScore !== undefined ? result.riskScore : result.risk_score
  const level = result.risk_level || result.classification

  return [
    'ScamShield AI report',
    `Classification: ${formatClassification(result.classification || level)}`,
    `Risk Score: ${score}/100`,
    '',
    `Summary: ${result.summary}`,
    '',
    'Warning signs:',
    ...signs.map((signal) => `- ${signal.type}: ${signal.evidence}`),
    '',
    'Safer next steps:',
    ...actions.map((action) => `- ${action}`),
    '',
    `Assessment note: ${result.confidence || result.uncertainty || 'Verify through official channels.'}`,
  ].join('\n')
}

async function shareOrCopyResult(result, message) {
  const shareText = `${createSummaryText(result)}\n\nMessage checked:\n${message}`

  try {
    if (navigator.share) {
      await navigator.share({
        title: 'ScamShield AI assessment',
        text: shareText,
      })
      return 'Shared successfully.'
    }

    if (navigator.clipboard) {
      await navigator.clipboard.writeText(shareText)
      return 'Copied to clipboard.'
    }

    return 'Copy is unavailable in this browser.'
  } catch (error) {
    if (error && error.name === 'AbortError') {
      return 'Share cancelled.'
    }
    return 'Could not share this result right now.'
  }
}

function App() {
  const [message, setMessage] = useState('')
  const [selectedExample, setSelectedExample] = useState(null)
  const [result, setResult] = useState(null)
  const [resultSource, setResultSource] = useState(null)
  const [resultNotice, setResultNotice] = useState('')
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [error, setError] = useState('')
  const [darkMode, setDarkMode] = useState(() => {
    if (typeof window === 'undefined') return false
    return localStorage.getItem('scamshield-theme') === 'dark'
  })
  const [history, setHistory] = useState(() => {
    if (typeof window === 'undefined') return []
    try {
      const stored = JSON.parse(localStorage.getItem('scamshield-history') || '[]')
      return Array.isArray(stored) ? stored : []
    } catch {
      return []
    }
  })

  useEffect(() => {
    if (typeof document !== 'undefined') {
      document.body.dataset.theme = darkMode ? 'dark' : 'light'
    }
    if (typeof window !== 'undefined') {
      localStorage.setItem('scamshield-theme', darkMode ? 'dark' : 'light')
    }
  }, [darkMode])

  useEffect(() => {
    if (typeof window !== 'undefined') {
      localStorage.setItem('scamshield-history', JSON.stringify(history))
    }
  }, [history])

  function addToHistory(entry) {
    setHistory((previous) => [entry, ...previous.filter((item) => item.id !== entry.id)].slice(0, 5))
  }

  async function handleShareOrCopy() {
    if (!result) return
    const status = await shareOrCopyResult(result, message)
    setResultNotice(status)
  }

  function downloadResult() {
    if (!result) return
    const blob = new Blob([JSON.stringify({ message, result }, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = 'scamshield-report.json'
    link.click()
    URL.revokeObjectURL(url)
  }

  function chooseExample(example) {
    setMessage(example.message)
    setSelectedExample(example.id)
    setResult(null)
    setResultSource(null)
    setResultNotice('')
    setError('')
  }

  function handleMessageChange(event) {
    setMessage(event.target.value)
    setSelectedExample(null)
    setResult(null)
    setResultSource(null)
    setResultNotice('')
    setError('')
  }

  async function analyzeMessage() {
    setResult(null)
    setResultSource(null)
    setResultNotice('')
    setError('')

    if (!message.trim()) {
      setError('Paste a message or choose an example to get started.')
      return
    }

    const matchedExample = examples.find(
      (item) => item.id === selectedExample && item.message === message,
    )

    setIsAnalyzing(true)

    try {
      // Connect to real backend API service
      const aiResult = await analyzeMessageApi(message.trim())

      setResult(aiResult)
      setResultSource('ai')
      addToHistory({
        id: `ai-${Date.now()}`,
        message,
        result: aiResult,
        source: 'ai',
        notice: '',
        level: aiResult.risk_level,
        title: `${aiResult.risk_level} risk · ${formatClassification(aiResult.classification)}`,
        timestamp: new Date().toISOString(),
      })
    } catch (analysisError) {
      // If user selected a prepared sample and backend/Gemini is unavailable, fallback to demo with clear labeling
      if (matchedExample) {
        const demoResult = matchedExample.result
        const notice = 'Gemini backend is currently unavailable, so this prepared example is shown as a local demo result.'
        setResult(demoResult)
        setResultSource('demo')
        setResultNotice(notice)
        addToHistory({
          id: `demo-${Date.now()}`,
          message,
          result: demoResult,
          source: 'demo',
          notice,
          level: demoResult.risk_level,
          title: `${demoResult.risk_level} risk (Demo)`,
          timestamp: new Date().toISOString(),
        })
      } else {
        // Honest error reporting for user's actual messages: Never mislabel as demo or claim success
        setError(analysisError.message || 'Analysis failed. Please check the server connection and try again.')
      }
    } finally {
      setIsAnalyzing(false)
    }
  }

  const warningSignals = result?.warningSigns || result?.signals || []
  const safeRecommendations = result?.recommendedActions || result?.safe_actions || []

  return (
    <main className="app-shell">
      <header className="topbar">
        <a className="brand" href="/" aria-label="ScamShield AI home">
          <span className="brand-mark" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none">
              <path
                d="M12 3.25 19 6v5.08c0 4.57-2.94 8.28-7 9.67-4.06-1.39-7-5.1-7-9.67V6l7-2.75Z"
                stroke="currentColor"
                strokeWidth="1.7"
                strokeLinejoin="round"
              />
              <path
                d="m9 12.1 2 2 4-4.2"
                stroke="currentColor"
                strokeWidth="1.7"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
          </span>
          <span>ScamShield <span className="brand-ai">AI</span></span>
        </a>

        <div className="topbar-actions">
          <button
            type="button"
            className="theme-toggle"
            onClick={() => setDarkMode((current) => !current)}
            aria-label={darkMode ? 'Switch to light mode' : 'Switch to dark mode'}
          >
            {darkMode ? 'Light mode' : 'Dark mode'}
          </button>
          <span className="demo-indicator">
            <span className="status-dot" />
            Gemini Client-Server
          </span>
        </div>
      </header>

      <section className="intro" aria-labelledby="page-title">
        <div className="eyebrow"><span /> A clearer look at suspicious messages</div>
        <h1 id="page-title">Pause. Check. Stay safe.</h1>
        <p>
          Paste a suspicious message in English, Hindi, or Hinglish to spot common warning signs and learn what
          to do next.
        </p>
      </section>

      <section className="workspace" aria-label="Message risk assessment">
        <div className="input-panel">
          <div className="section-heading">
            <div>
              <span className="step-label">STEP 01</span>
              <h2>What did you receive?</h2>
            </div>
            <span className="input-hint">SMS · WhatsApp · email · Hindi/Hinglish</span>
          </div>

          <label className="visually-hidden" htmlFor="message-input">
            Suspicious message
          </label>
          <textarea
            id="message-input"
            value={message}
            onChange={handleMessageChange}
            placeholder="Paste the message here (English, Hindi, or Hinglish). You can remove names or personal details first."
            rows={6}
            maxLength={6000}
            disabled={isAnalyzing}
          />

          <div className="examples">
            <span className="examples-label">TRY A FICTIONAL EXAMPLE</span>
            <div className="example-list">
              {examples.map((example) => (
                <button
                  className={`example-chip${selectedExample === example.id ? ' selected' : ''}`}
                  key={example.id}
                  type="button"
                  onClick={() => chooseExample(example)}
                  aria-pressed={selectedExample === example.id}
                  disabled={isAnalyzing}
                >
                  {example.label}
                </button>
              ))}
            </div>
          </div>

          <div className="analyze-row">
            <p className="privacy-note">
              <svg viewBox="0 0 20 20" fill="none" aria-hidden="true">
                <path
                  d="M10 2.5 16 5v4.36c0 3.92-2.52 7.1-6 8.29-3.48-1.19-6-4.37-6-8.29V5l6-2.5Z"
                  stroke="currentColor"
                  strokeWidth="1.4"
                  strokeLinejoin="round"
                />
              </svg>
              Gemini AI server-side analysis
            </p>
            <button
              className="analyze-button"
              type="button"
              onClick={analyzeMessage}
              disabled={isAnalyzing}
              aria-busy={isAnalyzing}
            >
              {isAnalyzing ? (
                <>
                  <span className="loading-spinner" aria-hidden="true" />
                  Analyzing...
                </>
              ) : (
                <>
                  Analyze message
                  <span aria-hidden="true">→</span>
                </>
              )}
            </button>
          </div>

          {error && (
            <p className="error-message" role="alert">
              <span aria-hidden="true">!</span>
              {error}
            </p>
          )}
        </div>

        <div className="results-panel" aria-live="polite">
          {result ? (
            <div className="result-content">
              <div className="result-topline">
                <span className="step-label">
                  {resultSource === 'ai' ? 'STEP 02 · GEMINI AI ANALYSIS' : 'STEP 02 · LOCAL PREPARED DEMO'}
                </span>
                <span className={`demo-tag${resultSource === 'demo' ? ' demo-tag--sample' : ''}`}>
                  {resultSource === 'ai' ? 'Live AI result' : 'Prepared demo'}
                </span>
              </div>
              {resultNotice && (
                <p className="fallback-note" role="status">
                  {resultNotice}
                </p>
              )}
              <div className="risk-overview">
                <div className={`risk-icon risk-${result.risk_level.toLowerCase()}`}>
                  {result.risk_level === 'High' ? '!' : result.risk_level === 'Medium' ? '↗' : '✓'}
                </div>
                <div className="risk-copy">
                  <span className="risk-caption">ASSESSMENT</span>
                  <h2>{result.risk_level} risk</h2>
                  {result.classification && (
                    <span className="classification-pill">
                      Classification: {formatClassification(result.classification)}
                    </span>
                  )}
                </div>
                <div className="score">
                  <strong>{result.risk_score}</strong><span>/100</span>
                  <small>risk score</small>
                </div>
              </div>
              <div className="result-actions">
                <button type="button" className="secondary-button" onClick={handleShareOrCopy}>
                  Share result
                </button>
                <button type="button" className="secondary-button" onClick={downloadResult}>
                  Download JSON
                </button>
              </div>
              <p className="result-summary">{result.summary}</p>

              <div className="risk-factors">
                <h3>Why this score</h3>
                <div className="factor-list">
                  {buildRiskFactors(message, result).map((factor) => (
                    <span key={factor.label || factor} className="factor-pill">
                      {factor.label || factor}
                    </span>
                  ))}
                </div>
              </div>

              <div className="result-section">
                <h3>Warning signs ({warningSignals.length})</h3>
                {warningSignals.length > 0 ? (
                  <ul className="signal-list">
                    {warningSignals.map((signal) => (
                      <li className="signal-item" key={`${signal.type}-${signal.evidence}`}>
                        <span className="signal-type">{signal.type}</span>
                        <blockquote>“{signal.evidence}”</blockquote>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="no-signals">
                    No obvious warning signs detected. That does not guarantee the message is safe.
                  </p>
                )}
              </div>

              <div className="result-section actions-section">
                <h3>Safe recommendations</h3>
                <ul className="action-list">
                  {safeRecommendations.map((action) => (
                    <li key={action}>
                      <span aria-hidden="true">✓</span>
                      {action}
                    </li>
                  ))}
                </ul>
              </div>
              <p className="uncertainty">
                {result.confidence || result.uncertainty || 'This is an assessment based on visible patterns, not proof.'}
              </p>
            </div>
          ) : (
            <div className="empty-result">
              <div className="empty-icon" aria-hidden="true">
                <svg viewBox="0 0 48 48" fill="none">
                  <path
                    d="M24 5.5 39 11v10.89c0 9.8-6.3 17.74-15 20.11-8.7-2.37-15-10.31-15-20.11V11l15-5.5Z"
                    stroke="currentColor"
                    strokeWidth="1.7"
                    strokeLinejoin="round"
                  />
                  <path
                    d="M24 16v9m0 6h.02"
                    stroke="currentColor"
                    strokeWidth="2"
                    strokeLinecap="round"
                  />
                </svg>
              </div>
              <span className="step-label">STEP 02</span>
              <h2>Your assessment will appear here</h2>
              <p>
                Paste a suspicious message or choose an example, then click Analyze to see its risk score, evidence, and safe next steps.
              </p>
              <div className="empty-divider" />
              <p className="empty-disclaimer">
                A lower score never guarantees a message is safe. Always verify independently.
              </p>
            </div>
          )}

          {history.length > 0 && (
            <div className="history-card">
              <div className="history-header">
                <span className="step-label">RECENT CHECKS</span>
              </div>
              <ul className="history-list">
                {history.map((item) => (
                  <li key={item.id} className="history-item">
                    <button
                      type="button"
                      className="history-button"
                      onClick={() => {
                        setMessage(item.message)
                        setResult(item.result)
                        setResultSource(item.source)
                        setResultNotice(item.notice || '')
                        setError('')
                        setSelectedExample(null)
                      }}
                    >
                      <span className={`history-badge history-badge--${item.level.toLowerCase()}`}>
                        {item.level}
                      </span>
                      <span className="history-copy">
                        <strong>{item.title}</strong>
                        <small>{formatDate(item.timestamp)}</small>
                      </span>
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </section>

      <footer className="page-footer">
        <span>Think something feels off? Trust your instincts and verify first.</span>
        <span className="footer-mark">SCAMSHIELD AI <span>·</span> CLIENT-SERVER</span>
      </footer>
    </main>
  )
}

export default App
