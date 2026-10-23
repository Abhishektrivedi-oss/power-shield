/**
 * Custom error class for API errors with an associated HTTP status code.
 */
export class AppError extends Error {
  constructor(status, message) {
    super(message)
    this.status = status
    this.name = 'AppError'
  }
}

/**
 * Centralized Express error handler middleware.
 */
export function errorHandler(err, req, res, next) {
  // Handle JSON parse syntax error from express.json()
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return res.status(400).json({
      error: 'Send a valid JSON request.',
    })
  }

  // Handle payload too large
  if (err.type === 'entity.too.large' || err.status === 413) {
    return res.status(413).json({
      error: 'The request is too large. Messages must be 6000 characters or fewer.',
    })
  }

  const status = err.status || (res.statusCode >= 400 ? res.statusCode : 500)
  const message = err.message || 'An unexpected server error occurred.'

  // Log 5xx errors server-side (without exposing sensitive tokens)
  if (status >= 500) {
    console.error(`[ScamShield Server Error] [${status}] ${err.message}`)
    if (err.stack) {
      console.error(err.stack)
    }
  }

  return res.status(status).json({
    error: message,
  })
}
