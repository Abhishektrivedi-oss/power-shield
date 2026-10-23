import type { Config } from '@netlify/functions'
import { AppError, analyzeMessageWithGemini } from '../lib/gemini.mts'

const MAX_MESSAGE_LENGTH = 6000

export default async (req: Request) => {
  if (req.method !== 'POST') {
    return Response.json({ error: 'Use POST to analyze a message.' }, { status: 405 })
  }

  try {
    let body
    try {
      body = await req.json()
    } catch {
      throw new AppError(400, 'Send a valid JSON request.')
    }

    const message = body?.message
    if (typeof message !== 'string' || !message.trim()) {
      throw new AppError(400, 'Enter a message to analyze.')
    }

    if (message.length > MAX_MESSAGE_LENGTH) {
      throw new AppError(413, `Messages must be ${MAX_MESSAGE_LENGTH} characters or fewer.`)
    }

    const analysis = await analyzeMessageWithGemini(message.trim())
    return Response.json(analysis)
  } catch (error) {
    if (error instanceof AppError) {
      return Response.json({ error: error.message }, { status: error.status })
    }

    console.error('ScamShield analysis failed:', error)
    return Response.json({ error: 'An unexpected server error occurred.' }, { status: 500 })
  }
}

export const config: Config = {
  path: '/api/analyze',
}
