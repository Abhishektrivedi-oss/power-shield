import { Router } from 'express'
import { AppError } from '../middleware/errorHandler.js'
import { analyzeMessageWithGemini } from '../services/geminiService.js'

const router = Router()

/**
 * POST /api/analyze
 * Analyzes an untrusted user message for scam / phishing indicators using Gemini AI.
 */
router.post('/', async (req, res, next) => {
  try {
    const { message } = req.body || {}

    if (typeof message !== 'string' || !message.trim()) {
      throw new AppError(400, 'Enter a message to analyze.')
    }

    if (message.length > 6000) {
      throw new AppError(413, 'Messages must be 6000 characters or fewer.')
    }

    const analysis = await analyzeMessageWithGemini(message.trim())
    return res.status(200).json(analysis)
  } catch (error) {
    next(error)
  }
})

export default router
