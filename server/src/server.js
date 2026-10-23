import express from 'express'
import cors from 'cors'
import dotenv from 'dotenv'
import rateLimit from 'express-rate-limit'
import analyzeRouter from './routes/analyze.js'
import { errorHandler } from './middleware/errorHandler.js'

dotenv.config()

const app = express()
const PORT = process.env.PORT || 5000
const normalizeOrigin = (value) => value.trim().replace(/\/+$/, '').toLowerCase()

// FRONTEND_ORIGIN accepts one origin or a comma-separated list, e.g.
// "https://your-site.netlify.app,https://www.your-domain.com"
const FRONTEND_ORIGINS = (process.env.FRONTEND_ORIGIN || 'http://localhost:5173')
  .split(',')
  .map(normalizeOrigin)
  .filter(Boolean)

const ALLOWED_ORIGINS = new Set([
  ...FRONTEND_ORIGINS,
  'http://localhost:5173',
  'http://127.0.0.1:5173',
])

// Render (and most PaaS hosts) sit behind a single proxy; required for accurate per-IP rate limiting.
app.set('trust proxy', 1)

// Restrict CORS to configured frontend origins
app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (like mobile apps, curl, or same-origin)
      if (!origin || ALLOWED_ORIGINS.has(normalizeOrigin(origin))) {
        callback(null, true)
      } else {
        // Respond without CORS headers instead of throwing, so disallowed origins get a clean browser-side block
        console.warn(`[ScamShield AI] Blocked CORS request from origin: ${origin}`)
        callback(null, false)
      }
    },
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Accept'],
    credentials: true,
  }),
)

// Request body parser with 32kb limit
app.use(express.json({ limit: '32kb' }))

// Rate limiting (60 requests per 15 minutes per IP)
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Too many requests from this IP. Please try again after 15 minutes.',
  },
})

app.use('/api/', apiLimiter)

// Service landing endpoint for deployment checks and browser visits
app.get('/', (req, res) => {
  res.status(200).json({
    status: 'ok',
    service: 'scamshield-api',
    message: 'ScamShield API is running.',
    endpoints: {
      health: '/api/health',
      analyze: 'POST /api/analyze',
    },
  })
})

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    service: 'scamshield-api',
    uptime: Math.floor(process.uptime()),
    timestamp: new Date().toISOString(),
  })
})

// Analyze message route
app.use('/api/analyze', analyzeRouter)

// 404 handler for unknown routes
app.use((req, res) => {
  res.status(404).json({
    error: `Route ${req.method} ${req.originalUrl} not found.`,
  })
})

// Centralized error handling middleware
app.use(errorHandler)

if (process.env.NODE_ENV !== 'test') {
  app.listen(PORT, () => {
    console.log(`[ScamShield AI] Backend server running on http://localhost:${PORT}`)
    console.log(`[ScamShield AI] CORS allowed origins: ${[...ALLOWED_ORIGINS].join(', ')}`)
  })
}

export default app
