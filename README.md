# ScamShield AI — Client-Server Architecture

An intelligent scam and phishing detection system featuring a clean, decoupled client-server architecture powered by Google Gemini AI.

## Project Structure

```text
ScamShield-AI/
├── client/
│   ├── public/
│   │   ├── favicon.svg
│   │   └── icons.svg
│   ├── src/
│   │   ├── assets/
│   │   ├── services/
│   │   │   └── api.js
│   │   ├── App.css
│   │   ├── App.jsx
│   │   ├── index.css
│   │   └── main.jsx
│   ├── .env.example
│   ├── .oxlintrc.json
│   ├── index.html
│   ├── package.json
│   └── vite.config.js
│
├── server/
│   ├── src/
│   │   ├── middleware/
│   │   │   └── errorHandler.js
│   │   ├── routes/
│   │   │   └── analyze.js
│   │   ├── services/
│   │   │   └── geminiService.js
│   │   └── server.js
│   ├── .env
│   ├── .env.example
│   └── package.json
│
├── .gitignore
└── README.md
```

---

## Getting Started (Windows VS Code Terminals)

### Terminal 1 — Backend Server

```powershell
cd server
npm install
npm run dev
```

The backend server starts on **`http://localhost:5000`**.

### Terminal 2 — Frontend Client

```powershell
cd client
npm install
npm run dev
```

The frontend client starts on **`http://localhost:5173`**.

---

## Environment Configuration

### Server (`server/.env`)

Copy `server/.env.example` to `server/.env`:

```env
PORT=5000
GEMINI_API_KEY=your_actual_gemini_api_key_here
FRONTEND_ORIGIN=http://localhost:5173
```

- `GEMINI_API_KEY`: Your Google Gemini API key from Google AI Studio. Stored strictly server-side and never exposed to the client bundle.
- `FRONTEND_ORIGIN`: Allowed origin for CORS protection (defaults to `http://localhost:5173`).

### Client (`client/.env`)

Copy `client/.env.example` to `client/.env`:

```env
VITE_API_BASE_URL=http://localhost:5000
```

- `VITE_API_BASE_URL`: Base URL pointing to the Express backend API.

---

## API Endpoints

### 1. Health Check
- **Route:** `GET /api/health`
- **Response:**
  ```json
  {
    "status": "ok",
    "service": "scamshield-api",
    "uptime": 120,
    "timestamp": "2026-10-23T18:30:00.000Z"
  }
  ```

### 2. Message Analysis
- **Route:** `POST /api/analyze`
- **Request Headers:** `Content-Type: application/json`
- **Request Body:**
  ```json
  {
    "message": "ALERT: Your bank account will be locked in 10 minutes. Reply with OTP."
  }
  ```
- **Response:**
  ```json
  {
    "classification": "likely_scam",
    "riskScore": 94,
    "summary": "The message uses an artificial deadline and demands sensitive authentication credentials.",
    "warningSigns": [
      {
        "type": "Urgency",
        "evidence": "Your bank account will be locked in 10 minutes"
      },
      {
        "type": "Credential request",
        "evidence": "Reply with OTP"
      }
    ],
    "recommendedActions": [
      "Do not reply or share passwords or one-time codes.",
      "Check your account through the official banking app or website."
    ],
    "confidence": "High confidence based on typical credential-phishing urgency patterns."
  }
  ```

---

## Key Architectural & Security Features

1. **Decoupled Architecture:** Frontend and backend run independently with separate `package.json` dependencies and dedicated runtimes.
2. **Untrusted Input Treatment:** All analyzed messages are treated as untrusted strings, wrapped safely to prevent prompt injection and instruction hijacking.
3. **Multilingual Support:** Supports English, Hindi (Devanagari), and Hinglish (Hindi written in Roman letters) scam patterns (such as KYC suspension, electricity disconnection threats, Telegram task scams, and fake lottery rewards).
4. **No Secret Leakage:** The Gemini API key remains securely on the server and is never exposed in client bundles or network requests.
5. **CORS & Rate Limiting:** Backend limits origin access to the configured frontend and applies IP rate-limiting to protect API quotas.
6. **Honest Reporting:** If Gemini is unconfigured or unavailable, real user messages display clear errors instead of fabricated results, while prepared samples are explicitly labeled as demo results.
7. **Unchanged Vite Config:** The frontend Vite configuration is preserved verbatim, ensuring 100% build compatibility and independent operation.
