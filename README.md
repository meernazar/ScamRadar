# ScamRadar (Standalone)

AI-powered scam detection tool — single-process Node.js + Express app.

## Run

```bash
npm install
export GEMINI_API_KEY=...
export VIRUSTOTAL_API_KEY=...        # optional, used for URL mode
export GOOGLE_SAFE_BROWSING_KEY=...  # optional, used for URL mode
node server.js
```

Open http://localhost:3000

## Requirements

- Node.js >= 18 (uses the built-in `fetch` API)
- A Google Gemini API key (required)
- VirusTotal + Google Safe Browsing keys (optional, enable extra URL signals)
