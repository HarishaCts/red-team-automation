# Red-Team Dashboard

React + Vite frontend for the red-teaming framework.

## Develop

```bash
npm install
npm run dev        # http://localhost:5173  (proxies /api -> :8000)
```

Start the backend in another terminal:

```bash
uvicorn api.server:app --reload --port 8000
```

## Build for production

```bash
npm run build      # emits dist/
```

Serve `dist/` behind the same origin as the API (or set `REDTEAM_CORS_ORIGINS`).

## Features

- **Launch** a campaign and watch a **live attack feed** (Server-Sent Events).
- **Summary tiles**: safety score, breach count, breach rate.
- **Score heatmap**: category × severity.
- **Breach transcript viewer**: expand any breach to see prompt, response, and
  the judge's reasoning.