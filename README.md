<h1 align="left">WhatsApp / Signal Activity Tracker (Docker + Next UI)</h1>

Fork of the original WhatsApp Activity Tracker. MIT license. Focus: always-on Docker stack, SQLite persistence, high-frequency probes, and a Next.js dashboard.

> Research/education only. Use only with consent and lawful purpose.

## Features
- WhatsApp (Baileys) + Signal (signal-cli-rest-api) probing with RTT analysis
- SQLite persistence for all probes, profile-pic proxy, aliasing
- Next.js dashboard (live Socket.IO, sortable table, detail charts, CSV export)
- Dockerized stack with persisted auth (WA) and Signal link data

## Quick start (Docker)
```bash
docker-compose up --build -d
# UI:        http://localhost:3002
# API/WS:    http://localhost:3005
# Signal API: http://localhost:8082
```
Then in the UI: scan WhatsApp QR. For Signal, scan the Signal QR once; data stays in volumes.

Reset everything (drops DB and auth):
```bash
docker-compose down -v && docker-compose up --build -d
```

## Local dev
```bash
npm install
cd client-next && npm install && cd ..

# Backend
npm run start:backend   # serves API/WS on :3001

# Frontend (Next)
cd client-next && npm run dev -- -H 0.0.0.0 -p 3002
```
Env for the frontend (host dev):
- `NEXT_PUBLIC_API_BASE` / `NEXT_PUBLIC_SOCKET_URL` (default to http://localhost:3005, auto-swaps 3002->3005 in browser)

## Architecture
- `src/server.ts` – Express + Socket.IO; WhatsApp via Baileys; Signal via signal-cli-rest-api; persists to SQLite
- `src/tracker.ts` / `src/signal-tracker.ts` – probe loops, RTT/state calc, ping events
- `src/storage.ts` – better-sqlite3 store (contacts, pings)
- `client-next/` – Next.js app with live table, detail pane, charts, CSV export
- Docker: `docker-compose.yml` runs `dat-server`, `dat-client`, `signal-api`; volumes `sqlite-data`, `signal-data`, `wa-auth`

## Ports
- Backend container: 3001 (mapped to host 3005)
- Frontend container: 3002
- Signal API container: 8080 (mapped to host 8082)

## Troubleshooting
- No QR (WA/Signal): refresh UI; ensure host 8082 reachable for Signal
- “Online” stale: UI marks sessions stale if no update >30s; reload and rescan if needed
- Reset stack: `docker-compose down -v && docker-compose up --build -d`

## Security / ethics
- Research/education only; obey law and consent requirements
- Do not commit auth/session data or SQLite files

## License
MIT. Copyright (c) 2025 WhatsApp Activity Tracker Contributors.
