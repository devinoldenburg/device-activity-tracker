<h1 align="left">WhatsApp Activity Tracker (Docker + Next UI)</h1>

Fork of the original WhatsApp Activity Tracker. MIT license. Focus: always-on Docker stack, SQLite persistence, and a Next.js dashboard.

> **Security hazard / research-only.** This probes messaging platforms to infer presence. Using it without explicit consent can be illegal and unethical. See [docs/README.md](docs/README.md) and do not run it against accounts you do not own or administer with permission.

## Features
- WhatsApp (Baileys) probing with RTT analysis
- SQLite persistence for all probes, profile-pic proxy, aliasing
- Next.js dashboard (live Socket.IO, sortable table, detail charts, CSV export)
- Dockerized stack with persisted auth (WA)

## Quick start (Docker)
```bash
docker-compose up --build -d
# UI:        http://localhost:3002
# API/WS:    http://localhost:3005
# API/WS:    http://localhost:3005
```
Then in the UI: scan the WhatsApp QR once; auth stays in volumes.

Reset everything (drops DB and auth):
```bash
docker-compose down -v && docker-compose up --build -d
```

### Authentication
- Default user: `admin` / `changeme` (stored in SQLite). Change immediately after first login.
- Env: `ALLOW_REGISTRATION=true` to enable self-signup; otherwise only existing users can log in.
- Env: `JWT_SECRET` for signing auth cookies (defaults to a dev secret); set to a strong random string in production.
- Env: `COOKIE_SECURE=true` to force secure cookies behind HTTPS.

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
- `src/server.ts` – Express + Socket.IO; WhatsApp via Baileys; persists to SQLite
- `src/tracker.ts` – probe loops, RTT/state calc, ping events
- `src/storage.ts` – better-sqlite3 store (contacts, pings)
- `client-next/` – Next.js app with live table, detail pane, charts, CSV export
- Docker: `docker-compose.yml` runs `dat-server`, `dat-client`; volumes `wa-auth`, `mysql-data`

## Ports
- Backend container: 3001 (mapped to host 3005)
- Frontend container: 3002

## Troubleshooting
- No QR (WA): refresh UI
- “Online” stale: UI marks sessions stale if no update >30s; reload and rescan if needed
- Reset stack: `docker-compose down -v && docker-compose up --build -d`

## Security / ethics
- Research/education only; obey law, consent, and platform terms
- Do not commit auth/session data or SQLite files
- Read the docs: [docs/security-risks.md](docs/security-risks.md), [docs/legal-ethics.md](docs/legal-ethics.md), [docs/deployment-notes.md](docs/deployment-notes.md)

## License
MIT. Copyright (c) 2025 WhatsApp Activity Tracker Contributors.
