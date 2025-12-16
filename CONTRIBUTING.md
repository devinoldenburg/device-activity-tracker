## Contributing

Fork of the WhatsApp Activity Tracker. Copyright (c) 2025 WhatsApp Activity Tracker Contributors.

Guidelines:
- Keep PRs small and focused; TypeScript preferred.
- Do not commit auth/session data, SQLite DBs, or secrets.
- Research/education only; comply with applicable law and consent requirements.

Setup:
```bash
npm install
cd client-next && npm install && cd ..
```

Run locally:
- Backend: `npm run start:backend`
- Frontend: `cd client-next && npm run dev -- -H 0.0.0.0 -p 3002`

Process:
- Use feature branches; describe intent + testing in PRs.
- Respect ethical/legal notes in README.
