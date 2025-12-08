Silissia client form ready for Render.com (Node/Express web service).

## Environment variables
- `PORT` (optional) — Render injects one automatically.
- `FASTLY_API_TOKEN` — required for Domainr availability checks.
- `SMTP_HOST` — SMTP host for notifications.
- `SMTP_PORT` — SMTP port (default `587`).
- `SMTP_USER` — SMTP username.
- `SMTP_PASS` — SMTP password.
- `SMTP_FROM` — optional "from" address (defaults to `SMTP_USER`).
- `NOTIFY_TO` — notification recipient (defaults to `contact@silissia.com`).
- `APPS_SCRIPT_WEBHOOK` — optional webhook URL to forward selections.
- `DISABLE_COMPLETION_GUARD` — set to `true` to bypass completion checks (leave unset/false on Render).

## Build and start commands for Render
- Build command: `npm install`
- Start command: `npm start`

## Notes
- Entry point: `server.js` (listens on `process.env.PORT || 3000`).
- Static assets are served from `public/` via `express.static`.
- API endpoints: `/api/check`, `/api/selection`, `/api/completion` return JSON and use the env vars above.
- Data is persisted to `data/selections.json` and `data/completions.json` on disk.
