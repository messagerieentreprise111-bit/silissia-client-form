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
- `APPS_SCRIPT_TIMEOUT_MS` — optional timeout in ms for the Apps Script webhook (default `12000`).
- `STRIPE_SECRET_KEY` ? required to validate Stripe sessions (webhook + status lookups).
- `STRIPE_SETUP_PRICE_ID` ? kept for Stripe config (unused by the frontend flow).
- `STRIPE_SUBSCRIPTION_PRICE_ID` ? kept for Stripe config (unused by the frontend flow).
- `STRIPE_WEBHOOK_SECRET` ? set to verify `/webhook/stripe` calls from Stripe.
- `PUBLIC_BASE_URL` ? optional; used as the public base URL when checking Stripe session status.
- `DISABLE_COMPLETION_GUARD` ? set to `true` to bypass completion checks (leave unset/false on Render).

## Build and start commands for Render
- Build command: `npm install`
- Start command: `npm start`

## Notes
- Entry point: `server.js` (listens on `process.env.PORT || 3000`).
- Static assets are served from `public/` via `express.static`.
- API endpoints: `/api/check`, `/api/selection`, `/api/completion` return JSON and use the env vars above.
- Stripe webhook endpoint: `/webhook/stripe` (expects the raw body; configure `STRIPE_WEBHOOK_SECRET`).
- `/api/completion` and `/api/selection` require a paid Stripe Checkout session (validated via `checkout.session.completed`).
- Data is persisted to `data/selections.json` and `data/completions.json` on disk.

## Logging overview
- Structured JSON logs via `logger.js` with scopes: `process`, `express`, `domain-check`, `selection`, `sendgrid-notif`, `smtp-notif`, `apps-script`, `json-store`.
- Key events logged: incoming selections, completion guard hits, domain checks, SendGrid/SMTP notifications, Apps Script calls, JSON store recovery, unhandled errors/rejections.
- Apps Script webhook timeout is configurable (`APPS_SCRIPT_TIMEOUT_MS`, default 12000ms). Longer timeout reduces false timeouts when Apps Script is slow while keeping the call fire-and-forget so the client response remains fast.

## Manual test checklist
1) Nominal path: run `npm start`, submit the form with a valid domain and email. Check logs for `domain-check` (availability), then `selection`, `sendgrid-notif`/`smtp-notif`, and `apps-script` entries showing success.
2) Domain API failure: set a bad `FASTLY_API_TOKEN` or cut network, call `/api/check?domain=example.com`. Expect HTTP 502 and a `domain-check` error log with the failing domain.
3) SendGrid failure: set an invalid `SENDGRID_API_KEY`, keep SMTP unset, submit the form. The client still gets `success: true` while `sendgrid-notif` logs an error for the notification attempt.
4) Apps Script failure: set `APPS_SCRIPT_WEBHOOK` to an invalid URL (e.g. `https://example.com/fail`), submit the form. The client succeeds but `apps-script` logs the non-blocking error code/message.
5) Stripe paid flow: start from the Stripe Payment Link (outside this app), let Stripe redirect to `/?session_id=<id>`, and ensure `/api/completion` returns paid and the form stays blocked when unpaid or when `session_id` is missing.
