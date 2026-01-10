const { Pool } = require('pg');
const nodemailer = require('nodemailer');

const DATABASE_URL = process.env.DATABASE_URL || '';
const APPS_SCRIPT_WEBHOOK = process.env.APPS_SCRIPT_WEBHOOK || '';
const APPS_SCRIPT_TIMEOUT_MS = parseInt(process.env.APPS_SCRIPT_TIMEOUT_MS || '12000', 10);
const META_CAPI_MODE = (process.env.META_CAPI_MODE || 'off').trim().toLowerCase();
const META_PIXEL_ID = (process.env.META_PIXEL_ID || '').trim();
const META_CAPI_TOKEN = (process.env.META_CAPI_TOKEN || '').trim();
const META_CAPI_TIMEOUT_MS = parseInt(process.env.META_CAPI_TIMEOUT_MS || '5000', 10);
const META_TEST_EVENT_CODE = (process.env.META_TEST_EVENT_CODE || '').trim();
const OUTBOX_BATCH_SIZE = parseInt(process.env.OUTBOX_BATCH_SIZE || '20', 10);
const OUTBOX_MAX_ATTEMPTS = parseInt(process.env.OUTBOX_MAX_ATTEMPTS || '5', 10);
const DATABASE_SSL = process.env.DATABASE_SSL || '';
const OUTBOX_MONITOR_ONLY = process.env.OUTBOX_MONITOR_ONLY === 'true';
const ALERT_TEST = process.env.ALERT_TEST === 'true';
const STRIPE_ALERT_TEST = process.env.STRIPE_ALERT_TEST === 'true';
const ALERT_COOLDOWN_MINUTES = parseInt(process.env.ALERT_COOLDOWN_MINUTES || '30', 10);
const ALERT_TO = (process.env.ALERT_TO || process.env.NOTIFY_TO || '').trim();
const ALERT_FROM = (process.env.ALERT_FROM || process.env.SMTP_FROM || process.env.SMTP_USER || '').trim();
const SENDGRID_API_KEY = (process.env.SENDGRID_API_KEY || '').trim();
const SMTP_HOST = process.env.SMTP_HOST || '';
const SMTP_PORT = parseInt(process.env.SMTP_PORT || '587', 10);
const SMTP_USER = process.env.SMTP_USER || '';
const SMTP_PASS = process.env.SMTP_PASS || '';
const PUBLIC_BASE_URL = (process.env.PUBLIC_BASE_URL || '').trim();
const SERVICE_NAME = (process.env.RENDER_SERVICE_NAME || 'outbox-replay').trim();
const STRIPE_WEBHOOK_MONITOR_WINDOW_MINUTES = parseInt(
  process.env.STRIPE_WEBHOOK_MONITOR_WINDOW_MINUTES || '10',
  10
);
const STRIPE_WEBHOOK_ERROR_THRESHOLD = parseInt(
  process.env.STRIPE_WEBHOOK_ERROR_THRESHOLD || '1',
  10
);
const STRIPE_WINDOW_MINUTES = Number.isFinite(STRIPE_WEBHOOK_MONITOR_WINDOW_MINUTES)
  ? STRIPE_WEBHOOK_MONITOR_WINDOW_MINUTES
  : 10;
const STRIPE_ERROR_THRESHOLD = Number.isFinite(STRIPE_WEBHOOK_ERROR_THRESHOLD)
  ? STRIPE_WEBHOOK_ERROR_THRESHOLD
  : 1;

function getDbSslConfig() {
  if (DATABASE_SSL === 'true') {
    return { rejectUnauthorized: false };
  }
  try {
    const url = new URL(DATABASE_URL);
    const sslMode = url.searchParams.get('sslmode');
    if (sslMode && sslMode !== 'disable') {
      return { rejectUnauthorized: false };
    }
  } catch {
    return undefined;
  }
  return undefined;
}

function redactDbUrl(value) {
  if (!value) return '(none)';
  try {
    const url = new URL(value);
    if (url.password) url.password = '***';
    return url.toString();
  } catch {
    return value.replace(/:[^:@]+@/, ':***@');
  }
}

function getNextRetryDelayMs(attemptCount) {
  const minutesByAttempt = [1, 5, 15, 60, 360];
  const index = Math.max(0, attemptCount - 1);
  const minutes = minutesByAttempt[index] ?? minutesByAttempt[minutesByAttempt.length - 1];
  return minutes * 60 * 1000;
}

function normalizeMetaMode(mode) {
  const value = (mode || 'off').trim().toLowerCase();
  if (value === 'live') return 'live';
  if (value === 'dry_run' || value === 'dry-run') return 'dry_run';
  return 'off';
}

function createMailer() {
  if (!SMTP_HOST || !SMTP_USER || !SMTP_PASS) {
    return null;
  }
  return nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: SMTP_PORT === 465,
    auth: { user: SMTP_USER, pass: SMTP_PASS },
    connectionTimeout: 5000,
    greetingTimeout: 5000,
    socketTimeout: 5000,
    timeout: 5000,
  });
}

async function sendWithSendGrid({ subject, text }) {
  if (!SENDGRID_API_KEY) {
    throw new Error('SENDGRID_API_KEY missing');
  }
  if (!ALERT_FROM || !ALERT_TO) {
    throw new Error('ALERT_FROM or ALERT_TO missing');
  }
  const payload = {
    personalizations: [
      {
        to: [{ email: ALERT_TO }],
        subject,
      },
    ],
    from: { email: ALERT_FROM },
    content: [{ type: 'text/plain', value: text }],
  };
  const response = await fetch('https://api.sendgrid.com/v3/mail/send', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${SENDGRID_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
  });
  if (!response.ok) {
    const body = await response.text().catch(() => '');
    throw new Error(`SendGrid error ${response.status}: ${body || '(empty)'}`);
  }
}

async function sendWithSmtp({ subject, text }) {
  const mailer = createMailer();
  if (!mailer) {
    throw new Error('SMTP config missing');
  }
  if (!ALERT_FROM || !ALERT_TO) {
    throw new Error('ALERT_FROM or ALERT_TO missing');
  }
  await mailer.sendMail({
    from: ALERT_FROM,
    to: ALERT_TO,
    subject,
    text,
  });
}

async function sendAlertEmail({
  pendingCount,
  oldestPendingAgeSec,
  deadCount,
  batchPickedCount = null,
  sentCount = null,
  retryCount = null,
  durationMs = null,
  isTest = false,
}) {
  if (!ALERT_TO) {
    console.error('Alert skipped: ALERT_TO missing.');
    return;
  }
  if (!ALERT_FROM) {
    console.error('Alert skipped: ALERT_FROM missing.');
    return;
  }
  const alertType = deadCount > 0 ? 'dead' : 'pending';
  const subject = isTest
    ? '[TEST] Outbox monitoring'
    : alertType === 'dead'
    ? '[ALERTE] Outbox dead detecte'
    : '[ALERTE] Outbox pending accumule';
  const lines = [];
  if (isTest) {
    lines.push("TEST MODE (ALERT_TEST=true) -- ceci n'est pas une vraie alerte");
  }
  lines.push(`service: ${SERVICE_NAME}`);
  lines.push(`timestamp: ${new Date().toISOString()}`);
  lines.push(`pending_count: ${pendingCount}`);
  lines.push(`oldest_pending_age_sec: ${oldestPendingAgeSec}`);
  lines.push(`dead_count: ${deadCount}`);
  if (batchPickedCount !== null) {
    lines.push(`batch_picked_count: ${batchPickedCount}`);
  }
  if (sentCount !== null) {
    lines.push(`sent_count: ${sentCount}`);
  }
  if (retryCount !== null) {
    lines.push(`retry_count: ${retryCount}`);
  }
  if (durationMs !== null) {
    lines.push(`duration_ms: ${durationMs}`);
  }
  if (PUBLIC_BASE_URL) {
    lines.push(`url: ${PUBLIC_BASE_URL}`);
  }
  lines.push('');
  lines.push('QUE FAIRE:');
  const actionLines = [];
  const pendingTrigger = pendingCount > 5 || oldestPendingAgeSec > 600;
  if (pendingTrigger || (isTest && deadCount === 0)) {
    actionLines.push('- Ouvrir Render -> service "outbox-replay" -> Logs : verifier erreurs HTTP Apps Script.');
    actionLines.push('- Verifier APPS_SCRIPT_WEBHOOK present et correct dans les env du cron job.');
    actionLines.push('- Verifier Apps Script accessible (Web App active) et pas en erreur/rate-limit.');
    actionLines.push(
      '- Si ca persiste : augmenter APPS_SCRIPT_TIMEOUT_MS (ex 20000) ou reduire OUTBOX_BATCH_SIZE.'
    );
  }
  if (deadCount > 0 || (isTest && !pendingTrigger)) {
    actionLines.push('- Inspecter en DB les lignes outbox en status dead (last_error, attempts, payload).');
    actionLines.push('- Corriger la cause (Apps Script down / payload invalide / auth).');
    actionLines.push('- Prevoir une recuperation : remettre en pending ou script de requeue.');
  }
  actionLines.push('- Verifier variables email (SENDGRID_API_KEY ou SMTP_*).');
  actionLines.push('- Verifier ALERT_COOLDOWN_MINUTES pour eviter le spam.');
  lines.push(...actionLines);
  const text = lines.join('\n');
  if (SENDGRID_API_KEY) {
    await sendWithSendGrid({ subject, text });
    return;
  }
  await sendWithSmtp({ subject, text });
}

async function sendStripeAlertEmail({ errorCount, windowMinutes, examples, isTest = false }) {
  if (!ALERT_TO) {
    console.error('Stripe alert skipped: ALERT_TO missing.');
    return;
  }
  if (!ALERT_FROM) {
    console.error('Stripe alert skipped: ALERT_FROM missing.');
    return;
  }
  const subject = isTest
    ? '[TEST] Stripe webhook monitoring'
    : '[ALERTE] Stripe webhook errors detectees';
  const lines = [];
  if (isTest) {
    lines.push("TEST MODE (STRIPE_ALERT_TEST=true) -- ceci n'est pas une vraie alerte");
  }
  lines.push(`service: ${SERVICE_NAME}`);
  lines.push(`timestamp: ${new Date().toISOString()}`);
  lines.push(`error_count: ${errorCount}`);
  lines.push(`window_minutes: ${windowMinutes}`);
  if (PUBLIC_BASE_URL) {
    lines.push(`url: ${PUBLIC_BASE_URL}`);
  }
  lines.push('');
  lines.push('exemples_recents:');
  if (!examples.length) {
    lines.push('- (aucun exemple disponible)');
  } else {
    for (const example of examples) {
      lines.push(
        `- event_id=${example.event_id || '(none)'} type=${example.type || '(none)'} status=${
          example.status || '(none)'
        } http_status=${example.http_status ?? '(none)'} error_message=${
          example.error_message || '(none)'
        }`
      );
    }
  }
  lines.push('');
  lines.push('QUE FAIRE:');
  lines.push('- Ouvrir Render -> service web "silissia-client-form" -> Logs : chercher erreurs /webhook/stripe.');
  lines.push('- Verifier STRIPE_WEBHOOK_SECRET et STRIPE_SECRET_KEY.');
  lines.push('- Verifier que le webhook Stripe pointe sur la bonne URL (prod vs test).');
  lines.push('- Verifier dans Stripe Dashboard -> Developers -> Webhooks les retries/checs.');
  lines.push('- Si invalid_signature : probleme de secret ou mauvais endpoint.');
  lines.push('- Si 5xx : bug serveur/DB down a traiter en priorite haute.');

  const text = lines.join('\n');
  if (SENDGRID_API_KEY) {
    await sendWithSendGrid({ subject, text });
    return;
  }
  await sendWithSmtp({ subject, text });
}

async function postWithTimeout(url, payload, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    const bodyText = await response.text().catch(() => '');
    if (!response.ok) {
      const error = new Error(
        `Webhook responded with status ${response.status} ${response.statusText}: ${bodyText || '(empty)'}`
      );
      error.status = response.status;
      error.bodyText = bodyText;
      throw error;
    }
    return { status: response.status, bodyText };
  } finally {
    clearTimeout(timer);
  }
}

async function postMetaCapiEvent(eventPayload, mode) {
  const url = new URL(`https://graph.facebook.com/v18.0/${META_PIXEL_ID}/events`);
  url.searchParams.set('access_token', META_CAPI_TOKEN);
  if (mode === 'dry_run' && META_TEST_EVENT_CODE) {
    url.searchParams.set('test_event_code', META_TEST_EVENT_CODE);
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), META_CAPI_TIMEOUT_MS);
  try {
    const response = await fetch(url.toString(), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ data: [eventPayload] }),
      signal: controller.signal,
    });
    const bodyText = await response.text().catch(() => '');
    if (!response.ok) {
      const error = new Error(
        `Meta CAPI responded with ${response.status} ${response.statusText}: ${bodyText || '(empty)'}`
      );
      error.status = response.status;
      error.bodyText = bodyText;
      try {
        const parsed = JSON.parse(bodyText || '{}');
        error.fbtrace_id = parsed?.error?.fbtrace_id || null;
      } catch {
        error.fbtrace_id = null;
      }
      throw error;
    }
    return { status: response.status, bodyText };
  } finally {
    clearTimeout(timer);
  }
}

async function fetchAppsScriptBatch(client) {
  await client.query('BEGIN');
  try {
    const result = await client.query(
      `SELECT submission_id, payload, attempt_count
       FROM outbox
       WHERE sheet_status = 'pending'
         AND (payload->>'destination' IS NULL OR payload->>'destination' = 'apps_script')
         AND (next_retry_at IS NULL OR next_retry_at <= NOW())
       ORDER BY next_retry_at NULLS FIRST, created_at ASC
       LIMIT $1
       FOR UPDATE SKIP LOCKED`,
      [OUTBOX_BATCH_SIZE]
    );

    const rows = result.rows || [];
    if (!rows.length) {
      await client.query('COMMIT');
      return [];
    }

    const ids = rows.map((row) => row.submission_id);
    await client.query(
      `UPDATE outbox
       SET sheet_status = 'processing',
           last_attempt_at = NOW(),
           updated_at = NOW()
       WHERE submission_id = ANY($1::text[])
         AND sheet_status = 'pending'
         AND (payload->>'destination' IS NULL OR payload->>'destination' = 'apps_script')`,
      [ids]
    );
    await client.query('COMMIT');
    return rows;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  }
}

async function fetchMetaBatch(client) {
  await client.query('BEGIN');
  try {
    const result = await client.query(
      `SELECT submission_id, payload, attempt_count
       FROM outbox
       WHERE sheet_status = 'meta_pending'
         AND payload->>'destination' = 'meta_capi'
         AND (next_retry_at IS NULL OR next_retry_at <= NOW())
       ORDER BY next_retry_at NULLS FIRST, created_at ASC
       LIMIT $1
       FOR UPDATE SKIP LOCKED`,
      [OUTBOX_BATCH_SIZE]
    );

    const rows = result.rows || [];
    if (!rows.length) {
      await client.query('COMMIT');
      return [];
    }

    const ids = rows.map((row) => row.submission_id);
    await client.query(
      `UPDATE outbox
       SET sheet_status = 'processing',
           last_attempt_at = NOW(),
           updated_at = NOW()
       WHERE submission_id = ANY($1::text[])
         AND sheet_status = 'meta_pending'
         AND payload->>'destination' = 'meta_capi'`,
      [ids]
    );
    await client.query('COMMIT');
    return rows;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  }
}

async function getOutboxMetrics(pool) {
  const pendingResult = await pool.query(
    `SELECT
       COUNT(*)::int AS pending_count,
       COALESCE(EXTRACT(EPOCH FROM (NOW() - MIN(created_at)))::int, 0) AS oldest_pending_age_sec
     FROM outbox
     WHERE sheet_status = 'pending'`
  );
  const deadResult = await pool.query(
    `SELECT COUNT(*)::int AS dead_count FROM outbox WHERE sheet_status = 'dead'`
  );
  return {
    pendingCount: pendingResult.rows[0]?.pending_count || 0,
    oldestPendingAgeSec: pendingResult.rows[0]?.oldest_pending_age_sec || 0,
    deadCount: deadResult.rows[0]?.dead_count || 0,
  };
}

async function shouldSendAlert(pool) {
  const result = await pool.query(
    `SELECT last_alert_at FROM monitor_state WHERE key = 'outbox_alert'`
  );
  const lastAlertAt = result.rows[0]?.last_alert_at;
  if (!lastAlertAt) return true;
  const elapsedMs = Date.now() - new Date(lastAlertAt).getTime();
  return elapsedMs >= ALERT_COOLDOWN_MINUTES * 60 * 1000;
}

async function setAlertSent(pool) {
  await pool.query(
    `INSERT INTO monitor_state (key, last_alert_at)
     VALUES ('outbox_alert', NOW())
     ON CONFLICT (key) DO UPDATE SET last_alert_at = NOW()`
  );
}

async function shouldSendStripeAlert(pool) {
  const result = await pool.query(
    `SELECT last_alert_at FROM monitor_state WHERE key = 'stripe_webhook_alert_last_sent'`
  );
  const lastAlertAt = result.rows[0]?.last_alert_at;
  if (!lastAlertAt) return true;
  const elapsedMs = Date.now() - new Date(lastAlertAt).getTime();
  return elapsedMs >= ALERT_COOLDOWN_MINUTES * 60 * 1000;
}

async function setStripeAlertSent(pool) {
  await pool.query(
    `INSERT INTO monitor_state (key, last_alert_at)
     VALUES ('stripe_webhook_alert_last_sent', NOW())
     ON CONFLICT (key) DO UPDATE SET last_alert_at = NOW()`
  );
}

function logRunSummary(summary) {
  const payload = {
    level: 'info',
    scope: 'outbox-replay',
    message: 'Outbox replay summary',
    timestamp: new Date().toISOString(),
    meta: summary,
  };
  console.log(JSON.stringify(payload));
}

function logAppsScriptEvent(level, message, meta) {
  const payload = {
    level,
    scope: 'apps-script',
    message,
    timestamp: new Date().toISOString(),
    meta,
  };
  console.log(JSON.stringify(payload));
}

function truncateText(value, maxLen = 1000) {
  const text = typeof value === 'string' ? value : '';
  if (!text) return '';
  return text.length > maxLen ? `${text.slice(0, maxLen)}...(truncated)` : text;
}

async function markOutboxResult(pool, entry, outcome) {
  const attemptCount = (entry.attempt_count || 0) + 1;
  if (outcome.success) {
    await pool.query(
      `UPDATE outbox
       SET sheet_status = 'sent',
           last_error = NULL,
           attempt_count = $2,
           next_retry_at = NULL,
           updated_at = NOW(),
           last_attempt_at = NOW(),
           last_http_status = $3
       WHERE submission_id = $1`,
      [entry.submission_id, attemptCount, outcome.status || null]
    );
    return;
  }

  const shouldRetry = attemptCount < OUTBOX_MAX_ATTEMPTS;
  const nextRetryAt = shouldRetry
    ? new Date(Date.now() + getNextRetryDelayMs(attemptCount)).toISOString()
    : null;
  const status = shouldRetry ? 'pending' : 'dead';

  await pool.query(
    `UPDATE outbox
     SET sheet_status = $2,
         last_error = $3,
         attempt_count = $4,
         next_retry_at = $5,
         updated_at = NOW(),
         last_attempt_at = NOW(),
         last_http_status = $6
     WHERE submission_id = $1`,
    [
      entry.submission_id,
      status,
      outcome.errorMessage || 'Unknown error',
      attemptCount,
      nextRetryAt,
      outcome.status || null,
    ]
  );
}

async function markMetaResult(pool, entry, outcome) {
  const attemptCount = (entry.attempt_count || 0) + 1;
  if (outcome.success) {
    await pool.query(
      `UPDATE outbox
       SET sheet_status = 'sent',
           last_error = NULL,
           attempt_count = $2,
           next_retry_at = NULL,
           updated_at = NOW(),
           last_attempt_at = NOW(),
           last_http_status = $3
       WHERE submission_id = $1`,
      [entry.submission_id, attemptCount, outcome.status || null]
    );
    return;
  }

  if (outcome.deferMinutes) {
    const nextRetryAt = new Date(Date.now() + outcome.deferMinutes * 60 * 1000).toISOString();
    await pool.query(
      `UPDATE outbox
       SET sheet_status = 'meta_pending',
           last_error = $2,
           attempt_count = $3,
           next_retry_at = $4,
           updated_at = NOW(),
           last_attempt_at = NOW(),
           last_http_status = $5
       WHERE submission_id = $1`,
      [
        entry.submission_id,
        outcome.errorMessage || 'Deferred',
        attemptCount,
        nextRetryAt,
        outcome.status || null,
      ]
    );
    return;
  }

  const shouldRetry = attemptCount < OUTBOX_MAX_ATTEMPTS && !outcome.forceDead;
  const nextRetryAt = shouldRetry
    ? new Date(Date.now() + getNextRetryDelayMs(attemptCount)).toISOString()
    : null;
  const status = shouldRetry ? 'meta_pending' : 'dead';

  await pool.query(
    `UPDATE outbox
     SET sheet_status = $2,
         last_error = $3,
         attempt_count = $4,
         next_retry_at = $5,
         updated_at = NOW(),
         last_attempt_at = NOW(),
         last_http_status = $6
     WHERE submission_id = $1`,
    [
      entry.submission_id,
      status,
      outcome.errorMessage || 'Unknown error',
      attemptCount,
      nextRetryAt,
      outcome.status || null,
    ]
  );
}

async function main() {
  if (!DATABASE_URL) {
    console.error('DATABASE_URL missing. Aborting replay.');
    process.exit(1);
  }
  if (!STRIPE_ALERT_TEST && !OUTBOX_MONITOR_ONLY && !APPS_SCRIPT_WEBHOOK) {
    console.error('APPS_SCRIPT_WEBHOOK missing. Aborting replay.');
    process.exit(1);
  }

  const metaMode = normalizeMetaMode(META_CAPI_MODE);

  const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: getDbSslConfig(),
  });

  try {
    await pool.query('SELECT 1');
    console.log(`DB connected: ${redactDbUrl(DATABASE_URL)}`);
    await pool.query(
      `CREATE TABLE IF NOT EXISTS monitor_state (
        key TEXT PRIMARY KEY,
        last_alert_at TIMESTAMPTZ
      )`
    );

    if (STRIPE_ALERT_TEST) {
      await sendStripeAlertEmail({
        errorCount: STRIPE_ERROR_THRESHOLD,
        windowMinutes: STRIPE_WINDOW_MINUTES,
        examples: [
          {
            event_id: 'evt_test_stripe_alert',
            type: 'checkout.session.completed',
            status: 'error',
            http_status: 500,
            error_message: 'TEST MODE',
          },
        ],
        isTest: true,
      });
      console.log('Stripe alert test email sent.');
      return;
    }

    if (ALERT_TEST) {
      const runStart = Date.now();
      await sendAlertEmail({
        pendingCount: 0,
        oldestPendingAgeSec: 0,
        deadCount: 0,
        batchPickedCount: 0,
        sentCount: 0,
        retryCount: 0,
        durationMs: Date.now() - runStart,
        isTest: true,
      });
      console.log('Alert test email sent.');
      return;
    }

    const runStart = Date.now();
    const beforeMetrics = await getOutboxMetrics(pool);
    let batch = [];
    let sentCount = 0;
    let retryCount = 0;
    let deadCount = 0;

    if (!OUTBOX_MONITOR_ONLY) {
      const client = await pool.connect();
      try {
        batch = await fetchAppsScriptBatch(client);
      } finally {
        client.release();
      }
      if (batch.length) {
        console.log(`Processing ${batch.length} outbox item(s)...`);
      } else {
        console.log('No pending outbox items.');
      }

      for (const entry of batch) {
        const basePayload = entry.payload && typeof entry.payload === 'object' ? entry.payload : {};
        const submissionId =
          basePayload.submissionId ||
          basePayload.submission_id ||
          basePayload.submissionID ||
          basePayload.id ||
          entry.submission_id ||
          null;
        const payload = { ...basePayload, submissionId };
        const payloadKeys = Object.keys(payload).sort();
        try {
          logAppsScriptEvent('info', 'Apps Script webhook attempt', {
            submissionId,
            payloadKeys,
          });
          const result = await postWithTimeout(APPS_SCRIPT_WEBHOOK, payload, APPS_SCRIPT_TIMEOUT_MS);
          await markOutboxResult(pool, entry, { success: true, status: result.status });
          logAppsScriptEvent('info', 'Apps Script webhook success', {
            submissionId,
            payloadKeys,
            status: result.status,
            body: result.bodyText || '(empty)',
          });
          sentCount += 1;
          console.log(`Sent: ${entry.submission_id}`);
        } catch (error) {
          const attemptCount = (entry.attempt_count || 0) + 1;
          const shouldRetry = attemptCount < OUTBOX_MAX_ATTEMPTS;
          if (shouldRetry) {
            retryCount += 1;
          } else {
            deadCount += 1;
          }
          await markOutboxResult(pool, entry, {
            success: false,
            status: error.status || null,
            errorMessage: error.message || String(error),
          });
          logAppsScriptEvent('error', 'Apps Script webhook failed', {
            submissionId,
            payloadKeys,
            status: error.status || null,
            body: error.bodyText || '(empty)',
            error: error.message || String(error),
          });
          console.error(`Failed: ${entry.submission_id} -> ${error.message || error}`);
        }
      }
    }

    if (!OUTBOX_MONITOR_ONLY) {
      const client = await pool.connect();
      let metaBatch = [];
      try {
        metaBatch = await fetchMetaBatch(client);
      } finally {
        client.release();
      }
      for (const entry of metaBatch) {
        const basePayload = entry.payload && typeof entry.payload === 'object' ? entry.payload : {};
        const submissionId = entry.submission_id || null;
        const sessionId = basePayload.checkout_session_id || basePayload.event?.event_id || null;
        const eventId = basePayload.event?.event_id || null;
        const status = entry.sheet_status || 'processing';
        const attemptCount = (entry.attempt_count || 0) + 1;
        const metaMode = normalizeMetaMode(META_CAPI_MODE);

        console.log(
          JSON.stringify({
            tag: 'META_SEND_ATTEMPT',
            submissionId,
            sessionId,
            eventId,
            status,
            metaMode,
            pixelIdPresent: Boolean(META_PIXEL_ID),
            tokenPresent: Boolean(META_CAPI_TOKEN),
            hasTestEventCode: Boolean(META_TEST_EVENT_CODE),
            attemptCount,
          })
        );

        if (metaMode === 'off') {
          const outcome = {
            success: false,
            status: null,
            errorMessage: 'Meta CAPI disabled',
            deferMinutes: 60,
          };
          await markMetaResult(pool, entry, outcome);
          const nextRetryAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();
          console.log(
            JSON.stringify({
              tag: 'META_SEND_FAIL',
              submissionId,
              sessionId,
              eventId,
              status: 'off',
              metaMode,
              httpStatus: null,
              responseBody: '',
              fbtrace_id: null,
              errorMessage: outcome.errorMessage,
              nextRetryAt,
              willRetry: true,
              finalStatus: 'meta_pending',
            })
          );
          continue;
        }

        if (metaMode === 'dry_run' && !META_TEST_EVENT_CODE) {
          const outcome = {
            success: false,
            status: null,
            errorMessage: 'META_TEST_EVENT_CODE missing',
            deferMinutes: 60,
          };
          await markMetaResult(pool, entry, outcome);
          const nextRetryAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();
          console.log(
            JSON.stringify({
              tag: 'META_SEND_FAIL',
              submissionId,
              sessionId,
              eventId,
              status: 'test_event_code_missing',
              metaMode,
              httpStatus: null,
              responseBody: '',
              fbtrace_id: null,
              errorMessage: outcome.errorMessage,
              nextRetryAt,
              willRetry: true,
              finalStatus: 'meta_pending',
            })
          );
          continue;
        }

        if (metaMode === 'live' && (!META_PIXEL_ID || !META_CAPI_TOKEN)) {
          const outcome = {
            success: false,
            status: null,
            errorMessage: 'META_PIXEL_ID or META_CAPI_TOKEN missing',
            deferMinutes: 60,
          };
          await markMetaResult(pool, entry, outcome);
          const nextRetryAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();
          console.log(
            JSON.stringify({
              tag: 'META_SEND_FAIL',
              submissionId,
              sessionId,
              eventId,
              status: 'config_missing',
              metaMode,
              httpStatus: null,
              responseBody: '',
              fbtrace_id: null,
              errorMessage: outcome.errorMessage,
              nextRetryAt,
              willRetry: true,
              finalStatus: 'meta_pending',
            })
          );
          continue;
        }

        if (!basePayload.event) {
          const outcome = {
            success: false,
            status: null,
            errorMessage: 'Meta payload missing',
          };
          await markMetaResult(pool, entry, outcome);
          console.log(
            JSON.stringify({
              tag: 'META_SEND_FAIL',
              submissionId,
              sessionId,
              eventId,
              status: 'payload_missing',
              metaMode,
              httpStatus: null,
              responseBody: '',
              fbtrace_id: null,
              errorMessage: outcome.errorMessage,
              nextRetryAt: null,
              willRetry: false,
              finalStatus: 'dead',
            })
          );
          continue;
        }

        try {
          const result = await postMetaCapiEvent(basePayload.event, metaMode);
          await markMetaResult(pool, entry, { success: true, status: result.status });
          console.log(
            JSON.stringify({
              tag: 'META_SEND_OK',
              submissionId,
              sessionId,
              eventId,
              metaMode,
              httpStatus: result.status,
              responseBody: truncateText(result.bodyText || '(empty)'),
              matchedTestCode: metaMode === 'dry_run' ? true : null,
            })
          );
        } catch (error) {
          const httpStatus = error.status || null;
          const isRetryable =
            httpStatus === 429 || httpStatus === null || (httpStatus >= 500 && httpStatus < 600);
          const forceDead =
            !isRetryable && (httpStatus === 400 || httpStatus === 401 || httpStatus === 403);
          const outcome = {
            success: false,
            status: httpStatus,
            errorMessage: error.message || String(error),
            forceDead,
          };
          await markMetaResult(pool, entry, outcome);
          const nextRetryAt = isRetryable
            ? new Date(Date.now() + getNextRetryDelayMs(attemptCount)).toISOString()
            : null;
          const finalStatus = isRetryable ? 'meta_pending' : 'dead';
          console.log(
            JSON.stringify({
              tag: 'META_SEND_FAIL',
              submissionId,
              sessionId,
              eventId,
              metaMode,
              httpStatus,
              responseBody: truncateText(error.bodyText || ''),
              fbtrace_id: error.fbtrace_id || null,
              errorMessage: outcome.errorMessage,
              nextRetryAt,
              willRetry: isRetryable,
              finalStatus,
            })
          );
        }
      }
    }

    const afterMetrics = await getOutboxMetrics(pool);
    const durationMs = Date.now() - runStart;
    logRunSummary({
      pending_count: beforeMetrics.pendingCount,
      oldest_pending_age_sec: beforeMetrics.oldestPendingAgeSec,
      batch_picked_count: batch.length,
      sent_count: sentCount,
      retry_count: retryCount,
      dead_count: deadCount,
      duration_ms: durationMs,
    });

    const shouldAlert =
      afterMetrics.pendingCount > 5 ||
      afterMetrics.oldestPendingAgeSec > 600 ||
      afterMetrics.deadCount > 0;

    if (shouldAlert && (await shouldSendAlert(pool))) {
      await sendAlertEmail({
        pendingCount: afterMetrics.pendingCount,
        oldestPendingAgeSec: afterMetrics.oldestPendingAgeSec,
        deadCount: afterMetrics.deadCount,
        batchPickedCount: batch.length,
        sentCount,
        retryCount,
        durationMs,
      });
      await setAlertSent(pool);
      console.log('Alert email sent.');
    }

    const stripeErrorResult = await pool.query(
      `SELECT COUNT(*)::int AS error_count
       FROM stripe_events
       WHERE received_at >= NOW() - ($1::int * INTERVAL '1 minute')
         AND (status IN ('error','invalid_signature') OR http_status >= 400)`,
      [STRIPE_WINDOW_MINUTES]
    );
    const stripeErrorCount = stripeErrorResult.rows[0]?.error_count || 0;
    if (stripeErrorCount >= STRIPE_ERROR_THRESHOLD && (await shouldSendStripeAlert(pool))) {
      const stripeExamples = await pool.query(
        `SELECT event_id, type, status, http_status, error_message
         FROM stripe_events
         WHERE received_at >= NOW() - ($1::int * INTERVAL '1 minute')
           AND (status IN ('error','invalid_signature') OR http_status >= 400)
         ORDER BY received_at DESC NULLS LAST
         LIMIT 3`,
        [STRIPE_WINDOW_MINUTES]
      );
      await sendStripeAlertEmail({
        errorCount: stripeErrorCount,
        windowMinutes: STRIPE_WINDOW_MINUTES,
        examples: stripeExamples.rows || [],
      });
      await setStripeAlertSent(pool);
      console.log('Stripe webhook alert email sent.');
    }
  } catch (error) {
    console.error(`Replay failed: ${error.message || error}`);
    process.exit(1);
  } finally {
    await pool.end().catch(() => {});
  }
}

main();
