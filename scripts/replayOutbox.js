const { Pool } = require('pg');
const nodemailer = require('nodemailer');

const DATABASE_URL = process.env.DATABASE_URL || '';
const APPS_SCRIPT_WEBHOOK = process.env.APPS_SCRIPT_WEBHOOK || '';
const APPS_SCRIPT_TIMEOUT_MS = parseInt(process.env.APPS_SCRIPT_TIMEOUT_MS || '12000', 10);
const OUTBOX_BATCH_SIZE = parseInt(process.env.OUTBOX_BATCH_SIZE || '20', 10);
const OUTBOX_MAX_ATTEMPTS = parseInt(process.env.OUTBOX_MAX_ATTEMPTS || '5', 10);
const DATABASE_SSL = process.env.DATABASE_SSL || '';
const OUTBOX_MONITOR_ONLY = process.env.OUTBOX_MONITOR_ONLY === 'true';
const ALERT_TEST = process.env.ALERT_TEST === 'true';
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
      throw error;
    }
    return { status: response.status, bodyText };
  } finally {
    clearTimeout(timer);
  }
}

async function fetchBatch(client) {
  await client.query('BEGIN');
  try {
    const result = await client.query(
      `SELECT submission_id, payload, attempt_count
       FROM outbox
       WHERE sheet_status = 'pending'
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
       WHERE submission_id = ANY($1::text[])`,
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

async function main() {
  if (!DATABASE_URL) {
    console.error('DATABASE_URL missing. Aborting replay.');
    process.exit(1);
  }
  if (!OUTBOX_MONITOR_ONLY && !APPS_SCRIPT_WEBHOOK) {
    console.error('APPS_SCRIPT_WEBHOOK missing. Aborting replay.');
    process.exit(1);
  }

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
        batch = await fetchBatch(client);
      } finally {
        client.release();
      }
      if (batch.length) {
        console.log(`Processing ${batch.length} outbox item(s)...`);
      } else {
        console.log('No pending outbox items.');
      }

      for (const entry of batch) {
        try {
          await postWithTimeout(APPS_SCRIPT_WEBHOOK, entry.payload, APPS_SCRIPT_TIMEOUT_MS);
          await markOutboxResult(pool, entry, { success: true, status: 200 });
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
          console.error(`Failed: ${entry.submission_id} -> ${error.message || error}`);
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
  } catch (error) {
    console.error(`Replay failed: ${error.message || error}`);
    process.exit(1);
  } finally {
    await pool.end().catch(() => {});
  }
}

main();
