require('dotenv').config();
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const Stripe = require('stripe');
const { Pool } = require('pg');
const logger = require('./logger');

const app = express();
const PORT = process.env.PORT || 3000;
const FASTLY_API_TOKEN = process.env.FASTLY_API_TOKEN;
const DATABASE_URL = process.env.DATABASE_URL || '';
const SENDGRID_API_KEY = process.env.SENDGRID_API_KEY || '';
const SMTP_HOST = process.env.SMTP_HOST;
const SMTP_PORT = parseInt(process.env.SMTP_PORT || '587', 10);
const SMTP_USER = process.env.SMTP_USER;
const SMTP_PASS = process.env.SMTP_PASS;
const SMTP_FROM = process.env.SMTP_FROM || SMTP_USER;
const SMTP_TO = process.env.NOTIFY_TO || 'contact@silissia.com';
const DISABLE_COMPLETION_GUARD = process.env.DISABLE_COMPLETION_GUARD === 'true';
const APPS_SCRIPT_WEBHOOK = process.env.APPS_SCRIPT_WEBHOOK || '';
const NOTIFICATION_TIMEOUT_MS = 8000;
const APPS_SCRIPT_TIMEOUT_MS = parseInt(process.env.APPS_SCRIPT_TIMEOUT_MS || '12000', 10);
const OUTBOX_POLL_INTERVAL_MS = parseInt(process.env.OUTBOX_POLL_INTERVAL_MS || '60000', 10);
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || '';
const STRIPE_SETUP_PRICE_ID = process.env.STRIPE_SETUP_PRICE_ID || '';
const STRIPE_SUBSCRIPTION_PRICE_ID = process.env.STRIPE_SUBSCRIPTION_PRICE_ID || '';
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || '';
const ADMIN_TOKEN = (process.env.ADMIN_TOKEN || '').trim();
const stripe = STRIPE_SECRET_KEY
  ? new Stripe(STRIPE_SECRET_KEY, { apiVersion: '2023-10-16' })
  : null;

if (!FASTLY_API_TOKEN) {
  logger.error('process', 'Missing FASTLY_API_TOKEN in environment', { hasToken: Boolean(FASTLY_API_TOKEN) });
  process.exit(1);
}

process.on('unhandledRejection', (reason) => {
  logger.error('process', 'Unhandled promise rejection', {
    reason: reason?.message || reason,
    stack: reason?.stack,
  });
});

process.on('uncaughtException', (error) => {
  logger.error('process', 'Uncaught exception', {
    message: error?.message || error,
    stack: error?.stack,
  });
});

// Behind Render's proxy we trust a single hop to keep rate-limit effective.
app.set('trust proxy', 1);

// Stripe webhooks need the raw body for signature verification
app.use('/webhook/stripe', express.raw({ type: 'application/json' }));

app.use(
  express.json({
    limit: '10kb',
    verify: (req, res, buf) => {
      req.rawBodyLength = buf.length;
    },
  })
);
app.use(express.static(path.join(__dirname, 'public')));

app.get('/config.js', (req, res) => {
  res.type('application/javascript').set('Cache-Control', 'no-store').send(
    `window.APP_CONFIG = ${JSON.stringify({
      disableCompletionGuard: DISABLE_COMPLETION_GUARD,
    })};`
  );
});

const availabilityKeys = ['available', 'inactive', 'undelegated'];
const domainRegex = /^[a-z0-9-]+\.[a-z]{2,24}$/;
const emailRegex =
  /^[\w.!#$%&'*+/=?^`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i;

const sendGridEnabled = Boolean(SENDGRID_API_KEY);
const mailer =
  !sendGridEnabled && SMTP_HOST && SMTP_USER && SMTP_PASS
    ? nodemailer.createTransport({
        host: SMTP_HOST,
        port: SMTP_PORT,
        secure: SMTP_PORT === 465,
        auth: { user: SMTP_USER, pass: SMTP_PASS },
        connectionTimeout: 5000,
        greetingTimeout: 5000,
        socketTimeout: 5000,
        timeout: 5000,
      })
    : null;

logger.info('process', 'SMTP config summary', {
  enabled: Boolean(mailer),
  host: SMTP_HOST || '(none)',
  port: SMTP_PORT || '(none)',
  secure: SMTP_PORT === 465,
  from: SMTP_FROM || '(none)',
  to: SMTP_TO || '(none)',
});
logger.info('process', 'SendGrid config summary', {
  enabled: sendGridEnabled,
  from: SMTP_FROM || '(none)',
  to: SMTP_TO || '(none)',
});
logger.info('process', 'Stripe config summary', {
  enabled: Boolean(stripe),
  hasSetupPrice: Boolean(STRIPE_SETUP_PRICE_ID),
  hasSubscriptionPrice: Boolean(STRIPE_SUBSCRIPTION_PRICE_ID),
  webhookConfigured: Boolean(STRIPE_WEBHOOK_SECRET),
});
logger.info('process', 'Apps Script webhook config', {
  configured: Boolean(APPS_SCRIPT_WEBHOOK),
  url: APPS_SCRIPT_WEBHOOK || '(none)',
  timeoutMs: APPS_SCRIPT_TIMEOUT_MS,
});

if (mailer) {
  withTimeout(mailer.verify(), 6000, 'SMTP verify')
    .then(() => {
      logger.info('process', 'SMTP verify success', {
        host: SMTP_HOST || '(none)',
        port: SMTP_PORT || '(none)',
        secure: SMTP_PORT === 465,
      });
    })
    .catch((error) => {
      logger.error('process', 'SMTP verify failed (non-blocking)', {
        message: error.message || error,
        code: error.code,
        response: error.response,
        command: error.command,
        host: SMTP_HOST || '(none)',
        port: SMTP_PORT || '(none)',
        secure: SMTP_PORT === 465,
      });
    });
}

const apiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Trop de requetes. Merci de reessayer dans une minute.' },
});
app.use('/api/', apiLimiter);

function getPublicBaseUrl(req) {
  const envUrl = (process.env.PUBLIC_BASE_URL || '').trim();
  if (envUrl) {
    return envUrl.replace(/\/+$/, '');
  }
  const host = req.get('host') || '';
  const protocol = req.protocol || 'https';
  return `${protocol}://${host}`;
}

function normalizeDomain(raw) {
  if (!raw) return null;
  const cleaned = raw.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '');
  if (!domainRegex.test(cleaned)) {
    return null;
  }
  return cleaned;
}

function generateVariants(domain) {
  const [label, ...rest] = domain.split('.');
  const tld = rest.join('.') || 'com';
  const altTlds = [tld, 'com', 'fr', 'net', 'org', 'io', 'co'];
  const variants = new Set();

  const labelNoHyphen = label.replace(/-/g, '');
  const labelWithHyphen =
    label.includes('-') || label.length < 8
      ? label
      : `${label.slice(0, Math.ceil(label.length / 2))}-${label.slice(Math.ceil(label.length / 2))}`;

  for (const alt of altTlds) {
    const tldCandidate = alt.startsWith('.') ? alt.slice(1) : alt;
    variants.add(`${label}.${tldCandidate}`);
    variants.add(`${labelNoHyphen}.${tldCandidate}`);
    variants.add(`${labelWithHyphen}.${tldCandidate}`);
  }

  variants.delete(domain);
  return Array.from(variants).slice(0, 12);
}

async function checkAvailability(domain) {
  const response = await fetch(
    `https://api.domainr.com/v2/status?domain=${encodeURIComponent(domain)}`,
    {
      headers: {
        'Fastly-Key': FASTLY_API_TOKEN,
        Accept: 'application/json',
      },
    }
  );

  if (!response.ok) {
    throw new Error(`Domain check failed with status ${response.status}`);
  }

  const payload = await response.json();
  const entry = payload?.status?.[0];
  if (!entry) {
    return { available: false, status: 'unknown' };
  }

  const statusText = (entry.status || '').toLowerCase();
  const summaryText = (entry.summary || '').toLowerCase();

  const available = availabilityKeys.some(
    (key) => statusText.includes(key) || summaryText.includes(key)
  );

  return {
    available,
    status: entry.status,
    summary: entry.summary,
  };
}

async function ensureDbSchema() {
  await dbQuery(
    `CREATE TABLE IF NOT EXISTS payments (
      session_id TEXT PRIMARY KEY,
      paid BOOLEAN NOT NULL DEFAULT FALSE,
      amount_total INTEGER,
      currency TEXT,
      customer_email TEXT,
      source TEXT,
      livemode BOOLEAN,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`
  );

  await dbQuery(
    `CREATE TABLE IF NOT EXISTS stripe_events (
      event_id TEXT PRIMARY KEY,
      type TEXT,
      received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      created TIMESTAMPTZ,
      status TEXT,
      http_status INTEGER,
      error_message TEXT,
      session_id TEXT,
      customer_email TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`
  );
  await dbQuery(`ALTER TABLE stripe_events ADD COLUMN IF NOT EXISTS received_at TIMESTAMPTZ`);
  await dbQuery(`ALTER TABLE stripe_events ADD COLUMN IF NOT EXISTS created TIMESTAMPTZ`);
  await dbQuery(`ALTER TABLE stripe_events ADD COLUMN IF NOT EXISTS status TEXT`);
  await dbQuery(`ALTER TABLE stripe_events ADD COLUMN IF NOT EXISTS http_status INTEGER`);
  await dbQuery(`ALTER TABLE stripe_events ADD COLUMN IF NOT EXISTS error_message TEXT`);
  await dbQuery(`ALTER TABLE stripe_events ADD COLUMN IF NOT EXISTS customer_email TEXT`);

  await dbQuery(
    `CREATE TABLE IF NOT EXISTS completions (
      completion_key TEXT PRIMARY KEY,
      completed BOOLEAN NOT NULL DEFAULT FALSE,
      completed_at TIMESTAMPTZ,
      meta JSONB,
      payment_status TEXT,
      payment_intent TEXT,
      customer_email TEXT,
      payment_updated_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`
  );

  await dbQuery(
    `CREATE TABLE IF NOT EXISTS outbox (
      submission_id TEXT PRIMARY KEY,
      payload JSONB NOT NULL,
      sheet_status TEXT NOT NULL,
      last_error TEXT,
      attempt_count INTEGER NOT NULL DEFAULT 0,
      next_retry_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_attempt_at TIMESTAMPTZ,
      last_http_status INTEGER
    )`
  );

  await dbQuery(
    `CREATE TABLE IF NOT EXISTS selections (
      submission_id TEXT PRIMARY KEY,
      domain TEXT NOT NULL,
      requested_domain TEXT,
      local_part TEXT NOT NULL,
      client_email TEXT,
      chosen_at TIMESTAMPTZ NOT NULL,
      has_existing_domain TEXT,
      display_name TEXT,
      comment TEXT,
      full_name TEXT,
      company TEXT,
      session_id TEXT,
      sheet_status TEXT,
      last_error TEXT,
      attempt_count INTEGER NOT NULL DEFAULT 0,
      next_retry_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`
  );
}

async function initDb() {
  if (!DATABASE_URL) {
    if (process.env.ALLOW_NO_DB === 'true') {
      logger.warn('db', 'DATABASE_URL missing, running without database');
      dbReady = false;
      return;
    }
    logger.error('db', 'DATABASE_URL missing, aborting startup');
    throw new Error('DATABASE_URL missing');
  }

  dbPool = new Pool({
    connectionString: DATABASE_URL,
    ssl: getDbSslConfig(),
  });

  try {
    await dbPool.query('SELECT 1');
    await ensureDbSchema();
    dbReady = true;
    logger.info('db', 'DB connected', { url: redactDbUrl(DATABASE_URL) });
  } catch (error) {
    dbReady = false;
    logger.error('db', 'DB connection failed, aborting startup', {
      message: error.message || error,
    });
    throw error;
  }
}

async function readOutbox() {
  if (!dbReady) {
    throw new Error('DB not ready');
  }
  const result = await dbQuery('SELECT * FROM outbox ORDER BY created_at ASC');
  return result.rows.map(mapOutboxRow);
}

function mapOutboxRow(row) {
  return {
    submissionId: row.submission_id,
    payload: row.payload || {},
    sheetStatus: row.sheet_status,
    lastError: row.last_error,
    attemptCount: row.attempt_count,
    nextRetryAt: row.next_retry_at ? new Date(row.next_retry_at).toISOString() : null,
    createdAt: row.created_at ? new Date(row.created_at).toISOString() : null,
    updatedAt: row.updated_at ? new Date(row.updated_at).toISOString() : null,
    lastAttemptAt: row.last_attempt_at ? new Date(row.last_attempt_at).toISOString() : null,
    lastHttpStatus: row.last_http_status,
  };
}

let outboxLock = Promise.resolve();
const outboxInFlight = new Set();

function withOutboxLock(task) {
  const next = outboxLock.then(task, task);
  outboxLock = next.catch(() => {});
  return next;
}

function withTimeout(promise, ms, label = 'Operation') {
  let timer;
  const timeoutPromise = new Promise((_, reject) => {
    timer = setTimeout(() => {
      reject(new Error(`${label} timed out after ${ms}ms`));
    }, ms);
  });
  return Promise.race([promise, timeoutPromise]).finally(() => clearTimeout(timer));
}

let dbPool = null;
let dbReady = false;

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

function getDbSslConfig() {
  if (process.env.DATABASE_SSL === 'true') {
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

async function dbQuery(text, params) {
  if (!dbPool) {
    throw new Error('DB pool not initialized');
  }
  return dbPool.query(text, params);
}

function generateSubmissionId(sessionId) {
  const base = (sessionId || '').trim();
  let randomPart;
  if (typeof crypto.randomUUID === 'function') {
    randomPart = crypto.randomUUID();
  } else {
    randomPart = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  }
  return base ? `${base}-${randomPart}` : randomPart;
}

function getNextRetryDelayMs(attemptCount) {
  const minutesByAttempt = [1, 5, 15, 60, 360];
  const index = Math.max(0, attemptCount - 1);
  const minutes = minutesByAttempt[index] ?? minutesByAttempt[minutesByAttempt.length - 1];
  return minutes * 60 * 1000;
}

async function updateSelectionStatusBySubmissionId(submissionId, patch) {
  if (!submissionId) return;
  if (!dbReady) {
    throw new Error('DB not ready');
  }
  await dbQuery(
    `UPDATE selections SET
      sheet_status = COALESCE($2, sheet_status),
      last_error = $3,
      attempt_count = COALESCE($4, attempt_count),
      next_retry_at = $5,
      updated_at = NOW()
     WHERE submission_id = $1`,
    [
      submissionId,
      patch.sheetStatus || null,
      patch.lastError || null,
      typeof patch.attemptCount === 'number' ? patch.attemptCount : null,
      patch.nextRetryAt || null,
    ]
  );
}

async function updateOutboxEntry(submissionId, patch) {
  return withOutboxLock(async () => {
    if (!dbReady) {
      throw new Error('DB not ready');
    }
    const result = await dbQuery(
      `UPDATE outbox SET
        payload = COALESCE($2, payload),
        sheet_status = COALESCE($3, sheet_status),
        last_error = $4,
        attempt_count = COALESCE($5, attempt_count),
        next_retry_at = $6,
        updated_at = NOW(),
        last_attempt_at = $7,
        last_http_status = $8
       WHERE submission_id = $1
       RETURNING *`,
      [
        submissionId,
        patch.payload || null,
        patch.sheetStatus || null,
        patch.lastError || null,
        typeof patch.attemptCount === 'number' ? patch.attemptCount : null,
        patch.nextRetryAt || null,
        patch.lastAttemptAt || null,
        patch.lastHttpStatus || null,
      ]
    );
    const row = result.rows[0];
    if (!row) return null;
    const updated = mapOutboxRow(row);
    await updateSelectionStatusBySubmissionId(submissionId, {
      sheetStatus: updated.sheetStatus,
      lastError: updated.lastError,
      attemptCount: updated.attemptCount,
      nextRetryAt: updated.nextRetryAt,
    });
    return updated;
  });
}

async function addOutboxEntry(entry) {
  return withOutboxLock(async () => {
    if (!dbReady) {
      throw new Error('DB not ready');
    }
    await dbQuery(
      `INSERT INTO outbox
        (submission_id, payload, sheet_status, last_error, attempt_count, next_retry_at, created_at, updated_at, last_attempt_at, last_http_status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
       ON CONFLICT (submission_id) DO NOTHING`,
      [
        entry.submissionId,
        entry.payload || {},
        entry.sheetStatus || 'pending',
        entry.lastError || null,
        entry.attemptCount || 0,
        entry.nextRetryAt || null,
        entry.createdAt || new Date().toISOString(),
        entry.updatedAt || new Date().toISOString(),
        entry.lastAttemptAt || null,
        entry.lastHttpStatus || null,
      ]
    );
    return entry;
  });
}

async function getOutboxEntry(submissionId) {
  if (!dbReady) {
    throw new Error('DB not ready');
  }
  const result = await dbQuery('SELECT * FROM outbox WHERE submission_id = $1', [submissionId]);
  const row = result.rows[0];
  return row ? mapOutboxRow(row) : null;
}

async function attemptOutboxSend(submissionId, reason = 'auto') {
  if (!submissionId || outboxInFlight.has(submissionId)) return;
  outboxInFlight.add(submissionId);
  try {
    const entry = await getOutboxEntry(submissionId);
    if (!entry) return;
    if (entry.sheetStatus === 'sent') return;
    if (!APPS_SCRIPT_WEBHOOK) {
      await updateOutboxEntry(submissionId, {
        sheetStatus: 'failed',
        lastError: 'Apps Script webhook not configured',
        nextRetryAt: null,
        lastAttemptAt: new Date().toISOString(),
      });
      logger.error('apps-script', 'Apps Script webhook missing, cannot send', {
        submissionId,
      });
      return;
    }

    const attemptCount = (entry.attemptCount || 0) + 1;
    const payload = { ...entry.payload, submissionId };
    const attemptStartedAt = new Date().toISOString();

    logger.info('apps-script', 'Apps Script webhook attempt', {
      submissionId,
      attemptCount,
      reason,
      timeoutMs: APPS_SCRIPT_TIMEOUT_MS,
    });

    let response;
    let responseText = '';
    try {
      response = await withTimeout(
        fetch(APPS_SCRIPT_WEBHOOK, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        }),
        APPS_SCRIPT_TIMEOUT_MS,
        'Webhook call'
      );
      responseText = await response.text().catch(() => '');
      if (!response.ok) {
        throw new Error(
          `Webhook responded with status ${response.status} ${response.statusText}: ${responseText || '(empty)'}`
        );
      }
    } catch (error) {
      const delayMs = getNextRetryDelayMs(attemptCount);
      const nextRetryAt = new Date(Date.now() + delayMs).toISOString();
      await updateOutboxEntry(submissionId, {
        sheetStatus: 'pending',
        attemptCount,
        lastError: error.message || String(error),
        nextRetryAt,
        lastAttemptAt: attemptStartedAt,
        lastHttpStatus: response?.status || null,
      });
      logger.error('apps-script', 'Apps Script webhook failed', {
        submissionId,
        attemptCount,
        status: response?.status || null,
        error: error.message || error,
        nextRetryAt,
      });
      return;
    }

    await updateOutboxEntry(submissionId, {
      sheetStatus: 'sent',
      attemptCount,
      lastError: null,
      nextRetryAt: null,
      lastAttemptAt: attemptStartedAt,
      lastHttpStatus: response?.status || null,
    });
    logger.info('apps-script', 'Apps Script webhook success', {
      submissionId,
      attemptCount,
      status: response?.status || null,
      body: responseText || '(empty)',
    });
  } finally {
    outboxInFlight.delete(submissionId);
  }
}

let retryWorkerRunning = false;

async function processDueOutbox() {
  if (retryWorkerRunning) return;
  retryWorkerRunning = true;
  try {
    const outbox = await readOutbox();
    const now = Date.now();
    const due = outbox.filter(
      (entry) =>
        entry.sheetStatus === 'pending' &&
        entry.nextRetryAt &&
        new Date(entry.nextRetryAt).getTime() <= now
    );
    for (const entry of due) {
      await attemptOutboxSend(entry.submissionId, 'retry');
    }
  } finally {
    retryWorkerRunning = false;
  }
}

function buildNotificationContent({ domain, localPart, clientEmail }) {
  const subject = `Nouveau choix de domaine : ${domain}`;
  const text = [
    'Un client a confirme un domaine.',
    `Domaine : ${domain}`,
    `Debut d'adresse : ${localPart || '(non renseigne)'}`,
    `Email client : ${clientEmail || '(non renseigne)'}`,
  ].join('\n');

  return { subject, text };
}

async function sendWithSendGrid({ subject, text, domain, clientEmail }) {
  const payload = {
    personalizations: [
      {
        to: [{ email: SMTP_TO }],
        subject,
      },
    ],
    from: { email: SMTP_FROM },
    content: [{ type: 'text/plain', value: text }],
  };

  logger.info('sendgrid-notif', 'Sending SendGrid notification', {
    to: SMTP_TO,
    from: SMTP_FROM || '(none)',
    domain: domain || '(none)',
    clientEmail: clientEmail || '(none)',
  });

  try {
    const response = await withTimeout(
      fetch('https://api.sendgrid.com/v3/mail/send', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${SENDGRID_API_KEY}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      }),
      NOTIFICATION_TIMEOUT_MS,
      'SendGrid notification'
    );

    if (!response.ok) {
      const body = await response.text().catch(() => '');
      throw new Error(
        `SendGrid responded with ${response.status} ${response.statusText}: ${body || '(empty)'}`
      );
    }

    logger.info('sendgrid-notif', 'SendGrid notification sent', {
      to: SMTP_TO,
      subject,
      status: response.status,
    });
  } catch (error) {
    logger.error('sendgrid-notif', 'SendGrid notification failed', {
      message: error.message || error,
      to: SMTP_TO,
      subject,
      domain: domain || '(none)',
      clientEmail: clientEmail || '(none)',
    });
    throw error;
  }
}

async function sendWithSmtp({ subject, text, domain, clientEmail }) {
  if (!mailer) {
    logger.warn('smtp-notif', 'SMTP settings missing, skipping email notification', {
      domain: domain || '(none)',
      clientEmail: clientEmail || '(none)',
    });
    return;
  }

  logger.info('smtp-notif', 'Sending SMTP notification', {
    to: SMTP_TO,
    from: SMTP_FROM || '(none)',
    domain: domain || '(none)',
    clientEmail: clientEmail || '(none)',
  });

  try {
    const sendPromise = mailer.sendMail({
      from: SMTP_FROM,
      to: SMTP_TO,
      subject,
      text,
    });

    const info = await withTimeout(sendPromise, NOTIFICATION_TIMEOUT_MS, 'Email notification');
    logger.info('smtp-notif', 'SMTP notification sent', {
      to: SMTP_TO,
      subject,
      accepted: info?.accepted || [],
      rejected: info?.rejected || [],
      response: info?.response || '(no response)',
    });
  } catch (error) {
    logger.error('smtp-notif', 'SMTP notification failed', {
      message: error.message || error,
      code: error.code,
      response: error.response,
      command: error.command,
      host: SMTP_HOST || '(none)',
      port: SMTP_PORT || '(none)',
      secure: SMTP_PORT === 465,
      from: SMTP_FROM || '(none)',
      to: SMTP_TO || '(none)',
      domain: domain || '(none)',
      clientEmail: clientEmail || '(none)',
    });
    throw error;
  }
}

async function sendNotification({ domain, localPart, clientEmail }) {
  const { subject, text } = buildNotificationContent({ domain, localPart, clientEmail });

  if (sendGridEnabled) {
    await sendWithSendGrid({ subject, text, domain, clientEmail });
    return;
  }

  await sendWithSmtp({ subject, text, domain, clientEmail });
}

async function safeSendNotification(payload) {
  try {
    await sendNotification(payload);
  } catch (error) {
    logger.error('sendgrid-notif', 'Notification failed (non-blocking, already logged)', {
      domain: payload?.domain || '(none)',
      clientEmail: payload?.clientEmail || '(none)',
    });
  }
}

async function sendStripeWebhookAlert({ eventType, sessionId, errorMessage }) {
  const subject = 'ALERTE : erreur webhook Stripe';
  const text = [
    'Une erreur est survenue lors du traitement du webhook Stripe.',
    `Type d'evenement : ${eventType || '(inconnu)'}`,
    `Session ID : ${sessionId || '(inconnu)'}`,
    `Erreur : ${errorMessage || '(aucun message)'}`,
  ].join('\n');

  try {
    if (sendGridEnabled) {
      await sendWithSendGrid({ subject, text });
    } else {
      await sendWithSmtp({ subject, text });
    }
    logger.info('stripe-alert', 'Stripe webhook alert email sent', {
      eventType: eventType || '(unknown)',
      sessionId: sessionId || '(unknown)',
    });
  } catch (error) {
    logger.error('stripe-alert', 'Stripe webhook alert email failed', {
      message: error.message || error,
      eventType: eventType || '(unknown)',
      sessionId: sessionId || '(unknown)',
    });
  }
}

function extractStripeEventContext(event, rawBody) {
  if (event) {
    const dataObject = event?.data?.object || {};
    return {
      eventType: event.type || null,
      sessionId:
        dataObject.id ||
        dataObject.session_id ||
        dataObject.client_reference_id ||
        dataObject.metadata?.session_id ||
        null,
    };
  }

  if (!rawBody) {
    return { eventType: null, sessionId: null };
  }

  try {
    const jsonString =
      typeof rawBody === 'string' ? rawBody : rawBody?.toString ? rawBody.toString('utf8') : '';
    const parsed = jsonString ? JSON.parse(jsonString) : null;
    const dataObject = parsed?.data?.object || {};
    return {
      eventType: parsed?.type || null,
      sessionId:
        dataObject.id ||
        dataObject.session_id ||
        dataObject.client_reference_id ||
        dataObject.metadata?.session_id ||
        null,
    };
  } catch {
    return { eventType: null, sessionId: null };
  }
}

function normalizeStripeTimestamp(value) {
  if (!value) return null;
  if (typeof value === 'number') {
    return new Date(value * 1000).toISOString();
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return date.toISOString();
}

function getStripeDataObjectContext(dataObject) {
  if (!dataObject || typeof dataObject !== 'object') {
    return { sessionId: null, customerEmail: null };
  }
  return {
    sessionId:
      dataObject.id ||
      dataObject.session_id ||
      dataObject.client_reference_id ||
      dataObject.metadata?.session_id ||
      null,
    customerEmail:
      dataObject.customer_details?.email ||
      dataObject.customer_email ||
      dataObject.receipt_email ||
      null,
  };
}

function parseStripeRawBody(rawBody) {
  if (!rawBody) return null;
  try {
    const jsonString =
      typeof rawBody === 'string' ? rawBody : rawBody?.toString ? rawBody.toString('utf8') : '';
    return jsonString ? JSON.parse(jsonString) : null;
  } catch {
    return null;
  }
}

function extractStripeEventDetails(event, rawBody) {
  if (event) {
    const dataObject = event?.data?.object || {};
    const { sessionId, customerEmail } = getStripeDataObjectContext(dataObject);
    return {
      eventId: event.id || null,
      type: event.type || null,
      created: normalizeStripeTimestamp(event.created),
      sessionId,
      customerEmail,
    };
  }

  const parsed = parseStripeRawBody(rawBody);
  const dataObject = parsed?.data?.object || {};
  const { sessionId, customerEmail } = getStripeDataObjectContext(dataObject);
  return {
    eventId: parsed?.id || null,
    type: parsed?.type || null,
    created: normalizeStripeTimestamp(parsed?.created),
    sessionId,
    customerEmail,
  };
}

function truncateErrorMessage(message, maxLength = 500) {
  if (!message) return null;
  const text = String(message);
  if (text.length <= maxLength) return text;
  return `${text.slice(0, maxLength - 3)}...`;
}

function generateStripeEventIdFallback() {
  if (typeof crypto.randomUUID === 'function') {
    return `invalid-${crypto.randomUUID()}`;
  }
  return `invalid-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

async function insertStripeEvent({
  eventId,
  type,
  created,
  sessionId,
  customerEmail,
  status,
  httpStatus,
  errorMessage,
}) {
  if (!dbReady) {
    return { inserted: true, eventId: eventId || null };
  }
  const resolvedId = eventId || generateStripeEventIdFallback();
  const result = await dbQuery(
    `INSERT INTO stripe_events
      (event_id, type, received_at, created, status, http_status, error_message, session_id, customer_email)
     VALUES ($1, $2, NOW(), $3, $4, $5, $6, $7, $8)
     ON CONFLICT (event_id) DO NOTHING`,
    [
      resolvedId,
      type || null,
      created || null,
      status || null,
      typeof httpStatus === 'number' ? httpStatus : null,
      truncateErrorMessage(errorMessage),
      sessionId || null,
      customerEmail || null,
    ]
  );
  return { inserted: result.rowCount === 1, eventId: resolvedId };
}

async function updateStripeEventStatus({ eventId, status, httpStatus, errorMessage }) {
  if (!dbReady || !eventId) return;
  await dbQuery(
    `UPDATE stripe_events
     SET status = $2,
         http_status = $3,
         error_message = $4,
         received_at = NOW()
     WHERE event_id = $1`,
    [
      eventId,
      status || null,
      typeof httpStatus === 'number' ? httpStatus : null,
      truncateErrorMessage(errorMessage),
    ]
  );
}

async function enqueueOutbox(payload, submissionId) {
  const nowIso = new Date().toISOString();
  const entry = {
    submissionId,
    payload,
    sheetStatus: 'pending',
    lastError: null,
    attemptCount: 0,
    nextRetryAt: nowIso,
    createdAt: nowIso,
    updatedAt: nowIso,
    lastAttemptAt: null,
    lastHttpStatus: null,
  };
  await addOutboxEntry(entry);
  attemptOutboxSend(submissionId, 'initial').catch(() => {});
}

app.get('/api/check', async (req, res) => {
  const rawDomain = req.query.domain;
  const normalized = normalizeDomain(rawDomain);
  if (!normalized) {
    logger.warn('domain-check', 'Invalid domain parameter', {
      rawDomain: rawDomain || '(none)',
      path: req.originalUrl,
    });
    return res.status(400).json({ error: 'Nom de domaine invalide.' });
  }

  logger.info('domain-check', 'Domain availability check started', { domain: normalized });
  try {
    const checkResult = await checkAvailability(normalized);

    if (checkResult.available) {
      logger.info('domain-check', 'Domain available', {
        domain: normalized,
        status: checkResult.status || '(none)',
      });
      return res.json({
        domain: normalized,
        available: true,
        status: checkResult.status,
        alternatives: [],
      });
    }

    const variantCandidates = generateVariants(normalized);
    const availabilityChecks = await Promise.all(
      variantCandidates.map(async (candidate) => {
        try {
          const candidateResult = await checkAvailability(candidate);
          return candidateResult.available
            ? { domain: candidate, status: candidateResult.status }
            : null;
        } catch {
          return null;
        }
      })
    );

    const alternatives = availabilityChecks.filter(Boolean);
    const shortAlternatives = alternatives.slice(0, 5).map((item) => item?.domain || '(unknown)');

    logger.info('domain-check', 'Domain unavailable, proposing alternatives', {
      domain: normalized,
      status: checkResult.status || '(none)',
      alternatives: shortAlternatives,
    });

    return res.json({
      domain: normalized,
      available: false,
      status: checkResult.status,
      alternatives,
    });
  } catch (error) {
    logger.error('domain-check', 'Domain availability check failed', {
      domain: normalized,
      message: error.message || error,
    });
    return res.status(502).json({ error: 'Impossible de verifier le domaine.' });
  }
});

function validateLocalPart(value) {
  const local = (value || '').toLowerCase();
  if (!local || local.length > 40 || !/^[a-z0-9-]+$/.test(local)) {
    return null;
  }
  return local;
}

function getCompletionKeys({ sessionId, email }) {
  const keys = [];
  const bySession = (sessionId || '').trim();
  const byEmail = (email || '').trim().toLowerCase();

  if (bySession) {
    keys.push(`session:${bySession}`);
  } else if (byEmail) {
    keys.push(`email:${byEmail}`);
  }
  return keys;
}

function getExpectedStripeLivemode() {
  if (!STRIPE_SECRET_KEY) return null;
  if (STRIPE_SECRET_KEY.startsWith('sk_test_')) return false;
  if (STRIPE_SECRET_KEY.startsWith('sk_live_')) return true;
  return null;
}

function getExpectedPriceIds() {
  return [STRIPE_SETUP_PRICE_ID, STRIPE_SUBSCRIPTION_PRICE_ID].filter(Boolean);
}

function validateStripeSession(session) {
  if (!session) return { ok: false, errors: ['missing_session'] };
  const errors = [];
  const expectedLivemode = getExpectedStripeLivemode();
  if (expectedLivemode !== null && session.livemode !== expectedLivemode) {
    errors.push('livemode_mismatch');
  }

  const expectedPriceIds = getExpectedPriceIds();
  if (expectedPriceIds.length) {
    const lineItems = session.line_items?.data || [];
    const priceIds = lineItems.map((item) => item.price?.id).filter(Boolean);
    const hasMatch = priceIds.some((id) => expectedPriceIds.includes(id));
    if (!hasMatch) {
      errors.push('price_mismatch');
    }
  }

  return { ok: errors.length === 0, errors };
}

async function ensureStripeSessionWithLineItems(sessionId, session) {
  const expectedPriceIds = getExpectedPriceIds();
  const hasLineItems = Boolean(session?.line_items?.data?.length);
  if (!stripe || !sessionId || !expectedPriceIds.length || hasLineItems) {
    return session;
  }
  try {
    return await stripe.checkout.sessions.retrieve(sessionId, {
      expand: ['line_items.data.price'],
    });
  } catch (error) {
    logger.warn('stripe', 'Stripe session expand failed', {
      sessionId,
      message: error.message || error,
    });
    return session;
  }
}

async function upsertPaymentRecord({
  sessionId,
  paid,
  amountTotal,
  currency,
  customerEmail,
  source,
  livemode,
}) {
  if (!dbReady || !sessionId) return;
  await dbQuery(
    `INSERT INTO payments
      (session_id, paid, amount_total, currency, customer_email, source, livemode)
     VALUES ($1, $2, $3, $4, $5, $6, $7)
     ON CONFLICT (session_id) DO UPDATE SET
      paid = EXCLUDED.paid,
      amount_total = EXCLUDED.amount_total,
      currency = EXCLUDED.currency,
      customer_email = EXCLUDED.customer_email,
      source = EXCLUDED.source,
      livemode = EXCLUDED.livemode,
      updated_at = NOW()`,
    [
      sessionId,
      Boolean(paid),
      amountTotal || null,
      currency || null,
      customerEmail || null,
      source || null,
      typeof livemode === 'boolean' ? livemode : null,
    ]
  );
}

async function recordStripeEvent(event) {
  const details = extractStripeEventDetails(event, null);
  return insertStripeEvent({
    ...details,
    status: 'processed',
    httpStatus: 200,
  });
}

function hasAccessContext({ sessionId, email }) {
  return Boolean((sessionId || '').trim() || (email || '').trim());
}

function requireAdmin(req, res, next) {
  if (!ADMIN_TOKEN) {
    logger.error('admin', 'Admin token missing, admin route disabled');
    return res.status(503).json({ error: 'Admin non configure.' });
  }
  const header = req.headers.authorization || '';
  const bearer = header.toLowerCase().startsWith('bearer ')
    ? header.slice(7).trim()
    : '';
  const token = bearer || req.headers['x-admin-token'] || '';
  if (token !== ADMIN_TOKEN) {
    logger.warn('admin', 'Admin access denied', { path: req.originalUrl });
    return res.status(401).json({ error: 'Non autorise.' });
  }
  return next();
}

async function upsertPaymentStatus({ sessionId, email, paymentStatus, paymentIntent, customerEmail }) {
  const keys = getCompletionKeys({ sessionId, email: email || customerEmail });
  if (!keys.length) return;
  const patch = {
    paymentStatus: paymentStatus || null,
    paymentIntent: paymentIntent || null,
    customerEmail: customerEmail || email || null,
    paymentUpdatedAt: new Date().toISOString(),
  };

  if (!dbReady) {
    throw new Error('DB not ready');
  }
  for (const key of keys) {
    await dbQuery(
      `INSERT INTO completions
        (completion_key, payment_status, payment_intent, customer_email, payment_updated_at)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (completion_key) DO UPDATE SET
        payment_status = EXCLUDED.payment_status,
        payment_intent = EXCLUDED.payment_intent,
        customer_email = EXCLUDED.customer_email,
        payment_updated_at = EXCLUDED.payment_updated_at,
        updated_at = NOW()`,
      [key, patch.paymentStatus, patch.paymentIntent, patch.customerEmail, patch.paymentUpdatedAt]
    );
  }

  logger.info('selection', 'Stripe session status cached', {
    keys,
    paymentStatus: paymentStatus || '(none)',
    paymentIntent: paymentIntent || '(none)',
  });
}

async function markCompletion({ sessionId, email, meta = {} }) {
  const keys = getCompletionKeys({ sessionId, email });
  if (!keys.length) return;
  const entry = {
    completed: true,
    completedAt: new Date().toISOString(),
    meta,
  };

  if (!dbReady) {
    throw new Error('DB not ready');
  }
  for (const key of keys) {
    const existing = await dbQuery('SELECT meta FROM completions WHERE completion_key = $1', [
      key,
    ]);
    const existingMeta = existing.rows[0]?.meta || {};
    const mergedMeta = { ...existingMeta, ...(entry.meta || {}) };
    await dbQuery(
      `INSERT INTO completions
        (completion_key, completed, completed_at, meta)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (completion_key) DO UPDATE SET
        completed = EXCLUDED.completed,
        completed_at = EXCLUDED.completed_at,
        meta = EXCLUDED.meta,
        updated_at = NOW()`,
      [key, entry.completed, entry.completedAt, mergedMeta]
    );
  }
  logger.info('selection', 'Completion guard updated', {
    keys,
    sessionId: sessionId || '(none)',
    email: email || '(none)',
  });
}

async function isCompleted({ sessionId, email }) {
  const keys = getCompletionKeys({ sessionId, email });
  if (!keys.length) return { completed: false, key: null };
  if (!dbReady) {
    throw new Error('DB not ready');
  }
  const result = await dbQuery(
    'SELECT completion_key, completed FROM completions WHERE completion_key = ANY($1)',
    [keys]
  );
  const hit = result.rows.find((row) => row.completed);
  if (hit) {
    return { completed: true, key: hit.completion_key };
  }
  return { completed: false, key: null };
}

async function getStripeSessionStatus(sessionId) {
  if (!stripe || !sessionId) {
    return { found: false, paid: false, paymentStatus: null };
  }

  if (dbReady) {
    const existing = await dbQuery('SELECT * FROM payments WHERE session_id = $1', [sessionId]);
    const payment = existing.rows[0];
    if (payment?.paid) {
      return { found: true, paid: true, paymentStatus: 'paid', session: null };
    }
  }

  try {
    const session = await stripe.checkout.sessions.retrieve(sessionId, {
      expand: ['line_items.data.price'],
    });
    const validation = validateStripeSession(session);
    if (!validation.ok) {
      logger.warn('stripe', 'Stripe session validation failed', {
        sessionId,
        reasons: validation.errors,
      });
      return { found: true, paid: false, paymentStatus: 'invalid', session };
    }

    const paid = session.payment_status === 'paid' || session.status === 'complete';
    if (paid) {
      await upsertPaymentRecord({
        sessionId,
        paid: true,
        amountTotal: session.amount_total || null,
        currency: session.currency || null,
        customerEmail: session.customer_details?.email || session.customer_email || null,
        source: 'fallback_api',
        livemode: session.livemode,
      });
      await upsertPaymentStatus({
        sessionId,
        paymentStatus: session.payment_status || session.status || null,
        paymentIntent: session.payment_intent || null,
        customerEmail: session.customer_details?.email || session.customer_email || null,
      });
    }

    return {
      found: true,
      paid,
      paymentStatus: session.payment_status || session.status || null,
      session,
    };
  } catch (error) {
    logger.error('stripe', 'Stripe session lookup failed', {
      sessionId,
      message: error.message || error,
      type: error?.type,
    });
    return { found: false, paid: false, paymentStatus: null };
  }
}

app.get('/api/completion', async (req, res) => {
  const sessionId = (req.query.session_id || req.query.token || '').trim();
  const email = (req.query.email || '').trim().toLowerCase();

  if (!DISABLE_COMPLETION_GUARD && !hasAccessContext({ sessionId, email })) {
    logger.warn('selection', 'Completion check denied: missing context', {
      path: req.originalUrl,
      sessionId: sessionId || '(none)',
      email: email || '(none)',
    });
    return res.status(400).json({ error: 'Acces non valide.' });
  }

  try {
    const { completed, key } = await isCompleted({ sessionId, email });
    const stripeStatus = sessionId ? await getStripeSessionStatus(sessionId) : null;
    if (!DISABLE_COMPLETION_GUARD && !stripeStatus?.paid) {
      logger.warn('selection', 'Completion check denied: unpaid session', {
        sessionId: sessionId || '(none)',
        email: email || '(none)',
        paymentStatus: stripeStatus?.paymentStatus || '(none)',
      });
      return res.status(402).json({ error: 'Paiement requis.' });
    }
    if (completed) {
      logger.warn('selection', 'Completion already marked', {
        sessionId: sessionId || '(none)',
        email: email || '(none)',
        key: key || '(none)',
        path: req.originalUrl,
      });
    }
    return res.json({
      completed,
      paymentStatus: stripeStatus?.paymentStatus || null,
      paid: Boolean(stripeStatus?.paid),
    });
  } catch (error) {
    logger.error('selection', 'Completion lookup failed', {
      sessionId: sessionId || '(none)',
      email: email || '(none)',
      path: req.originalUrl,
      message: error.message || error,
    });
    return res.status(500).json({ error: 'Erreur interne.' });
  }
});

app.post('/api/selection', async (req, res) => {
  const normalizedChosen = normalizeDomain(req.body?.chosenDomain || req.body?.domain);
  const normalizedRequested = normalizeDomain(
    req.body?.requestedDomain || req.body?.domain || req.body?.chosenDomain
  );
  const localPart = validateLocalPart(req.body?.localPart);
  const honeypot = (req.body?.honeypot || '').trim();
  const clientEmail = (req.body?.currentEmail || req.body?.clientEmail || '')
    .trim()
    .toLowerCase();
  const sessionId = (req.body?.sessionId || '').trim();
  const hasExistingDomain = (req.body?.hasExistingDomain || '').trim();
  const displayName = (req.body?.displayName || '').trim();
  const comment = (req.body?.comment || '').trim();
  const fullName = (req.body?.fullName || '').trim();
  const company = (req.body?.company || '').trim();

  logger.info('selection', 'Selection payload received', {
    sessionId: sessionId || '(none)',
    currentEmail: clientEmail || '(none)',
    chosenDomain: normalizedChosen || req.body?.chosenDomain || '(none)',
    requestedDomain: normalizedRequested || req.body?.requestedDomain || '(none)',
    localPart: localPart || '(invalid)',
    path: req.originalUrl,
  });

  if (req.rawBodyLength && req.rawBodyLength > 10240) {
    logger.warn('selection', 'Selection rejected: payload too large', {
      rawBodyLength: req.rawBodyLength,
      path: req.originalUrl,
    });
    return res.status(400).json({ error: 'Donnees invalides.' });
  }
  if (honeypot) {
    logger.warn('selection', 'Selection rejected: honeypot triggered', { path: req.originalUrl });
    return res.status(400).json({ error: 'Donnees invalides.' });
  }
  if (!normalizedChosen || !localPart) {
    logger.warn('selection', 'Selection rejected: invalid domain or local part', {
      chosenDomain: req.body?.chosenDomain || '(none)',
      normalizedChosen: normalizedChosen || '(invalid)',
      localPart: localPart || '(invalid)',
      path: req.originalUrl,
    });
    return res.status(400).json({ error: 'Donnees invalides.' });
  }
  if (clientEmail && !emailRegex.test(clientEmail)) {
    logger.warn('selection', 'Selection rejected: invalid client email', {
      clientEmail: clientEmail || '(none)',
      path: req.originalUrl,
    });
    return res.status(400).json({ error: 'Donnees invalides.' });
  }

  if (!DISABLE_COMPLETION_GUARD) {
    const { completed, key } = await isCompleted({ sessionId, email: clientEmail });
    if (completed) {
      logger.warn('selection', 'Form already completed', {
        sessionId: sessionId || '(none)',
        email: clientEmail || '(none)',
        completionKey: key || '(none)',
        path: req.originalUrl,
      });
      return res.status(400).json({ error: 'Formulaire deja complete.' });
    }
    if (!hasAccessContext({ sessionId, email: clientEmail })) {
      logger.warn('selection', 'Selection rejected: missing context', {
        sessionId: sessionId || '(none)',
        email: clientEmail || '(none)',
        path: req.originalUrl,
      });
      return res.status(400).json({ error: 'Acces non valide.' });
    }
    if (!sessionId) {
      logger.warn('selection', 'Selection rejected: missing Stripe session', {
        sessionId: '(none)',
        email: clientEmail || '(none)',
        path: req.originalUrl,
      });
      return res.status(400).json({ error: 'Acces non valide.' });
    }

    const stripeStatus = await getStripeSessionStatus(sessionId);
    if (!stripeStatus?.paid) {
      logger.warn('selection', 'Selection rejected: unpaid session', {
        sessionId: sessionId || '(none)',
        email: clientEmail || '(none)',
        paymentStatus: stripeStatus?.paymentStatus || '(none)',
        path: req.originalUrl,
      });
      return res.status(402).json({ error: 'Paiement requis.' });
    }
  }

  try {
    const submissionId = generateSubmissionId(sessionId);
    const nowIso = new Date().toISOString();
    const record = {
      domain: normalizedChosen,
      requestedDomain: normalizedRequested || null,
      localPart,
      clientEmail: clientEmail || null,
      chosenAt: nowIso,
      hasExistingDomain: hasExistingDomain || null,
      displayName: displayName || null,
      comment: comment || null,
      fullName: fullName || null,
      company: company || null,
      sessionId: sessionId || null,
      submissionId,
      sheetStatus: 'pending',
      lastError: null,
      attemptCount: 0,
      nextRetryAt: nowIso,
    };
    if (!dbReady) {
      if (process.env.ALLOW_NO_DB === 'true') {
        logger.warn('selection', 'DB not ready, skipping persistence (local mode)', {
          submissionId,
          chosenDomain: normalizedChosen,
          email: clientEmail || '(none)',
        });
        return res.json({ success: true, skippedDb: true });
      }
      throw new Error('DB not ready');
    }
    await dbQuery(
      `INSERT INTO selections
        (submission_id, domain, requested_domain, local_part, client_email, chosen_at, has_existing_domain, display_name, comment, full_name, company, session_id, sheet_status, last_error, attempt_count, next_retry_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
      [
        record.submissionId,
        record.domain,
        record.requestedDomain,
        record.localPart,
        record.clientEmail,
        record.chosenAt,
        record.hasExistingDomain,
        record.displayName,
        record.comment,
        record.fullName,
        record.company,
        record.sessionId,
        record.sheetStatus,
        record.lastError,
        record.attemptCount,
        record.nextRetryAt,
      ]
    );
    logger.info('selection', 'Selection stored', {
      chosenDomain: normalizedChosen,
      sessionId: sessionId || '(none)',
      email: clientEmail || '(none)',
      requestedDomain: normalizedRequested || null,
      submissionId,
    });
    Promise.allSettled([
      safeSendNotification(record),
      enqueueOutbox(
        {
          fullName: fullName || null,
          company: company || null,
          currentEmail: clientEmail || null,
          hasExistingDomain: hasExistingDomain || null,
          requestedDomain: normalizedRequested || normalizedChosen,
          chosenDomain: normalizedChosen,
          localPart,
          displayName: displayName || null,
          comment: comment || null,
          sessionId: sessionId || null,
        },
        submissionId
      ),
    ]).catch(() => {});
    if (!DISABLE_COMPLETION_GUARD) {
      await markCompletion({
        sessionId,
        email: clientEmail,
        meta: {
          domain: normalizedChosen,
          requestedDomain: normalizedRequested || null,
          hasExistingDomain: hasExistingDomain || null,
          displayName: displayName || null,
          fullName: fullName || null,
          company: company || null,
          ip: req.ip,
          userAgent: req.headers['user-agent'] || '',
        },
      });
    }

    return res.json({ success: true });
  } catch (error) {
    logger.error('selection', 'Selection save failed', {
      message: error.message || error,
      chosenDomain: normalizedChosen,
      requestedDomain: normalizedRequested || '(none)',
      sessionId: sessionId || '(none)',
      clientEmail: clientEmail || '(none)',
      path: req.originalUrl,
    });
    return res.status(500).json({ error: "Impossible d'enregistrer le choix." });
  }
});

app.get('/admin/outbox', requireAdmin, async (req, res) => {
  try {
    const outbox = await readOutbox();
    const pending = outbox.filter((entry) => entry.sheetStatus === 'pending');
    const failed = outbox.filter((entry) => entry.sheetStatus === 'failed');
    return res.json({
      pendingCount: pending.length,
      failedCount: failed.length,
      items: [...pending, ...failed],
    });
  } catch (error) {
    logger.error('admin', 'Outbox list failed', {
      message: error.message || error,
    });
    return res.status(500).json({ error: 'Erreur interne.' });
  }
});

app.post('/admin/replay-sheets', requireAdmin, async (req, res) => {
  try {
    const outbox = await readOutbox();
    const pending = outbox.filter((entry) => entry.sheetStatus === 'pending');
    const nowIso = new Date().toISOString();
    await Promise.all(
      pending.map((entry) =>
        updateOutboxEntry(entry.submissionId, {
          nextRetryAt: nowIso,
        })
      )
    );
    pending.forEach((entry) => {
      attemptOutboxSend(entry.submissionId, 'manual').catch(() => {});
    });
    return res.json({ replayed: pending.length });
  } catch (error) {
    logger.error('admin', 'Outbox replay failed', {
      message: error.message || error,
    });
    return res.status(500).json({ error: 'Erreur interne.' });
  }
});

app.post('/webhook/stripe', async (req, res) => {
  if (!stripe || !STRIPE_WEBHOOK_SECRET) {
    logger.warn('stripe', 'Webhook received but Stripe is not configured', {
      hasStripe: Boolean(stripe),
      hasWebhookSecret: Boolean(STRIPE_WEBHOOK_SECRET),
    });
    return res.status(400).send('Stripe non configure');
  }

  const signature = req.headers['stripe-signature'];
  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, signature, STRIPE_WEBHOOK_SECRET);
  } catch (error) {
    logger.error('stripe', 'Webhook signature verification failed', {
      message: error.message || error,
      type: error?.type,
    });
    const details = extractStripeEventDetails(null, req.body);
    await insertStripeEvent({
      ...details,
      status: 'invalid_signature',
      httpStatus: 400,
      errorMessage: error.message || String(error),
    });
    return res.status(400).send(`Webhook Error: ${error.message}`);
  }

  const details = extractStripeEventDetails(event, null);
  const recorded = await insertStripeEvent({
    ...details,
    status: 'processed',
    httpStatus: 200,
  });
  if (!recorded.inserted) {
    await updateStripeEventStatus({
      eventId: recorded.eventId,
      status: 'duplicate',
      httpStatus: 200,
    });
    logger.info('stripe', 'Webhook duplicate ignored', {
      eventId: event.id,
      type: event.type,
    });
    return res.json({ received: true, duplicate: true });
  }

  try {
    if (
      event.type === 'checkout.session.completed' ||
      event.type === 'checkout.session.async_payment_succeeded'
    ) {
      let session = event.data.object;
      session = await ensureStripeSessionWithLineItems(session.id, session);
      const validation = validateStripeSession(session);
      if (!validation.ok) {
        logger.warn('stripe', 'Webhook session validation failed', {
          sessionId: session.id,
          type: event.type,
          reasons: validation.errors,
        });
        return res.json({ received: true, ignored: true });
      }

      const paid =
        session.payment_status === 'paid' ||
        session.status === 'complete' ||
        event.type === 'checkout.session.async_payment_succeeded';

      if (paid) {
        await upsertPaymentRecord({
          sessionId: session.id,
          paid: true,
          amountTotal: session.amount_total || null,
          currency: session.currency || null,
          customerEmail: session.customer_details?.email || session.customer_email || null,
          source: 'webhook',
          livemode: session.livemode,
        });
        await upsertPaymentStatus({
          sessionId: session.id,
          email: session.customer_email || session.customer_details?.email || null,
          paymentStatus: session.payment_status || session.status || null,
          paymentIntent: session.payment_intent || null,
          customerEmail: session.customer_details?.email || session.customer_email || null,
        });
      }

      logger.info('stripe', 'Checkout session processed', {
        sessionId: session.id,
        paymentStatus: session.payment_status || session.status || '(unknown)',
        paid,
        type: event.type,
      });
    } else {
      logger.info('stripe', 'Webhook received (ignored type)', { type: event.type });
    }

    return res.json({ received: true });
  } catch (error) {
    logger.error('stripe', 'Webhook handling failed', {
      message: error.message || error,
      type: error?.type,
      eventType: event?.type,
    });
    await updateStripeEventStatus({
      eventId: recorded.eventId,
      status: 'error',
      httpStatus: 500,
      errorMessage: error.message || String(error),
    });
    return res.status(500).send('Webhook handler error');
  }
});

app.use((err, req, res, next) => {
  logger.error('express', 'Unhandled application error', {
    path: req.originalUrl,
    method: req.method,
    message: err?.message || err,
    stack: err?.stack,
  });
  if (res.headersSent) {
    return next(err);
  }
  return res.status(500).json({ error: 'Erreur interne.' });
});

// Serve the frontend for any other route (root or refresh)
app.use((req, res) => {
  if (req.path === '/merci') {
    return res.sendFile(path.join(__dirname, 'public', 'merci.html'));
  }
  if (req.path === '/deja-complete') {
    return res.sendFile(path.join(__dirname, 'public', 'deja-complete.html'));
  }
  if (req.path === '/acces-non-valide') {
    return res.sendFile(path.join(__dirname, 'public', 'acces-non-valide.html'));
  }
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

async function startServer() {
  await initDb();
  if (dbReady) {
    setInterval(() => {
      processDueOutbox().catch(() => {});
    }, OUTBOX_POLL_INTERVAL_MS);
    processDueOutbox().catch(() => {});
  } else {
    logger.warn('db', 'Outbox processing disabled (DB not ready)');
  }

  app.listen(PORT, () => {
    logger.info('process', 'Server ready', { port: PORT });
  });
}

startServer().catch((error) => {
  logger.error('process', 'Startup failed', { message: error.message || error });
  process.exit(1);
});
