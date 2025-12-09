require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs/promises');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const Stripe = require('stripe');
const logger = require('./logger');

const app = express();
const PORT = process.env.PORT || 3000;
const FASTLY_API_TOKEN = process.env.FASTLY_API_TOKEN;
const SELECTIONS_PATH = path.join(__dirname, 'data', 'selections.json');
const COMPLETIONS_PATH = path.join(__dirname, 'data', 'completions.json');
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
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || '';
const STRIPE_SETUP_PRICE_ID = process.env.STRIPE_SETUP_PRICE_ID || '';
const STRIPE_SUBSCRIPTION_PRICE_ID = process.env.STRIPE_SUBSCRIPTION_PRICE_ID || '';
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || '';
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

// Behind Render's proxy we need trust proxy so rate-limit and IPs work
app.set('trust proxy', true);

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

async function writeJsonFile(filePath, data, label) {
  try {
    await fs.writeFile(filePath, JSON.stringify(data, null, 2), 'utf8');
  } catch (error) {
    logger.error('json-store', `${label} write failed`, {
      filePath,
      message: error.message || error,
      code: error.code,
    });
    throw error;
  }
}

async function ensureJsonFile(filePath, fallbackValue, label) {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  try {
    await fs.access(filePath);
    return false;
  } catch (error) {
    await writeJsonFile(filePath, fallbackValue, label);
    logger.warn('json-store', `${label} file missing, created default`, { filePath });
    return true;
  }
}

async function readJsonFile(filePath, fallbackValue, label) {
  await ensureJsonFile(filePath, fallbackValue, label);
  try {
    const raw = await fs.readFile(filePath, 'utf8');
    if (!raw.trim()) {
      logger.warn('json-store', `${label} file empty, resetting`, { filePath });
      await writeJsonFile(filePath, fallbackValue, label);
      return fallbackValue;
    }
    const parsed = JSON.parse(raw);
    if (Array.isArray(fallbackValue) && Array.isArray(parsed)) {
      return parsed;
    }
    if (!Array.isArray(fallbackValue) && parsed && typeof parsed === 'object') {
      return parsed;
    }
    logger.warn('json-store', `${label} file has unexpected shape, resetting`, { filePath });
    await writeJsonFile(filePath, fallbackValue, label);
    return fallbackValue;
  } catch (error) {
    if (error instanceof SyntaxError) {
      logger.warn('json-store', `${label} file invalid JSON, resetting`, {
        filePath,
        message: error.message || error,
      });
      await writeJsonFile(filePath, fallbackValue, label);
      return fallbackValue;
    }
    logger.error('json-store', `${label} file access failed`, {
      filePath,
      message: error.message || error,
      code: error.code,
    });
    throw error;
  }
}

async function readSelections() {
  return readJsonFile(SELECTIONS_PATH, [], 'selections');
}

async function readCompletions() {
  return readJsonFile(COMPLETIONS_PATH, {}, 'completions');
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

async function forwardToWebhook(payload) {
  if (!APPS_SCRIPT_WEBHOOK) return;
  try {
    logger.info('apps-script', 'Forwarding selection to Apps Script webhook', {
      url: APPS_SCRIPT_WEBHOOK,
      sessionId: payload?.sessionId || payload?.session_id || '(none)',
      currentEmail: payload?.currentEmail || '(none)',
      chosenDomain: payload?.chosenDomain || '(none)',
      localPart: payload?.localPart || '(none)',
      timeoutMs: APPS_SCRIPT_TIMEOUT_MS,
    });
    const response = await withTimeout(
      fetch(APPS_SCRIPT_WEBHOOK, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }),
      APPS_SCRIPT_TIMEOUT_MS,
      'Webhook call'
    );
    const text = await response.text().catch(() => '');
    if (!response.ok) {
      logger.error('apps-script', 'Apps Script webhook failed', {
        url: APPS_SCRIPT_WEBHOOK,
        status: response.status,
        statusText: response.statusText,
        body: text || '(no body)',
        payload,
      });
      throw new Error(`Webhook responded with status ${response.status}`);
    }
    logger.info('apps-script', 'Apps Script webhook success', {
      status: response.status,
      body: text || '(empty)',
      payload,
    });
  } catch (error) {
    logger.error('apps-script', 'Apps Script webhook failed (non-blocking)', {
      url: APPS_SCRIPT_WEBHOOK || '(none)',
      message: error.message || error,
      name: error.name,
      timeoutMs: APPS_SCRIPT_TIMEOUT_MS,
    });
  }
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

function hasAccessContext({ sessionId, email }) {
  return Boolean((sessionId || '').trim() || (email || '').trim());
}

async function upsertPaymentStatus({ sessionId, email, paymentStatus, paymentIntent, customerEmail }) {
  const keys = getCompletionKeys({ sessionId, email: email || customerEmail });
  if (!keys.length) return;
  const store = await readCompletions();
  const patch = {
    paymentStatus: paymentStatus || null,
    paymentIntent: paymentIntent || null,
    customerEmail: customerEmail || email || null,
    paymentUpdatedAt: new Date().toISOString(),
  };

  for (const key of keys) {
    const existing = store[key] || {};
    store[key] = {
      ...existing,
      ...patch,
      meta: { ...(existing.meta || {}), ...(patch.meta || {}) },
    };
  }

  await writeJsonFile(COMPLETIONS_PATH, store, 'completions');
  logger.info('selection', 'Stripe session status cached', {
    keys,
    paymentStatus: paymentStatus || '(none)',
    paymentIntent: paymentIntent || '(none)',
  });
}

async function markCompletion({ sessionId, email, meta = {} }) {
  const keys = getCompletionKeys({ sessionId, email });
  if (!keys.length) return;
  const store = await readCompletions();
  const entry = {
    completed: true,
    completedAt: new Date().toISOString(),
    meta,
  };
  for (const key of keys) {
    const existing = store[key] || {};
    store[key] = {
      ...existing,
      ...entry,
      meta: { ...(existing.meta || {}), ...(entry.meta || {}) },
    };
  }
  await writeJsonFile(COMPLETIONS_PATH, store, 'completions');
  logger.info('selection', 'Completion guard updated', {
    keys,
    sessionId: sessionId || '(none)',
    email: email || '(none)',
  });
}

async function isCompleted({ sessionId, email }) {
  const keys = getCompletionKeys({ sessionId, email });
  if (!keys.length) return { completed: false, key: null };
  const store = await readCompletions();
  const hit = keys.find((key) => store[key]?.completed);
  return { completed: Boolean(hit), key: hit || null };
}

async function getStripeSessionStatus(sessionId) {
  if (!stripe || !sessionId) {
    return { found: false, paid: false, paymentStatus: null };
  }

  try {
    const session = await stripe.checkout.sessions.retrieve(sessionId);
    const paid = session.payment_status === 'paid';
    await upsertPaymentStatus({
      sessionId,
      paymentStatus: session.payment_status,
      paymentIntent: session.payment_intent || null,
      customerEmail: session.customer_details?.email || session.customer_email || null,
    });
    return {
      found: true,
      paid,
      paymentStatus: session.payment_status,
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
    const selections = await readSelections();
    const record = {
      domain: normalizedChosen,
      requestedDomain: normalizedRequested || null,
      localPart,
      clientEmail: clientEmail || null,
      chosenAt: new Date().toISOString(),
      hasExistingDomain: hasExistingDomain || null,
      displayName: displayName || null,
      comment: comment || null,
      fullName: fullName || null,
      company: company || null,
      sessionId: sessionId || null,
    };
    selections.push(record);
    await writeJsonFile(SELECTIONS_PATH, selections, 'selections');
    logger.info('selection', 'Selection stored', {
      chosenDomain: normalizedChosen,
      sessionId: sessionId || '(none)',
      email: clientEmail || '(none)',
      requestedDomain: normalizedRequested || null,
    });
    Promise.allSettled([
      safeSendNotification(record),
      forwardToWebhook({
        fullName: fullName || null,
        company: company || null,
        currentEmail: clientEmail || null,
        hasExistingDomain: hasExistingDomain || null,
        requestedDomain: normalizedRequested || normalizedChosen,
        chosenDomain: normalizedChosen,
        localPart,
        displayName: displayName || null,
        comment: comment || null,
      }),
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
    const context = extractStripeEventContext(null, req.body);
    await sendStripeWebhookAlert({
      eventType: context.eventType,
      sessionId: context.sessionId,
      errorMessage: error.message || String(error),
    });
    return res.status(400).send(`Webhook Error: ${error.message}`);
  }

  try {
    if (event.type === 'checkout.session.completed') {
      const session = event.data.object;
      await upsertPaymentStatus({
        sessionId: session.id,
        email: session.customer_email || session.customer_details?.email || null,
        paymentStatus: session.payment_status || session.status || null,
        paymentIntent: session.payment_intent || null,
        customerEmail: session.customer_details?.email || session.customer_email || null,
      });
      logger.info('stripe', 'Checkout session completed', {
        sessionId: session.id,
        paymentStatus: session.payment_status || session.status || '(unknown)',
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
    const context = extractStripeEventContext(event, req.body);
    await sendStripeWebhookAlert({
      eventType: context.eventType,
      sessionId: context.sessionId,
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

app.listen(PORT, () => {
  logger.info('process', 'Server ready', { port: PORT });
});
