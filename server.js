require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs/promises');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');

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
const WEBHOOK_TIMEOUT_MS = 5000;

if (!FASTLY_API_TOKEN) {
  console.error('Missing FASTLY_API_TOKEN in .env');
  process.exit(1);
}

// Behind Render's proxy we need trust proxy so rate-limit and IPs work
app.set('trust proxy', true);

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

console.log('SMTP config summary', {
  enabled: Boolean(mailer),
  host: SMTP_HOST || '(none)',
  port: SMTP_PORT || '(none)',
  secure: SMTP_PORT === 465,
  from: SMTP_FROM || '(none)',
  to: SMTP_TO || '(none)',
});
console.log('SendGrid config summary', {
  enabled: sendGridEnabled,
  from: SMTP_FROM || '(none)',
  to: SMTP_TO || '(none)',
});
console.log('Apps Script webhook', {
  configured: Boolean(APPS_SCRIPT_WEBHOOK),
  url: APPS_SCRIPT_WEBHOOK || '(none)',
  timeoutMs: WEBHOOK_TIMEOUT_MS,
});

if (mailer) {
  withTimeout(mailer.verify(), 6000, 'SMTP verify')
    .then(() => {
      console.log('SMTP verify success (connection OK)');
    })
    .catch((error) => {
      console.error('SMTP verify failed (non-blocking)', {
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

async function ensureFile(filePath, defaultContent) {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  try {
    await fs.access(filePath);
  } catch {
    await fs.writeFile(filePath, defaultContent, 'utf8');
  }
}

async function readJsonFile(filePath, fallbackValue, label) {
  await ensureFile(filePath, JSON.stringify(fallbackValue, null, 2));
  try {
    const raw = await fs.readFile(filePath, 'utf8');
    if (!raw.trim()) {
      await fs.writeFile(filePath, JSON.stringify(fallbackValue, null, 2), 'utf8');
      return fallbackValue;
    }
    const parsed = JSON.parse(raw);
    if (Array.isArray(fallbackValue) && Array.isArray(parsed)) {
      return parsed;
    }
    if (!Array.isArray(fallbackValue) && parsed && typeof parsed === 'object') {
      return parsed;
    }
    console.error(`${label} file has unexpected shape, resetting`, { filePath });
    await fs.writeFile(filePath, JSON.stringify(fallbackValue, null, 2), 'utf8');
    return fallbackValue;
  } catch (error) {
    console.error(`${label} file unreadable, resetting`, { filePath, error: error.message });
    await fs.writeFile(filePath, JSON.stringify(fallbackValue, null, 2), 'utf8');
    return fallbackValue;
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

async function sendWithSendGrid({ subject, text }) {
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

    console.log('SendGrid notification sent', {
      to: SMTP_TO,
      subject,
      status: response.status,
    });
  } catch (error) {
    console.error('SendGrid notification failed', {
      message: error.message || error,
      to: SMTP_TO,
      subject,
    });
    throw error;
  }
}

async function sendWithSmtp({ subject, text, domain, clientEmail }) {
  if (!mailer) {
    console.warn('SMTP settings missing, skipping email notification.');
    return;
  }

  try {
    const sendPromise = mailer.sendMail({
      from: SMTP_FROM,
      to: SMTP_TO,
      subject,
      text,
    });

    const info = await withTimeout(sendPromise, NOTIFICATION_TIMEOUT_MS, 'Email notification');
    console.log('Notification email sent', {
      to: SMTP_TO,
      subject,
      accepted: info?.accepted || [],
      rejected: info?.rejected || [],
      response: info?.response || '(no response)',
    });
  } catch (error) {
    console.error('SMTP notification failed', {
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
    await sendWithSendGrid({ subject, text });
    return;
  }

  await sendWithSmtp({ subject, text, domain, clientEmail });
}

async function safeSendNotification(payload) {
  try {
    await sendNotification(payload);
  } catch (error) {
    console.error('Notification failed (non-blocking, already logged)', {
      domain: payload?.domain,
      clientEmail: payload?.clientEmail || '(none)',
    });
  }
}

async function forwardToWebhook(payload) {
  if (!APPS_SCRIPT_WEBHOOK) return;
  try {
    console.log('Calling webhook URL:', APPS_SCRIPT_WEBHOOK);
    const response = await withTimeout(
      fetch(APPS_SCRIPT_WEBHOOK, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }),
      WEBHOOK_TIMEOUT_MS,
      'Webhook call'
    );
    const text = await response.text().catch(() => '');
    if (!response.ok) {
      console.error('Webhook call failed', {
        url: APPS_SCRIPT_WEBHOOK,
        status: response.status,
        statusText: response.statusText,
        body: text || '(no body)',
        payload,
      });
      throw new Error(`Webhook responded with status ${response.status}`);
    }
    console.log('Webhook success', { status: response.status, body: text || '(empty)', payload });
  } catch (error) {
    console.error('Webhook forwarding failed (non-blocking):', {
      url: APPS_SCRIPT_WEBHOOK || '(none)',
      error: error.message || error,
      name: error.name,
      timeoutMs: WEBHOOK_TIMEOUT_MS,
    });
  }
}

app.get('/api/check', async (req, res) => {
  const normalized = normalizeDomain(req.query.domain);
  if (!normalized) {
    return res.status(400).json({ error: 'Nom de domaine invalide.' });
  }

  try {
    const checkResult = await checkAvailability(normalized);

    if (checkResult.available) {
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

    return res.json({
      domain: normalized,
      available: false,
      status: checkResult.status,
      alternatives,
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Impossible de verifier le domaine.' });
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
    store[key] = entry;
  }
  await fs.writeFile(COMPLETIONS_PATH, JSON.stringify(store, null, 2), 'utf8');
}

async function isCompleted({ sessionId, email }) {
  const keys = getCompletionKeys({ sessionId, email });
  if (!keys.length) return false;
  try {
    const store = await readCompletions();
    const hit = keys.find((key) => store[key]?.completed);
    const completed = Boolean(hit);
    if (completed) {
      console.warn('Completion guard hit', {
        sessionId: sessionId || '(none)',
        email: email || '(none)',
        key: hit,
      });
    } else {
      console.log('Completion guard check', {
        sessionId: sessionId || '(none)',
        email: email || '(none)',
        keys,
        completed: false,
      });
    }
    return completed;
  } catch {
    return false;
  }
}

app.get('/api/completion', async (req, res) => {
  const sessionId = (req.query.session_id || req.query.token || '').trim();
  const email = (req.query.email || '').trim().toLowerCase();

  if (!DISABLE_COMPLETION_GUARD && !hasAccessContext({ sessionId, email })) {
    console.warn('Completion check denied: missing context', {
      path: req.originalUrl,
      sessionId: sessionId || '(none)',
      email: email || '(none)',
    });
    return res.status(400).json({ error: 'Accès non valide.' });
  }

  const completed = await isCompleted({ sessionId, email });
  return res.json({ completed });
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

  if (req.rawBodyLength && req.rawBodyLength > 10240) {
    return res.status(400).json({ error: 'Données invalides.' });
  }
  if (honeypot) {
    return res.status(400).json({ error: 'Données invalides.' });
  }
  if (!normalizedChosen || !localPart) {
    return res.status(400).json({ error: 'Données invalides.' });
  }
  if (clientEmail && !emailRegex.test(clientEmail)) {
    return res.status(400).json({ error: 'Données invalides.' });
  }
  if (!DISABLE_COMPLETION_GUARD && (await isCompleted({ sessionId, email: clientEmail }))) {
    console.warn('Selection rejected: already completed', {
      sessionId: sessionId || '(none)',
      email: clientEmail || '(none)',
      path: req.originalUrl,
    });
    return res.status(400).json({ error: 'Formulaire déjà complété.' });
  }
  if (!DISABLE_COMPLETION_GUARD && !hasAccessContext({ sessionId, email: clientEmail })) {
    console.warn('Selection rejected: missing context', {
      sessionId: sessionId || '(none)',
      email: clientEmail || '(none)',
      path: req.originalUrl,
    });
    return res.status(400).json({ error: 'Accès non valide.' });
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
    await fs.writeFile(SELECTIONS_PATH, JSON.stringify(selections, null, 2), 'utf8');
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
    console.error('Selection save failed', {
      error: error.message || error,
      chosenDomain: normalizedChosen,
      requestedDomain: normalizedRequested || '(none)',
      sessionId: sessionId || '(none)',
      clientEmail: clientEmail || '(none)',
      path: req.originalUrl,
    });
    return res.status(500).json({ error: "Impossible d'enregistrer le choix." });
  }
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
  console.log(`Server ready on http://localhost:${PORT}`);
});
