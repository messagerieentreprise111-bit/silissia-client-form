const { Pool } = require('pg');

const DATABASE_URL = process.env.DATABASE_URL || '';
const APPS_SCRIPT_WEBHOOK = process.env.APPS_SCRIPT_WEBHOOK || '';
const APPS_SCRIPT_TIMEOUT_MS = parseInt(process.env.APPS_SCRIPT_TIMEOUT_MS || '12000', 10);
const OUTBOX_BATCH_SIZE = parseInt(process.env.OUTBOX_BATCH_SIZE || '20', 10);
const OUTBOX_MAX_ATTEMPTS = parseInt(process.env.OUTBOX_MAX_ATTEMPTS || '5', 10);
const DATABASE_SSL = process.env.DATABASE_SSL || '';

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
  if (!APPS_SCRIPT_WEBHOOK) {
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

    const client = await pool.connect();
    let batch = [];
    try {
      batch = await fetchBatch(client);
    } finally {
      client.release();
    }

    if (!batch.length) {
      console.log('No pending outbox items.');
      return;
    }

    console.log(`Processing ${batch.length} outbox item(s)...`);
    for (const entry of batch) {
      try {
        await postWithTimeout(APPS_SCRIPT_WEBHOOK, entry.payload, APPS_SCRIPT_TIMEOUT_MS);
        await markOutboxResult(pool, entry, { success: true, status: 200 });
        console.log(`Sent: ${entry.submission_id}`);
      } catch (error) {
        await markOutboxResult(pool, entry, {
          success: false,
          status: error.status || null,
          errorMessage: error.message || String(error),
        });
        console.error(`Failed: ${entry.submission_id} -> ${error.message || error}`);
      }
    }
  } catch (error) {
    console.error(`Replay failed: ${error.message || error}`);
    process.exit(1);
  } finally {
    await pool.end().catch(() => {});
  }
}

main();
