const { Pool } = require('pg');

const DATABASE_URL = process.env.DATABASE_URL || '';
const DATABASE_SSL = process.env.DATABASE_SSL || '';
const REQUEUE_OLDER_THAN_MINUTES = process.env.REQUEUE_OLDER_THAN_MINUTES;
const REQUEUE_LIMIT = parseInt(process.env.REQUEUE_LIMIT || '200', 10);
const REQUEUE_DRY_RUN = process.env.REQUEUE_DRY_RUN === 'true';
const REQUEUE_REASON = (process.env.REQUEUE_REASON || '').trim();

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

function parseMinutes(value) {
  if (!value) return null;
  const parsed = parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) return null;
  return parsed;
}

function buildFilter({ olderThanMinutes }) {
  const clauses = [`sheet_status = 'dead'`];
  const params = [];
  if (olderThanMinutes) {
    params.push(olderThanMinutes);
    clauses.push(
      `COALESCE(updated_at, created_at) <= NOW() - ($${params.length}::int * INTERVAL '1 minute')`
    );
  }
  return {
    where: clauses.length ? clauses.join(' AND ') : 'TRUE',
    params,
  };
}

async function fetchCount(pool, filter) {
  const result = await pool.query(
    `SELECT COUNT(*)::int AS count
     FROM outbox
     WHERE ${filter.where}`,
    filter.params
  );
  return result.rows[0]?.count || 0;
}

async function fetchCandidateIds(pool, filter, limit) {
  const result = await pool.query(
    `SELECT submission_id
     FROM outbox
     WHERE ${filter.where}
     ORDER BY COALESCE(updated_at, created_at) ASC NULLS LAST
     LIMIT $${filter.params.length + 1}`,
    [...filter.params, limit]
  );
  return (result.rows || []).map((row) => row.submission_id);
}

async function requeueDead(pool, filter, limit) {
  const result = await pool.query(
    `UPDATE outbox
     SET sheet_status = 'pending',
         next_retry_at = NOW(),
         last_error = NULL,
         attempt_count = 0,
         last_attempt_at = NULL,
         updated_at = NOW()
     WHERE submission_id IN (
       SELECT submission_id
       FROM outbox
       WHERE ${filter.where}
       ORDER BY COALESCE(updated_at, created_at) ASC NULLS LAST
       LIMIT $${filter.params.length + 1}
     )
     RETURNING submission_id`,
    [...filter.params, limit]
  );
  return (result.rows || []).map((row) => row.submission_id);
}

async function main() {
  if (!DATABASE_URL) {
    console.error('DATABASE_URL missing. Aborting requeue.');
    process.exit(1);
  }

  const limit = Number.isFinite(REQUEUE_LIMIT) && REQUEUE_LIMIT > 0 ? REQUEUE_LIMIT : 200;
  const olderThanMinutes = parseMinutes(REQUEUE_OLDER_THAN_MINUTES);
  const filter = buildFilter({ olderThanMinutes });

  const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: getDbSslConfig(),
  });

  try {
    const totalDead = await fetchCount(pool, buildFilter({ olderThanMinutes: null }));
    const candidateCount = await fetchCount(pool, filter);
    const plannedCount = Math.min(candidateCount, limit);
    const sampleIds = await fetchCandidateIds(pool, filter, Math.min(limit, 20));

    const summaryParts = [
      `dead_total=${totalDead}`,
      `candidate_count=${candidateCount}`,
      `limit=${limit}`,
      `dry_run=${REQUEUE_DRY_RUN}`,
    ];
    if (olderThanMinutes) {
      summaryParts.push(`older_than_minutes=${olderThanMinutes}`);
    }
    console.log(`Requeue summary: ${summaryParts.join(' ')}`);

    if (REQUEUE_REASON) {
      console.log(`Requeue reason: ${REQUEUE_REASON}`);
    }

    if (!plannedCount) {
      console.log('No dead outbox rows to requeue.');
      return;
    }

    if (sampleIds.length) {
      console.log(`Sample ids (up to 20): ${sampleIds.join(', ')}`);
    }

    if (REQUEUE_DRY_RUN) {
      console.log(`Dry run: would requeue ${plannedCount} row(s).`);
      return;
    }

    const requeuedIds = await requeueDead(pool, filter, limit);
    console.log(`Requeued ${requeuedIds.length} row(s).`);
  } catch (error) {
    console.error(`Requeue failed: ${error.message || error}`);
    process.exit(1);
  } finally {
    await pool.end().catch(() => {});
  }
}

main();
