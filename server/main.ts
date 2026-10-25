import { writeEvent } from './events';
import { loadConfig } from './config';
import { createPool, migrate, transaction, get, put, REQUIRED_SCHEMA_VERSION } from './db';
import { applyCommand } from './commands';
import { RECOMMENDED_FEEDS } from './recommendedFeeds';
import { createApp } from './app';
import { createRequester } from './network';
import { createMailSender, deliverNext } from './delivery';
import { processPipeline } from './pipeline';
import { runRetention } from './retention';
import { DEFAULT_SETTINGS } from '../shared/state.ts';
import type { AppSettings } from '../src/types/index.ts';
const config = loadConfig(),
  pool = createPool(config.DATABASE_URL);
pool.on('error', (error) =>
  console.error(JSON.stringify({ level: 'error', event: 'database-connection', code: (error as any).code })),
);
if (config.NODE_ENV === 'production') {
  const initialized = await pool.query("SELECT to_regclass('schema_migrations') AS name");
  if (!initialized.rows[0]?.name)
    throw new Error('Database schema is not initialized; run migrations before starting');
  const result = await pool.query('SELECT COALESCE(MAX(version), 0)::int AS version FROM schema_migrations');
  const version = Number(result.rows[0]?.version || 0);
  if (version < REQUIRED_SCHEMA_VERSION)
    throw new Error(
      `Database schema version ${version} is older than required version ${REQUIRED_SCHEMA_VERSION}; run migrations before starting`,
    );
} else await migrate(pool);
// Upgrade existing installations once; the marker makes later operator deletions persist.
await transaction(pool, async (db) => {
  if (await get(db, 'systemState', 'recommended-feeds-v2')) return;
  const missing = [];
  const previousBootstrap = await get(db, 'systemState', 'recommended-feeds-v1');
  for (const feed of RECOMMENDED_FEEDS.filter((feed) => !previousBootstrap || feed.type === 'RSS_ATOM'))
    if (!(await get(db, 'feeds', feed.id))) missing.push(feed);
  if (missing.length)
    await applyCommand(db, config, {
      action: 'feed.import',
      data: missing,
      actor: 'system-bootstrap',
    });
  await put(db, 'systemState', 'recommended-feeds-v2', { completedAt: new Date().toISOString() });
});
// Add the official CVE List once, without restoring sources an operator later deletes.
await transaction(pool, async (db) => {
  if (await get(db, 'systemState', 'recommended-feeds-v3')) return;
  const feed = RECOMMENDED_FEEDS.find(feed => feed.type === 'MITRE_CVE')!;
  if (!(await get(db, 'feeds', feed.id)))
    await applyCommand(db, config, { action: 'feed.import', data: [feed], actor: 'system-bootstrap' });
  await put(db, 'systemState', 'recommended-feeds-v3', { completedAt: new Date().toISOString() });
});
await writeEvent(pool, {category:'SYSTEM', code:'system.started', message:'Application initialized', context:{workerEnabled:config.WORKER_ENABLED === 'true'}});
const request = createRequester(config),
  sendMail = createMailSender(config, pool, request);
const server = createApp(pool, config, request).listen(config.PORT, '0.0.0.0', () =>
  console.log(JSON.stringify({ event: 'listening', port: config.PORT })),
);
server.requestTimeout = 30000;
server.headersTimeout = 15000;
let stopping = false,
  pipeline: Promise<unknown> | null = null,
  outbox: Promise<unknown> | null = null;
const report = (event: string) => (error: unknown) => {
  void writeEvent(pool, {category:'ISSUE', level:'ERROR', code:'worker.failed', message:'Background worker failed', context:{component:event,errorType:error instanceof Error ? error.name : 'Error'}}).catch(() => {});
  console.error(
    JSON.stringify({ level: 'error', event, type: error instanceof Error ? error.name : 'Error' }),
  );
};
const tick = () => {
  if (stopping || config.WORKER_ENABLED !== 'true') return;
  if (!pipeline)
    pipeline = processPipeline(pool, config, request)
      .catch(report('pipeline'))
      .finally(() => {
        pipeline = null;
      });
  if (!outbox)
    outbox = (async () => {
      for (let i = 0; i < 20 && !stopping; i++)
        if (!(await deliverNext(pool, config, request, sendMail))) break;
    })()
      .catch(report('outbox'))
      .finally(() => {
        outbox = null;
      });
};
const timer = setInterval(tick, 5000);
tick();
// Retention runs on its own cadence because the policy is operator-configurable
// and can be much slower than the worker tick. The last successful run is
// persisted in the database so replicas do not each schedule the same cleanup,
// and a failed run releases its claim so the next tick can retry immediately.
const RETENTION_SCHEDULE_ID = 'retention-schedule';
const RETENTION_CLAIM_TTL_MS = 5 * 60_000;
async function claimRetention(policy: AppSettings['retentionConfig']): Promise<boolean> {
  return transaction(
    pool,
    async (db) => {
      const row = await db.query(
        "SELECT data FROM records WHERE kind='systemState' AND id=$1 FOR UPDATE",
        [RETENTION_SCHEDULE_ID],
      );
      const data = row.rows[0]?.data ?? {};
      const now = Date.now();
      const lastRun = typeof data.lastRun === 'string' ? Date.parse(data.lastRun) : NaN;
      const claimedAt = typeof data.claimedAt === 'string' ? Date.parse(data.claimedAt) : NaN;
      if (Number.isFinite(lastRun) && now - lastRun < policy.cleanupIntervalMinutes * 60_000)
        return false;
      if (Number.isFinite(claimedAt) && now - claimedAt < RETENTION_CLAIM_TTL_MS) return false;
      await put(db, 'systemState', RETENTION_SCHEDULE_ID, {
        ...data,
        claimedAt: new Date(now).toISOString(),
      });
      return true;
    },
    undefined,
    // The schedule row may not exist yet; a scoped advisory lock serializes the
    // first claim from multiple replicas before there is a row to lock.
    { locks: ['retention-claim'] },
  );
}
async function releaseRetention(success: boolean, nextRetryAt?: string) {
  await transaction(
    pool,
    async (db) => {
      const row = await db.query(
        "SELECT data FROM records WHERE kind='systemState' AND id=$1 FOR UPDATE",
        [RETENTION_SCHEDULE_ID],
      );
      const data = row.rows[0]?.data ?? {};
      await put(db, 'systemState', RETENTION_SCHEDULE_ID, {
        ...data,
        claimedAt: null,
        lastRun: success ? new Date().toISOString() : (data.lastRun ?? null),
        lastFailedAt: success ? null : new Date().toISOString(),
        nextRetryAt: success ? null : (nextRetryAt || new Date(Date.now() + 60_000).toISOString()),
      });
    },
    undefined,
    { locks: ['retention-claim'] },
  );
}
let retentionRunning: Promise<unknown> | null = null;
const retentionTick = () => {
  if (stopping || config.WORKER_ENABLED !== 'true' || retentionRunning) return;
  retentionRunning = (async () => {
    const settings = (await get<AppSettings>(pool, 'settings', 'main')) || DEFAULT_SETTINGS;
    const policy = settings.retentionConfig;
    if (!policy?.enabled || !policy.autoCleanup) return;
    const row = await pool.query(
      "SELECT data FROM records WHERE kind='systemState' AND id=$1",
      [RETENTION_SCHEDULE_ID],
    );
    const data = row.rows[0]?.data ?? {};
    const now = Date.now();
    // Honor nextRetryAt for failed runs to enable immediate retry.
    if (typeof data.nextRetryAt === 'string' && Date.parse(data.nextRetryAt) > now) return;
    if (!(await claimRetention(policy))) return;
    try {
      await runRetention(pool, 'system-retention');
      await releaseRetention(true);
    } catch (error) {
      await releaseRetention(false).catch(() => {});
      throw error;
    }
  })()
    .catch(report('retention'))
    .finally(() => {
      retentionRunning = null;
    });
};
const retentionTimer = setInterval(retentionTick, 60000);
retentionTick();
const cleanup = setInterval(() => {
  // Session and login-attempt expiry are security invariants, not retained
  // business data. Queue rows and operational events follow the retention
  // policy in runRetention so an operator's configured window stays authoritative.
  void pool
    .query(
      `DELETE FROM sessions WHERE expires_at<now();
       DELETE FROM login_attempts WHERE window_start<now()-interval '1 day';`,
    )
    .catch(report('session-cleanup'));
}, 60000);
async function shutdown() {
  if (stopping) return;
  stopping = true;
  clearInterval(timer);
  clearInterval(retentionTimer);
  clearInterval(cleanup);
  const deadline = setTimeout(() => process.exit(1), 30000);
  deadline.unref();
  await new Promise<void>((resolve) => server.close(() => resolve()));
  await Promise.allSettled([pipeline, outbox, retentionRunning].filter(Boolean) as Promise<unknown>[]);
  await pool.end();
  clearTimeout(deadline);
}
process.on('SIGTERM', () => void shutdown());
process.on('SIGINT', () => void shutdown());
// Node terminates the process immediately on an unhandled rejection/exception
// with no listener registered. That would skip shutdown() entirely, leaving the
// HTTP server and any in-flight pipeline/outbox work to die mid-transaction
// without the structured event log entry operators rely on to diagnose it.
// PostgreSQL releases the session-level pipeline advisory lock when the
// connection closes, so a crash here is still safe for the next worker to
// recover from; this handler only makes the failure visible and gives
// in-flight work a chance at a clean stop before the process exits.
const fatal = (event: string) => (error: unknown) => {
  report(event)(error);
  // If a graceful SIGTERM/SIGINT shutdown is already under way, let its own
  // 30-second deadline govern the exit instead of racing it with a second,
  // immediate process.exit here.
  if (stopping) return;
  void shutdown().finally(() => process.exit(1));
};
process.on('unhandledRejection', fatal('unhandled-rejection'));
process.on('uncaughtException', fatal('uncaught-exception'));
