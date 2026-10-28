import { readFileSync, existsSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { createServer, type Server } from 'node:http';
import { join } from 'node:path';
const _envPath = join(process.cwd(), '.env');
if (existsSync(_envPath) && !process.env.DATABASE_URL) {
  const _raw = readFileSync(_envPath, 'utf8');
  for (const _line of _raw.split(String.fromCharCode(10))) {
    const _trimmed = _line.trim();
    if (!_trimmed || _trimmed.startsWith('#')) continue;
    const _eq = _trimmed.indexOf('=');
    if (_eq === -1) continue;
    const _key = _trimmed.slice(0, _eq).trim();
    const _value = _trimmed
      .slice(_eq + 1)
      .trim()
      .replace(/^['"]|['"]$/g, '');
    if (!(_key in process.env)) process.env[_key] = _value;
  }
}

import { backfillCorrelationInventory } from './correlation/inventory.ts';
import { CorrelationRuntime } from './correlation/runtime.ts';
import { describeError, writeEvent } from './events';
import { loadConfig } from './config';
import { createPool, migrate, transaction, get, put, REQUIRED_SCHEMA_VERSION } from './db';
import { createApp } from './app';
import { createRequester } from './network';
import { createMailSender, deliverNext } from './delivery';
import { flushDueDigest } from './digest';
import { runDailyDigest } from './dailyDigest';
import { closePdfRenderer } from './pdf';
import { processPipeline } from './pipeline';
import { runRetention } from './retention';
import { DEFAULT_SETTINGS } from '../shared/state.ts';
import type { AppSettings } from '../src/types/index.ts';
const config = loadConfig(),
  pool = createPool(config.DATABASE_URL);
const VERBOSE = config.LOG_LEVEL === 'verbose';
const verboseLog = (event: string, context: Record<string, unknown> = {}) => {
  if (VERBOSE) console.log(JSON.stringify({ level: 'info', event, ...context }));
};
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
await transaction(
  pool,
  async (db) => {
    if (await get(db, 'systemState', 'native-inventory-v1')) return;
    await backfillCorrelationInventory(db);
    await put(db, 'systemState', 'native-inventory-v1', { completedAt: new Date().toISOString() });
  },
  undefined,
  { locks: ['native-inventory-bootstrap'] },
);
// Recommended threat-feed seeding is intentionally NOT run on startup: it must be
// triggered explicitly via `npm run seed` with BOOTSTRAP_RECOMMENDED_FEEDS=true
// (see .env.example), so the server never opens egress to external feeds in
// dev or prod without an operator's deliberate action.
await writeEvent(pool, {
  category: 'SYSTEM',
  code: 'system.started',
  message: 'Application initialized',
  context: { workerEnabled: config.WORKER_ENABLED === 'true' },
});
const request = createRequester(config),
  sendMail = createMailSender(config, pool, request);
const correlation = new CorrelationRuntime(
  pool,
  config.ENCRYPTION_KEY,
  config.CORRELATION_DLQ_DIRECTORY,
  {
    url: config.HEARTBEAT_URL,
    intervalSeconds: config.HEARTBEAT_INTERVAL_SECONDS,
    logLevel: config.LOG_LEVEL === 'verbose' ? 'verbose' : 'standard',
  },
);
if (config.WORKER_ENABLED === 'true') correlation.start();
else correlation.supervisor.start();
const app = createApp(pool, config, request, {
  correlation,
  // The liveness probe only performs the stall check where the probe timeout is
  // comfortably above the block threshold; see the option's documentation.
  hangDetection: config.HANG_DETECTION_ENABLED === 'true',
});
/**
 * Start listening on `port`, retrying up to `maxAttempts` times when the port
 * is already in use. On EADDRINUSE the process holding the port is killed
 * (it is invariably a stale dev-server instance from an ungraceful shutdown or
 * a `tsx watch` restart race), then the listen is retried after a short delay.
 * This makes `npm run dev:server` robust without requiring a separate pre-start
 * step on every `tsx watch` restart.
 */
async function listenWithRetry(port: number, host: string, maxAttempts = 5): Promise<Server> {
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const server = createServer(app);
    try {
      await new Promise<void>((resolve, reject) => {
        const onError = (error: Error) => reject(error);
        server.on('error', onError);
        server.listen(port, host, () => {
          server.removeListener('error', onError);
          console.log(JSON.stringify({ event: 'listening', port }));
          resolve();
        });
      });
      return server;
    } catch (error: unknown) {
      const code = (error as NodeJS.ErrnoException)?.code;
      if (code !== 'EADDRINUSE') throw error;
      if (attempt === maxAttempts) throw error;
      let pids = '';
      try {
        pids = execSync(`lsof -ti:${port}`, { stdio: ['pipe', 'pipe', 'pipe'] })
          .toString()
          .trim();
      } catch {}
      if (pids) {
        console.log(JSON.stringify({ event: 'port_conflict.resolve', port, attempt, pids }));
        for (const pid of pids.split('\n').filter(Boolean)) {
          try {
            process.kill(Number(pid), 'SIGKILL');
          } catch {}
        }
      }
      await new Promise((resolve) => setTimeout(resolve, 1000 * attempt));
    }
  }
  throw new Error('listenWithRetry: unreachable');
}
const server = await listenWithRetry(config.PORT, '0.0.0.0');
server.requestTimeout = 30000;
server.headersTimeout = 15000;
let stopping = false,
  pipeline: Promise<unknown> | null = null,
  outbox: Promise<unknown> | null = null,
  digest: Promise<unknown> | null = null;
const report = (event: string) => (error: unknown) => {
  const detail = describeError(error);
  void writeEvent(pool, {
    category: 'ISSUE',
    level: 'ERROR',
    code: 'worker.failed',
    message: 'Background worker failed',
    context: { component: event, ...detail },
  }).catch((writeError: unknown) => {
    console.error(
      JSON.stringify({
        level: 'error',
        event: 'event.write_failed',
        component: event,
        message: writeError instanceof Error ? writeError.message : String(writeError),
      }),
    );
  });
  console.error(JSON.stringify({ level: 'error', event, ...detail }));
};
const tick = () => {
  if (stopping || config.WORKER_ENABLED !== 'true') return;
  verboseLog('worker.tick');
  if (!pipeline)
    pipeline = processPipeline(pool, config, request)
      .then((result) => {
        verboseLog('pipeline.completed', { processed: result });
        return result;
      })
      .catch(report('pipeline'))
      .finally(() => {
        pipeline = null;
      });
  if (!outbox)
    outbox = (async () => {
      for (let i = 0; i < 20 && !stopping; i++) {
        const delivered = await deliverNext(pool, config, request, sendMail);
        if (!delivered) break;
        verboseLog('outbox.delivered');
      }
    })()
      .catch(report('outbox'))
      .finally(() => {
        outbox = null;
      });
  if (!digest)
    digest = flushDueDigest(pool)
      .then((count) => {
        verboseLog('digest.flushed', { count });
        return count;
      })
      .catch(report('digest'))
      .finally(() => {
        digest = null;
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
      const row = await db.query("SELECT data FROM records WHERE kind='systemState' AND id=$1 FOR UPDATE", [
        RETENTION_SCHEDULE_ID,
      ]);
      const data = row.rows[0]?.data ?? {};
      const now = Date.now();
      const lastRun = typeof data.lastRun === 'string' ? Date.parse(data.lastRun) : NaN;
      const claimedAt = typeof data.claimedAt === 'string' ? Date.parse(data.claimedAt) : NaN;
      if (Number.isFinite(lastRun) && now - lastRun < policy.cleanupIntervalMinutes * 60_000) return false;
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
      const row = await db.query("SELECT data FROM records WHERE kind='systemState' AND id=$1 FOR UPDATE", [
        RETENTION_SCHEDULE_ID,
      ]);
      const data = row.rows[0]?.data ?? {};
      await put(db, 'systemState', RETENTION_SCHEDULE_ID, {
        ...data,
        claimedAt: null,
        lastRun: success ? new Date().toISOString() : (data.lastRun ?? null),
        lastFailedAt: success ? null : new Date().toISOString(),
        nextRetryAt: success ? null : nextRetryAt || new Date(Date.now() + 60_000).toISOString(),
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
    const row = await pool.query("SELECT data FROM records WHERE kind='systemState' AND id=$1", [
      RETENTION_SCHEDULE_ID,
    ]);
    const data = row.rows[0]?.data ?? {};
    const now = Date.now();
    // Honor nextRetryAt for failed runs to enable immediate retry.
    if (typeof data.nextRetryAt === 'string' && Date.parse(data.nextRetryAt) > now) return;
    if (!(await claimRetention(policy))) return;
    verboseLog('retention.start');
    try {
      await runRetention(pool, 'system-retention');
      await releaseRetention(true);
      verboseLog('retention.completed');
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
// The daily digest is a calendar job (daily summary + health report at the
// configured time/timezone). It is polled on the same cadence as retention and
// self-claims the calendar day, so it needs no separate clock.
let dailyDigestRunning: Promise<unknown> | null = null;
const dailyDigestTick = () => {
  if (stopping || config.WORKER_ENABLED !== 'true' || dailyDigestRunning) return;
  dailyDigestRunning = (async () => {
    verboseLog('dailyDigest.start');
    await runDailyDigest(pool);
    verboseLog('dailyDigest.completed');
  })()
    .catch(report('dailyDigest'))
    .finally(() => {
      dailyDigestRunning = null;
    });
};
const dailyDigestTimer = setInterval(dailyDigestTick, 60000);
dailyDigestTick();
const cleanup = setInterval(() => {
  // Session and login-attempt expiry are security invariants, not retained
  // business data. Queue rows and operational events follow the retention
  // policy in runRetention so an operator's configured window stays authoritative.
  void pool
    .query(
      `DELETE FROM sessions WHERE expires_at<now();
       DELETE FROM login_attempts WHERE window_start<now()-interval '1 day';
       DELETE FROM password_reset_tokens WHERE expires_at<now();`,
    )
    .then((result) => {
      verboseLog('session.cleanup', { removed: result?.rowCount ?? 0 });
    })
    .catch(report('session-cleanup'));
}, 60000);
async function shutdown() {
  if (stopping) return;
  stopping = true;
  clearInterval(timer);
  clearInterval(retentionTimer);
  clearInterval(dailyDigestTimer);
  clearInterval(cleanup);
  const deadline = setTimeout(() => process.exit(1), 30000);
  deadline.unref();
  await new Promise<void>((resolve) => server.close(() => resolve()));
  await Promise.allSettled(
    [pipeline, outbox, digest, retentionRunning].filter(Boolean) as Promise<unknown>[],
  );
  await correlation.stop();
  await closePdfRenderer();
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
  correlation.supervisor.ingestor.telemetry.log('CRITICAL', 'process.restart_required');
  report(event)(error);
  // If a graceful SIGTERM/SIGINT shutdown is already under way, let its own
  // 30-second deadline govern the exit instead of racing it with a second,
  // immediate process.exit here.
  if (stopping) return;
  void shutdown().finally(() => process.exit(1));
};
process.on('unhandledRejection', fatal('unhandled-rejection'));
process.on('uncaughtException', fatal('uncaught-exception'));
