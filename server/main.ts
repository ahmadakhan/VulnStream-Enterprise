import { loadConfig } from './config';
import { createPool, migrate, transaction, get, put } from './db';
import { applyCommand } from './commands';
import { RECOMMENDED_FEEDS } from './recommendedFeeds';
import { createApp } from './app';
import { createRequester } from './network';
import { createMailSender, deliverNext } from './delivery';
import { processPipeline } from './pipeline';
const config = loadConfig(),
  pool = createPool(config.DATABASE_URL);
pool.on('error', (error) =>
  console.error(JSON.stringify({ level: 'error', event: 'database-connection', code: (error as any).code })),
);
if (config.NODE_ENV === 'production') {
  const version = await pool.query('SELECT version FROM schema_migrations WHERE version=2');
  if (!version.rowCount) throw new Error('Required migration missing');
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
const report = (event: string) => (error: unknown) =>
  console.error(
    JSON.stringify({ level: 'error', event, type: error instanceof Error ? error.name : 'Error' }),
  );
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
const cleanup = setInterval(() => {
  void pool
    .query(
      "DELETE FROM sessions WHERE expires_at<now(); DELETE FROM login_attempts WHERE window_start<now()-interval '1 day'",
    )
    .catch(report('session-cleanup'));
}, 60000);
async function shutdown() {
  if (stopping) return;
  stopping = true;
  clearInterval(timer);
  clearInterval(cleanup);
  const deadline = setTimeout(() => process.exit(1), 30000);
  deadline.unref();
  await new Promise<void>((resolve) => server.close(() => resolve()));
  await Promise.allSettled([pipeline, outbox].filter(Boolean) as Promise<unknown>[]);
  await pool.end();
  clearTimeout(deadline);
}
process.on('SIGTERM', () => void shutdown());
process.on('SIGINT', () => void shutdown());
