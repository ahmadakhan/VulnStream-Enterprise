import { compileCustomizedTemplate } from '../src/utils/templateCompiler.ts';
import pg, { type PoolClient } from 'pg';
import { readFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import {
  emptyState,
  type AppState,
  type CollectionKind,
  type HeavyCollectionKind,
  COLLECTION_KINDS,
} from '../shared/state.ts';
import { chainAuditLogs } from '../src/utils/cryptoChain.ts';
import type { AuditLog } from '../src/types/index.ts';
import { orderWatchlist } from '../src/utils/watchlist.ts';
export type Db = pg.Pool | PoolClient;
export const createPool = (url: string) =>
  new pg.Pool({
    connectionString: url,
    max: 12,
    connectionTimeoutMillis: 5000,
    idleTimeoutMillis: 30000,
    statement_timeout: 15000,
    application_name: 'vulnstream',
  });
/**
 * Advisory locks are scoped to the database, not to the active schema. Mixing
 * in the schema keeps independent deployments (and isolated per-schema test
 * databases) that share one PostgreSQL database from blocking each other.
 * COALESCE covers a search_path whose first schema does not exist yet.
 */
export const schemaLockKey = 'hashtext(COALESCE(current_schema(), current_database()))';

/**
 * The newest migration this build depends on. Production startup refuses to
 * run against an older schema instead of failing later on a missing column.
 */
export const REQUIRED_SCHEMA_VERSION = 10;

export async function migrate(pool: pg.Pool) {
  const client = await pool.connect();
  let failed = false;
  try {
    await client.query('BEGIN');
    // Fail fast instead of queueing behind long-running worker transactions and
    // stalling the application behind an AccessExclusive DDL lock.
    await client.query("SET LOCAL lock_timeout = '10000ms'");
    // Migrations may include index builds; do not inherit the 15-second API
    // statement timeout.
    await client.query("SET LOCAL statement_timeout = '300000ms'");
    await client.query(`SELECT pg_advisory_xact_lock(800001, ${schemaLockKey})`);
    const exists = await client.query("SELECT to_regclass('schema_migrations') AS name");
    const applied =
      exists.rows[0].name &&
      (await client.query('SELECT version FROM schema_migrations WHERE version=1')).rowCount;
    if (!applied)
      await client.query(await readFile(new URL('./migrations/001_initial.sql', import.meta.url), 'utf8'));
    if (!(await client.query('SELECT version FROM schema_migrations WHERE version=2')).rowCount)
      await client.query(
        await readFile(new URL('./migrations/002_operational_events.sql', import.meta.url), 'utf8'),
      );
    if (!(await client.query('SELECT version FROM schema_migrations WHERE version=3')).rowCount)
      await client.query(
        await readFile(new URL('./migrations/003_record_creation_order.sql', import.meta.url), 'utf8'),
      );
    if (!(await client.query('SELECT version FROM schema_migrations WHERE version=4')).rowCount)
      await client.query(
        await readFile(new URL('./migrations/004_email_review_queue.sql', import.meta.url), 'utf8'),
      );
    if (!(await client.query('SELECT version FROM schema_migrations WHERE version=5')).rowCount)
      await client.query(
        await readFile(new URL('./migrations/005_outbox_priority.sql', import.meta.url), 'utf8'),
      );
    if (!(await client.query('SELECT version FROM schema_migrations WHERE version=6')).rowCount)
      await client.query(
        await readFile(new URL('./migrations/006_catchup_scheduler.sql', import.meta.url), 'utf8'),
      );
    if (!(await client.query('SELECT version FROM schema_migrations WHERE version=7')).rowCount)
      await client.query(
        await readFile(new URL('./migrations/007_delivery_and_audit_guards.sql', import.meta.url), 'utf8'),
      );
    if (!(await client.query('SELECT version FROM schema_migrations WHERE version=8')).rowCount)
      await client.query(
        await readFile(new URL('./migrations/008_match_index.sql', import.meta.url), 'utf8'),
      );
    if (!(await client.query('SELECT version FROM schema_migrations WHERE version=9')).rowCount)
      await client.query(
        await readFile(new URL('./migrations/009_safe_json_casts.sql', import.meta.url), 'utf8'),
      );
    if (!(await client.query('SELECT version FROM schema_migrations WHERE version=10')).rowCount)
      await client.query(
        await readFile(new URL('./migrations/010_shared_rate_limit.sql', import.meta.url), 'utf8'),
      );
    await client.query('COMMIT');
  } catch (e) {
    failed = true;
    // A failure here may mean the connection itself is broken (e.g. the BEGIN
    // never completed); do not let a secondary ROLLBACK error mask the real cause.
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    // Passing the failure tells the pool to destroy a possibly-broken connection
    // instead of recycling it back into the pool for the next caller.
    client.release(failed);
  }
}
export interface TransactionOptions {
  /**
   * Optional named advisory locks acquired for the duration of the transaction.
   * Locks are sorted before acquisition to prevent deadlocks between callers.
   * The previous single global 800002 lock serialized every write in the
   * installation; scoped locks let independent domains proceed concurrently.
   */
  locks?: string[];
}

export async function transaction<T>(
  pool: pg.Pool,
  fn: (db: PoolClient) => Promise<T>,
  client?: PoolClient,
  options: TransactionOptions = {},
): Promise<T> {
  const db = client || (await pool.connect());
  let failed = false;
  try {
    await db.query('BEGIN');
    // Named, transaction-scoped locks replace the former global mutation lock.
    // Row-level locks on the records being mutated provide the per-record
    // serialization that operators actually need.
    for (const lock of [...(options.locks ?? [])].sort())
      await db.query(`SELECT pg_advisory_xact_lock(hashtext($1), ${schemaLockKey})`, [lock]);
    const result = await fn(db);
    await db.query('COMMIT');
    return result;
  } catch (error) {
    failed = true;
    // ROLLBACK can itself fail when the connection is already broken; swallow
    // that secondary failure so the caller sees the original, more useful error.
    await db.query('ROLLBACK').catch(() => {});
    throw error;
  } finally {
    // Release with the failure flag so a connection left in a bad state by a
    // transport-level error is destroyed rather than returned to the pool,
    // where a future caller would otherwise inherit an unusable connection.
    if (!client) db.release(failed);
  }
}
export async function put(db: Db, kind: string, id: string, data: unknown) {
  await db.query(
    'INSERT INTO records(kind,id,data) VALUES($1,$2,$3) ON CONFLICT(kind,id) DO UPDATE SET data=EXCLUDED.data,updated_at=now()',
    [kind, id, JSON.stringify(data)],
  );
}
export async function putMany(db: Db, kind: string, items: { id: string; data: unknown }[]) {
  // PostgreSQL permits at most 65,535 bind parameters. Bound statement size as
  // well, and coalesce repeated IDs so a batch never updates one row twice.
  const unique = [...new Map(items.map((item) => [item.id, item])).values()];
  for (let offset = 0; offset < unique.length; offset += 1000) {
    const values: unknown[] = [];
    const params = unique.slice(offset, offset + 1000).map((item, index) => {
      values.push(kind, item.id, JSON.stringify(item.data));
      const first = index * 3 + 1;
      return `($${first},$${first + 1},$${first + 2})`;
    });
    await db.query(
      `INSERT INTO records(kind,id,data) VALUES${params.join(',')} ON CONFLICT(kind,id) DO UPDATE SET data=EXCLUDED.data,updated_at=now() WHERE records.data IS DISTINCT FROM EXCLUDED.data`,
      values,
    );
  }
}
export async function get<T>(db: Db, kind: string, id: string): Promise<T | undefined> {
  return (await db.query('SELECT data FROM records WHERE kind=$1 AND id=$2', [kind, id])).rows[0]?.data;
}
/**
 * Reads a record while holding a row-level lock. Command handlers use this for
 * read-modify-write sequences so two concurrent operators cannot overwrite each
 * other's changes without taking the installation-wide lock.
 */
export async function getForUpdate<T>(db: Db, kind: string, id: string): Promise<T | undefined> {
  return (
    await db.query('SELECT data FROM records WHERE kind=$1 AND id=$2 FOR UPDATE', [kind, id])
  ).rows[0]?.data;
}
export async function list<T>(db: Db, kind: string): Promise<T[]> {
  return (
    await db.query(
      "SELECT data FROM records WHERE kind=$1 ORDER BY CASE WHEN kind='feeds' THEN created_at ELSE updated_at END DESC,id",
      [kind],
    )
  ).rows.map((r) => r.data);
}
export async function remove(db: Db, kind: string, id: string) {
  return (await db.query('DELETE FROM records WHERE kind=$1 AND id=$2', [kind, id])).rowCount;
}
export async function appendAudit(
  db: Db,
  event: string,
  details: string,
  actor: string,
  category: AuditLog['category'] = 'SECURITY',
  level: AuditLog['level'] = 'INFO',
  ipAddress: string = '',
): Promise<void> {
  // Outside a transaction, wrap the read/insert pair so the audit lock is held
  // for the whole operation instead of being released after the lock statement.
  if (db instanceof pg.Pool)
    return transaction(db, (tx) => appendAudit(tx, event, details, actor, category, level, ipAddress));
  // The audit chain is a single linked list; a dedicated named lock serializes
  // only audit appends instead of every state mutation in the installation.
  await db.query(`SELECT pg_advisory_xact_lock(hashtext($1), ${schemaLockKey})`, ['audit-chain']);
  const previous = (await db.query('SELECT data FROM audit ORDER BY seq DESC LIMIT 1 FOR UPDATE')).rows[0]
    ?.data;
  const entry = chainAuditLogs(
    [
      {
        id: randomUUID(),
        timestamp: new Date().toISOString(),
        category,
        level,
        event,
        details,
        actor,
        ipAddress,
        prevHash: '',
        hash: '',
      },
    ],
    previous?.hash,
  )[0];
  await db.query('INSERT INTO audit(data) VALUES($1)', [JSON.stringify(entry)]);
}
export interface StateOptions {
  /**
   * Maximum rows returned for a heavy collection. Omit a kind to return all of
   * its rows (internal callers only). `/api/state` always supplies limits.
   */
  limits?: Partial<Record<HeavyCollectionKind, number>>;
}

const recordOrder = "ORDER BY CASE WHEN kind='feeds' THEN created_at ELSE updated_at END DESC,id";

export async function state(db: Db, options: StateOptions = {}): Promise<AppState> {
  const snapshot = emptyState();
  const arrayKinds = Object.entries(snapshot)
    .filter(([, value]) => Array.isArray(value))
    .map(([kind]) => kind)
    .filter((kind) => kind !== 'auditLogs');
  const limits = options.limits ?? {};
  const bounded = new Set(
    Object.entries(limits)
      .filter(([, limit]) => typeof limit === 'number' && limit >= 0)
      .map(([kind]) => kind),
  );
  const rows: { kind: string; data: unknown }[] = [];
  const unbounded = arrayKinds.filter((kind) => !bounded.has(kind));
  if (unbounded.length)
    rows.push(
      ...(
        await db.query(`SELECT kind,data FROM records WHERE kind=ANY($1::text[]) ${recordOrder}`, [unbounded])
      ).rows,
    );
  for (const kind of bounded) {
    const limit = Math.max(0, Math.floor(limits[kind as HeavyCollectionKind]!));
    if (!limit) continue;
    if (kind === 'auditLogs') continue;
    rows.push(
      ...(
        await db.query(`SELECT kind,data FROM records WHERE kind=$1 ${recordOrder} LIMIT $2`, [kind, limit])
      ).rows,
    );
  }
  // Audit rows live in their own append-only table. Keep the historical 500-row
  // default for internal snapshots; the browser always supplies an explicit limit.
  const auditLimit = bounded.has('auditLogs') ? Math.max(0, Math.floor(limits.auditLogs!)) : 500;
  if (auditLimit)
    rows.push(
      ...(await db.query('SELECT data FROM audit ORDER BY seq DESC LIMIT $1', [auditLimit])).rows.map(
        (row) => ({ kind: 'auditLogs', data: row.data }),
      ),
    );
  rows.push(
    ...(
      await db.query('SELECT kind,data FROM records WHERE kind=ANY($1::text[])', [
        ['settings', 'emailConfig', 'template'],
      ])
    ).rows,
  );
  for (const row of rows) {
    if (Array.isArray(snapshot[row.kind as keyof AppState]))
      (snapshot[row.kind as keyof AppState] as unknown[]).push(row.data);
    else if (row.kind === 'settings') snapshot.settings = row.data as AppState['settings'];
    else if (row.kind === 'emailConfig') snapshot.emailConfig = row.data as AppState['emailConfig'];
    else if (row.kind === 'template') Object.assign(snapshot, row.data);
  }
  // Keep inventory position tied to original creation time. PostgreSQL record
  // updates change updated_at, so using the generic query order made edits jump
  // to the top of the monitored-products table.
  snapshot.watchlist = orderWatchlist(snapshot.watchlist);
  // Saved branding is authoritative; regenerate HTML with the current layout so
  // existing installations receive layout fixes without losing customization.
  snapshot.advisoryTemplate = compileCustomizedTemplate(snapshot.templateCustomization);
  await attachCounts(db, snapshot);
  return snapshot;
}

/**
 * Exact collection sizes and KPI aggregates. They are computed independently of
 * the bounded arrays so a large installation still shows truthful totals.
 */
async function attachCounts(db: Db, snapshot: AppState) {
  const recordKinds = COLLECTION_KINDS.filter((kind) => kind !== 'auditLogs');
  const counts = (
    await db.query<{ kind: CollectionKind; count: number }>(
      'SELECT kind, count(*)::int AS count FROM records WHERE kind=ANY($1::text[]) GROUP BY kind',
      [recordKinds],
    )
  ).rows;
  for (const row of counts) snapshot.counts[row.kind] = Number(row.count);
  snapshot.counts.auditLogs = Number(
    (await db.query('SELECT count(*)::int AS count FROM audit')).rows[0].count,
  );
  const summary = (
    await db.query(
      `SELECT
        (SELECT count(*) FROM records WHERE kind='findings'
          AND COALESCE(data->>'status','') NOT IN ('RESOLVED','FALSE_POSITIVE','PATCH_APPLIED')
          AND COALESCE(data->>'notificationStatus','') <> 'NOT_APPLICABLE')::int AS "activeFindings",
        (SELECT count(*) FROM records WHERE kind='findings'
          AND COALESCE(data->>'status','') NOT IN ('RESOLVED','FALSE_POSITIVE','PATCH_APPLIED')
          AND COALESCE(data->>'notificationStatus','') <> 'NOT_APPLICABLE'
          AND data->'cve'->'cvss'->>'severity'='CRITICAL')::int AS "criticalFindings",
        (SELECT count(*) FROM records WHERE kind='findings'
          AND COALESCE(data->>'status','') NOT IN ('RESOLVED','FALSE_POSITIVE','PATCH_APPLIED')
          AND COALESCE(data->>'notificationStatus','') <> 'NOT_APPLICABLE'
          AND (data->'cve'->'cisaKev'->>'isKev')::boolean IS TRUE)::int AS "kevFindings",
        (SELECT count(*) FROM records WHERE kind='emailLogs'
          AND data->>'status' = ANY($1::text[]))::int AS "deliveredEmails"`,
      [['ACCEPTED', 'DELIVERED']],
    )
  ).rows[0];
  snapshot.summary = {
    activeFindings: Number(summary.activeFindings),
    criticalFindings: Number(summary.criticalFindings),
    kevFindings: Number(summary.kevFindings),
    deliveredEmails: Number(summary.deliveredEmails),
  };
}

/** Pipeline-only snapshot avoids loading executions, delivery logs, recipients and audit history. */
export async function pipelineState(db: Db): Promise<AppState> {
  const snapshot = emptyState();
  const kinds = [
    'settings',
    'watchlist',
    'cveData',
    'findings',
    'alertedCves',
    'intelligenceArticles',
    'template',
  ];
  const rows = await db.query(
    'SELECT kind,data FROM records WHERE kind=ANY($1::text[]) ORDER BY updated_at DESC,id',
    [kinds],
  );
  for (const row of rows.rows) {
    if (Array.isArray(snapshot[row.kind as keyof AppState]))
      (snapshot[row.kind as keyof AppState] as unknown[]).push(row.data);
    else if (row.kind === 'settings') snapshot.settings = row.data;
    else if (row.kind === 'template') Object.assign(snapshot, row.data);
  }
  snapshot.advisoryTemplate = compileCustomizedTemplate(snapshot.templateCustomization);
  return snapshot;
}
