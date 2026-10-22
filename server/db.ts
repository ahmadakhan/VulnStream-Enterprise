import { compileCustomizedTemplate } from '../src/utils/templateCompiler';
import pg, { type PoolClient } from 'pg';
import { readFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { emptyState, type AppState } from '../shared/state';
import { chainAuditLogs } from '../src/utils/cryptoChain';
import type { AuditLog } from '../src/types';
import { orderWatchlist } from '../src/utils/watchlist';
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
export async function migrate(pool: pg.Pool) {
  const client = await pool.connect();
  let failed = false;
  try {
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock(800001)');
    const exists = await client.query("SELECT to_regclass('schema_migrations') AS name");
    const applied =
      exists.rows[0].name &&
      (await client.query('SELECT version FROM schema_migrations WHERE version=1')).rowCount;
    if (!applied)
      await client.query(await readFile(new URL('./migrations/001_initial.sql', import.meta.url), 'utf8'));
    if (!(await client.query('SELECT version FROM schema_migrations WHERE version=2')).rowCount)
      await client.query(await readFile(new URL('./migrations/002_operational_events.sql', import.meta.url), 'utf8'));
    if (!(await client.query('SELECT version FROM schema_migrations WHERE version=3')).rowCount)
      await client.query(await readFile(new URL('./migrations/003_record_creation_order.sql', import.meta.url), 'utf8'));
    if (!(await client.query('SELECT version FROM schema_migrations WHERE version=4')).rowCount)
      await client.query(await readFile(new URL('./migrations/004_email_review_queue.sql', import.meta.url), 'utf8'));
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
export async function transaction<T>(
  pool: pg.Pool,
  fn: (db: PoolClient) => Promise<T>,
  client?: PoolClient,
): Promise<T> {
  const db = client || (await pool.connect());
  let failed = false;
  try {
    await db.query('BEGIN');
    // Serializes state mutation and audit append; network I/O is never done here.
    await db.query('SELECT pg_advisory_xact_lock(800002)');
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
) {
  const previous = (await db.query('SELECT data FROM audit ORDER BY seq DESC LIMIT 1')).rows[0]?.data;
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
export async function state(db: Db): Promise<AppState> {
  const snapshot = emptyState();
  const kinds = [
    ...Object.entries(snapshot)
      .filter(([, value]) => Array.isArray(value))
      .map(([kind]) => kind),
    'settings',
    'emailConfig',
    'template',
  ];
  // Internal source snapshots and dispatch ledgers are not browser state.
  const rows = await db.query(
    "SELECT kind,data FROM records WHERE kind=ANY($1::text[]) ORDER BY CASE WHEN kind='feeds' THEN created_at ELSE updated_at END DESC,id",
    [kinds],
  );
  for (const row of rows.rows) {
    if (Array.isArray(snapshot[row.kind as keyof AppState]))
      (snapshot[row.kind as keyof AppState] as unknown[]).push(row.data);
    else if (row.kind === 'settings') snapshot.settings = row.data;
    else if (row.kind === 'emailConfig') snapshot.emailConfig = row.data;
    else if (row.kind === 'template') Object.assign(snapshot, row.data);
  }
  // Keep inventory position tied to original creation time. PostgreSQL record
  // updates change updated_at, so using the generic query order made edits jump
  // to the top of the monitored-products table.
  snapshot.watchlist = orderWatchlist(snapshot.watchlist);
  // Saved branding is authoritative; regenerate HTML with the current layout so
  // existing installations receive layout fixes without losing customization.
  snapshot.advisoryTemplate = compileCustomizedTemplate(snapshot.templateCustomization);
  snapshot.auditLogs = (await db.query('SELECT data FROM audit ORDER BY seq DESC LIMIT 500')).rows.map(
    (r) => r.data,
  );
  return snapshot;
}

/** Pipeline-only snapshot avoids loading executions, delivery logs, recipients and audit history. */
export async function pipelineState(db: Db): Promise<AppState> {
  const snapshot = emptyState();
  const kinds = ['settings', 'watchlist', 'cveData', 'findings', 'alertedCves', 'intelligenceArticles', 'template'];
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
