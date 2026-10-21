import pg, { type PoolClient } from 'pg';
import { readFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { emptyState, type AppState } from '../shared/state';
import { chainAuditLogs } from '../src/utils/cryptoChain';
import type { AuditLog } from '../src/types';
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
  try {
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock(800001)');
    const exists = await client.query("SELECT to_regclass('schema_migrations') AS name");
    const applied =
      exists.rows[0].name &&
      (await client.query('SELECT version FROM schema_migrations WHERE version=1')).rowCount;
    if (!applied)
      await client.query(await readFile(new URL('./migrations/001_initial.sql', import.meta.url), 'utf8'));
    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}
export async function transaction<T>(
  pool: pg.Pool,
  fn: (db: PoolClient) => Promise<T>,
  client?: PoolClient,
): Promise<T> {
  const db = client || (await pool.connect());
  try {
    await db.query('BEGIN');
    // Serializes state mutation and audit append; network I/O is never done here.
    await db.query('SELECT pg_advisory_xact_lock(800002)');
    const result = await fn(db);
    await db.query('COMMIT');
    return result;
  } catch (error) {
    await db.query('ROLLBACK');
    throw error;
  } finally {
    if (!client) db.release();
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
    await db.query('SELECT data FROM records WHERE kind=$1 ORDER BY updated_at DESC,id', [kind])
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
  const rows = await db.query('SELECT kind,data FROM records ORDER BY updated_at DESC,id');
  for (const row of rows.rows) {
    if (Array.isArray(snapshot[row.kind as keyof AppState]))
      (snapshot[row.kind as keyof AppState] as unknown[]).push(row.data);
    else if (row.kind === 'settings') snapshot.settings = row.data;
    else if (row.kind === 'template') Object.assign(snapshot, row.data);
  }
  snapshot.auditLogs = (await db.query('SELECT data FROM audit ORDER BY seq DESC LIMIT 500')).rows.map(
    (r) => r.data,
  );
  return snapshot;
}
