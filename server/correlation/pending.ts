import { randomUUID } from 'node:crypto';
import type { Db } from '../db.ts';
import { timedQuery } from './query.ts';
export interface PendingBatch {
  token: string;
  jobs: { id: string; payload: unknown }[];
}
export async function claimPending(db: Db, limit: number): Promise<PendingBatch> {
  if (!Number.isInteger(limit) || limit < 1 || limit > 32) throw new Error('INVALID_CLAIM_LIMIT');
  const token = randomUUID();
  const result = await db.query<{ id: string; payload: unknown }>(timedQuery(`WITH selected AS (
    SELECT id FROM correlation_pending WHERE lease_until IS NULL OR lease_until<now()
    ORDER BY created_at,id LIMIT $1 FOR UPDATE SKIP LOCKED)
    UPDATE correlation_pending p SET lease_until=now()+interval '60 seconds',lease_token=$2
    FROM selected s WHERE p.id=s.id RETURNING p.id,p.payload`, [limit, token]));
  return { token, jobs: result.rows };
}
/** A stale worker can neither delete nor extend another worker's claim. */
export async function renewPending(db: Db, batch: PendingBatch): Promise<number> {
  const result = await db.query(timedQuery(`UPDATE correlation_pending SET lease_until=now()+interval '60 seconds'
    WHERE id=ANY($1::text[]) AND lease_token=$2 AND lease_until>now()`, [batch.jobs.map(job => job.id), batch.token]));
  return result.rowCount || 0;
}
export async function acknowledgePending(db: Db, batch: PendingBatch): Promise<number> {
  const result = await db.query(timedQuery(`DELETE FROM correlation_pending
    WHERE id=ANY($1::text[]) AND lease_token=$2 AND lease_until>now()`, [batch.jobs.map(job => job.id), batch.token]));
  return result.rowCount || 0;
}
