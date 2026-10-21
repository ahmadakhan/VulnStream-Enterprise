import { z } from 'zod';
import type { Db } from './db';
import { EVENT_CATEGORIES, type OperationalEvent } from '../src/types';

const sensitive = /password|secret|token|authorization|cookie|api.?key|payload|html|body/i;
export function redactEventContext(value: unknown, depth = 0): unknown {
  if (depth > 5) return '[truncated]';
  if (typeof value === 'string') return value.slice(0, 2000);
  if (value === null || typeof value === 'number' || typeof value === 'boolean') return value;
  if (Array.isArray(value)) return value.slice(0, 50).map((item) => redactEventContext(item, depth + 1));
  if (value && typeof value === 'object')
    return Object.fromEntries(
      Object.entries(value)
        .slice(0, 50)
        .map(([key, item]) => [
          key,
          sensitive.test(key) ? '[redacted]' : redactEventContext(item, depth + 1),
        ]),
    );
  return undefined;
}
export async function writeEvent(
  db: Db,
  event: Omit<OperationalEvent, 'id' | 'timestamp' | 'context' | 'level'> & {
    level?: OperationalEvent['level'];
    context?: Record<string, unknown>;
  },
) {
  let context = redactEventContext(event.context || {});
  if (JSON.stringify(context).length > 32000) context = { truncated: true };
  await db.query(
    'INSERT INTO operational_events(category,level,code,message,run_id,context) VALUES($1,$2,$3,$4,$5,$6)',
    [
      event.category,
      event.level || 'INFO',
      event.code.slice(0, 100),
      event.message.slice(0, 1000),
      event.runId || null,
      JSON.stringify(context),
    ],
  );
}
const querySchema = z.object({
  category: z.enum(EVENT_CATEGORIES).optional(),
  level: z.enum(['INFO', 'WARNING', 'ERROR']).optional(),
  runId: z.uuid().optional(),
  q: z.string().trim().max(200).optional(),
  before: z
    .string()
    .regex(/^\d{1,19}$/)
    .refine(
      (value) => /^\d{1,19}$/.test(value) && BigInt(value) <= 9223372036854775807n,
      'Cursor is out of range',
    )
    .optional(),
  limit: z.coerce.number().int().min(1).max(100).default(50),
});
export async function readEvents(
  db: Db,
  input: unknown,
): Promise<{ events: OperationalEvent[]; nextCursor: string | null }> {
  const query = querySchema.parse(input);
  const clauses: string[] = [],
    values: unknown[] = [];
  const where = (sql: string, value: unknown) => {
    values.push(value);
    clauses.push(sql.replace('?', `$${values.length}`));
  };
  if (query.category) where('category=?', query.category);
  if (query.level) where('level=?', query.level);
  if (query.runId) where('run_id=?', query.runId);
  if (query.before) where('id < ?::bigint', query.before);
  if (query.q)
    where(
      "to_tsvector('simple',code || ' ' || message || ' ' || context::text) @@ plainto_tsquery('simple',?)",
      query.q,
    );
  values.push(query.limit + 1);
  const rows = (
    await db.query(
      `SELECT id::text,occurred_at,category,level,code,message,run_id,context FROM operational_events ${clauses.length ? 'WHERE ' + clauses.join(' AND ') : ''} ORDER BY operational_events.id DESC LIMIT $${values.length}`,
      values,
    )
  ).rows;
  const hasMore = rows.length > query.limit;
  const selected = rows.slice(0, query.limit);
  return {
    events: selected.map((row) => ({
      id: row.id,
      timestamp: row.occurred_at.toISOString(),
      category: row.category,
      level: row.level,
      code: row.code,
      message: row.message,
      runId: row.run_id || undefined,
      context: row.context,
    })),
    nextCursor: hasMore ? selected[selected.length - 1].id : null,
  };
}
