import type pg from 'pg';
import type { AppSettings, RetentionConfig, RetentionKind, RetentionPreview, RetentionRunResult } from '../src/types/index.ts';
import { DEFAULT_SETTINGS } from '../shared/state.ts';
import { appendAudit, get, transaction } from './db.ts';

/**
 * Only transient, regenerable records are eligible for retention. Findings,
 * advisories, audit history, checkpoints and configuration are never touched:
 * they are the evidence trail the retention policy exists to preserve.
 */
export const RETENTION_KINDS: readonly RetentionKind[] = [
  'cveData',
  'intelligenceArticles',
  'emailLogs',
  'webhookLogs',
  'executions',
];

/** The data timestamp shown in the UI, not the row's insertion time. */
const TIMESTAMP_FIELDS: Record<RetentionKind, string> = {
  cveData: 'publishedDate',
  intelligenceArticles: 'publishedDate',
  emailLogs: 'sentAt',
  webhookLogs: 'sentAt',
  executions: 'startTime',
};

export interface RetentionRecord {
  kind: RetentionKind;
  id: string;
  timestamp: string | null;
}

export interface RetentionPlan {
  cutoff: string;
  /** Records the policy removes, already filtered and sorted oldest first. */
  delete: { kind: RetentionKind; id: string }[];
  byKind: Record<RetentionKind, number>;
  scanned: number;
  /** Records whose timestamp is missing or unparseable; always retained. */
  unknownAge: number;
}

export type RetentionPolicy = Pick<
  RetentionConfig,
  'enabled' | 'retentionHours' | 'maxArchivedRecords' | 'retentionMode'
>;

const DAY_MS = 86_400_000;

const parseTimestamp = (raw: string | null | undefined): number | null => {
  if (typeof raw !== 'string' || raw.trim() === '') return null;
  const value = Date.parse(raw);
  return Number.isFinite(value) ? value : null;
};

const keyOf = (record: { kind: string; id: string }) => `${record.kind}\u0000${record.id}`;
const dayOf = (timestamp: number) => Math.floor(timestamp / DAY_MS);

/**
 * Pure selection step so the destructive part stays small and testable.
 *
 * - strict: delete everything outside the window.
 * - rolling: delete everything outside the window, then trim the oldest
 *   remaining records until the archive ceiling is met.
 * - checkpoints: delete everything outside the window, except keep the newest
 *   record for each UTC day so a daily snapshot of the data survives.
 *
 * A record whose timestamp cannot be parsed is never deleted: silently
 * removing data we cannot age is worse than keeping it.
 */
export function selectRetention(
  records: readonly RetentionRecord[],
  policy: RetentionPolicy,
  nowMs: number,
): RetentionPlan {
  const cutoffMs = nowMs - policy.retentionHours * 3_600_000;
  const byKind = Object.fromEntries(RETENTION_KINDS.map((kind) => [kind, 0])) as Record<
    RetentionKind,
    number
  >;
  const plan: RetentionPlan = {
    cutoff: new Date(cutoffMs).toISOString(),
    delete: [],
    byKind,
    scanned: records.length,
    unknownAge: 0,
  };
  if (!policy.enabled || !Number.isFinite(cutoffMs) || policy.retentionHours <= 0) return plan;

  const aged: { record: RetentionRecord; at: number }[] = [];
  for (const record of records) {
    const at = parseTimestamp(record.timestamp);
    if (at === null) plan.unknownAge++;
    else aged.push({ record, at });
  }

  const doomed = new Set<string>();
  const mark = (record: RetentionRecord) => {
    const key = keyOf(record);
    if (doomed.has(key)) return;
    doomed.add(key);
    byKind[record.kind]++;
  };
  const expired = aged.filter((entry) => entry.at < cutoffMs);

  if (policy.retentionMode === 'checkpoints') {
    // Keep the newest expired record per kind and UTC day; drop the rest.
    const keep = new Map<string, { key: string; at: number; id: string }>();
    for (const entry of expired) {
      const bucket = `${entry.record.kind}\u0000${dayOf(entry.at)}`;
      const current = keep.get(bucket);
      if (
        !current ||
        entry.at > current.at ||
        (entry.at === current.at && entry.record.id > current.id)
      )
        keep.set(bucket, { key: keyOf(entry.record), at: entry.at, id: entry.record.id });
    }
    for (const entry of expired) {
      const bucket = `${entry.record.kind}\u0000${dayOf(entry.at)}`;
      if (keep.get(bucket)?.key !== keyOf(entry.record)) mark(entry.record);
    }
  } else {
    for (const entry of expired) mark(entry.record);
  }

  if (policy.retentionMode === 'rolling' && policy.maxArchivedRecords > 0) {
    const survivors = aged
      .filter((entry) => !doomed.has(keyOf(entry.record)))
      .sort((left, right) => left.at - right.at || left.record.id.localeCompare(right.record.id));
    let total = survivors.length;
    for (const entry of survivors) {
      if (total <= policy.maxArchivedRecords) break;
      mark(entry.record);
      total--;
    }
  }

  plan.delete = aged
    .filter((entry) => doomed.has(keyOf(entry.record)))
    .sort(
      (left, right) =>
        left.at - right.at ||
        left.record.kind.localeCompare(right.record.kind) ||
        left.record.id.localeCompare(right.record.id),
    )
    .map((entry) => ({ kind: entry.record.kind, id: entry.record.id }));
  return plan;
}

const timestampExpression = RETENTION_KINDS.map(
  (kind) => `WHEN '${kind}' THEN data->>'${TIMESTAMP_FIELDS[kind]}'`,
).join('\n        ');

async function loadRetentionRecords(db: pg.Pool | pg.PoolClient): Promise<RetentionRecord[]> {
  const rows = await db.query<RetentionRecord>(
    `SELECT kind, id,
      CASE kind
      ${timestampExpression}
      END AS timestamp
     FROM records
     WHERE kind = ANY($1::text[])`,
    [RETENTION_KINDS],
  );
  return rows.rows;
}

/**
 * Read-only footprint for the archive screen. Mirrors the selection logic used by
 * a real run so the operator sees both "past the window" and "would be removed"
 * without loading every record into the browser.
 */
export async function previewRetention(
  pool: pg.Pool,
  policy: RetentionPolicy,
): Promise<RetentionPreview> {
  const rows = await loadRetentionRecords(pool);
  const now = Date.now();
  const plan = selectRetention(rows, { ...policy, enabled: true }, now);
  const cutoffMs = now - policy.retentionHours * 3_600_000;
  const records = Object.fromEntries(
    RETENTION_KINDS.map((kind) => [kind, { total: 0, past: 0, deletable: plan.byKind[kind] }]),
  ) as RetentionPreview['records'];
  for (const record of rows) {
    const bucket = records[record.kind];
    bucket.total++;
    const at = parseTimestamp(record.timestamp);
    if (at !== null && at < cutoffMs) bucket.past++;
  }
  const protectedRows = (
    await pool.query<{ kind: string; count: number }>(
      "SELECT kind, count(*)::int AS count FROM records WHERE kind IN ('findings','advisories') GROUP BY kind",
    )
  ).rows;
  const protectedCount = (kind: string) =>
    Number(protectedRows.find((row) => row.kind === kind)?.count ?? 0);
  const auditLogs = Number((await pool.query('SELECT count(*)::int AS count FROM audit')).rows[0].count);
  return {
    cutoff: plan.cutoff,
    records,
    protected: {
      findings: protectedCount('findings'),
      advisories: protectedCount('advisories'),
      auditLogs,
    },
    scanned: rows.length,
  };
}

/**
 * Apply the saved retention policy once. Returns null when the policy is
 * disabled so callers can distinguish "nothing to do" from "cleanup ran".
 *
 * Runs inside the shared state transaction (advisory lock 800002) so a
 * concurrent pipeline write cannot observe a half-applied cleanup, and writes
 * one audit entry only when records were actually removed.
 */
export async function runRetention(
  pool: pg.Pool,
  actor: string,
  ipAddress = '',
): Promise<RetentionRunResult | null> {
  return transaction(
    pool,
    async (db) => {
      const settings = (await get<AppSettings>(db, 'settings', 'main')) || DEFAULT_SETTINGS;
      const policy = settings.retentionConfig;
      if (!policy?.enabled) return null;

    const records = await loadRetentionRecords(db);
    const plan = selectRetention(records, policy, Date.now());
    for (const kind of RETENTION_KINDS) {
      const ids = plan.delete.filter((record) => record.kind === kind).map((record) => record.id);
      // Keep each statement's row count bounded so one large backlog cannot hold
      // the state lock for an unbounded amount of time.
      for (let offset = 0; offset < ids.length; offset += 1000)
        await db.query('DELETE FROM records WHERE kind=$1 AND id=ANY($2::text[])', [
          kind,
          ids.slice(offset, offset + 1000),
        ]);
    }

    // Terminal queue rows and operational telemetry are transient too. Applying
    // the same policy window keeps an operator's configured retention period
    // authoritative instead of silently trimming them on a fixed schedule.
    // Deletions are batched in 10,000-row chunks using subquery-scoped
    // primary-key lookups to avoid table-level lock contention.
    let outboxDeleted = 0;
    for (;;) {
      const outbox = await db.query(
        "DELETE FROM outbox WHERE id IN (SELECT id FROM outbox WHERE status IN ('ACCEPTED','FAILED','REJECTED') AND updated_at < $1 LIMIT 10000)",
        [new Date(plan.cutoff)],
      );
      outboxDeleted += outbox.rowCount ?? 0;
      if ((outbox.rowCount ?? 0) < 10000) break;
    }
    let eventsDeleted = 0;
    for (;;) {
      const events = await db.query(
        "DELETE FROM operational_events WHERE id IN (SELECT id FROM operational_events WHERE occurred_at < $1 LIMIT 10000)",
        [new Date(plan.cutoff)],
      );
      eventsDeleted += events.rowCount ?? 0;
      if ((events.rowCount ?? 0) < 10000) break;
    }

    if (plan.delete.length || outboxDeleted || eventsDeleted) {
      const summary = RETENTION_KINDS.filter((kind) => plan.byKind[kind] > 0)
        .map((kind) => `${kind}: ${plan.byKind[kind]}`)
        .join(', ');
      const system = [
        outboxDeleted ? `outbox: ${outboxDeleted}` : '',
        eventsDeleted ? `operationalEvents: ${eventsDeleted}` : '',
      ]
        .filter(Boolean)
        .join(', ');
      await appendAudit(
        db,
        'Retention cleanup',
        `${plan.delete.length} record(s) removed${summary ? ` (${summary})` : ''}${system ? `; transient system rows removed (${system})` : ''} using ${policy.retentionMode} mode and a ${policy.retentionHours}h window`,
        actor,
        'SECURITY',
        'INFO',
        ipAddress,
      );
    }

    return {
      ranAt: new Date().toISOString(),
      mode: policy.retentionMode,
      retentionHours: policy.retentionHours,
      cutoff: plan.cutoff,
      scanned: plan.scanned,
      deleted: plan.delete.length,
      unknownAge: plan.unknownAge,
      byKind: plan.byKind,
      system: { outbox: outboxDeleted, events: eventsDeleted },
    };
    },
    undefined,
    // Serialize destructive cleanup across replicas; ordinary mutations are no
    // longer blocked behind a multi-second retention sweep.
    { locks: ['retention-run'] },
  );
}
