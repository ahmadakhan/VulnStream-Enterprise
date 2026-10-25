import { timedQuery } from './query.ts';
import { createHash, randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { setTimeout as delay } from 'node:timers/promises';
import type { Pool, PoolClient, QueryResultRow } from 'pg';
import { AdvisoryInputSchema } from './validation.ts';
import { extractText } from './extraction.ts';
import { TextCorrelationEngine, type TimedQuery } from './engine.ts';
import type { CorrelationTelemetry } from './telemetry.ts';
import type { DeadLetterQueue } from './deadLetter.ts';
export type IngestionResult = 'PROCESSED' | 'DUPLICATE' | 'DEAD_LETTER';
export const databaseCode = (error: unknown): string => {
  const code = error && typeof error === 'object' && 'code' in error ? String(error.code) : '';
  return /^[A-Z0-9]{5,20}$/.test(code) ? code : 'DATABASE_FAILURE';
};
export const transientDatabaseError = (error: unknown) =>
  /^(40001|40P01|08[A-Z0-9]{3}|57P0[123]|ECONNRESET|ECONNREFUSED|EPIPE|ETIMEDOUT|ENETUNREACH)$/.test(
    databaseCode(error),
  ) ||
  (error instanceof Error &&
    /connection terminated|connection timeout|timeout exceeded when trying to connect/i.test(error.message));
export class AdvisoryIngestor {
  constructor(
    readonly telemetry: CorrelationTelemetry,
    readonly deadLetterQueue: DeadLetterQueue,
    private readonly engine = new TextCorrelationEngine(),
  ) {}
  async processIncomingAdvisory(
    rawInput: unknown,
    dbPool: Pool,
    trackingId = randomUUID(),
    signal?: AbortSignal,
  ): Promise<IngestionResult> {
    const started = performance.now();
    let databaseTime = 0;
    this.telemetry.log('INFO', 'ingestion.started', { trackingId });
    const parsed = AdvisoryInputSchema.safeParse(rawInput);
    if (!parsed.success) {
      this.telemetry.log('WARN', 'validation.failed', { trackingId, count: parsed.error.issues.length });
      await this.deadLetterQueue.capture(rawInput, 'VALIDATION_FAILED', trackingId, dbPool);
      this.telemetry.completed++;
      this.telemetry.latencyTotal += performance.now() - started;
      return 'DEAD_LETTER';
    }
    const input = parsed.data;
    const fingerprint = createHash('sha256')
      .update(JSON.stringify([input.url, input.title]))
      .digest('hex');
    try {
      const extracted = await extractText(
        `${input.title} ${input.content}`,
        this.telemetry,
        trackingId,
        signal,
      );
      for (let attempt = 0; attempt <= 3; attempt++) {
        let client: PoolClient | undefined;
        let released = false;
        let failed = false;
        let connectionError: Error | undefined;
        const onClientError = (error: Error) => {
          connectionError = error;
          failed = true;
        };
        const abort = () => {
          if (client && !released) {
            released = true;
            client.release(true);
          }
        };
        try {
          signal?.throwIfAborted();
          const connectStart = performance.now();
          client = await dbPool.connect();
          client.on('error', onClientError);
          databaseTime += performance.now() - connectStart;
          signal?.addEventListener('abort', abort, { once: true });
          signal?.throwIfAborted();
          const query: TimedQuery = async <T extends QueryResultRow>(sql: string, values?: unknown[]) => {
            signal?.throwIfAborted();
            if (connectionError) throw connectionError;
            const queryStart = performance.now();
            try {
              return await client!.query<T>(timedQuery(sql, values));
            } finally {
              databaseTime += performance.now() - queryStart;
            }
          };
          await query('BEGIN TRANSACTION ISOLATION LEVEL READ COMMITTED');
          await query("SET LOCAL statement_timeout='3500ms'");
          await query("SET LOCAL lock_timeout='2000ms'");
          await query("SET LOCAL idle_in_transaction_session_timeout='5000ms'");
          const duplicate = await query('SELECT id FROM unstructured_advisories WHERE fingerprint=$1', [
            fingerprint,
          ]);
          if (duplicate.rowCount) {
            await query('COMMIT');
            this.telemetry.log('INFO', 'ingestion.duplicate', { trackingId });
            return 'DUPLICATE';
          }
          const inserted = await query<{ id: string }>(
            `INSERT INTO unstructured_advisories(id,title,content,url,fingerprint)
            VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING RETURNING id`,
            [randomUUID(), input.title, extracted.cleanContent, input.url, fingerprint],
          );
          if (!inserted.rowCount) {
            await query('COMMIT');
            this.telemetry.log('INFO', 'ingestion.duplicate', { trackingId });
            return 'DUPLICATE';
          }
          const advisoryId = inserted.rows[0].id;
          const matches = await this.engine.correlate(input, extracted, query);
          for (const match of matches) {
            if (match.confidence === 'LOW')
              await query(
                `INSERT INTO low_confidence_review_buffer(advisory_id,asset_id,reason)
                VALUES($1,$2,$3) ON CONFLICT DO NOTHING`,
                [advisoryId, match.assetId || null, match.reason],
              );
            else
              await query(
                `INSERT INTO correlation_matches(advisory_id,asset_id,vendor,product,confidence,reason)
                VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`,
                [advisoryId, match.assetId, match.vendor, match.product, match.confidence, match.reason],
              );
          }
          for (const match of matches)
            if (match.assetId && match.assetRevision)
              await query(
                `INSERT INTO correlation_match_evidence(advisory_id,asset_id,asset_revision) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`,
                [advisoryId, match.assetId, match.assetRevision],
              );
          await query('UPDATE unstructured_advisories SET processed_at=now() WHERE id=$1', [advisoryId]);
          await query('COMMIT');
          this.telemetry.log('INFO', 'ingestion.committed', {
            trackingId,
            count: matches.length,
            ingestionLatencyMs: performance.now() - started,
            totalDatabaseTimeMs: databaseTime,
          });
          return 'PROCESSED';
        } catch (error) {
          failed = true;
          if (client && !released) await client.query(timedQuery('ROLLBACK', [], 1000)).catch(() => {});
          if (signal?.aborted || !transientDatabaseError(error) || attempt === 3) throw error;
          this.telemetry.log('WARN', 'database.transaction_retry', { trackingId, attempt: attempt + 1 });
        } finally {
          signal?.removeEventListener('abort', abort);
          client?.removeListener('error', onClientError);
          if (client && !released) {
            released = true;
            client.release(failed);
          }
        }
        await delay(100 * 2 ** attempt + Math.random() * 50, undefined, { signal });
      }
      throw new Error('RETRIES_EXHAUSTED');
    } catch (error) {
      this.telemetry.log('ERROR', 'ingestion.failed', { trackingId, totalDatabaseTimeMs: databaseTime });
      await this.deadLetterQueue.capture(rawInput, databaseCode(error), trackingId, dbPool);
      return 'DEAD_LETTER';
    } finally {
      this.telemetry.completed++;
      this.telemetry.latencyTotal += performance.now() - started;
    }
  }
}
