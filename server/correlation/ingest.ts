import { timedQuery } from './query.ts';
import { createHash, randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { setTimeout as delay } from 'node:timers/promises';
import type { Pool, PoolClient, QueryResultRow } from 'pg';
import { AdvisoryInputSchema } from './validation.ts';
import { extractText } from './extraction.ts';
import { TextCorrelationEngine, type TimedQuery } from './engine.ts';
import { linkPreCveClusters, clusterWindowDays, DEFAULT_CLUSTER_OPEN_WINDOW_DAYS } from './clusters.ts';
import type { CorrelationTelemetry } from './telemetry.ts';
import type { DeadLetterQueue } from './deadLetter.ts';
export type IngestionResult = 'PROCESSED' | 'DUPLICATE' | 'DEAD_LETTER' | 'UNDURABLE';
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
  /**
   * Cached logging detail level, refreshed at the start of each advisory.
   *
   * It cannot be resolved inside the ingest transaction: the first telemetry
   * entries (`ingestion.started`, `extraction.completed`) are emitted before a
   * connection is even acquired, so reading the setting later meant those lines
   * were filtered under the previous level and the advisory committed with an
   * empty telemetry buffer. Refreshing per advisory keeps a settings change
   * effective without a restart while ensuring the level is known up front.
   */
  private verbosityLevel: 'standard' | 'verbose' = 'standard';
  private verbosityCheckedAt = 0;
  constructor(
    readonly telemetry: CorrelationTelemetry,
    readonly deadLetterQueue: DeadLetterQueue,
    private readonly engine = new TextCorrelationEngine(),
  ) {}
  /** Refresh from the settings record at most once per second. */
  private async refreshVerbosity(pool: Pool): Promise<void> {
    const now = Date.now();
    if (now - this.verbosityCheckedAt < 1000) return;
    this.verbosityCheckedAt = now;
    try {
      const row = (
        await pool.query<{ value: string | null }>(
          "SELECT data->>'logVerbosity' AS value FROM records WHERE kind='settings' AND id='main'",
        )
      ).rows[0];
      this.verbosityLevel = row?.value === 'verbose' ? 'verbose' : 'standard';
    } catch {
      this.verbosityLevel = 'standard';
    }
    this.telemetry.verbosity = this.verbosityLevel;
  }
  /** Resolve the operator-configured cluster window; falls back to the
   * default when the policy row is absent (pre-021 database mid-migration). */
  private async clusterWindowDays(query: TimedQuery): Promise<number> {
    try {
      const row = (
        await query<{ days: number | null }>(
          'SELECT pre_cve_cluster_window_days AS days FROM correlation_policy WHERE id=1',
        )
      ).rows[0];
      return clusterWindowDays(row?.days);
    } catch {
      return DEFAULT_CLUSTER_OPEN_WINDOW_DAYS;
    }
  }
  async processIncomingAdvisory(
    rawInput: unknown,
    dbPool: Pool,
     trackingId: string = randomUUID(),
    signal?: AbortSignal,
  ): Promise<IngestionResult> {
    const started = performance.now();
    let databaseTime = 0;
    // Resolve the logging level before the first entry so the whole advisory is
    // recorded under one consistent level.
    await this.refreshVerbosity(dbPool);
    this.telemetry.log('INFO', 'ingestion.started', { trackingId });
    const parsed = AdvisoryInputSchema.safeParse(rawInput);
    if (!parsed.success) {
      this.telemetry.log('WARN', 'validation.failed', { trackingId, count: parsed.error.issues.length });
      const durable = await this.persistFailure(rawInput, 'VALIDATION_FAILED', trackingId, dbPool);
      this.telemetry.completed++;
      this.telemetry.latencyTotal += performance.now() - started;
      return durable ? 'DEAD_LETTER' : 'UNDURABLE';
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
          await query('SET LOCAL idle_in_transaction_session_timeout=\'5000ms\'');
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
            VALUES($1,$2,$3,$4,$5) ON CONFLICT (fingerprint) DO UPDATE SET processed_at=now() WHERE unstructured_advisories.fingerprint = EXCLUDED.fingerprint AND unstructured_advisories.id = EXCLUDED.id RETURNING id`,
            [randomUUID(), input.title, extracted.cleanContent, input.url, fingerprint],
          );
          if (!inserted.rowCount) {
            await query('COMMIT');
            this.telemetry.log('INFO', 'ingestion.duplicate', { trackingId });
            return 'DUPLICATE';
          }
          const advisoryId = inserted.rows[0].id;
          const matches = await this.engine.correlate(input, extracted, query);
          // Pre-CVE cluster linkage runs inside the same transaction: the
          // advisory, its matches, and its cluster membership commit atomically.
          // The window is read here rather than cached so an operator policy
          // change takes effect on the next advisory without a restart.
          const entities = matches
            .filter((match) => match.vendor && match.product)
            .map((match) => ({ vendor: match.vendor, product: match.product }));
          const windowDays = await this.clusterWindowDays(query);
          // Adapt the transaction-bound TimedQuery to the structural query
          // interface used by the cluster module (both are the same client).
          const clusterDb = {
            query: (sql: string, values?: unknown[]) => query<Record<string, unknown>>(sql, values),
          };
          await linkPreCveClusters(clusterDb, advisoryId, entities, matches.length, extracted.cveIds, windowDays);
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
          // Persist telemetry to operational_events BEFORE commit for crash durability
          await this.telemetry.persistBeforeCommit(client, trackingId);
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
      const durable = await this.persistFailure(rawInput, databaseCode(error), trackingId, dbPool);
      return durable ? 'DEAD_LETTER' : 'UNDURABLE';
    } finally {
      this.telemetry.completed++;
      this.telemetry.latencyTotal += performance.now() - started;
    }
  }



  /**
   * Durable fallback chain: encrypted spool first, then the database.
   *
   * A failed advisory must never be dropped. The previous implementation let a
   * full spool throw out of the caller, which both lost the record and aborted
   * the surrounding stream — turning a disk-pressure event into a pipeline-wide
   * outage precisely when load was highest. Every failure here is contained and
   * reported, never propagated.
   */
  private async persistFailure(
    raw: unknown,
    errorCode: string,
    trackingId: string,
    dbPool: Pool,
  ): Promise<boolean> {
    try {
      const outcome = await this.deadLetterQueue.capture(raw, errorCode, trackingId, dbPool);
      if (outcome === 'SPOOLED') return true;
    } catch (error) {
      this.telemetry.log('CRITICAL', 'dead_letter.spool_failed', { trackingId });
    }
    if (await this.deadLetterQueue.captureToDatabase(raw, errorCode, trackingId, dbPool)) return true;
    // Both stores are unavailable. This is the only remaining loss window, so
    // the caller must NOT treat the record as durably handled. It is logged at
    // CRITICAL with enough identifiers to reconstruct the record from the
    // source feed, and the ingest outcome is UNDURABLE so a pending row is not
    // acknowledged and deleted.
    this.telemetry.log('CRITICAL', 'dead_letter.undurable', { trackingId });
    return false;
  }
}
