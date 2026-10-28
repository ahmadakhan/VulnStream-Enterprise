import { transaction } from '../db.ts';
import { queueNativeNotifications } from './notifications.ts';
import { retainCorrelationData, cleanupStaleMatches } from './operations.ts';
import { Readable } from 'node:stream';
import type { Pool } from 'pg';
import { CorrelationTelemetry } from './telemetry.ts';
import { DeadLetterQueue } from './deadLetter.ts';
import { AdvisoryIngestor } from './ingest.ts';
import { PipelineSupervisor } from './supervisor.ts';
import { AdvisoryStreamProcessor } from './stream.ts';
import { claimPending, renewPending, acknowledgePending, acknowledgePendingExcept } from './pending.ts';

/** Structural equality for pending payloads (plain JSON values only). */
const samePayload = (left: unknown, right: unknown): boolean => {
  if (left === right) return true;
  try {
    return JSON.stringify(left) === JSON.stringify(right);
  } catch {
    return false;
  }
};
import { Heartbeat } from './heartbeat.ts';
export class CorrelationRuntime {
  readonly supervisor: PipelineSupervisor;
  readonly processor: AdvisoryStreamProcessor;
  /** Publishes liveness to an external receiver; disabled when no URL is set. */
  readonly heartbeat: Heartbeat;
  private timer?: ReturnType<typeof setInterval>;
  private draining?: Promise<void>;
  private stopped = false;
  private lastMaintenance = 0;
  /**
   * Durable queue depth, sampled by the drain loop rather than by /metrics.
   * /metrics must stay database-independent (it is scraped during outages, which
   * is exactly when the database is unavailable), so the sampler lives here and
   * the route just reads the cached number.
   */
  pendingDepth = -1;
  /** When `pendingDepth` was last refreshed; 0 means never. */
  pendingSampledAt = 0;
  /** Set when the consumer is disabled, so readiness does not claim it runs. */
  readonly workerEnabled: boolean;
  constructor(
    private readonly pool: Pool,
    key: string,
    directory: string,
    options: {
      url: string;
      intervalSeconds: number;
      logLevel?: 'standard' | 'verbose';
    } = { url: '', intervalSeconds: 60 },
  ) {
    const telemetry = new CorrelationTelemetry();
    telemetry.verbosity = options.logLevel ?? 'standard';
    const queue = new DeadLetterQueue(directory, key, telemetry);
    this.supervisor = new PipelineSupervisor(pool, new AdvisoryIngestor(telemetry, queue));
    this.processor = new AdvisoryStreamProcessor(this.supervisor);
    this.heartbeat = new Heartbeat({
      url: options.url,
      intervalMs: options.intervalSeconds * 1000,
      suppressOnUnhealthy: true,
    });
    this.workerEnabled = process.env.WORKER_ENABLED !== 'false';
  }
  start(): void {
    if (this.timer) return;
    this.stopped = false;
    this.supervisor.start();
    // The ping reports on the pipeline, not on the HTTP process: a heartbeat
    // that fires while ingestion is refusing every advisory would tell the
    // external receiver that it is safe to stay silent.
    this.heartbeat.start(() => {
      if (!this.workerEnabled) return { healthy: true, reason: 'WORKER_DISABLED_MONITORING_ONLY' };
      if (this.supervisor.health !== 'HEALTHY')
        return { healthy: false, reason: this.supervisor.health };
      return { healthy: true, reason: 'HEALTHY' };
    });
    this.timer = setInterval(() => {
      if (this.draining || this.stopped || this.supervisor.health !== 'HEALTHY') return;
      this.draining = this.drain()
        .catch(() => {
          this.supervisor.ingestor.telemetry.log('ERROR', 'pending.drain_failed');
        })
        .finally(() => {
          this.draining = undefined;
          // Refresh the queue depth the stuck-ingestion alert depends on. A
          // failure leaves the previous sample rather than reporting zero, which
          // would read as "nothing queued" during a database outage.
          void this.pool
            .query('SELECT count(*)::int AS depth FROM correlation_pending')
            .then((result) => {
              this.pendingDepth = Number(result.rows[0]?.depth ?? 0);
              this.pendingSampledAt = Date.now();
            })
            .catch(() => {});
        });
    }, 1000);
    this.timer.unref();
  }
  private async drain(): Promise<void> {
    await this.cleanupStaleMatches();
    await this.queueNotifications();
    if (Date.now() - this.lastMaintenance >= 60_000) {
      await transaction(this.pool, (db) => retainCorrelationData(db)).catch(() => {
        this.supervisor.ingestor.telemetry.log('ERROR', 'retention.failed');
      });
      this.lastMaintenance = Date.now();
    }
    while (!this.stopped && this.supervisor.health === 'HEALTHY') {
      // Leased SKIP LOCKED claims survive crashes; final ingestion is idempotent.
      // Claim at most concurrency slots, so leases don't expire behind a local queue.
      const batch = await claimPending(this.pool, this.supervisor.concurrencyLimit);
      if (!batch.jobs.length) return;
      let renewing: Promise<unknown> | undefined;
      const heartbeat = setInterval(() => {
        if (renewing) return;
        renewing = renewPending(this.pool, batch).catch(() => {
          this.supervisor.ingestor.telemetry.log('WARN', 'pending.lease_renewal_failed');
        }).finally(() => { renewing = undefined; });
      }, 20_000);
      heartbeat.unref();
      try {
        await this.processor.processAdvisoryStream(
          Readable.from(batch.jobs.map((job) => job.payload)),
          this.supervisor.concurrencyLimit,
          this.pool,
        );
        await acknowledgePending(this.pool, batch);
      } catch (error) {
        // At least one record could not be made durable. Its pending row is the
        // last copy, so it is retained — but only it. Acknowledging the whole
        // batch would delete the record; acknowledging none replays the entire
        // batch and re-runs every advisory that already committed. The stream
        // reports which payloads failed, and those are matched back to the jobs
        // by payload identity (pending payloads are JSON-round-tripped, so the
        // comparison is structural and stable).
        const failed = (error as { failedRecords?: unknown[] }).failedRecords ?? [];
        const retainedIds = failed.length
          ? batch.jobs
              .filter((job) => failed.some((record) => samePayload(record, job.payload)))
              .map((job) => job.id)
          : // The stream failed before it could attribute records (e.g. the
            // source itself threw): nothing may be acknowledged.
            batch.jobs.map((job) => job.id);
        if (retainedIds.length < batch.jobs.length) {
          await acknowledgePendingExcept(this.pool, batch, retainedIds).catch(() => 0);
        }
        this.supervisor.ingestor.telemetry.log('CRITICAL', 'pending.batch_partially_acknowledged', {
          count: batch.jobs.length - retainedIds.length,
        });
        throw error;
      } finally {
        clearInterval(heartbeat);
        await renewing;
      }
      await this.queueNotifications();
    }
  }
  private async cleanupStaleMatches(): Promise<void> {
    await transaction(this.pool, (db) => cleanupStaleMatches(db)).catch(() => {
      this.supervisor.ingestor.telemetry.log('ERROR', 'stale_matches.cleanup_failed');
    });
  }
  private async queueNotifications(): Promise<void> {
    await transaction(this.pool, (db) => queueNativeNotifications(db)).catch(() => {
      this.supervisor.ingestor.telemetry.log('ERROR', 'notifications.queue_failed');
    });
  }
  async stop(): Promise<void> {
    this.stopped = true;
    clearInterval(this.timer);
    this.timer = undefined;
    this.heartbeat.stop();
    await this.supervisor.stop();
    await this.draining;
  }
}
