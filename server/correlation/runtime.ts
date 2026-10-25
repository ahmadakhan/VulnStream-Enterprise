import { transaction } from '../db.ts';
import { queueNativeNotifications } from './notifications.ts';
import { retainCorrelationData } from './operations.ts';
import { Readable } from 'node:stream';
import type { Pool } from 'pg';
import { CorrelationTelemetry } from './telemetry.ts';
import { DeadLetterQueue } from './deadLetter.ts';
import { AdvisoryIngestor } from './ingest.ts';
import { PipelineSupervisor } from './supervisor.ts';
import { AdvisoryStreamProcessor } from './stream.ts';
export class CorrelationRuntime {
  readonly supervisor: PipelineSupervisor;
  readonly processor: AdvisoryStreamProcessor;
  private timer?: ReturnType<typeof setInterval>;
  private draining?: Promise<void>;
  private stopped = false;
  private lastMaintenance = 0;
  constructor(
    private readonly pool: Pool,
    key: string,
    directory: string,
  ) {
    const telemetry = new CorrelationTelemetry();
    const queue = new DeadLetterQueue(directory, key, telemetry);
    this.supervisor = new PipelineSupervisor(pool, new AdvisoryIngestor(telemetry, queue));
    this.processor = new AdvisoryStreamProcessor(this.supervisor);
  }
  start(): void {
    this.supervisor.start();
    this.timer = setInterval(() => {
      if (this.draining || this.stopped || this.supervisor.health !== 'HEALTHY') return;
      this.draining = this.drain()
        .catch(() => {
          this.supervisor.ingestor.telemetry.log('ERROR', 'pending.drain_failed');
        })
        .finally(() => {
          this.draining = undefined;
        });
    }, 1000);
    this.timer.unref();
  }
  private async drain(): Promise<void> {
    await transaction(this.pool, (db) => queueNativeNotifications(db));
    if (Date.now() - this.lastMaintenance >= 60_000) {
      await transaction(this.pool, (db) => retainCorrelationData(db));
      this.lastMaintenance = Date.now();
    }
    while (!this.stopped && this.supervisor.health === 'HEALTHY') {
      // Leased SKIP LOCKED claims survive crashes; final ingestion is idempotent.
      // Claim at most concurrency slots, so leases don't expire behind a local queue.
      const jobs = await this.pool.query<{ id: string; payload: unknown }>(
        `WITH selected AS (
      SELECT id FROM correlation_pending WHERE lease_until IS NULL OR lease_until<now()
      ORDER BY created_at LIMIT $1 FOR UPDATE SKIP LOCKED)
      UPDATE correlation_pending p SET lease_until=now()+interval '60 seconds'
      FROM selected s WHERE p.id=s.id RETURNING p.id,p.payload`,
        [this.supervisor.concurrencyLimit],
      );
      if (!jobs.rowCount) return;
      await this.processor.processAdvisoryStream(
        Readable.from(jobs.rows.map((job) => job.payload)),
        this.supervisor.concurrencyLimit,
        this.pool,
      );
      await transaction(this.pool, (db) => queueNativeNotifications(db));
      await this.pool.query('DELETE FROM correlation_pending WHERE id=ANY($1::text[])', [
        jobs.rows.map((job) => job.id),
      ]);
    }
  }
  async stop(): Promise<void> {
    this.stopped = true;
    clearInterval(this.timer);
    await this.supervisor.stop();
    await this.draining;
  }
}
