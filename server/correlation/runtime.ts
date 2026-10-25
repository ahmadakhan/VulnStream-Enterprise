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
import { claimPending, renewPending, acknowledgePending } from './pending.ts';
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
    if (this.timer) return;
    this.stopped = false;
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
      } finally {
        clearInterval(heartbeat);
        await renewing;
      }
      await this.queueNotifications();
    }
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
    await this.supervisor.stop();
    await this.draining;
  }
}
