import { timedQuery } from './query.ts';
import { getHeapStatistics } from 'node:v8';
import { setTimeout as delay } from 'node:timers/promises';
import type { Pool } from 'pg';
import type { PipelineHealth, CorrelationSnapshot } from '../../shared/correlation.ts';
import type { AdvisoryIngestor } from './ingest.ts';
export class PipelineSupervisor {
  health: PipelineHealth = 'HEALTHY';
  desiredConcurrency = 4;
  concurrencyLimit = 4;
  private memoryPressure = false;
  private timer?: ReturnType<typeof setInterval>;
  private checking = false;
  private stopped = false;
  private simulatedUntil = 0;
  private simulated: 'memory' | 'database' | null = null;
  readonly active = new Map<string, { started: number; controller: AbortController }>();
  constructor(
    readonly pool: Pool,
    readonly ingestor: AdvisoryIngestor,
  ) {}
  setConcurrency(limit: number): void {
    if (!Number.isInteger(limit) || limit < 1 || limit > 32) throw new Error('CONCURRENCY_OUT_OF_RANGE');
    this.desiredConcurrency = limit;
    this.concurrencyLimit = this.memoryPressure ? Math.max(1, Math.floor(limit / 2)) : limit;
    this.ingestor.telemetry.log('INFO', 'supervisor.concurrency_changed', { count: this.concurrencyLimit });
  }
  memoryPercent(): number {
    const memory = process.memoryUsage();
    const constrained = process.constrainedMemory?.() || 0;
    return Math.min(
      100,
      Math.max(
        memory.heapUsed / getHeapStatistics().heap_size_limit,
        constrained ? memory.rss / constrained : 0,
      ) * 100,
    );
  }
  start(): void {
    if (this.timer) return;
    this.stopped = false;
    this.ingestor.telemetry.log('INFO', 'supervisor.started');
    this.timer = setInterval(() => {
      void this.check();
    }, 1000);
    this.timer.unref();
    void this.check();
  }
  async stop(): Promise<void> {
    this.stopped = true;
    clearInterval(this.timer);
    this.timer = undefined;
    for (const task of this.active.values()) task.controller.abort();
    while (this.active.size || this.checking) await delay(20);
  }
  simulate(fault: 'memory' | 'database'): void {
    this.simulated = fault;
    this.simulatedUntil = Date.now() + 5000;
    this.ingestor.telemetry.log('WARN', 'supervisor.fault_simulated');
    void this.check();
  }
  async check(): Promise<void> {
    if (this.checking || this.stopped) return;
    this.checking = true;
    const log = this.ingestor.telemetry;
    try {
      if (Date.now() >= this.simulatedUntil) this.simulated = null;
      const memory = this.simulated === 'memory' ? 90 : this.memoryPercent();
      if (memory >= 85 && !this.memoryPressure) {
        this.memoryPressure = true;
        this.concurrencyLimit = Math.max(1, Math.floor(this.desiredConcurrency / 2));
        log.log('WARN', 'supervisor.memory_shedding', { count: this.concurrencyLimit });
        globalThis.gc?.();
      } else if (memory < 60 && this.memoryPressure) {
        this.memoryPressure = false;
        this.concurrencyLimit = this.desiredConcurrency;
        log.log('INFO', 'supervisor.memory_recovered');
      }
      for (const [trackingId, task] of this.active)
        if (Date.now() - task.started >= 15_000 && !task.controller.signal.aborted) {
          log.log('CRITICAL', 'supervisor.worker_deadline', { trackingId });
          task.controller.abort();
        }
      try {
        if (this.simulated === 'database') throw new Error('SIMULATED_DATABASE_OUTAGE');
        await this.pool.query(timedQuery('SELECT 1', [], 2000));
        const next = this.memoryPressure ? 'DEGRADED_BACKPRESSURE' : 'HEALTHY';
        if (this.health !== next)
          log.log(
            next === 'HEALTHY' ? 'INFO' : 'WARN',
            next === 'HEALTHY' ? 'supervisor.recovered' : 'supervisor.backpressure_active',
          );
        this.health = next;
        await this.ingestor.deadLetterQueue.flush(this.pool).catch(() => {
          log.log('CRITICAL', 'dead_letter.flush_failed');
        });
      } catch {
        if (this.health !== 'RECOVERING_DB_SEVERANCE') log.log('CRITICAL', 'supervisor.database_unavailable');
        this.health = 'RECOVERING_DB_SEVERANCE';
        // pg destroys failed clients; a new connect resolves the configured
        // failover/proxy endpoint. Never pool.end() the shared application pool.
      }
    } finally {
      this.checking = false;
    }
  }
  async acquire(trackingId: string, controller: AbortController): Promise<void> {
    await this.ingestor.telemetry.ready();
    while (
      !this.stopped &&
      (this.health === 'RECOVERING_DB_SEVERANCE' ||
        this.memoryPressure ||
        this.active.size >= this.concurrencyLimit)
    )
      await delay(50);
    if (this.stopped) throw new Error('SUPERVISOR_STOPPED');
    this.active.set(trackingId, { started: Date.now(), controller });
  }
  async snapshot(): Promise<CorrelationSnapshot> {
    const telemetry = this.ingestor.telemetry;
    type StoredMatch = Omit<CorrelationSnapshot['matches'][number], 'createdAt'> & { createdAt: Date };
    const result = await this.pool
      .query<StoredMatch>(
        timedQuery(
          `SELECT advisory_id AS "advisoryId", asset_id AS "assetId",vendor,product,confidence,reason,
      created_at AS "createdAt" FROM correlation_matches ORDER BY created_at DESC LIMIT 100`,
          [],
          2000,
        ),
      )
      .catch(() => ({ rows: [] }));
    return {
      health: this.health,
      concurrencyLimit: this.concurrencyLimit,
      activeWorkers: this.active.size,
      memoryPercent: this.memoryPercent(),
      itemsPerSecond: telemetry.completed / Math.max(1, (performance.now() - telemetry.startedAt) / 1000),
      averageLatencyMs: telemetry.latencyTotal / Math.max(1, telemetry.completed),
      deadLetters: telemetry.deadLetters,
      droppedLogs: telemetry.droppedLogs,
      pool: { total: this.pool.totalCount, idle: this.pool.idleCount, waiting: this.pool.waitingCount },
      logs: [...telemetry.logs],
      matches: result.rows.map((row) => ({ ...row, createdAt: row.createdAt.toISOString() })),
    };
  }
}
