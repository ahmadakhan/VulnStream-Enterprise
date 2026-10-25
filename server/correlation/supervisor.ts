import { randomUUID } from 'node:crypto';
import { timedQuery } from './query.ts';
import { getHeapStatistics } from 'node:v8';
import { setTimeout as delay } from 'node:timers/promises';
import type { Pool } from 'pg';
import type { PipelineHealth, CorrelationSnapshot } from '../../shared/correlation.ts';
import type { AdvisoryIngestor } from './ingest.ts';
export type IngestPriority = 'HIGH' | 'MEDIUM' | 'LOW';
export interface SupervisorConfig {
  highPool: number;
  mediumPool: number;
  lowPool: number;
}
const DEFAULT_CONFIG: SupervisorConfig = { highPool: 4, mediumPool: 8, lowPool: 16 };
// Circuit breaker configuration
const CRASH_WINDOW_MS = 60_000;
const CRASH_THRESHOLD = 3;
const PAUSE_DURATION_MS = 5 * 60_000; // 5 minutes
export class PipelineSupervisor {
  readonly instanceId = randomUUID();
  health: PipelineHealth = 'HEALTHY';
  desiredConcurrency = 4;
  concurrencyLimit = 4;
  readonly config: SupervisorConfig;
  readonly queues = {
    HIGH: [] as Array<{ trackingId: string; controller: AbortController; resolve: () => void }>,
    MEDIUM: [] as Array<{ trackingId: string; controller: AbortController; resolve: () => void }>,
    LOW: [] as Array<{ trackingId: string; controller: AbortController; resolve: () => void }>,
  };
  private memoryPressure = false;
  private timer?: ReturnType<typeof setInterval>;
  private checking = false;
  private stopped = false;
  private shutdown = new AbortController();
  private simulatedUntil = 0;
  private simulated: 'memory' | 'database' | null = null;
  readonly active = new Map<string, { started: number; controller: AbortController; priority: IngestPriority }>();
  private activeCount = { HIGH: 0, MEDIUM: 0, LOW: 0 };
  // Circuit breaker state
  private crashTimestamps: number[] = [];
  private pausedUntil = 0;
  private pauseReason: string | null = null;
  constructor(
    readonly pool: Pool,
    readonly ingestor: AdvisoryIngestor,
    config: Partial<SupervisorConfig> = {},
  ) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.desiredConcurrency = this.config.highPool + this.config.mediumPool + this.config.lowPool;
    this.concurrencyLimit = this.desiredConcurrency;
  }
  setConcurrency(limit: number): void {
    if (!Number.isInteger(limit) || limit < 1 || limit > 32) throw new Error('CONCURRENCY_OUT_OF_RANGE');
    this.desiredConcurrency = limit;
    // Distribute proportionally across priorities
    const total = this.config.highPool + this.config.mediumPool + this.config.lowPool;
    this.config.highPool = Math.max(1, Math.round(limit * this.config.highPool / total));
    this.config.mediumPool = Math.max(1, Math.round(limit * this.config.mediumPool / total));
    this.config.lowPool = limit - this.config.highPool - this.config.mediumPool;
    this.concurrencyLimit = this.memoryPressure ? Math.max(1, Math.floor(limit / 2)) : limit;
    this.ingestor.telemetry.log('INFO', 'supervisor.concurrency_changed', { 
      count: this.concurrencyLimit,
      highPool: this.config.highPool,
      mediumPool: this.config.mediumPool,
      lowPool: this.config.lowPool,
    });
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
    this.shutdown = new AbortController();
    this.ingestor.telemetry.log('INFO', 'supervisor.started');
    this.timer = setInterval(() => {
      void this.check();
    }, 1000);
    this.timer.unref();
    void this.check();
  }
  async stop(): Promise<void> {
    this.stopped = true;
    this.shutdown.abort();
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
  private recordCrash(): void {
    const now = Date.now();
    this.crashTimestamps = this.crashTimestamps.filter(ts => now - ts < CRASH_WINDOW_MS);
    this.crashTimestamps.push(now);
    if (this.crashTimestamps.length >= CRASH_THRESHOLD) {
      this.pausedUntil = Date.now() + PAUSE_DURATION_MS;
      this.pauseReason = `Circuit breaker triggered: ${this.crashTimestamps.length} crashes in ${CRASH_WINDOW_MS}ms`;
      this.ingestor.telemetry.log('CRITICAL', 'supervisor.circuit_breaker_open', {
        crashCount: this.crashTimestamps.length,
        pauseDurationMs: PAUSE_DURATION_MS,
      });
    }
  }
  private isPaused(): boolean {
    return Date.now() < this.pausedUntil;
  }
  start(): void {
    if (this.timer) return;
    this.stopped = false;
    this.shutdown = new AbortController();
    this.ingestor.telemetry.log('INFO', 'supervisor.started');
    this.timer = setInterval(() => {
      void this.check();
    }, 1000);
    this.timer.unref();
    void this.check();
  }
  async stop(): Promise<void> {
    this.stopped = true;
    this.shutdown.abort();
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
        const policy = await this.pool.query<{ concurrency_limit: number }>(
          timedQuery('SELECT concurrency_limit FROM correlation_policy WHERE id=1', [], 2000),
        );
        if (policy.rows[0] && policy.rows[0].concurrency_limit !== this.desiredConcurrency)
          this.setConcurrency(policy.rows[0].concurrency_limit);
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
      } catch (error) {
        if (this.health !== 'RECOVERING_DB_SEVERANCE') log.log('CRITICAL', 'supervisor.database_unavailable');
        this.health = 'RECOVERING_DB_SEVERANCE';
        // pg destroys failed clients; a new connect resolves the configured
        // failover/proxy endpoint. Never pool.end() the shared application pool.
        this.recordCrash();
      }
    } finally {
      this.checking = false;
    }
  }
  async acquire(trackingId: string, controller: AbortController, priority: IngestPriority = 'LOW'): Promise<void> {
    if (this.isPaused()) {
      const error = new Error(`Supervisor paused: ${this.pauseReason}`);
      this.ingestor.telemetry.log('CRITICAL', 'supervisor.acquire_rejected_circuit_open', { trackingId });
      throw error;
    }
    const signal = AbortSignal.any([controller.signal, this.shutdown.signal]);
    await this.ingestor.telemetry.ready(signal);
    // HIGH confidence alerts bypass *soft* backpressure (memory shedding and
    // DB-severance recovery) but never the hard global worker ceiling. The
    // previous condition skipped every check for HIGH, so a burst of
    // CVE-bearing advisories could open unbounded workers, exhaust the pool,
    // and starve the very queue it was meant to prioritize.
    const isHighPriority = priority === 'HIGH';
    while (
      !this.stopped &&
      ((!isHighPriority &&
        (this.health === 'RECOVERING_DB_SEVERANCE' || this.memoryPressure)) ||
        this.active.size >= this.concurrencyLimit ||
        this.activeCount[priority] >= this.getPoolLimit(priority))
    )
      await delay(50, undefined, { signal });
    signal.throwIfAborted();
    if (this.stopped) throw new Error('SUPERVISOR_STOPPED');
    this.active.set(trackingId, { started: Date.now(), controller, priority });
    this.activeCount[priority]++;
  }
  private getPoolLimit(priority: IngestPriority): number {
    switch (priority) {
      case 'HIGH': return this.config.highPool;
      case 'MEDIUM': return this.config.mediumPool;
      case 'LOW': return this.config.lowPool;
    }
  }
  release(trackingId: string): void {
    const task = this.active.get(trackingId);
    if (task) {
      this.activeCount[task.priority]--;
      this.active.delete(trackingId);
    }
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
      instanceId: this.instanceId,
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