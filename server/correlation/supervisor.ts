import { randomUUID } from 'node:crypto';
import { timedQuery } from './query.ts';
import { getHeapStatistics } from 'node:v8';
import { totalmem } from 'node:os';
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
const WORKER_DEADLINE_MS = 15_000;

interface Waiter {
  trackingId: string;
  controller: AbortController;
  priority: IngestPriority;
  signal: AbortSignal;
  resolve: () => void;
  reject: (error: Error) => void;
  cleanup: () => void;
}

export class PipelineSupervisor {
  readonly instanceId = randomUUID();
  health: PipelineHealth = 'HEALTHY';
  desiredConcurrency = 4;
  concurrencyLimit = 4;
  readonly config: SupervisorConfig;
  /** Original shares, retained so repeated rebalancing cannot drift ratios. */
  private readonly baseConfig: SupervisorConfig;
  private memoryPressure = false;
  /** When shedding began. A single high sample under a 1s poll is a spike, not
   * sustained pressure; the interval guard in check() requires it to persist. */
  private sheddingSince = 0;
  private timer?: ReturnType<typeof setInterval>;
  private checking = false;
  private stopped = false;
  private shutdown = new AbortController();
  private simulatedUntil = 0;
  private simulated: 'memory' | 'database' | null = null;
  readonly active = new Map<
    string,
    { started: number; controller: AbortController; priority: IngestPriority }
  >();
  private activeCount = { HIGH: 0, MEDIUM: 0, LOW: 0 };
  /**
   * Priority waiters are admitted by an explicit scheduler rather than by
   * polling. A HIGH advisory can therefore be admitted ahead of a queued LOW
   * advisory without waiting for a 50 ms timer or for the low-priority work to
   * finish, and a release immediately wakes the next eligible waiter.
   */
  private readonly waiters: Waiter[] = [];
  // Circuit breaker state
  private crashTimestamps: number[] = [];
  private pausedUntil = 0;
  private pauseReason: string | null = null;
  /**
   * Simulation-triggered failures. These are operator-initiated and must not
   * contribute to the real breaker: three simulated database faults inside the
   * crash window would open a genuine five-minute pause after the simulation
   * had already 'ended', turning the endpoint into a five-minute outage.
   */
  private simulatedCrashes: number[] = [];
  /** The persisted breaker this instance adopted from the database. */
  private adoptedPause = 0;

  constructor(
    readonly pool: Pool,
    readonly ingestor: AdvisoryIngestor,
    config: Partial<SupervisorConfig> = {},
  ) {
    this.baseConfig = { ...DEFAULT_CONFIG, ...config };
    this.config = { ...this.baseConfig };
    this.desiredConcurrency = this.config.highPool + this.config.mediumPool + this.config.lowPool;
    this.concurrencyLimit = this.desiredConcurrency;
  }

  setConcurrency(limit: number): void {
    if (!Number.isInteger(limit) || limit < 1 || limit > 32) throw new Error('CONCURRENCY_OUT_OF_RANGE');
    this.desiredConcurrency = limit;
    // Recompute from the original shares, never from the last result. Deriving
    // from the current pool sizes made repeated calls path-dependent and could
    // produce a zero or negative LOW pool (limits 1 and 2), permanently
    // starving low-priority ingestion.
    const total = Math.max(
      1,
      this.baseConfig.highPool + this.baseConfig.mediumPool + this.baseConfig.lowPool,
    );
    const highPool = Math.max(1, Math.round((limit * this.baseConfig.highPool) / total));
    const mediumPool = Math.max(1, Math.round((limit * this.baseConfig.mediumPool) / total));
    // The sum may exceed the global limit for very small limits; that is
    // intentional. The global ceiling still bounds concurrency, while every
    // priority keeps at least one admission slot instead of a negative quota.
    const lowPool = Math.max(1, limit - highPool - mediumPool);
    this.config.highPool = highPool;
    this.config.mediumPool = mediumPool;
    this.config.lowPool = lowPool;
    this.concurrencyLimit = this.memoryPressure ? Math.max(1, Math.floor(limit / 2)) : limit;
    this.ingestor.telemetry.log('INFO', 'supervisor.concurrency_changed', {
      count: this.concurrencyLimit,
      highPool: this.config.highPool,
      mediumPool: this.config.mediumPool,
      lowPool: this.config.lowPool,
    });
    this.pump();
  }

  memoryPercent(): number {
    const memory = process.memoryUsage();
    // constrainedMemory() is zero on hosts without a cgroup limit. Falling
    // back to total system memory keeps RSS pressure visible there instead of
    // silently ignoring everything outside the V8 old generation (including
    // worker threads and large Buffer payloads).
    const limit = process.constrainedMemory?.() || totalmem();
    const heap = memory.heapUsed / getHeapStatistics().heap_size_limit;
    const rss = limit > 0 ? memory.rss / limit : 0;
    return Math.min(100, Math.max(heap, rss) * 100);
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
    this.rejectWaiters(new Error('SUPERVISOR_STOPPED'));
    for (const task of this.active.values()) task.controller.abort();
    while (this.active.size || this.checking) await delay(20);
  }

  /**
   * Simulate a control-plane fault for five seconds. Deliberately in-process:
   * this never severs a real socket or exhausts real memory.
   *
   * The window is published to the shared policy row so a sibling replica
   * reflects the transition and a restart mid-simulation cannot leave a
   * half-applied fault behind. Simulated failures are counted separately from
   * real ones (see `simulatedCrashes`).
   */
  simulate(fault: 'memory' | 'database'): void {
    this.simulated = fault;
    this.simulatedUntil = Date.now() + 5000;
    this.ingestor.telemetry.log('WARN', 'supervisor.fault_simulated');
    void this.pool
      .query(
        timedQuery(
          `UPDATE correlation_policy SET simulated_fault=$1,simulated_until=$2 WHERE id=1`,
          [fault, new Date(this.simulatedUntil)],
          2000,
        ),
      )
      .catch(() => {});
    void this.check();
  }

  /** Clear an expired simulation locally and on the shared row. */
  private expireSimulation(): void {
    if (!this.simulated) return;
    this.simulated = null;
    this.simulatedCrashes = [];
    this.sheddingSince = 0;
    void this.pool
      .query(
        timedQuery(
          'UPDATE correlation_policy SET simulated_fault=NULL,simulated_until=NULL WHERE id=1 AND simulated_fault IS NOT NULL',
          [],
          2000,
        ),
      )
      .catch(() => {});
  }

  private recordCrash(): void {
    const now = Date.now();
    this.crashTimestamps = this.crashTimestamps.filter((ts) => now - ts < CRASH_WINDOW_MS);
    this.crashTimestamps.push(now);
    if (this.crashTimestamps.length >= CRASH_THRESHOLD && !this.isPaused()) {
      this.pausedUntil = now + PAUSE_DURATION_MS;
      this.pauseReason = `Circuit breaker triggered: ${this.crashTimestamps.length} crashes in ${CRASH_WINDOW_MS}ms`;
      this.ingestor.telemetry.log('CRITICAL', 'supervisor.circuit_breaker_open', {
        crashCount: this.crashTimestamps.length,
        pauseDurationMs: PAUSE_DURATION_MS,
      });
      this.rejectWaiters(new Error(`Supervisor paused: ${this.pauseReason}`));
      this.persistCircuit();
    }
  }

  /**
   * Publish the open breaker so a restart, or a sibling replica, honours it.
   * Fire-and-forget on purpose: admission is already blocked in memory, and the
   * breaker must hold even when this write fails.
   */
  private persistCircuit(): void {
    void this.pool
      .query(
        timedQuery(
          `UPDATE correlation_policy SET circuit_open_until=$1,circuit_reason=$2,circuit_instance=$3 WHERE id=1`,
          [new Date(this.pausedUntil), this.pauseReason, this.instanceId],
          2000,
        ),
      )
      .catch(() => this.ingestor.telemetry.log('WARN', 'supervisor.circuit_persist_failed'));
  }

  /** Clear the open breaker in the shared policy row. */
  private clearPersistedCircuit(): void {
    void this.pool
      .query(timedQuery('UPDATE correlation_policy SET circuit_open_until=NULL,circuit_reason=NULL WHERE id=1', [], 2000))
      .catch(() => {});
  }

  private resetCircuit(): void {
    if (!this.crashTimestamps.length && !this.pausedUntil) return;
    const wasShared = this.adoptedPause > 0;
    this.crashTimestamps = [];
    this.simulatedCrashes = [];
    this.pausedUntil = 0;
    this.pauseReason = null;
    this.adoptedPause = 0;
    this.ingestor.telemetry.log('INFO', 'supervisor.circuit_breaker_reset');
    if (wasShared) this.clearPersistedCircuit();
    this.pump();
  }

  private isPaused(): boolean {
    return Date.now() < this.pausedUntil;
  }

  async check(): Promise<void> {
    if (this.checking || this.stopped) return;
    this.checking = true;
    const log = this.ingestor.telemetry;
    try {
      if (Date.now() >= this.simulatedUntil) this.expireSimulation();
      // A breaker must not outlive the outage that opened it. Without this
      // reset, a recovered database still rejected every advisory for the
      // remainder of the five-minute pause.
      if (this.pausedUntil && !this.isPaused()) this.resetCircuit();

      const memory = this.simulated === 'memory' ? 90 : this.memoryPercent();
      if (memory >= 85 && !this.memoryPressure) {
        // Hysteresis on the rise: a single sample is a transient allocation
        // spike, not sustained pressure. Require it to persist for one more
        // probe interval before halving the whole pipeline's concurrency.
        if (!this.sheddingSince) {
          this.sheddingSince = Date.now();
        } else if (Date.now() - this.sheddingSince >= 1000) {
          this.memoryPressure = true;
          this.concurrencyLimit = Math.max(1, Math.floor(this.desiredConcurrency / 2));
          log.log('WARN', 'supervisor.memory_shedding', {
            count: this.concurrencyLimit,
            highPool: this.getPoolLimit('HIGH'),
          });
          if (typeof globalThis.gc === 'function') globalThis.gc();
        }
      } else if (memory < 60 && this.memoryPressure) {
        this.memoryPressure = false;
        this.sheddingSince = 0;
        this.concurrencyLimit = this.desiredConcurrency;
        log.log('INFO', 'supervisor.memory_recovered');
      } else if (memory < 85) {
        this.sheddingSince = 0;
      }

      for (const [trackingId, task] of this.active)
        if (Date.now() - task.started >= WORKER_DEADLINE_MS && !task.controller.signal.aborted) {
          log.log('CRITICAL', 'supervisor.worker_deadline', { trackingId });
          task.controller.abort();
        }

      try {
        if (this.simulated === 'database') throw new Error('SIMULATED_DATABASE_OUTAGE');
        await this.pool.query(timedQuery('SELECT 1', [], 2000));
        const policy = await this.pool.query<{
          concurrency_limit: number;
          circuit_open_until: Date | null;
          circuit_reason: string | null;
        }>(
          timedQuery(
            `SELECT concurrency_limit,circuit_open_until,circuit_reason FROM correlation_policy WHERE id=1`,
            [],
            2000,
          ),
        );
        const row = policy.rows[0];
        if (row && row.concurrency_limit !== this.desiredConcurrency)
          this.setConcurrency(row.concurrency_limit);
        // Adopt a breaker opened by another replica, or by this process before a
        // restart. A crash-loop must not delete the evidence that patience is
        // required: without this, restarting the process cleared the five-minute
        // pause and poured admission straight back into the outage.
        const persisted = row?.circuit_open_until ? row.circuit_open_until.getTime() : 0;
        const sharedPauseActive = persisted > Date.now();
        if (sharedPauseActive) {
          this.pausedUntil = persisted;
          this.adoptedPause = persisted;
          this.pauseReason = row?.circuit_reason ?? 'Circuit breaker open (shared state)';
          if (this.health !== 'RECOVERING_DB_SEVERANCE') {
            log.log('CRITICAL', 'supervisor.circuit_breaker_adopted', {
              pauseDurationMs: persisted - Date.now(),
            });
            this.health = 'RECOVERING_DB_SEVERANCE';
          }
          this.rejectWaiters(new Error(`Supervisor paused: ${this.pauseReason}`));
        } else if (persisted) {
          // Expired shared pause: clear it so a later crash can open a new one.
          this.adoptedPause = 0;
          this.clearPersistedCircuit();
          this.resetCircuit();
        }
        if (!sharedPauseActive) {
          // The database is reachable. Clear crash evidence and release any
          // remaining pause so recovery is immediate, not five minutes later.
          this.resetCircuit();
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
        }
      } catch (error) {
        if (this.health !== 'RECOVERING_DB_SEVERANCE')
          log.log('CRITICAL', 'supervisor.database_unavailable');
        this.health = 'RECOVERING_DB_SEVERANCE';
        // pg destroys failed clients; a new connect resolves the configured
        // failover/proxy endpoint. Never pool.end() the shared application pool.
        // A simulated outage never contributes to the real breaker.
        if (this.simulated === 'database') this.simulatedCrashes.push(Date.now());
        else this.recordCrash();
      }
    } finally {
      this.checking = false;
      this.pump();
    }
  }

  async acquire(
    trackingId: string,
    controller: AbortController,
    priority: IngestPriority = 'LOW',
  ): Promise<void> {
    if (this.isPaused()) {
      const error = new Error(`Supervisor paused: ${this.pauseReason}`);
      this.ingestor.telemetry.log('CRITICAL', 'supervisor.acquire_rejected_circuit_open', { trackingId });
      throw error;
    }
    if (this.stopped) throw new Error('SUPERVISOR_STOPPED');
    const signal = AbortSignal.any([controller.signal, this.shutdown.signal]);
    signal.throwIfAborted();
    if (this.tryAdmit(trackingId, controller, priority)) return;

    await new Promise<void>((resolve, reject) => {
      const waiter: Waiter = {
        trackingId,
        controller,
        priority,
        signal,
        resolve,
        reject,
        cleanup: () => signal.removeEventListener('abort', onAbort),
      };
      const onAbort = () => {
        const index = this.waiters.indexOf(waiter);
        if (index >= 0) this.waiters.splice(index, 1);
        waiter.cleanup();
        reject(signal.reason instanceof Error ? signal.reason : new Error('INGEST_ABORTED'));
      };
      signal.addEventListener('abort', onAbort, { once: true });
      this.waiters.push(waiter);
      // A release can happen between the tryAdmit() above and this push, and
      // the breaker can open in the same window. Re-check after registering so
      // neither race can strand the waiter forever.
      if (this.stopped) {
        waiter.cleanup();
        this.waiters.splice(this.waiters.indexOf(waiter), 1);
        reject(new Error('SUPERVISOR_STOPPED'));
        return;
      }
      if (this.isPaused()) {
        waiter.cleanup();
        this.waiters.splice(this.waiters.indexOf(waiter), 1);
        reject(new Error(`Supervisor paused: ${this.pauseReason}`));
        return;
      }
      this.pump();
    });
  }

  /**
   * Admit directly when capacity is available. HIGH bypasses *soft*
   * backpressure (memory shedding and database-recovery holds) up to its own
   * pool limit, but never the global worker ceiling or the circuit breaker.
   */
  private tryAdmit(
    trackingId: string,
    controller: AbortController,
    priority: IngestPriority,
  ): boolean {
    if (this.stopped || this.isPaused()) return false;
    if (!this.canAdmit(priority)) return false;
    this.active.set(trackingId, { started: Date.now(), controller, priority });
    this.activeCount[priority]++;
    return true;
  }

  private canAdmit(priority: IngestPriority): boolean {
    if (this.stopped || this.isPaused()) return false;
    if (priority !== 'HIGH') {
      if (this.health === 'RECOVERING_DB_SEVERANCE' || this.memoryPressure) return false;
      if (this.active.size >= this.concurrencyLimit) return false;
    } else {
      // HIGH is protected from soft shedding, but still bounded by its own
      // pool and by the configured desired ceiling. It must not open an
      // unbounded number of workers while memory is exhausted.
      //
      // Shedding halves the GLOBAL ceiling, and a proportional share then rounds
      // HIGH down to a single slot — starving exactly the critical advisories
      // that shed-for-memory exists to keep alive. HIGH therefore gets its own
      // floor. The global ceiling and the HIGH pool still bound it.
      const highFloor = Math.min(
        this.desiredConcurrency,
        Math.max(2, Math.ceil(this.desiredConcurrency / 4)),
      );
      if (this.active.size >= Math.max(this.concurrencyLimit, highFloor)) return false;
    }
    if (this.activeCount[priority] >= this.getPoolLimit(priority)) return false;
    return true;
  }

  /** Admit queued work in priority order. FIFO within one priority. */
  private pump(): void {
    if (this.stopped || this.isPaused()) return;
    for (const priority of ['HIGH', 'MEDIUM', 'LOW'] as const) {
      for (let index = 0; index < this.waiters.length; ) {
        const waiter = this.waiters[index];
        if (waiter.priority !== priority) {
          index++;
          continue;
        }
        // Stop this priority as soon as its own pool or the global ceiling is
        // full. Lower priorities still get a chance only if a global slot is
        // free; canAdmit() decides that independently.
        if (!this.canAdmit(priority)) {
          index++;
          continue;
        }
        this.waiters.splice(index, 1);
        waiter.cleanup();
        if (waiter.signal.aborted) {
          waiter.reject(new Error('INGEST_ABORTED'));
          continue;
        }
        this.active.set(waiter.trackingId, {
          started: Date.now(),
          controller: waiter.controller,
          priority,
        });
        this.activeCount[priority]++;
        waiter.resolve();
      }
    }
  }

  private rejectWaiters(error: Error): void {
    for (const waiter of this.waiters.splice(0)) {
      waiter.cleanup();
      waiter.reject(error);
    }
  }

  private getPoolLimit(priority: IngestPriority): number {
    switch (priority) {
      case 'HIGH': {
        // Shedding halves the ceiling but must not shrink HIGH below its floor,
        // otherwise the soft-shedding bypass documented on canAdmit means nothing.
        const floor = Math.min(this.desiredConcurrency, Math.max(2, Math.ceil(this.desiredConcurrency / 4)));
        return Math.max(1, this.config.highPool, floor);
      }
      case 'MEDIUM':
        return Math.max(1, this.config.mediumPool);
      case 'LOW':
        return Math.max(1, this.config.lowPool);
    }
  }

  release(trackingId: string): void {
    const task = this.active.get(trackingId);
    if (task) {
      this.activeCount[task.priority] = Math.max(0, this.activeCount[task.priority] - 1);
      this.active.delete(trackingId);
    }
    this.pump();
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
