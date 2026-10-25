import type { CorrelationLog } from '../../shared/correlation.ts';
import type { Pool, PoolClient } from 'pg';
/** Fixed allowlist: caller-controlled strings, errors, URLs and payloads cannot enter context. */
export class CorrelationTelemetry {
  private sequence = 0;
  readonly logs: CorrelationLog[] = [];
  completed = 0;
  deadLetters = 0;
  latencyTotal = 0;
  readonly startedAt = performance.now();
  private outputBlocked = false;
  private pendingOutput: string[] = [];
  private drainWaiters = new Set<(error?: Error) => void>();
  private outputError?: Error;
  droppedLogs = 0;
  constructor(private readonly output: NodeJS.WritableStream = process.stdout) {
    output.on('error', () => this.failOutput());
    output.on('close', () => this.failOutput());
  }
  private failOutput(): void {
    this.outputError = new Error('TELEMETRY_OUTPUT_UNAVAILABLE');
    this.droppedLogs += this.pendingOutput.length;
    this.pendingOutput = [];
    for (const settle of this.drainWaiters) settle(this.outputError);
    this.drainWaiters.clear();
  }
  async ready(signal?: AbortSignal): Promise<void> {
    signal?.throwIfAborted();
    if (this.outputError) throw this.outputError;
    if (this.outputBlocked || this.pendingOutput.length)
      await new Promise<void>((resolve, reject) => {
        const settle = (error?: Error) => {
          signal?.removeEventListener('abort', abort);
          this.drainWaiters.delete(settle);
          if (error) reject(error); else resolve();
        };
        const abort = () => settle(new Error('TELEMETRY_WAIT_ABORTED'));
        this.drainWaiters.add(settle);
        signal?.addEventListener('abort', abort, { once: true });
      });
  }
  /** Scrub PII, secrets, and credentials from log entries before emission. */
  private scrub(entry: CorrelationLog): CorrelationLog {
    const scrubbed = { ...entry };
    if (scrubbed.trackingId) scrubbed.trackingId = '[REDACTED]';
    // Scrub any metrics that might contain sensitive data
    for (const key of ['ingestionLatencyMs', 'extractionLatencyMs', 'totalDatabaseTimeMs', 'count', 'attempt'] as const) {
      if (typeof scrubbed[key] === 'number' && scrubbed[key] > 1000000) {
        // Likely a timestamp or large ID - redact
        delete scrubbed[key];
      }
    }
    return scrubbed;
  }
  log(
    level: CorrelationLog['level'],
    event: string,
    metrics: Partial<CorrelationLog> = {},
  ): void {
    // Event names are constants at every call site. Never accept external event names.
    const entry: CorrelationLog = {
      sequence: ++this.sequence,
      timestamp: new Date().toISOString(),
      level,
      event,
    };
    if (metrics.trackingId && /^[a-f0-9-]{36}$/i.test(metrics.trackingId))
      entry.trackingId = metrics.trackingId;
    for (const key of [
      'ingestionLatencyMs',
      'extractionLatencyMs',
      'totalDatabaseTimeMs',
      'count',
      'attempt',
    ] as const) {
      const value = metrics[key];
      if (typeof value === 'number' && Number.isFinite(value)) entry[key] = Math.round(value * 100) / 100;
    }
    this.logs.push(entry);
    if (this.logs.length > 300) this.logs.shift();
    // Bound both the viewer ring and the stdout queue. Admission waits for drain.
    const outputEntry = this.scrub(entry);
    if (!this.outputError && this.pendingOutput.length < 512) this.pendingOutput.push(JSON.stringify(outputEntry) + '\n');
    else this.droppedLogs++;
    this.flushOutput();
  }
  /** Write-ahead logging: persist telemetry entries to operational_events before commit.
   * Caller MUST call this inside the same transaction that commits the advisory. */
  async persistBeforeCommit(db: PoolClient): Promise<void> {
    if (!this.logs.length) return;
    const entries = this.logs.map((log) => ({
      sequence: log.sequence,
      timestamp: log.timestamp,
      level: log.level,
      event: log.event,
      tracking_id: log.trackingId ?? null,
      ingestion_latency_ms: log.ingestionLatencyMs ?? null,
      extraction_latency_ms: log.extractionLatencyMs ?? null,
      total_database_time_ms: log.totalDatabaseTimeMs ?? null,
      count: log.count ?? null,
      attempt: log.attempt ?? null,
    }));
    // Use COPY for bulk insert performance
    const values = entries.map((e) =>
      `(${e.sequence},'${e.timestamp}','${e.level}','${e.event}',
        ${e.tracking_id ? `'${e.tracking_id}'` : 'NULL'},
        ${e.ingestion_latency_ms ?? 'NULL'},
        ${e.extraction_latency_ms ?? 'NULL'},
        ${e.total_database_time_ms ?? 'NULL'},
        ${e.count ?? 'NULL'},
        ${e.attempt ?? 'NULL'})`
    ).join(',');
    await db.query(
      `INSERT INTO operational_events(sequence,timestamp,level,event,tracking_id,
        ingestion_latency_ms,extraction_latency_ms,total_database_time_ms,count,attempt)
       VALUES ${values}`,
    );
    // Clear in-memory buffer after successful persistence
    this.logs.length = 0;
  }
  private flushOutput(): void {
    if (this.outputBlocked || this.outputError) return;
    while (this.pendingOutput.length) {
      let accepted: boolean;
      try { accepted = this.output.write(this.pendingOutput.shift()!); }
      catch { this.droppedLogs++; this.failOutput(); return; }
      if (!accepted) {
        this.outputBlocked = true;
        this.output.once('drain', () => {
          this.outputBlocked = false;
          this.flushOutput();
        });
        return;
      }
    }
    for (const resolve of this.drainWaiters) resolve();
    this.drainWaiters.clear();
  }
  private failOutput(): void {
    this.outputError = new Error('TELEMETRY_OUTPUT_UNAVAILABLE');
    this.droppedLogs += this.pendingOutput.length;
    this.pendingOutput = [];
    for (const settle of this.drainWaiters) settle(this.outputError);
    this.drainWaiters.clear();
  }
  async ready(signal?: AbortSignal): Promise<void> {
    signal?.throwIfAborted();
    if (this.outputError) throw this.outputError;
    if (this.outputBlocked || this.pendingOutput.length)
      await new Promise<void>((resolve, reject) => {
        const settle = (error?: Error) => {
          signal?.removeEventListener('abort', abort);
          this.drainWaiters.delete(settle);
          if (error) reject(error); else resolve();
        };
        const abort = () => settle(new Error('TELEMETRY_WAIT_ABORTED'));
        this.drainWaiters.add(settle);
        signal?.addEventListener('abort', abort, { once: true });
      });
  }
}