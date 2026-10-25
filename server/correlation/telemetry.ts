import type { CorrelationLog } from '../../shared/correlation.ts';
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
  log(
    level: CorrelationLog['level'],
    event: string,
    metrics: Partial<
      Pick<
        CorrelationLog,
        | 'trackingId'
        | 'ingestionLatencyMs'
        | 'extractionLatencyMs'
        | 'totalDatabaseTimeMs'
        | 'count'
        | 'attempt'
      >
    > = {},
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
    if (!this.outputError && this.pendingOutput.length < 512) this.pendingOutput.push(JSON.stringify(entry) + '\n');
    else this.droppedLogs++;
    this.flushOutput();
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
}
