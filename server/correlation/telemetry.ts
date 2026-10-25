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
  private drainWaiters = new Set<() => void>();
  droppedLogs = 0;
  constructor(private readonly output: NodeJS.WritableStream = process.stdout) {}
  async ready(): Promise<void> {
    if (this.outputBlocked || this.pendingOutput.length)
      await new Promise<void>((resolve) => this.drainWaiters.add(resolve));
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
    if (this.pendingOutput.length < 512) this.pendingOutput.push(JSON.stringify(entry) + '\n');
    else this.droppedLogs++;
    this.flushOutput();
  }
  private flushOutput(): void {
    if (this.outputBlocked) return;
    while (this.pendingOutput.length) {
      if (!this.output.write(this.pendingOutput.shift()!)) {
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
