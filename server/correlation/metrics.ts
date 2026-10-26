import type { PipelineSupervisor } from './supervisor.ts';
import type { Heartbeat } from './heartbeat.ts';
/** Available without a database roundtrip; the HTTP route requires a dedicated token. */
export function correlationMetrics(
  supervisor: PipelineSupervisor,
  heartbeat?: Heartbeat,
  /** Pending durable jobs, sampled by the caller on an interval (it needs a DB read). */
  pending = -1,
  /** Epoch ms of the last pending sample; 0 = never sampled. */
  pendingSampledAt = 0,
): string {
  const telemetry = supervisor.ingestor.telemetry;
  // The pipeline is only expected to make progress while the worker is enabled
  // and the supervisor is admitting. Every stall rule must qualify on this, or
  // a deployment that intentionally runs as monitoring-only (`WORKER_ENABLED`
  // false, or disabled until an operator completes setup) alarms forever about
  // "stalled ingestion" for a consumer nobody asked to start.
  const workerEnabled = process.env.WORKER_ENABLED !== 'false';
  const gauges: Record<string, number> = {
    vulnstream_correlation_memory_percent: supervisor.memoryPercent(),
    vulnstream_correlation_workers: supervisor.active.size,
    vulnstream_correlation_concurrency_limit: supervisor.concurrencyLimit,
    vulnstream_correlation_worker_enabled: workerEnabled ? 1 : 0,
    vulnstream_database_pool_total: supervisor.pool.totalCount,
    vulnstream_database_pool_waiting: supervisor.pool.waitingCount,
    // -1 means "not sampled yet". A real value is only ever >= 0, so every rule
    // must be written as `> 0`; `-1 > 0` is false and the sentinel is inert.
    vulnstream_correlation_pending: pending,
    // Staleness of the queue sample. The alert engine is called through a path
    // that can be reached before the first sample, and a sampler that has
    // stopped (drain loop wedged) would otherwise keep publishing an old depth
    // forever. -1 means never sampled.
    vulnstream_correlation_pending_sample_age_seconds: pendingSampledAt
      ? Math.round((Date.now() - pendingSampledAt) / 1000)
      : -1,
  };
  const counters: Record<string, number> = {
    vulnstream_correlation_items_total: telemetry.completed,
    vulnstream_correlation_dead_letters_total: telemetry.deadLetters,
    vulnstream_correlation_dropped_logs_total: telemetry.droppedLogs,
    vulnstream_correlation_latency_milliseconds_total: telemetry.latencyTotal,
  };
  const lines: string[] = [];
  for (const [name, value] of Object.entries(gauges))
    lines.push(`# TYPE ${name} gauge`, `${name} ${Number.isFinite(value) ? value : 0}`);
  for (const [name, value] of Object.entries(counters))
    lines.push(`# TYPE ${name} counter`, `${name} ${value}`);
  lines.push('# TYPE vulnstream_correlation_health gauge');
  for (const state of ['HEALTHY', 'DEGRADED_BACKPRESSURE', 'RECOVERING_DB_SEVERANCE'])
    lines.push(`vulnstream_correlation_health{state="${state}"} ${supervisor.health === state ? 1 : 0}`);
  if (heartbeat)
    lines.push(
      '# TYPE vulnstream_heartbeat_enabled gauge',
      `vulnstream_heartbeat_enabled ${heartbeat.enabled ? 1 : 0}`,
      '# TYPE vulnstream_heartbeat_age_seconds gauge',
      // Age of the last successful ping, or -1 when no ping has ever succeeded.
      // -1 is a sentinel, NOT a measurement: any rule must guard on
      // `vulnstream_heartbeat_state{state="pinged"} == 1`, because `-1 > 180`
      // is false and an unstarted or disabled heartbeat would otherwise be
      // silently exempt from the staleness check.
      `vulnstream_heartbeat_age_seconds ${heartbeat.lastPingAt ? Math.round((Date.now() - heartbeat.lastPingAt) / 1000) : -1}`,
      '# TYPE vulnstream_heartbeat_consecutive_failures gauge',
      `vulnstream_heartbeat_consecutive_failures ${heartbeat.consecutiveFailures}`,
      '# TYPE vulnstream_heartbeat_failed_pings_total counter',
      `vulnstream_heartbeat_failed_pings_total ${heartbeat.failedPingsTotal}`,
      '# TYPE vulnstream_heartbeat_state gauge',
      ...['pinged', 'failed', 'suppressed', 'idle', 'disabled'].map(
        (state) => `vulnstream_heartbeat_state{state="${state}"} ${heartbeat.state.status === state ? 1 : 0}`,
      ),
    );
  return lines.join('\n') + '\n';
}
