import type { PipelineSupervisor } from './supervisor.ts';
import type { Heartbeat } from './heartbeat.ts';
/** Available without a database roundtrip; the HTTP route requires a dedicated token. */
export function correlationMetrics(
  supervisor: PipelineSupervisor,
  heartbeat?: Heartbeat,
  /** Pending durable jobs, sampled by the caller on an interval (it needs a DB read). */
  pending = -1,
): string {
  const telemetry = supervisor.ingestor.telemetry;
  const gauges: Record<string, number> = {
    vulnstream_correlation_memory_percent: supervisor.memoryPercent(),
    vulnstream_correlation_workers: supervisor.active.size,
    vulnstream_correlation_concurrency_limit: supervisor.concurrencyLimit,
    vulnstream_database_pool_total: supervisor.pool.totalCount,
    vulnstream_database_pool_waiting: supervisor.pool.waitingCount,
    // -1 means "not sampled yet"; Prometheus treats it as a real value, so the
    // alert rule only fires on > 0, never on the sentinel.
    vulnstream_correlation_pending: pending,
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
      // Age of the last successful ping. A value that keeps climbing means the
      // receiver is NOT learning that this instance is alive -- the early
      // warning of a dead-man's switch about to fire.
      `vulnstream_heartbeat_age_seconds ${heartbeat.lastPingAt ? Math.round((Date.now() - heartbeat.lastPingAt) / 1000) : -1}`,
      '# TYPE vulnstream_heartbeat_failures_total counter',
      `vulnstream_heartbeat_failures_total ${heartbeat.consecutiveFailures}`,
      '# TYPE vulnstream_heartbeat_state gauge',
      ...['pinged', 'failed', 'suppressed', 'idle', 'disabled'].map(
        (state) => `vulnstream_heartbeat_state{state="${state}"} ${heartbeat.state.status === state ? 1 : 0}`,
      ),
    );
  return lines.join('\n') + '\n';
}
