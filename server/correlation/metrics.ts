import type { PipelineSupervisor } from './supervisor.ts';
/** Available without a database roundtrip; the HTTP route requires a dedicated token. */
export function correlationMetrics(supervisor: PipelineSupervisor): string {
  const telemetry = supervisor.ingestor.telemetry;
  const gauges: Record<string, number> = {
    vulnstream_correlation_memory_percent: supervisor.memoryPercent(),
    vulnstream_correlation_workers: supervisor.active.size,
    vulnstream_correlation_concurrency_limit: supervisor.concurrencyLimit,
    vulnstream_database_pool_total: supervisor.pool.totalCount,
    vulnstream_database_pool_waiting: supervisor.pool.waitingCount,
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
  return lines.join('\n') + '\n';
}
