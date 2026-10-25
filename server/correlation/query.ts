import type { QueryConfig } from 'pg';
/** node-postgres supports per-query timeouts; its public QueryConfig omits the field. */
export function timedQuery(
  text: string,
  values: unknown[] = [],
  timeout = 4000,
): QueryConfig & { query_timeout: number } {
  return { text, values, query_timeout: timeout };
}
