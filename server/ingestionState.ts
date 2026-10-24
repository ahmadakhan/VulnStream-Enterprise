/** Internal state, committed in the same transaction as the imported records. */
export interface IngestionState {
  cursor?: string;
  hasMore?: boolean;
  revisions?: Record<string, string>;
  indexEtag?: string;
  epssScope?: string[];
  epssExpiresAt?: string;
  /** True when a multi-run catch-up is in progress after extended downtime. */
  catch_up?: boolean;
  /** Next time to start a catch-up run, used by the scheduler to prioritize catch-up. */
  next_catchup_at?: string;
}
export interface FeedCursor extends IngestionState { fingerprint: string }
const HOUR = 3600000;
export const SYNC_OVERLAP_MS = 10 * 60000;

/** Bootstrap at most one day; resume older checkpoints in bounded daily slices. */
export function ingestionWindow(scopeHours: number, state: IngestionState = {}, now = Date.now()) {
  const cursor = state.cursor ? Date.parse(state.cursor) : NaN;
  const valid = Number.isFinite(cursor) && cursor <= now;
  const start = valid ? cursor - SYNC_OVERLAP_MS : now - Math.min(24, Math.max(0, scopeHours)) * HOUR;
  const end = valid ? Math.min(now, cursor + 24 * HOUR - SYNC_OVERLAP_MS) : now;
  return { start: new Date(start), end: new Date(end), incremental: valid, hasMore: end < now - 60000 };
}
export function recentRevisions(revisions: Record<string, string>, since: Date) {
  return Object.fromEntries(Object.entries(revisions).filter(([, value]) => Date.parse(value) >= since.getTime() - 24 * HOUR));
}
