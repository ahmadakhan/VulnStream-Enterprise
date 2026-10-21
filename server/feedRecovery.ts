import type { ThreatFeed } from '../src/types';

/** Persistent cooldowns survive restarts; only enabled, failed sources trigger recovery. */
export function recoveryDue(feed: ThreatFeed, now = Date.now()): boolean {
  return feed.enabled && feed.healthStatus === 'DOWN' && !!feed.circuitOpenUntil &&
    Date.parse(feed.circuitOpenUntil) <= now;
}

export function recoveryAt(feed: ThreatFeed, failures: number, now = Date.now()): string {
  const base = (feed.recoveryDelayMinutes ?? 5) * 60000;
  return new Date(now + Math.min(3600000, base * 2 ** Math.min(6, Math.max(0, failures - 1)))).toISOString();
}
