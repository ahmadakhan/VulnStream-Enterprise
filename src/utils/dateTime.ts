/**
 * Centralized, timezone-aware date formatting.
 *
 * All human-readable dates in the UI are rendered through these helpers so that
 * the display shape (`dd MMM yyyy`) and the operator-configured timezone stay
 * consistent. `timezone` is sourced from `settings.timezone`. When the operator
 * has not configured one — or stored a value this runtime cannot render — the
 * system falls back to the documented default (`DEFAULT_TIMEZONE`, UTC) rather
 * than the browser's local clock, which keeps rendering deterministic across
 * replicas and matches the server's daily-digest scheduling.
 */
import { DEFAULT_TIMEZONE } from '../../shared/state';

const CACHE = new Map<string, Intl.DateTimeFormat>();

/**
 * Configured timezone when valid, otherwise the documented system default.
 * The server's daily-digest scheduler uses the same rule, so a displayed time
 * and the schedule that produced it never disagree.
 */
export const resolveTimezone = (timezone?: string | null): string => {
  if (!timezone) return DEFAULT_TIMEZONE;
  try {
    new Intl.DateTimeFormat('en', { timeZone: timezone });
    return timezone;
  } catch {
    return DEFAULT_TIMEZONE;
  }
};

const formatter = (
  timezone: string | undefined,
  options: Intl.DateTimeFormatOptions,
): Intl.DateTimeFormat => {
  const tz = resolveTimezone(timezone);
  const key = `${tz}|${JSON.stringify(options)}`;
  const cached = CACHE.get(key);
  if (cached) return cached;
  const instance = new Intl.DateTimeFormat('en-GB', { timeZone: tz, ...options });
  CACHE.set(key, instance);
  return instance;
};

const toDate = (value: string | Date | undefined | null): Date | null => {
  if (value === undefined || value === null) return null;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
};

export const formatTime = (value: string | Date | undefined | null, timezone?: string): string => {
  const date = toDate(value);
  if (!date) return '—';
  return formatter(timezone, { hour: '2-digit', minute: '2-digit', hourCycle: 'h23' }).format(date);
};

export const formatDate = (value: string | Date | undefined | null, timezone?: string): string => {
  const date = toDate(value);
  if (!date) return '—';
  return formatter(timezone, { day: '2-digit', month: 'short', year: 'numeric' }).format(date);
};

/** Timezone label to append to a rendered timestamp, so the reader knows which
 * clock it refers to (e.g. `29 Oct 2026, 14:03 UTC`). */
export const timezoneLabel = (timezone?: string | null): string => resolveTimezone(timezone);

export const formatDateTime = (value: string | Date | undefined | null, timezone?: string): string => {
  const date = toDate(value);
  if (!date) return '—';
  return formatter(timezone, {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  }).format(date);
};

export const formatDateTimeShort = (value: string | Date | undefined | null, timezone?: string): string => {
  const date = toDate(value);
  if (!date) return '—';
  return formatter(timezone, {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    hourCycle: 'h12',
  }).format(date);
};
