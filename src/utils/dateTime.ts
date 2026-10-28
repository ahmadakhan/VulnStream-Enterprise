/**
 * Centralized, timezone-aware date formatting.
 *
 * All human-readable dates in the UI are rendered through these helpers so that
 * the display shape (`dd MMM yyyy`) and the operator-configured timezone stay
 * consistent. `timezone` should be sourced from `settings.timezone`; when it is
 * absent or invalid the helpers fall back to `UTC` rather than the server's
 * local clock, which keeps rendering deterministic across replicas.
 */
const CACHE = new Map<string, Intl.DateTimeFormat>();

const formatter = (
  timezone: string | undefined,
  options: Intl.DateTimeFormatOptions,
): Intl.DateTimeFormat => {
  const tz = resolveTimezone(timezone);
  const key = `${tz ?? '__default'}|${JSON.stringify(options)}`;
  const cached = CACHE.get(key);
  if (cached) return cached;
  const instance = new Intl.DateTimeFormat('en-GB', tz ? { timeZone: tz, ...options } : options);
  CACHE.set(key, instance);
  return instance;
};

function resolveTimezone(timezone: string | undefined): string | undefined {
  if (!timezone) return undefined;
  try {
    new Intl.DateTimeFormat('en', { timeZone: timezone });
    return timezone;
  } catch {
    return undefined;
  }
}

const toDate = (value: string | Date | undefined | null): Date | null => {
  if (value === undefined || value === null) return null;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
};

export const formatDate = (value: string | Date | undefined | null, timezone?: string): string => {
  const date = toDate(value);
  if (!date) return '—';
  return formatter(timezone, { day: '2-digit', month: 'short', year: 'numeric' }).format(date);
};

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
