/** Build a short, human-friendly display name for a pipeline execution from its id.
 *
 * Executions are keyed by an opaque UUID, but the Execution history list renders a
 * readable label (e.g. `Run 3add6860`) instead of the raw identifier. Legacy rows
 * stored before this name was persisted fall back to this helper on read. */
export const formatExecutionName = (id: string): string => `Run ${id.slice(0, 8)}`;

function shortUuid(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID().split('-')[0].toUpperCase();
  }
  const fallback = Math.random().toString(36).slice(2, 10).toUpperCase();
  return fallback.padStart(8, '0');
}

/** Build a professional, human-readable advisory identifier.
 *
 * Format: `PREFIX-ddMMMyyyy-SHORTUUID` (e.g. `ADV-29Oct2026-A1B2C3D4`).
 * The date portion makes the ID immediately useful for triage and filing,
 * while the short UUID suffix guarantees global uniqueness within a day. */
export const formatAdvisoryId = (prefix: string, now: Date = new Date()): string => {
  const datePart = now
    .toLocaleDateString('en-GB', {
      day: '2-digit',
      month: 'short',
      year: 'numeric',
    })
    .replace(/ /g, '');
  return `${prefix}${datePart}-${shortUuid()}`;
};
