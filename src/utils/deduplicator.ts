/**
 * CVE ID Normalization and Deduplication Engine
 * Enforces canonical CVE-YYYY-NNNN+ format and O(1) tracking.
 */

const CVE_REGEX = /^CVE-\d{4}-\d{4,}$/i;

/**
 * Normalizes any CVE string into canonical uppercase, trimmed format.
 * Returns null if not a valid CVE ID.
 */
export function normalizeCveId(rawId: string): string | null {
  if (!rawId || typeof rawId !== 'string') return null;

  const trimmed = rawId.trim().toUpperCase();
  if (CVE_REGEX.test(trimmed)) {
    return trimmed;
  }
  return null;
}

/**
 * Checks if a CVE falls within the processing window based on scope_hours
 */
export function isWithinTimelineScope(
  publishedDate: string,
  modifiedDate: string,
  scopeHours: number,
  now: Date = new Date()
): boolean {
  if (!scopeHours || scopeHours <= 0) return true; // If 0, no filter

  const windowMillis = scopeHours * 60 * 60 * 1000;
  const cutoffTime = now.getTime() - windowMillis;

  const pubTime = new Date(publishedDate).getTime();
  const modTime = new Date(modifiedDate).getTime();

  const latestActivity = Math.max(
    isNaN(pubTime) ? 0 : pubTime,
    isNaN(modTime) ? 0 : modTime
  );

  return latestActivity >= cutoffTime;
}

/**
 * Deduplicator class for in-run O(1) deduplication
 */
export class InRunDeduplicator {
  private seenInRun = new Set<string>();
  private previouslyAlerted = new Set<string>();

  constructor(previouslyAlertedIds: string[] = []) {
    for (const id of previouslyAlertedIds) {
      const norm = normalizeCveId(id);
      if (norm) {
        this.previouslyAlerted.add(norm);
      }
    }
  }

  /**
   * Evaluates if a CVE is new or duplicate
   */
  public evaluate(rawCveId: string): {
    canonicalId: string | null;
    isDuplicateInRun: boolean;
    isPreviouslyAlerted: boolean;
    isProcessable: boolean;
  } {
    const canonical = normalizeCveId(rawCveId);
    if (!canonical) {
      return {
        canonicalId: null,
        isDuplicateInRun: false,
        isPreviouslyAlerted: false,
        isProcessable: false,
      };
    }

    if (this.seenInRun.has(canonical)) {
      return {
        canonicalId: canonical,
        isDuplicateInRun: true,
        isPreviouslyAlerted: this.previouslyAlerted.has(canonical),
        isProcessable: false,
      };
    }

    this.seenInRun.add(canonical);

    const isPrevAlerted = this.previouslyAlerted.has(canonical);

    return {
      canonicalId: canonical,
      isDuplicateInRun: false,
      isPreviouslyAlerted: isPrevAlerted,
      isProcessable: true,
    };
  }

  public getSeenCount(): number {
    return this.seenInRun.size;
  }
}
