import type { Finding } from '../types';
import { normalizeCveId } from '../utils/deduplicator';
const identity = (f: Finding) => `${normalizeCveId(f.cveId)}:${f.matchedAssetId}`;
/** Preserve finding identity, operator lifecycle decisions and delivery history while refreshing applicability. */
export function reconcileFindings(
  existing: Finding[],
  candidates: Finding[],
  now = new Date().toISOString(),
): Finding[] {
  const previous = new Map(existing.map((f) => [identity(f), f]));
  const current = new Set(candidates.map(identity));
  const result = candidates.map((candidate) => {
    const old = previous.get(identity(candidate));
    if (!old) return candidate;
    let notificationStatus = candidate.notificationStatus;
    if (notificationStatus !== 'REVIEW_REQUIRED' && old.advisoryId) {
      notificationStatus = old.autoDispatchedAt
        ? 'AUTO_DISPATCHED'
        : ['QUEUED_FOR_DISPATCH', 'DELIVERY_FAILED', 'SECURITY_REJECTED'].includes(old.notificationStatus)
          ? old.notificationStatus
          : 'DELIVERY_FAILED';
    }
    const changed =
      old.matchingEvidence !== candidate.matchingEvidence ||
      old.matchedCpe !== candidate.matchedCpe ||
      old.notificationStatus !== notificationStatus;
    return {
      ...old,
      cve: candidate.cve,
      matchedAssetName: candidate.matchedAssetName,
      matchedCpe: candidate.matchedCpe,
      matchingMethod: candidate.matchingMethod,
      matchingEvidence: candidate.matchingEvidence,
      exposure: candidate.exposure,
      exploitRisk: candidate.exploitRisk,
      notificationStatus,
      timeline: changed
        ? [
            ...old.timeline,
            {
              timestamp: now,
              action: 'Applicability re-evaluated',
              system: 'Server correlation engine',
              details: candidate.matchingEvidence,
            },
          ]
        : old.timeline,
    };
  });
  for (const old of existing)
    if (!current.has(identity(old)))
      result.push(
        old.notificationStatus === 'NOT_APPLICABLE'
          ? old
          : {
              ...old,
              notificationStatus: 'NOT_APPLICABLE',
              matchingEvidence:
                'No current match: inventory is inactive, removed, or outside the cached vulnerability criteria.',
              timeline: [
                ...old.timeline,
                {
                  timestamp: now,
                  action: 'Applicability re-evaluated',
                  system: 'Server correlation engine',
                  details: 'No current inventory match; excluded from notification.',
                },
              ],
            },
      );
  return result;
}
