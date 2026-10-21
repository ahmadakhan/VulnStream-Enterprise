import type {
  ThreatFeed,
  WatchListItem,
  NormalizedCVE,
  Finding,
  Advisory,
  AlertedCVE,
  PipelineExecution,
  AppSettings,
  ExploitRiskLevel,
  EmailDeliveryLog,
  AuditLog,
} from '../types';
import { normalizeCveId, isWithinTimelineScope, mergeCveRecords } from '../utils/deduplicator';
import { matchesWatchlistItem } from '../utils/cpeMatcher';
import ipaddr from 'ipaddr.js';
export interface PipelineRunResult {
  execution: PipelineExecution;
  newFindings: Finding[];
  newAdvisories: Advisory[];
  updatedAlertedCves: AlertedCVE[];
  newEmailLogs: EmailDeliveryLog[];
  newAuditLogs: AuditLog[];
}
/** Client-side hint only. The server validates DNS and pins every connection. */
export function validateSsrfSafety(value: string): { safe: boolean; reason?: string } {
  try {
    const u = new URL(value),
      host = u.hostname
        .replace(/^\[|\]$/g, '')
        .replace(/\.$/, '')
        .toLowerCase();
    if (!['https:', 'http:'].includes(u.protocol) || u.username || u.password)
      return { safe: false, reason: 'Invalid URL scheme or credentials' };
    if (
      host === 'localhost' ||
      /\.(localhost|local|internal)$/.test(host) ||
      (ipaddr.isValid(host) && ipaddr.process(host).range() !== 'unicast')
    )
      return { safe: false, reason: 'Non-public destination' };
    return { safe: true };
  } catch {
    return { safe: false, reason: 'Malformed URL' };
  }
}
export function determineExploitRisk(cve: NormalizedCVE): ExploitRiskLevel {
  return cve.cisaKev.isKev
    ? 'CISA_KEV_EXPLOITED'
    : cve.exploitationSources?.length || cve.exploitStatus === 'Reported In Wild'
      ? 'REPORTED_IN_WILD_EXPLOIT'
    : cve.exploitStatus === 'Active Weaponized'
      ? 'WEAPONIZED_EXPLOIT'
      : cve.epss.score >= 0.4
        ? 'HIGH_EPSS_PROBABILITY'
        : cve.cvss.score >= 7
          ? 'ELEVATED'
          : 'STANDARD';
}
/** Pure correlation. Network ingestion and transactional outbox delivery live on the server. */
export function runVulnerabilityPipeline(
  _feeds: ThreatFeed[],
  corpus: NormalizedCVE[],
  watchlist: WatchListItem[],
  alerted: AlertedCVE[],
  existing: Finding[],
  settings: AppSettings,
  _caller = 'Server worker',
  includeExistingCandidates = false,
): PipelineRunResult {
  const started = new Date(),
    known = new Set(existing.map((f) => `${normalizeCveId(f.cveId)}:${f.matchedAssetId}`));
  const newFindings: Finding[] = [];
  let processed = 0;
  const normalizationStarted = performance.now();
  const latest = mergeCveRecords(corpus);
  const duplicates = corpus.filter((cve) => normalizeCveId(cve.cveId)).length - latest.size;
  const normalizationDurationMs = Math.round(performance.now() - normalizationStarted);
  const activeAssets = watchlist.filter((asset) => asset.active);
  const matchingStarted = performance.now();
  for (const raw of latest.values()) {
    const canonical = normalizeCveId(raw.cveId);
    if (
      !canonical ||
      !isWithinTimelineScope(raw.publishedDate, raw.modifiedDate, settings.scopeHours, started)
    )
      continue;
    processed++;
    const cve = { ...raw, cveId: canonical };
    for (const asset of activeAssets) {
      const key = `${canonical}:${asset.id}`;
      if (known.has(key) && !includeExistingCandidates) continue;
      const applicabilitySets = cve.cpeMatchDetails?.length
        ? cve.cpeMatchDetails.map(({ criteria, range }) => ({
            cpes: [criteria],
            range: range || cve.versionRange,
          }))
        : [{ cpes: cve.cpeMatches, range: cve.versionRange }];
      // Per-CPE ranges apply only to that CPE criterion. PURLs use the
      // package-level range and must never borrow another product's bounds.
      const matches = applicabilitySets.map(({ cpes, range }) =>
        matchesWatchlistItem(
          asset.cpes,
          asset.vendor,
          asset.product,
          cpes,
          cve.title,
          cve.description,
          range,
          asset.purls,
          cve.purls,
          asset.targetHw,
          undefined,
          false,
        ),
      );
      if (asset.purls?.length && cve.purls?.length)
        matches.push(
          matchesWatchlistItem(
            [],
            '',
            '',
            [],
            '',
            '',
            cve.versionRange,
            asset.purls,
            cve.purls,
            asset.targetHw,
          ),
        );
      const result = matches.filter((match) => match.matched).sort((a, b) => b.confidence - a.confidence)[0];
      if (!result?.matched) continue;
      if (cve.applicabilityRequiresReview || result.applicabilityRequiresReview) result.confidence = 0;
      const confirmed = result.confidence >= 90;
      const evidence = confirmed
        ? 'Structured package/version correlation'
        : 'Product correlation; version or applicability requires review';
      newFindings.push({
        id: crypto.randomUUID(),
        cveId: canonical,
        cve,
        matchedAssetId: asset.id,
        matchedAssetName: `${asset.assetTag} (${asset.vendor} ${asset.product})`,
        matchedCpe: result.matchedCpe || '',
        matchingMethod: result.method,
        matchingEvidence: evidence,
        exposure: asset.exposure,
        exploitRisk: determineExploitRisk(cve),
        notificationStatus: confirmed ? 'QUEUED_FOR_DISPATCH' : 'REVIEW_REQUIRED',
        status: 'MONITORED',
        autoDispatchedAt: null,
        advisoryId: null,
        timeline: [
          {
            timestamp: started.toISOString(),
            action: 'Matched inventory',
            system: 'Server correlation engine',
            details: evidence,
          },
        ],
      });
      known.add(key);
    }
  }
  const matchingDurationMs = Math.round(performance.now() - matchingStarted);
  const execution: PipelineExecution = {
    id: crypto.randomUUID(),
    startTime: started.toISOString(),
    endTime: new Date().toISOString(),
    status: 'COMPLETED',
    scopeHours: settings.scopeHours,
    phases: [
      {
        name: 'Normalize & deduplicate',
        status: 'SUCCESS',
        durationMs: normalizationDurationMs,
        details: `${latest.size} canonical CVEs; ${duplicates} duplicates removed`,
      },
      {
        name: 'Product matching',
        status: 'SUCCESS',
        durationMs: matchingDurationMs,
        details: `${processed} CVEs evaluated against ${activeAssets.length} active products; ${newFindings.length} matches`,
      },
    ],
    stats: {
      rawIngested: corpus.length,
      normalized: processed,
      deduplicated: processed,
      inRunDuplicatesDropped: duplicates,
      matchedWatchlist: newFindings.length,
      autoDispatchedNotifications: 0,
      advisoriesDispatched: 0,
      webhooksFired: 0,
      vexSuppressedCount: 0,
    },
    logs: [],
  };
  return {
    execution,
    newFindings,
    newAdvisories: [],
    updatedAlertedCves: structuredClone(alerted),
    newEmailLogs: [],
    newAuditLogs: [],
  };
}
