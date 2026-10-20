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
import { normalizeCveId, isWithinTimelineScope } from '../utils/deduplicator';
import { matchCPE, matchPurl, parseCPE23 } from '../utils/cpeMatcher';
import { isVersionInNvdRange } from '../utils/versionComparator';
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
): PipelineRunResult {
  const started = new Date(),
    seen = new Set<string>(),
    known = new Set(existing.map((f) => `${normalizeCveId(f.cveId)}:${f.matchedAssetId}`));
  const newFindings: Finding[] = [];
  let duplicates = 0,
    processed = 0;
  for (const raw of corpus) {
    const canonical = normalizeCveId(raw.cveId);
    if (
      !canonical ||
      !isWithinTimelineScope(raw.publishedDate, raw.modifiedDate, settings.scopeHours, started)
    )
      continue;
    if (seen.has(canonical)) {
      duplicates++;
      continue;
    }
    seen.add(canonical);
    processed++;
    const cve = { ...raw, cveId: canonical };
    for (const asset of watchlist.filter((a) => a.active)) {
      const key = `${canonical}:${asset.id}`;
      if (known.has(key)) continue;
      let matched = '',
        confirmed = false;
      const criteria =
        cve.cpeMatchDetails || cve.cpeMatches.map((criteria) => ({ criteria, range: cve.versionRange }));
      for (const a of asset.cpes)
        for (const v of criteria) {
          if (matchCPE(a, v.criteria, v.range).matched) {
            matched = v.criteria;
            const version = parseCPE23(a).version;
            confirmed =
              confirmed ||
              (!['*', '-', ''].includes(version) &&
                (!v.range ||
                  (Object.values(v.range).every(
                    (bound) =>
                      !bound ||
                      /^[0-9]+(?:\.[0-9]+)*(?:-(?:h|p|patch|hotfix|sp|u|update|build|fix)[0-9]+)?$/.test(
                        bound,
                      ),
                  ) &&
                    /^[0-9]+(?:\.[0-9]+)*(?:-(?:h|p|patch|hotfix|sp|u|update|build|fix)[0-9]+)?$/.test(
                      version,
                    ))));
          }
        }
      for (const a of asset.purls || [])
        for (const v of cve.purls || []) {
          const base = a.split(/[?#]/)[0],
            at = base.lastIndexOf('@'),
            version = at > base.indexOf('/') + 1 ? base.slice(at + 1) : '';
          if (
            matchPurl(a, v) &&
            (!cve.versionRange || (version && isVersionInNvdRange(version, cve.versionRange).inRange))
          ) {
            matched = v;
            confirmed = confirmed || !!version;
          }
        }
      if (!matched) continue;
      if (cve.applicabilityRequiresReview) confirmed = false;
      // Unknown installed versions produce a reviewable finding, never an automatic notification.
      const evidence = confirmed
        ? 'Structured package/version correlation'
        : 'Product correlation; version or applicability requires review';
      newFindings.push({
        id: crypto.randomUUID(),
        cveId: canonical,
        cve,
        matchedAssetId: asset.id,
        matchedAssetName: `${asset.assetTag} (${asset.vendor} ${asset.product})`,
        matchedCpe: matched,
        matchingMethod: matched.startsWith('pkg:') ? 'PURL_EXACT' : 'STRICT_CPE',
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
  const execution: PipelineExecution = {
    id: crypto.randomUUID(),
    startTime: started.toISOString(),
    endTime: new Date().toISOString(),
    status: 'COMPLETED',
    scopeHours: settings.scopeHours,
    phases: [
      {
        name: 'Structured correlation',
        status: 'SUCCESS',
        durationMs: Date.now() - started.getTime(),
        details: `${processed} CVEs evaluated; ${newFindings.length} new findings`,
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
