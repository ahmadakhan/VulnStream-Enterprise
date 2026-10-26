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
  IntelligenceMatch,
  EmailDeliveryLog,
  AuditLog,
  AliasEntry,
} from '../types';
import { normalizeCveId, isWithinTimelineScope, mergeCveRecords } from '../utils/deduplicator';
import {
  DEFAULT_PRODUCT_ALIASES,
  DEFAULT_VENDOR_ALIASES,
  aliasGroupKeys,
  buildAliasMap,
  matchesWatchlistItem,
  parseCPE23,
} from '../utils/cpeMatcher';
import { deriveInventoryAliases } from '../utils/aliasLifecycle';
import { isPublicAddress } from '../utils/ipSafety';
import ipaddr from 'ipaddr.js';

/** Package identity (`npm/express`) used to index PURL inventory. */
const purlIdentity = (purl: string): string | null => {
  const match = /^pkg:([a-z][a-z0-9.+-]*)\/([^?#]+)/.exec(purl.trim());
  if (!match) return null;
  const at = match[2].lastIndexOf('@');
  return `${match[1]}/${at > 0 ? match[2].slice(0, at) : match[2]}`;
};
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
    if (u.protocol !== 'https:' || u.username || u.password)
      return { safe: false, reason: 'HTTPS without URL credentials required' };
    if (u.port && u.port !== '443')
      return { safe: false, reason: 'Non-default port on HTTPS is not permitted' };
    if (
      host === 'localhost' ||
      /\.(localhost|local|internal)$/.test(host) ||
      (ipaddr.isValid(host) && !isPublicAddress(host))
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
/**
 * VEX enforcement and the exploitability lattice live in their own module so
 * the resolution rules can be tested independently of correlation.
 */
export {
  applyVexSuppression,
  resolveExploitability,
  hasExploitIntelligence,
  vexImpact,
  vexStatementsFor,
} from './exploitability';
/**
 * Rate-limit zero-day matches and consolidate into digests.
 *
 * Zero-day matches (findings without a CVE, or with active exploit indicators)
 * are capped at MAX_ZERO_DAYS_PER_RUN to prevent notification storms.
 * Multiple zero-day matches for the same vendor/product are consolidated into
 * a single advisory (the "zero-day digest" mode).
 */
export const MAX_ZERO_DAYS_PER_RUN = 50;
export interface ZeroDayDigest {
  advisoryId: string;
  vendor: string;
  product: string;
  findingIds: string[];
  matchCount: number;
}
export function rankAndRateLimitZeroDays(
  findings: Finding[],
  matches: IntelligenceMatch[],
): { findings: Finding[]; matches: IntelligenceMatch[]; digests: ZeroDayDigest[] } {
  // Identify zero-day findings: REVIEW_REQUIRED with no CVE or with exploit
  // sources but no CVE ID.
  const zeroDayMatches = matches.filter((m) => m.zeroDay || (!m.cveId && m.status === 'REVIEW_REQUIRED'));
  if (zeroDayMatches.length <= MAX_ZERO_DAYS_PER_RUN) {
    return { findings, matches, digests: [] };
  }
  // Rate limit by credibility score: keep the highest-credibility matchups.
  const ranked = [...zeroDayMatches].sort((a, b) => (b.credibilityScore ?? 0) - (a.credibilityScore ?? 0));
  const dropped = ranked.slice(MAX_ZERO_DAYS_PER_RUN);
  const keptIds = new Set(ranked.slice(0, MAX_ZERO_DAYS_PER_RUN).map((m) => m.id));
  // Build digests for dropped zero-day matches grouped by vendor/product.
  const digests: ZeroDayDigest[] = [];
  const byAsset = new Map<string, IntelligenceMatch[]>();
  for (const match of dropped) {
    const key = `${match.assetId}`;
    if (!byAsset.has(key)) byAsset.set(key, []);
    byAsset.get(key)!.push(match);
  }
  for (const [_, matches] of byAsset) {
    const match = matches[0];
    digests.push({
      advisoryId: `ZDIGEST_${match.assetId}`,
      vendor: match.assetName.split('(')[1]?.split(')')[0]?.trim() || 'unknown',
      product: match.assetName.split('(')[0]?.trim() || 'unknown',
      findingIds: [],
      matchCount: matches.length,
    });
  }
  const filteredMatches = matches.filter((m) => keptIds.has(m.id) || !m.zeroDay);
  return { findings, matches: filteredMatches, digests };
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
  vendorAliases: Record<string, string[]> = {},
  productAliases: Record<string, string[]> = {},
  candidatePairs?: Map<string, Set<string>>,
  aliasEntries: readonly AliasEntry[] = [],
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
  // Auto aliases are derived from the operator's own inventory declarations
  // (vendor/product plus CPEs). They are ephemeral here and persisted by the
  // server pipeline, so both the browser simulation and server correlation
  // resolve the same spellings. Manual aliases always take precedence and are
  // never removed by this merge.
  const autoAliasEntries = deriveInventoryAliases(activeAssets, aliasEntries);
  const mergeAliasMaps = (
    base: Record<string, string[]>,
    extra: Record<string, string[]>,
  ): Record<string, string[]> => {
    const merged: Record<string, string[]> = Object.assign(Object.create(null), base);
    for (const [key, values] of Object.entries(extra))
      merged[key] = [...new Set([...(merged[key] || []), ...values])];
    return merged;
  };
  const effectiveVendorAliases = mergeAliasMaps(
    vendorAliases,
    buildAliasMap(autoAliasEntries, 'VENDOR'),
  );
  const effectiveProductAliases = mergeAliasMaps(
    productAliases,
    buildAliasMap(autoAliasEntries, 'PRODUCT'),
  );
  // Index inventory once. Matching the entire CVE cache against every asset
  // on every run is the dominant avoidable cost for large installations.
  // The candidate selection is deliberately a superset: wildcard criteria,
  // unstructured assets, and package assets stay eligible for full matching.
  const assetsByProduct = new Map<string, WatchListItem[]>();
  const assetsByPurl = new Map<string, WatchListItem[]>();
  // Assets with neither a CPE nor a PURL can only be matched by the text/alias
  // fallback, so they remain candidates for every CVE. PURL-only assets are
  // reachable through their package bucket instead of being scanned every time.
  const assetsWithoutIdentifiers: WatchListItem[] = [];
  const assetsWithBroadCpes: WatchListItem[] = [];
  // Build alias-expanded indices so assets are candidates when their vendor
  // or product differs from a CVE's by an alias rather than a canonical name.
  // Built-in aliases are included: the matcher accepts them, so the candidate
  // prefilter must not drop the pair before it can be evaluated.
  const aliasVendorKeys = (v: string): string[] =>
    !v
      ? [v]
      : [
          ...new Set([
            v.toLowerCase(),
            ...aliasGroupKeys(v, DEFAULT_VENDOR_ALIASES, effectiveVendorAliases),
          ]),
        ];
  const aliasProductKeys = (p: string): string[] =>
    !p
      ? [p]
      : [
          ...new Set([
            p.toLowerCase(),
            ...aliasGroupKeys(p, DEFAULT_PRODUCT_ALIASES, effectiveProductAliases),
          ]),
        ];
  for (const asset of activeAssets) {
    const seenPurls = new Set<string>();
    for (const purl of asset.purls ?? []) {
      const identity = purlIdentity(purl);
      if (!identity || seenPurls.has(identity)) continue;
      seenPurls.add(identity);
      const bucket = assetsByPurl.get(identity) || [];
      bucket.push(asset);
      assetsByPurl.set(identity, bucket);
    }
    if (!asset.cpes.length) {
      if (!asset.purls?.length) assetsWithoutIdentifiers.push(asset);
      continue;
    }
    const seenProducts = new Set<string>();
    for (const cpe of asset.cpes) {
      const parsed = parseCPE23(cpe);
      if (!parsed.isValid) continue;
      if (/[?*]/.test(parsed.vendor) || /[?*]/.test(parsed.product)) {
        assetsWithBroadCpes.push(asset);
        break;
      }
      // Register asset under all alias-expanded vendor/product keys.
      for (const vendorKey of aliasVendorKeys(parsed.vendor))
        for (const productKey of aliasProductKeys(parsed.product)) {
          const key = `${vendorKey}\u0000${productKey}`;
          if (seenProducts.has(key)) continue;
          seenProducts.add(key);
          const bucket = assetsByProduct.get(key) || [];
          bucket.push(asset);
          assetsByProduct.set(key, bucket);
        }
    }
    // Keep assets with non-empty but invalid CPE lists out of text fallback;
    // the matcher correctly treats structured identifiers as authoritative.
  }
  const candidateAssets = (cve: NormalizedCVE): WatchListItem[] => {
    const criteria = cve.cpeMatchDetails?.length
      ? cve.cpeMatchDetails.map((detail) => detail.criteria)
      : cve.cpeMatches;
    const candidates = new Map<string, WatchListItem>();
    const add = (items: WatchListItem[]) => items.forEach((asset) => candidates.set(asset.id, asset));
    add(assetsWithoutIdentifiers);
    add(assetsWithBroadCpes);
    if (cve.purls?.length)
      for (const purl of cve.purls) {
        const identity = purlIdentity(purl);
        if (identity) add(assetsByPurl.get(identity) || []);
      }
    if (!criteria.length) {
      // A CVE with no structured identifiers has to use the text/alias fallback
      // against the whole inventory. A package-only advisory stays bounded to
      // the matching package buckets.
      if (!cve.purls?.length) return activeAssets;
      return [...candidates.values()];
    }
    for (const criterion of criteria) {
      const parsed = parseCPE23(criterion);
      if (!parsed.isValid || /[?*]/.test(parsed.vendor) || /[?*]/.test(parsed.product)) {
        add(activeAssets);
        break;
      }
      for (const vendorKey of aliasVendorKeys(parsed.vendor))
        for (const productKey of aliasProductKeys(parsed.product))
          add(assetsByProduct.get(`${vendorKey}\u0000${productKey}`) || []);
    }
    return [...candidates.values()];
  };
  // Assets that can never be reached through a structured identity join are
  // added to every CVE's candidate set, matching candidateAssets' fallback.
  const alwaysCandidateAssets = [...assetsWithoutIdentifiers, ...assetsWithBroadCpes];
  const assetById = new Map(activeAssets.map((asset) => [asset.id, asset]));
  /**
   * When PostgreSQL supplied candidate pairs, iterate only those assets. A CVE
   * absent from the map has a wildcard/unstructured criterion and falls back to
   * the in-process candidate selection, preserving the text/alias path.
   */
  const assetsForCve = (cve: NormalizedCVE, canonical: string): WatchListItem[] => {
    const allowed = candidatePairs?.get(canonical);
    if (!allowed) return candidateAssets(cve);
    const candidates = new Map<string, WatchListItem>();
    for (const id of allowed) {
      const asset = assetById.get(id);
      if (asset) candidates.set(asset.id, asset);
    }
    for (const asset of alwaysCandidateAssets) candidates.set(asset.id, asset);
    return [...candidates.values()];
  };
  const matchingStarted = performance.now();
  for (const raw of latest.values()) {
    const canonical = normalizeCveId(raw.cveId);
    // Filter before candidate selection so every match method (strict CPE/PURL,
    // alias, and vendor/product fallback) sees only CVEs whose latest published
    // or modified date is inside the run's timeline scope.
    if (
      !canonical ||
      !isWithinTimelineScope(raw.publishedDate, raw.modifiedDate, settings.scopeHours, started)
    )
      continue;
    processed++;
    const cve = { ...raw, cveId: canonical };
    for (const asset of assetsForCve(cve, canonical)) {
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
          effectiveVendorAliases,
          effectiveProductAliases,
          asset.version,
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
        matchedAssetVendor: asset.vendor,
        matchedAssetProduct: asset.product,
        matchedAssetPurls: asset.purls,
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
