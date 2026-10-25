import type { Finding, IntelligenceArticle, IntelligenceMatch, WatchListItem, NormalizedCVE, ThreatFeed } from '../types';
import { quickHash } from './cryptoChain';

const text = (value: string) =>
  value
    .normalize('NFKC')
    .toLowerCase()
    .replace(/[^\p{L}\p{N}]+/gu, ' ')
    .trim();

/** Source feed weight: higher for authoritative threat intel feeds (0–40). */
const FEED_WEIGHTS: Record<string, number> = {
  NVD_API: 40,
  CISA_KEV: 40,
  MITRE_CVE: 35,
  VULNCHECK_KEV: 30,
  OPENCVE_API: 25,
  RSS_NEWS: 15,
  THREAT_FEED: 20,
};

/** Compute a credibility score (0–100) for an intelligence match.
 *
 * Combines the source feed weight with the confidence of the vendor/product
 * keyword match. Corroborated structural matches score higher than
 * heuristic text matches.
 */
export function computeCredibilityScore(
  match: IntelligenceMatch,
  sourceFeeds: string[] = [],
  hasStructuredFinding: boolean,
): number {
  let feedScore = 10; // baseline for unknown feeds
  if (sourceFeeds.length) {
    const maxWeight = Math.max(...sourceFeeds.map((f) => FEED_WEIGHTS[f] ?? 10));
    feedScore = maxWeight;
  }
  // Keyword confidence: corroborated by a structured finding = 100,
  // zero-day without CVE = 70, review-only text match = 50.
  let keywordScore: number;
  if (hasStructuredFinding && match.status === 'CORROBORATED') keywordScore = 100;
  else if (match.zeroDay) keywordScore = 70;
  else keywordScore = 50;
  // Average feed weight and keyword confidence, normalized to 0–100.
  return Math.round((feedScore * 0.6 + keywordScore * 0.4));
}

/**
 * Built-in vendor display-name aliases for the news text matcher.
 * These handle cases where a vendor's CPE identifier differs from how their
 * name appears in article prose (e.g. "paloaltonetworks" in CPE vs.
 * "palo alto networks" in a headline).
 *
 * Operator-managed aliases from the Alias Thesaurus are merged on top of
 * this table at call time via the `customVendorAliases` parameter of
 * matchIntelligence, so the Thesaurus page controls both CVE matching
 * and news evidence matching from a single place.
 */
const BUILTIN_VENDOR_ALIASES: Record<string, string[]> = {
  paloaltonetworks: ['palo alto networks'],
  checkpoint: ['check point'],
  f5networks: ['f5'],
  juniper: ['juniper networks'],
  microsoft: ['microsoft'],
  redhat: ['red hat'],
};
function mentions(document: string, value: string): boolean {
  const normalized = text(value);
  if (!normalized || normalized.length < 2 || normalized === 'unknown') return false;
  return ` ${document} `.includes(` ${normalized} `);
}
export function mergeArticles(records: IntelligenceArticle[]): IntelligenceArticle[] {
  const byId = new Map<string, IntelligenceArticle>();
  for (const article of records) {
    const old = byId.get(article.id);
    const winner =
      !old ||
      Date.parse(article.modifiedDate) > Date.parse(old.modifiedDate) ||
      (article.modifiedDate === old.modifiedDate && JSON.stringify(article) > JSON.stringify(old))
        ? article
        : old;
    const mergedCveIds = [...new Set([...(old?.cveIds || []), ...(winner.cveIds || []), ...(article.cveIds || [])])].sort();
    byId.set(article.id, {
      ...winner,
      sourceFeeds: [...new Set([...(old?.sourceFeeds || []), ...article.sourceFeeds])].sort(),
      zeroDay: (winner.zeroDay || old?.zeroDay || article.zeroDay) && mergedCveIds.length === 0,
      cveIds: mergedCveIds,
    });
  }
  return [...byId.values()];
}

/** News mentions are review evidence. Only the structured matcher can confirm installed-version applicability.
 *
 * @param customVendorAliases - Operator-managed vendor aliases from the Alias Thesaurus
 *   (buildAliasMap(aliasEntries, 'VENDOR')), merged on top of the built-in display-name
 *   table so a single Thesaurus entry covers both CVE matching and news evidence.
 * @param customProductAliases - Operator-managed product aliases from the Alias Thesaurus
 *   (buildAliasMap(aliasEntries, 'PRODUCT')), used to catch product name variants in article prose.
 */
export function matchIntelligence(
  articles: IntelligenceArticle[],
  inventory: WatchListItem[],
  findings: Finding[],
  corpus: NormalizedCVE[] = [],
  customVendorAliases: Record<string, string[]> = {},
  customProductAliases: Record<string, string[]> = {},
): IntelligenceMatch[] {
  const matches = new Map<string, IntelligenceMatch>();
  const current = new Map(findings.map((finding) => [`${finding.cveId}:${finding.matchedAssetId}`, finding]));
  const authoritative = new Set(
    corpus
      .filter((cve) => !cve.applicabilityRequiresReview && (cve.cpeMatches.length || cve.purls?.length))
      .map((cve) => cve.cveId),
  );
  for (const article of mergeArticles(articles)) {
    const document = text(`${article.title} ${article.summary}`);
    for (const asset of inventory.filter((item) => item.active)) {
      // Merge built-in display-name variants with any operator-managed aliases
      // from the Alias Thesaurus, deduplicated, then test each against the article.
      const normVendor = text(asset.vendor);
      const allVendorVariants = [
        asset.vendor,
        ...(BUILTIN_VENDOR_ALIASES[normVendor] || []),
        ...(customVendorAliases[normVendor] || []),
      ];
      const vendorMentioned = allVendorVariants.some((variant) => mentions(document, variant));

      // Also check product aliases so e.g. "globalprotect" in an article matches
      // an inventory item tagged as "globalprotect" even if the CPE uses "pan_os".
      const normProduct = text(asset.product);
      const allProductVariants = [
        asset.product,
        ...(customProductAliases[normProduct] || []),
      ];
      const productMentioned = allProductVariants.some((variant) => mentions(document, variant));
      const references = article.cveIds.length ? article.cveIds : [null];
      for (const cveId of references) {
        const finding = cveId ? current.get(`${cveId}:${asset.id}`) : undefined;
        if (finding && ['RESOLVED', 'FALSE_POSITIVE', 'PATCH_APPLIED'].includes(finding.status)) continue;
        // News cannot override a structured exclusion (for example, an installed patched version).
        if (cveId && authoritative.has(cveId) && !finding) continue;
        if (!finding && !(vendorMentioned && productMentioned)) continue;
        const id = quickHash(`${cveId || article.id}:${asset.id}`);
        // NOT_APPLICABLE and VEX-suppressed findings are explicit exclusions:
        // news coverage must not turn them back into corroborated evidence.
        const confirmed =
          finding &&
          ![
            'REVIEW_REQUIRED',
            'NOT_APPLICABLE',
            'SUPPRESSED_VEX_NOT_AFFECTED',
          ].includes(finding.notificationStatus) &&
          finding.status !== 'RESOLVED' &&
          finding.status !== 'FALSE_POSITIVE';
        const old = matches.get(id);
        const isZeroDay = article.zeroDay === true;
        const credibilityScore = computeCredibilityScore(
          { id, cveId, assetId: asset.id, assetName: '', articleIds: [], status: confirmed ? 'CORROBORATED' : 'REVIEW_REQUIRED', evidence: '', zeroDay: isZeroDay },
          article.sourceFeeds,
          Boolean(finding && confirmed),
        );
        matches.set(id, {
          id,
          cveId,
          assetId: asset.id,
          assetName: `${asset.assetTag} (${asset.vendor} ${asset.product})`,
          articleIds: [...new Set([...(old?.articleIds || []), article.id])].sort(),
          status: confirmed ? 'CORROBORATED' : 'REVIEW_REQUIRED',
          findingId: finding?.id,
          zeroDay: old?.zeroDay || isZeroDay,
          credibilityScore,
          evidence: confirmed
            ? 'Article references a CVE independently matched to this product by structured applicability.'
            : isZeroDay
              ? 'Potential zero-day: vendor and product mentioned in threat intelligence without an assigned CVE. Confirm affected versions and exploitability before acting.'
              : 'Vendor and product are mentioned together, or a review-only CVE correlation exists. Confirm affected versions and the CVE-to-product relationship before acting.',
        });
      }
    }
  }
  return [...matches.values()];
}
