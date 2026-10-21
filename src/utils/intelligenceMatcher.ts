import type { Finding, IntelligenceArticle, IntelligenceMatch, WatchListItem, NormalizedCVE } from '../types';
import { quickHash } from './cryptoChain';

const text = (value: string) => value.normalize('NFKC').toLowerCase().replace(/[^\p{L}\p{N}]+/gu,' ').trim();
const vendorAliases: Record<string,string[]> = {
  paloaltonetworks:['palo alto networks'], checkpoint:['check point'], f5networks:['f5'],
  juniper:['juniper networks'], microsoft:['microsoft'], redhat:['red hat'],
};
function mentions(document: string, value: string): boolean {
  const normalized = text(value);
  if (!normalized || normalized.length < 2 || normalized === 'unknown') return false;
  return (` ${document} `).includes(` ${normalized} `);
}
export function mergeArticles(records: IntelligenceArticle[]): IntelligenceArticle[] {
  const byId = new Map<string,IntelligenceArticle>();
  for (const article of records) {
    const old = byId.get(article.id);
    const winner = !old || Date.parse(article.modifiedDate) > Date.parse(old.modifiedDate) ||
      (article.modifiedDate === old.modifiedDate && JSON.stringify(article) > JSON.stringify(old)) ? article : old;
    byId.set(article.id, { ...winner, sourceFeeds:[...new Set([...(old?.sourceFeeds || []), ...article.sourceFeeds])].sort() });
  }
  return [...byId.values()];
}
/** News mentions are review evidence. Only the structured matcher can confirm installed-version applicability. */
export function matchIntelligence(articles: IntelligenceArticle[], inventory: WatchListItem[], findings: Finding[], corpus: NormalizedCVE[] = []): IntelligenceMatch[] {
  const matches = new Map<string,IntelligenceMatch>();
  const current = new Map(findings.map((finding) => [`${finding.cveId}:${finding.matchedAssetId}`,finding]));
  const authoritative = new Set(corpus.filter((cve) => !cve.applicabilityRequiresReview && (cve.cpeMatches.length || cve.purls?.length)).map((cve) => cve.cveId));
  for (const article of mergeArticles(articles)) {
    const document = text(`${article.title} ${article.summary}`);
    for (const asset of inventory.filter((item) => item.active)) {
      const vendorMentioned = [asset.vendor,...(vendorAliases[text(asset.vendor)] || [])].some((vendor) => mentions(document,vendor));
      const productMentioned = mentions(document,asset.product);
      const references = article.cveIds.length ? article.cveIds : [null];
      for (const cveId of references) {
        const finding = cveId ? current.get(`${cveId}:${asset.id}`) : undefined;
        if (finding && ['RESOLVED','FALSE_POSITIVE'].includes(finding.status)) continue;
        // News cannot override a structured exclusion (for example, an installed patched version).
        if (cveId && authoritative.has(cveId) && !finding) continue;
        if (!finding && !(vendorMentioned && productMentioned)) continue;
        const id = quickHash(`${cveId || article.id}:${asset.id}`);
        const confirmed = finding && finding.notificationStatus !== 'REVIEW_REQUIRED' && finding.status !== 'RESOLVED' && finding.status !== 'FALSE_POSITIVE';
        const old = matches.get(id);
        matches.set(id, { id, cveId, assetId:asset.id, assetName:`${asset.assetTag} (${asset.vendor} ${asset.product})`,
          articleIds:[...new Set([...(old?.articleIds || []),article.id])].sort(),
          status:confirmed ? 'CORROBORATED' : 'REVIEW_REQUIRED', findingId:finding?.id,
          evidence:confirmed ? 'Article references a CVE independently matched to this product by structured applicability.' :
            'Vendor and product are mentioned together, or a review-only CVE correlation exists. Confirm affected versions and the CVE-to-product relationship before acting.' });
      }
    }
  }
  return [...matches.values()];
}
