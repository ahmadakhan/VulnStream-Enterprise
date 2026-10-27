import type { Config } from './config';
import type { Requester } from './network';
import type { NormalizedCVE, ThreatSearchHit, ThreatSearchResponse } from '../src/types/index.ts';
import { loadNvdApiKey } from './cpeSearch';
import { normalizeNvd } from './ingestion';
import { parseCPE23, matchVendorWithAliases, matchProductWithAliases } from '../src/utils/cpeMatcher';
import type { Db } from './db';
import { list } from './db';
import { buildAliasMap } from '../src/utils/cpeMatcher';

const NVD_CVE_ENDPOINT = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

interface AliasEntry {
  scope: 'VENDOR' | 'PRODUCT';
  canonical: string;
  aliases: string[];
}

export interface ThreatSearchOptions {
  vendor: string;
  product: string;
  limit: number;
}

export class ThreatSearchRateLimitError extends Error {
  readonly retryAfter: number | null;
  constructor(message: string, retryAfter: number | null = null) {
    super(message);
    this.name = 'ThreatSearchRateLimitError';
    this.retryAfter = retryAfter;
  }
}

/**
 * Searches the NVD CVE API for vulnerabilities affecting the given vendor
 * and product. Uses NVD's CPE virtual match (`virtualMatchString`) as the
 * primary path so every version of a product is covered, falling back to
 * keyword search when the CPE dictionary yields no results. Custom aliases
 * from the operator-managed thesaurus are merged onto the built-in baseline
 * to broaden the vendor/product match.
 *
 * All requests go through the shared SSRF-protected requester, so the NVD
 * host must appear in EGRESS_ALLOWED_HOSTS (it is present by default).
 */
export async function searchThreatIntelligence(
  request: Requester,
  db: Db,
  config: Config,
  options: ThreatSearchOptions,
): Promise<ThreatSearchResponse> {
  const { vendor, product, limit } = options;
  const apiKey = await loadNvdApiKey(db, config);
  const trimmedVendor = vendor.trim().toLowerCase();
  const trimmedProduct = product.trim().toLowerCase();

  const allAliases = await list<AliasEntry>(db, 'aliases');
  const customVendorAliases = buildAliasMap(
    allAliases.filter((e) => e.scope === 'VENDOR'),
    'VENDOR',
  );
  const customProductAliases = buildAliasMap(
    allAliases.filter((e) => e.scope === 'PRODUCT'),
    'PRODUCT',
  );

  const hits: ThreatSearchHit[] = [];
  const seenCves = new Set<string>();
  let totalResults = 0;
  let rateLimited = false;
  let retryAfter: number | undefined;

  const cpePrefixes = generateCpePrefixes(trimmedVendor, trimmedProduct);

  // Try exact CPE 2.3 match first
  for (const cpePrefix of cpePrefixes) {
    try {
      const result = await fetchNvdCves(request, apiKey, cpePrefix, limit);
      for (const cve of result.cves) {
        const matchingCpes = findMatchingCpes(cve, cpePrefix, trimmedVendor, trimmedProduct, customVendorAliases, customProductAliases);
        if (matchingCpes.length > 0) {
          if (!seenCves.has(cve.cveId)) {
            seenCves.add(cve.cveId);
            hits.push({
              cve,
              matchingCpes,
              source: 'NVD_API',
            });
          }
          totalResults++;
        }
      }
      if (hits.length >= limit) break;
    } catch (err) {
      if (err instanceof ThreatSearchRateLimitError) {
        rateLimited = true;
        retryAfter = err.retryAfter ?? undefined;
        break;
      }
      // Continue to keyword fallback on other errors
    }
  }

  // If no exact CPE matches, fall back to keyword search. NVD keyword search
  // matches literal text, so CPE-style underscores must become spaces; a
  // query like "apache http_server" otherwise returns nothing.
  if (hits.length === 0 && !rateLimited) {
    const keyword = `${trimmedVendor} ${trimmedProduct}`.replace(/_/g, ' ').replace(/\s+/g, ' ');
    try {
      const result = await fetchNvdCvesByKeyword(request, apiKey, keyword, limit * 2);
      for (const cve of result.cves) {
        const matchingCpes = findMatchingCpesByAlias(
          cve,
          trimmedVendor,
          trimmedProduct,
          customVendorAliases,
          customProductAliases,
        );
        if (matchingCpes.length > 0) {
          if (!seenCves.has(cve.cveId)) {
            seenCves.add(cve.cveId);
            hits.push({
              cve,
              matchingCpes,
              source: 'KEYWORD_FALLBACK',
            });
          }
          totalResults++;
        }
      }
    } catch (err) {
      if (err instanceof ThreatSearchRateLimitError) {
        rateLimited = true;
        retryAfter = err.retryAfter ?? undefined;
      }
    }
  }

  // Sort by CVSS severity descending
  hits.sort((a, b) => {
    const sa = severityScore(a.cve.cvss.severity);
    const sb = severityScore(b.cve.cvss.severity);
    if (sb !== sa) return sb - sa;
    return b.cve.cvss.score - a.cve.cvss.score;
  });

  return {
    hits: hits.slice(0, Math.max(1, Math.min(limit, 200))),
    totalResults,
    vendor,
    product,
    rateLimited,
    retryAfter,
  };
}

interface NvdFetchResult {
  cves: NormalizedCVE[];
}

async function fetchNvdCves(
  request: Requester,
  apiKey: string,
  matchString: string,
  limit: number,
): Promise<NvdFetchResult> {
  const url = new URL(NVD_CVE_ENDPOINT);
  // `cpeName` requires an exact dictionary entry; a wildcard version suffix
  // (…:product:*:*) returns 404. `virtualMatchString` matches every version
  // of the CPE prefix, which is what an operator searching a product expects.
  url.searchParams.set('virtualMatchString', matchString);
  url.searchParams.set('resultsPerPage', String(Math.min(Math.max(1, limit), 2000)));
  if (apiKey) url.searchParams.set('apiKey', apiKey);

  return fetchNvdResponse(request, url.href);
}

async function fetchNvdCvesByKeyword(
  request: Requester,
  apiKey: string,
  keyword: string,
  limit: number,
): Promise<NvdFetchResult> {
  const url = new URL(NVD_CVE_ENDPOINT);
  url.searchParams.set('keywordSearch', keyword);
  url.searchParams.set('resultsPerPage', String(Math.min(Math.max(1, limit), 2000)));
  if (apiKey) url.searchParams.set('apiKey', apiKey);

  return fetchNvdResponse(request, url.href);
}

async function fetchNvdResponse(request: Requester, url: string): Promise<NvdFetchResult> {
  const response = await request(url, {
    timeoutMs: 30000,
    socketTimeoutMs: 20000,
    maxResponseBytes: 10 * 1024 * 1024,
  });

  if (response.status === 429) {
    const retryAfterHeader = response.headers['retry-after'];
    const retryAfter = retryAfterHeader
      ? typeof retryAfterHeader === 'string'
        ? parseRetryAfter(retryAfterHeader)
        : parseRetryAfter(retryAfterHeader[0])
      : null;
    throw new ThreatSearchRateLimitError(
      'NVD rate limit reached; retry later',
      retryAfter,
    );
  }

  if (response.status !== 200) {
    throw new Error(`NVD CVE search returned HTTP ${response.status}`);
  }

  let data: any;
  try {
    data = JSON.parse(response.body);
  } catch {
    throw new Error('NVD returned a non-JSON CVE search response');
  }

  const vulns = Array.isArray(data?.vulnerabilities) ? data.vulnerabilities : [];
  const cves: NormalizedCVE[] = [];
  for (const item of vulns) {
    const normalized = normalizeNvd(item, 'NVD_API');
    if (normalized) cves.push(normalized);
  }

  return {
    cves,
  };
}

function parseRetryAfter(header: string): number | undefined {
  const asSeconds = Number(header);
  if (Number.isFinite(asSeconds)) return Math.max(1, Math.round(asSeconds));
  const asDate = Date.parse(header);
  return Number.isFinite(asDate) ? Math.max(1, Math.round((asDate - Date.now()) / 1000)) : undefined;
}

function generateCpePrefixes(vendor: string, product: string): string[] {
  return (['a', 'o', 'h'] as const).map((part) => `cpe:2.3:${part}:${vendor}:${product}`);
}

function findMatchingCpes(
  cve: NormalizedCVE,
  cpePrefix: string,
  assetVendor: string,
  assetProduct: string,
  customVendorAliases: Record<string, string[]>,
  customProductAliases: Record<string, string[]>,
): string[] {
  return cve.cpeMatches.filter((cpe) => {
    const parsed = parseCPE23(cpe);
    if (!parsed.isValid) return false;

    const vendorMatch =
      parsed.vendor === assetVendor ||
      parsed.vendor === '*' ||
      matchVendorWithAliases(parsed.vendor, assetVendor, customVendorAliases);

    const productMatch =
      parsed.product === assetProduct ||
      parsed.product === '*' ||
      matchProductWithAliases(parsed.product, assetProduct, customProductAliases);

    return vendorMatch && productMatch;
  });
}

function findMatchingCpesByAlias(
  cve: NormalizedCVE,
  assetVendor: string,
  assetProduct: string,
  customVendorAliases: Record<string, string[]>,
  customProductAliases: Record<string, string[]>,
): string[] {
  return cve.cpeMatches.filter((cpe) => {
    const parsed = parseCPE23(cpe);
    if (!parsed.isValid) return false;

    return (
      matchVendorWithAliases(parsed.vendor, assetVendor, customVendorAliases) &&
      matchProductWithAliases(parsed.product, assetProduct, customProductAliases)
    );
  });
}

function severityScore(severity: NormalizedCVE['cvss']['severity']): number {
  switch (severity) {
    case 'CRITICAL':
      return 4;
    case 'HIGH':
      return 3;
    case 'MEDIUM':
      return 2;
    case 'LOW':
      return 1;
    default:
      return 0;
  }
}
