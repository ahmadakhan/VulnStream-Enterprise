import { normalizeNvd } from './ingestion.ts';
import { parseCPE23, matchVendorWithAliases, matchProductWithAliases, buildAliasMap } from '../src/utils/cpeMatcher.ts';
import { loadNvdApiKey, isNvdRateLimitError, nvdRetryAfterSeconds } from './cpeSearch.ts';
import type { Config } from './config';
import type { Requester } from './network';
import type { Db } from './db';
import { list } from './db';
import type { ThreatSearchHit, ThreatSearchResponse } from '../src/types/index.ts';

const NVD_CVE_ENDPOINT = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

export interface ThreatSearchOptions {
  vendor: string;
  product: string;
  limit: number;
  customVendorAliases?: Record<string, string[]>;
  customProductAliases?: Record<string, string[]>;
}

/**
 * Generates CPE 2.3 prefix strings (with trailing wildcards) for each valid
 * part tag so the NVD CVE Search API `cpeName` parameter can perform an exact
 * dictionary lookup rather than a loose keyword query.
 */
function generateCpePrefixes(vendor: string, product: string): string[] {
  const normalizedVendor = vendor.toLowerCase().trim().replace(/[^a-z0-9_.-]/g, '_');
  const normalizedProduct = product.toLowerCase().trim().replace(/[^a-z0-9_.-]/g, '_');
  if (!normalizedVendor || !normalizedProduct) return [];
  return ['a', 'o', 'h'].map((part) => `cpe:2.3:${part}:${normalizedVendor}:${normalizedProduct}:*:*:*:*:*:*:*`);
}

/**
 * Determines whether a CPE 2.3 string matches the requested vendor and product
 * using the enterprise alias thesaurus, so searches return results even when NVD
 * uses spelling variants (e.g. `microsoft` vs `msft`).
 */
function cpeMatchesIdentity(
  cpeStr: string,
  vendor: string,
  product: string,
  customVendorAliases: Record<string, string[]> = {},
  customProductAliases: Record<string, string[]> = {},
): boolean {
  const parsed = parseCPE23(cpeStr);
  if (!parsed.isValid) return false;
  const normVendor = vendor.toLowerCase().trim();
  const normProduct = product.toLowerCase().trim();
  if (!normVendor || !normProduct) return false;
  return (
    matchVendorWithAliases(normVendor, parsed.vendor, customVendorAliases) &&
    matchProductWithAliases(normProduct, parsed.product, customProductAliases)
  );
}

export class ThreatSearchRateLimitError extends Error {
  public retryAfter: number | null;
  constructor(message: string, retryAfter: number | null) {
    super(message);
    this.name = 'ThreatSearchRateLimitError';
    this.retryAfter = retryAfter;
  }
}

export class ThreatSearchError extends Error {
  public status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = 'ThreatSearchError';
    this.status = status;
  }
}

/**
 * Searches the NVD CVE API for vulnerabilities affecting the given vendor and
 * product. Uses `cpeName` exact dictionary search as the primary method, then
 * falls back to `keywordSearch` + CPE-matching filtering when the exact search
 * returns no usable results.
 *
 * The request is issued through the shared SSRF-protected requester, so the NVD
 * host must appear in EGRESS_ALLOWED_HOSTS (it is present by default).
 */
export async function searchThreatIntelligence(
  request: Requester,
  db: Db,
  config: Config,
  options: ThreatSearchOptions,
): Promise<ThreatSearchResponse> {
  const { vendor, product, limit } = options;
  const customVendorAliases = await buildCustomAliasMap(db, 'VENDOR');
  const customProductAliases = await buildCustomAliasMap(db, 'PRODUCT');

  const apiKey = await loadNvdApiKey(db, config);

  let hits: ThreatSearchHit[] = [];
  let totalResults = 0;
  let rateLimited = false;
  let retryAfter: number | null = null;

  const cpePrefixes = generateCpePrefixes(vendor, product);

  // ── Primary: exact CPE dictionary search via cpeName ──
  for (const cpe of cpePrefixes) {
    try {
      const { items, retryAfter: ra } = await searchNvdCveByCpeName(
        request, apiKey, cpe, limit,
      );
      if (ra !== null) retryAfter = ra;
      for (const item of items) {
        const normalized = normalizeNvd(item, 'NVD_API');
        if (!normalized) continue;
        const matchingCpes = normalized.cpeMatches.filter((c) =>
          cpeMatchesIdentity(c, vendor, product, customVendorAliases, customProductAliases),
        );
        if (matchingCpes.length > 0) {
          hits.push({ cve: normalized, matchingCpes, source: 'NVD_API' });
          totalResults += 1;
        }
      }
    } catch (error) {
      if (isNvdRateLimitError(error)) {
        rateLimited = true;
        const ra = nvdRetryAfterSeconds(error);
        if (ra !== null) retryAfter = ra;
        break;
      }
    }
    if (rateLimited) break;
  }

  // Deduplicate across the three part-prefix searches (a/o/h)
  hits = dedupeByCveId(hits);

  // ── Fallback: keyword search + CPE-matching when exact search yields nothing ──
  if (!rateLimited && hits.length === 0 && vendor && product) {
    try {
      const { items, total, rateLimit, retryAfter: ra } = await searchNvdCveByKeyword(
        request, apiKey, vendor, product, limit,
      );
      rateLimited = rateLimit;
      if (ra !== null) retryAfter = ra;
      totalResults = total;
      for (const item of items) {
        const normalized = normalizeNvd(item, 'NVD_API');
        if (!normalized) continue;
        const matchingCpes = normalized.cpeMatches.filter((c) =>
          cpeMatchesIdentity(c, vendor, product, customVendorAliases, customProductAliases),
        );
        if (matchingCpes.length > 0) {
          hits.push({ cve: normalized, matchingCpes, source: 'KEYWORD_FALLBACK' });
        }
      }
      // Deduplicate by CVE ID (keyword search can surface overlapping hits)
      hits = dedupeByCveId(hits);
    } catch (error) {
      if (isNvdRateLimitError(error)) {
        rateLimited = true;
        const ra = nvdRetryAfterSeconds(error);
        if (ra !== null) retryAfter = ra;
      }
    }
  }

  return {
    hits,
    totalResults,
    vendor,
    product,
    rateLimited,
    ...(retryAfter !== null ? { retryAfter } : {}),
  };
}

/**
 * Queries the NVD CVE Search API (`cpeName`) for CVEs that affect a specific
 * CPE 2.3 dictionary entry. Returns up to `limit` results.
 */
async function searchNvdCveByCpeName(
  request: Requester,
  apiKey: string,
  cpeName: string,
  limit: number,
): Promise<{ items: any[]; total: number; rateLimit: boolean; retryAfter: number | null }> {
  const url = new URL(NVD_CVE_ENDPOINT);
  url.searchParams.set('cpeName', cpeName);
  url.searchParams.set('resultsPerPage', String(Math.min(Math.max(1, limit), 2000)));
  url.searchParams.set('startIndex', '0');
  if (apiKey) url.searchParams.set('apiKey', apiKey);

  const response = await request(url.href, {
    timeoutMs: 20000,
    socketTimeoutMs: 15000,
    maxResponseBytes: 32 * 1024 * 1024,
  });

  if (response.status === 429) {
    throw {
      __nvdRateLimit: true,
      retryAfter: response.headers['retry-after'],
      status: 429,
      message: 'NVD rate limit reached; retry later',
    };
  }

  if (response.status !== 200)
    throw new ThreatSearchError(response.status, `NVD CVE search returned HTTP ${response.status}`);

  let data: any;
  try {
    data = JSON.parse(response.body);
  } catch {
    throw new Error('NVD returned a non-JSON CVE search response');
  }

  const items: any[] = Array.isArray(data?.vulnerabilities) ? data.vulnerabilities : [];
  const total = Number.isInteger(data?.totalResults) ? Number(data.totalResults) : items.length;
  return { items, total, rateLimit: false, retryAfter: null };
}

/**
 * Queries the NVD CVE Search API (`keywordSearch`) as a fallback. The keyword
 * search returns CVEs whose descriptions mention the vendor/product text; each
 * result is then filtered through strict CPE alias matching to ensure only
 * relevant hits are returned.
 */
async function searchNvdCveByKeyword(
  request: Requester,
  apiKey: string,
  vendor: string,
  product: string,
  limit: number,
): Promise<{ items: any[]; total: number; rateLimit: boolean; retryAfter: number | null }> {
  const url = new URL(NVD_CVE_ENDPOINT);
  url.searchParams.set('keywordSearch', `${vendor} ${product}`.trim());
  url.searchParams.set('resultsPerPage', String(Math.min(Math.max(1, limit), 2000)));
  url.searchParams.set('startIndex', '0');
  if (apiKey) url.searchParams.set('apiKey', apiKey);

  const response = await request(url.href, {
    timeoutMs: 20000,
    socketTimeoutMs: 15000,
    maxResponseBytes: 32 * 1024 * 1024,
  });

  if (response.status === 429) {
    throw {
      __nvdRateLimit: true,
      retryAfter: response.headers['retry-after'],
      status: 429,
      message: 'NVD rate limit reached; retry later',
    };
  }

  if (response.status !== 200)
    throw new ThreatSearchError(response.status, `NVD CVE search returned HTTP ${response.status}`);

  let data: any;
  try {
    data = JSON.parse(response.body);
  } catch {
    throw new Error('NVD returned a non-JSON CVE search response');
  }

  const items: any[] = Array.isArray(data?.vulnerabilities) ? data.vulnerabilities : [];
  const total = Number.isInteger(data?.totalResults) ? Number(data.totalResults) : items.length;
  return { items, total, rateLimit: false, retryAfter: null };
}

/**
 * Reads operator-managed custom aliases from the database and converts them
 * into the `{ canonical: string[] }` shape expected by the CPE matcher.
 */
async function buildCustomAliasMap(db: Db, scope: 'VENDOR' | 'PRODUCT'): Promise<Record<string, string[]>> {
  try {
     const rows = await list<{ scope: 'VENDOR' | 'PRODUCT'; canonical: string; aliases: string[] }>(db, 'aliases');
    return buildAliasMap(
      rows.filter((r) => r.scope === scope),
      scope,
    );
  } catch {
    return {};
  }
}

/**
 * Deduplicates threat-search hits by canonical CVE ID, keeping the first
 * occurrence (which preserves the highest-confidence matching CPE for each CVE).
 */
function dedupeByCveId(hits: ThreatSearchHit[]): ThreatSearchHit[] {
  const seen = new Set<string>();
  const result: ThreatSearchHit[] = [];
  for (const hit of hits) {
    if (seen.has(hit.cve.cveId)) continue;
    seen.add(hit.cve.cveId);
    result.push(hit);
  }
  return result;
}
