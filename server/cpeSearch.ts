import type { Db } from './db';
import { list } from './db';
import { decrypt } from './secrets';
import { parseCPE23 } from '../src/utils/cpeMatcher.ts';
import type { Config } from './config';
import type { Requester } from './network';
import type { ThreatFeed, NvdCpeSearchResult, NvdCpeSearchResponse } from '../src/types/index.ts';

const NVD_CPE_ENDPOINT = 'https://services.nvd.nist.gov/rest/json/cpes/2.0';

export function buildCpeUrl(
  keyword: string,
  resultsPerPage: number,
  apiKey: string,
): URL {
  const url = new URL(NVD_CPE_ENDPOINT);
  url.searchParams.set('keywordSearch', keyword);
  url.searchParams.set('resultsPerPage', String(resultsPerPage));
  if (apiKey) url.searchParams.set('apiKey', apiKey);
  return url;
}

/**
 * Reads the API key from the first enabled NVD feed configured with API-key
 * authentication. Returns an empty string when no NVD key is configured, in
 * which case the NVD CPE search is served from the public, unauthenticated
 * rate budget (5 requests / 30s).
 */
export async function loadNvdApiKey(db: Db, config: Config): Promise<string> {
  let feeds: ThreatFeed[];
  try {
    feeds = await list<ThreatFeed>(db, 'feeds');
  } catch {
    return '';
  }
  const nvd = feeds.find((f) => f.type === 'NVD_API' && f.authType === 'API_KEY' && f.enabled);
  if (!nvd?.authSecretKey) return '';
  try {
    return decrypt(nvd.authSecretKey, config.ENCRYPTION_KEY, `feed:${nvd.id}`);
  } catch {
    return '';
  }
}

/**
 * Queries the NVD CPE dictionary for verified CPE 2.3 names matching the
 * supplied vendor and product keywords. Only well-formed CPE 2.3 entries are
 * returned; partial matches that the NVD keyword search surfaces are parsed and
 * filtered so the operator only selects structurally valid CPEs.
 *
 * The request is issued through the shared SSRF-protected requester, so the NVD
 * host must appear in EGRESS_ALLOWED_HOSTS (it is present by default).
 */
export async function searchNvdCpes(
  request: Requester,
  apiKey: string,
  vendor: string,
  product: string,
  limit: number,
): Promise<NvdCpeSearchResponse> {
  const keyword = `${vendor} ${product}`.trim();
  const pageSize = Math.min(Math.max(1, limit), 200);
  const url = buildCpeUrl(keyword, pageSize, apiKey);

  let response = await request(url.href, {
    timeoutMs: 20000,
    socketTimeoutMs: 15000,
    maxResponseBytes: 4 * 1024 * 1024,
  });

  // NVD answers HTTP 404 for invalid/expired API keys in addition to unresolvable
  // keyword searches. When a key was supplied, retry the request without it so the
  // unauthenticated public rate budget is used instead of failing the operator's
  // search outright.
  if (response.status === 404 && apiKey) {
    const fallback = buildCpeUrl(keyword, pageSize, '');
    response = await request(fallback.href, {
      timeoutMs: 20000,
      socketTimeoutMs: 15000,
      maxResponseBytes: 4 * 1024 * 1024,
    });
  }

  if (response.status === 429) {
    throw {
      __nvdRateLimit: true,
      retryAfter: response.headers['retry-after'],
      status: 429,
      message: 'NVD rate limit reached; retry later',
    } as NvdRateLimitError;
  }

  // NVD answers 404 for keyword searches it cannot resolve (e.g. single-
  // character or otherwise unsupported terms) instead of an empty result set.
  // Treat that as "no matches" rather than a hard failure.
  if (response.status === 404) {
    return { results: [], totalResults: 0 };
  }

  if (response.status !== 200)
    throw new Error(`NVD CPE search returned HTTP ${response.status}`);

  let data: any;
  try {
    data = JSON.parse(response.body);
  } catch {
    throw new Error('NVD returned a non-JSON CPE search response');
  }

  const configurations: any[] = Array.isArray(data?.products) ? data.products : [];
  const results: NvdCpeSearchResult[] = [];
  for (const entry of configurations) {
    const cpe = entry?.cpe || entry;
    const name = typeof cpe?.cpeName === 'string' ? cpe.cpeName : '';
    if (!name) continue;
    const parsed = parseCPE23(name);
    if (!parsed.isValid) continue;
    const title = Array.isArray(cpe?.titles) && typeof cpe.titles[0]?.title === 'string' ? cpe.titles[0].title : undefined;
    results.push({
      cpeName: name,
      cpeNameId: typeof cpe?.cpeNameId === 'string' ? cpe.cpeNameId : '',
      part: parsed.part,
      vendor: parsed.vendor,
      product: parsed.product,
      version: parsed.version,
      update: parsed.update,
      targetSw: parsed.targetSw,
      targetHw: parsed.targetHw,
      ...(title ? { title } : {}),
    });
  }

  const total = Number.isInteger(data?.totalResults) ? Number(data.totalResults) : results.length;
  return { results, totalResults: total };
}

export interface NvdRateLimitError {
  __nvdRateLimit: boolean;
  retryAfter: string | string[] | undefined;
  status: 429;
  message: string;
}

export function isNvdRateLimitError(error: unknown): error is NvdRateLimitError {
  return (
    typeof error === 'object' &&
    error !== null &&
    (error as NvdRateLimitError).__nvdRateLimit === true
  );
}

export function nvdRetryAfterSeconds(error: NvdRateLimitError): number | null {
  const raw = error.retryAfter;
  const single = Array.isArray(raw) ? raw[0] : raw;
  if (!single) return null;
  const asSeconds = Number(single);
  if (Number.isFinite(asSeconds)) return Math.max(1, Math.round(asSeconds));
  const asDate = Date.parse(single);
  return Number.isFinite(asDate) ? Math.max(1, Math.round((asDate - Date.now()) / 1000)) : null;
}
