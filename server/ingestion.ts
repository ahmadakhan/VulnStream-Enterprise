import type { ThreatFeed, NormalizedCVE } from '../src/types';
import type { Requester, RequestOptions, ResponseData } from './network';
import { cveSchema } from './validation';
import { decrypt } from './secrets';
import type { Config } from './config';
import { setTimeout as delay } from 'node:timers/promises';
import { z } from 'zod';
export interface IngestResult {
  cves: NormalizedCVE[];
  kev?: Record<string, NormalizedCVE['cisaKev']>;
  epss?: Record<string, NormalizedCVE['epss']>;
  count: number;
  etag?: string;
  notModified?: boolean;
}
const iso = (s: string) => new Date(s).toISOString();
export function normalizeNvd(item: any, feedId: string): NormalizedCVE | null {
  const cve = item.cve;
  if (!cve || ['Rejected', 'Awaiting Analysis', 'Undergoing Analysis'].includes(cve.vulnStatus)) return null;
  const metric =
    cve.metrics?.cvssMetricV40?.[0]?.cvssData ||
    cve.metrics?.cvssMetricV31?.[0]?.cvssData ||
    cve.metrics?.cvssMetricV30?.[0]?.cvssData ||
    cve.metrics?.cvssMetricV2?.[0]?.cvssData;
  // Keep unscored CVEs for applicability matching. Score 0 is only a storage
  // sentinel; UNKNOWN prevents it from being presented as a real CVSS score.
  let applicabilityRequiresReview = false;
  const details: NonNullable<NormalizedCVE['cpeMatchDetails']> = [];
  const walk = (node: any) => {
    // Complex AND / negated configurations cannot safely be flattened into an OR.
    if (node.negate || node.operator === 'AND') applicabilityRequiresReview = true;
    for (const m of node.cpeMatch || [])
      if (m.vulnerable === true) {
        const { versionStartIncluding, versionStartExcluding, versionEndIncluding, versionEndExcluding } = m;
        details.push({
          criteria: m.criteria,
          range: { versionStartIncluding, versionStartExcluding, versionEndIncluding, versionEndExcluding },
        });
      }
    for (const child of node.nodes || node.children || []) walk(child);
  };
  for (const config of cve.configurations || []) walk(config);
  const description = cve.descriptions?.find((d: any) => d.lang === 'en')?.value || cve.id;
  const score = metric?.baseScore ?? 0;
  return cveSchema.parse({
    cveId: cve.id,
    title: description.slice(0, 500),
    description,
    publishedDate: iso(cve.published),
    modifiedDate: iso(cve.lastModified),
    cvss: {
      version: !metric
        ? 'UNKNOWN'
        : metric.version === '4.0'
          ? '4.0'
          : metric.version === '2.0'
            ? '2.0'
            : '3.1',
      score,
      vector: metric?.vectorString || '',
      severity: !metric
        ? 'UNKNOWN'
        : score >= 9
          ? 'CRITICAL'
          : score >= 7
            ? 'HIGH'
            : score >= 4
              ? 'MEDIUM'
              : 'LOW',
    },
    cwe: (cve.weaknesses || [])
      .flatMap((w: any) => (w.description || []).filter((d: any) => d.lang === 'en').map((d: any) => d.value))
      .slice(0, 100),
    cpeMatches: details.map((d) => d.criteria),
    cpeMatchDetails: details,
    applicabilityRequiresReview,
    sourceFeeds: [feedId],
    epss: { score: 0, percentile: 0 },
    cisaKev: { isKev: false },
    exploitStatus: 'None',
    remediation: {
      patchUrl: '',
      vendorAdvisoryRef:
        (cve.references || []).find((r: any) => r.tags?.includes('Vendor Advisory'))?.url || '',
      immediateActions: [],
      workarounds: [],
      rollbackPlan: '',
      stepByStep: [],
    },
  });
}
export async function ingestFeed(
  feed: ThreatFeed,
  scopeHours: number,
  request: Requester,
  config: Config,
  sleep = delay,
): Promise<IngestResult> {
  const headers: Record<string, string> = {};
  if (feed.authType !== 'NONE') {
    const secret = decrypt(feed.authSecretKey || '', config.ENCRYPTION_KEY, `feed:${feed.id}`);
    if (!secret) throw new Error('Feed credentials are not configured');
    if (feed.authType === 'API_KEY') headers.apiKey = secret;
    else
      headers.Authorization = `${feed.authType === 'BASIC' ? 'Basic' : 'Bearer'} ${feed.authType === 'BASIC' ? Buffer.from(secret).toString('base64') : secret}`;
  }
  const json = async (
    url: string,
    conditional = true,
    requestOptions: Omit<RequestOptions, 'headers'> = {},
    retryTransient = false,
  ): Promise<{ data: any; etag: string | undefined }> => {
    if (conditional && feed.etag) headers['If-None-Match'] = feed.etag;
    let response: ResponseData;
    for (let attempt = 0; ; attempt++) {
      try {
        response = await request(url, { headers, ...requestOptions });
      } catch (error) {
        const timedOut = error instanceof Error && /timed out|timeout/i.test(error.message);
        if (!retryTransient || !timedOut || attempt >= 2) throw error;
        await sleep(2000 * (attempt + 1));
        continue;
      }
      const retryableStatus = [429, 502, 503, 504].includes(response.status);
      if (!retryTransient || !retryableStatus || attempt >= 2) break;
      const retryAfter = response.headers['retry-after'];
      const retryAfterValue = Array.isArray(retryAfter) ? retryAfter[0] : retryAfter;
      const retryAfterSeconds = retryAfterValue ? Number(retryAfterValue) : NaN;
      const retryAfterDate = retryAfterValue ? Date.parse(retryAfterValue) : NaN;
      const retryDelay = Number.isFinite(retryAfterSeconds)
        ? retryAfterSeconds * 1000
        : Number.isFinite(retryAfterDate)
          ? retryAfterDate - Date.now()
          : response.status === 429
            ? 30000
            : 2000 * (attempt + 1);
      await sleep(Math.min(60000, Math.max(1000, retryDelay)));
    }
    if (response.status === 304) {
      return { data: null, etag: feed.etag };
    }
    if (response.status !== 200)
      throw new Error(
        response.status === 429
          ? 'NVD rate limit reached after retries; wait and run the pipeline again'
          : `Feed returned HTTP ${response.status}`,
      );
    const etag = response.headers.etag as string | undefined;
    try {
      return { data: JSON.parse(response.body), etag };
    } catch {
      throw new Error('Feed did not return valid JSON');
    }
  };
  if (feed.type === 'NVD_API') {
    const end = new Date(),
      start = new Date(end.getTime() - Math.min(scopeHours, 2880) * 3600000);
    const cves: NormalizedCVE[] = [];
    let rawCount = 0;
    for (let offset = 0; ;) {
      const url = new URL(feed.url);
      url.searchParams.set('lastModStartDate', start.toISOString());
      url.searchParams.set('lastModEndDate', end.toISOString());
      url.searchParams.set('startIndex', String(offset));
      url.searchParams.set('resultsPerPage', '1000');
      // Each page has a distinct URL and the time window moves on every run;
      // a single feed-level ETag cannot safely validate this paginated query.
      const { data } = await json(
        url.href,
        false,
        { timeoutMs: 60000, socketTimeoutMs: 30000, maxResponseBytes: 16 * 1024 * 1024 },
        true,
      );
      if (!data) return { cves: [], count: 0, notModified: true };
      const page = data;
      if (
        !Array.isArray(page.vulnerabilities) ||
        !Number.isInteger(page.totalResults) ||
        page.totalResults < 0 ||
        page.startIndex !== offset
      )
        throw new Error('Invalid NVD pagination response');
      if (page.totalResults > 50000) throw new Error('NVD window exceeds 50,000 records; reduce scope');
      for (const item of page.vulnerabilities) {
        const cve = normalizeNvd(item, feed.id);
        if (cve) cves.push(cve);
      }
      rawCount += page.vulnerabilities.length;
      offset += page.vulnerabilities.length;
      if (offset >= page.totalResults) break;
      if (!page.vulnerabilities.length) throw new Error('NVD pagination stopped before completion');
      await sleep(Math.max(60000 / feed.rateLimitPerMin, feed.authType === 'NONE' ? 6500 : 700));
    }
    return { cves, count: rawCount };
  }
  if (feed.type === 'CISA_KEV') {
    const { data: rawData, etag } = await json(feed.url);
    if (!rawData) return { cves: [], count: 0, notModified: true, etag };
    const data = z
      .object({
        vulnerabilities: z
          .array(
            z.object({
              cveID: z.string().regex(/^CVE-\d{4}-\d{4,}$/),
              dateAdded: z.string(),
              dueDate: z.string(),
              requiredAction: z.string(),
              knownRansomwareCampaignUse: z.enum(['Known', 'Unknown']),
            }),
          )
          .max(50000),
      })
      .parse(rawData);
    return {
      cves: [],
      count: data.vulnerabilities.length,
      etag,
      kev: Object.fromEntries(
        data.vulnerabilities.map((v) => [
          v.cveID,
          {
            isKev: true,
            dateAdded: v.dateAdded,
            dueDate: v.dueDate,
            requiredAction: v.requiredAction,
            knownRansomwareCampaignUse: v.knownRansomwareCampaignUse,
          },
        ]),
      ),
    };
  }
  if (feed.type === 'EPSS_API') {
    const epss: Record<string, NormalizedCVE['epss']> = {};
    let count = 0;
    for (let offset = 0; ;) {
      const url = new URL(feed.url);
      url.searchParams.set('offset', String(offset));
      url.searchParams.set('limit', '10000');
      // EPSS is paginated, so a feed-level ETag could validate the wrong page.
      const { data: page } = await json(url.href, false);
      if (!page) return { cves: [], epss, count, notModified: true };
      const rows = z
        .array(
          z.object({
            cve: z.string(),
            epss: z.coerce.number().min(0).max(1),
            percentile: z.coerce.number().min(0).max(1),
          }),
        )
        .max(10000)
        .parse(page.data);
      const total = Number(page.total);
      if (!Number.isInteger(total) || total < 0 || total > 500000) throw new Error('Invalid EPSS total');
      for (const row of rows) epss[row.cve] = { score: row.epss, percentile: row.percentile };
      count += rows.length;
      offset += rows.length;
      if (offset >= total) break;
      if (!rows.length) throw new Error('EPSS pagination stopped before completion');
      await sleep(60000 / feed.rateLimitPerMin);
    }
    return { cves: [], epss, count };
  }
  if (feed.type === 'JSON_SEARCH_API') {
    const { data, etag } = await json(feed.url);
    if (!data) return { cves: [], count: 0, notModified: true, etag };
    const cves = z.array(cveSchema).max(10000).parse(data);
    // Generic feeds may assert VEX, but unsigned claims cannot suppress alerts.
    return {
      cves: cves.map((c) => ({ ...c, vex: undefined, sourceFeeds: [feed.id] })),
      count: cves.length,
      etag,
    };
  }
  throw new Error(`Unsupported feed adapter: ${feed.type}`);
}
