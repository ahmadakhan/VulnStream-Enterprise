import type { ThreatFeed, NormalizedCVE } from '../src/types';
import type { Requester, RequestOptions, ResponseData } from './network';
import { cveSchema } from './validation';
import { decrypt } from './secrets';
import type { Config } from './config';
import { setTimeout as delay } from 'node:timers/promises';
import { z } from 'zod';
import { normalizeCveId } from '../src/utils/deduplicator';
export interface IngestResult {
  sourceId?: string;
  cves: NormalizedCVE[];
  kev?: Record<string, NormalizedCVE['cisaKev']>;
  /** Provider-asserted exploited-in-the-wild indicators, distinct from CISA KEV. */
  exploited?: Record<string, true>;
  epss?: Record<string, NormalizedCVE['epss']>;
  /** A successful targeted EPSS response is authoritative only for these IDs. */
  epssScope?: string[];
  withdrawals?: { cveId: string; modifiedDate: string }[];
  count: number;
  etag?: string;
  notModified?: boolean;
}
const iso = (s: string) => new Date(s).toISOString();
function normalizeOpenCve(detail: any, feedId: string): NormalizedCVE {
  const metrics = detail.metrics || {};
  const metric = metrics.cvssV4_0?.data?.score != null
    ? { ...metrics.cvssV4_0.data, version: '4.0' }
    : metrics.cvssV3_1?.data?.score != null
      ? { ...metrics.cvssV3_1.data, version: '3.1' }
      : metrics.cvssV3_0?.data?.score != null
        ? { ...metrics.cvssV3_0.data, version: '3.1' }
        : metrics.cvssV2_0?.data?.score != null
          ? { ...metrics.cvssV2_0.data, version: '2.0' }
          : undefined;
  const details: NonNullable<NormalizedCVE['cpeMatchDetails']> = [];
  let applicabilityRequiresReview = false;
  const walk = (node: any) => {
    if (!node || typeof node !== 'object') return;
    if (node.negate || node.operator === 'AND') applicabilityRequiresReview = true;
    for (const match of node.cpeMatch || []) {
      if (match.vulnerable !== true || typeof match.criteria !== 'string') continue;
      const criteria = match.criteria.trim();
      if (!criteria.startsWith('cpe:2.3:')) continue;
      details.push({ criteria, range: {
        versionStartIncluding: match.versionStartIncluding,
        versionStartExcluding: match.versionStartExcluding,
        versionEndIncluding: match.versionEndIncluding,
        versionEndExcluding: match.versionEndExcluding,
      } });
    }
    for (const child of node.nodes || node.children || []) walk(child);
  };
  for (const config of detail.nvd_cpe_configurations || []) walk(config);
  const score = Number(metric?.score || 0);
  const description = String(detail.description || detail.title || detail.cve_id).slice(0, 30000);
  return cveSchema.parse({
    cveId: detail.cve_id,
    title: String(detail.title || description).slice(0, 500),
    description,
    publishedDate: iso(detail.created_at),
    modifiedDate: iso(detail.updated_at),
    cvss: {
      version: metric?.version || 'UNKNOWN', score, vector: String(metric?.vector || ''),
      severity: !metric ? 'UNKNOWN' : score >= 9 ? 'CRITICAL' : score >= 7 ? 'HIGH' : score >= 4 ? 'MEDIUM' : 'LOW',
    },
    cwe: Array.isArray(detail.weaknesses) ? detail.weaknesses.filter((v: unknown) => typeof v === 'string').slice(0, 100) : [],
    cpeMatches: details.map(({ criteria }) => criteria),
    cpeMatchDetails: details,
    applicabilityRequiresReview: applicabilityRequiresReview || details.length === 0,
    sourceFeeds: [feedId],
    epss: { score: 0, percentile: 0 },
    cisaKev: metrics.kev?.provider === 'cisa' && metrics.kev?.data?.dateAdded
      ? { isKev: true, dateAdded: metrics.kev.data.dateAdded, dueDate: metrics.kev.data.dueDate }
      : { isKev: false },
    exploitStatus: 'None',
    remediation: { patchUrl: '', vendorAdvisoryRef: '', immediateActions: [], workarounds: [], rollbackPlan: '', stepByStep: [] },
  });
}
export function normalizeNvd(item: any, feedId: string): NormalizedCVE | null {
  const cve = item.cve;
  if (!cve || cve.vulnStatus === 'Rejected') return null;
  const metric =
    cve.metrics?.cvssMetricV40?.[0]?.cvssData ||
    cve.metrics?.cvssMetricV31?.[0]?.cvssData ||
    cve.metrics?.cvssMetricV30?.[0]?.cvssData ||
    cve.metrics?.cvssMetricV2?.[0]?.cvssData;
  // Keep unscored CVEs for applicability matching. Score 0 is only a storage
  // sentinel; UNKNOWN prevents it from being presented as a real CVSS score.
  let applicabilityRequiresReview = ['Received', 'Awaiting Analysis', 'Undergoing Analysis'].includes(
    cve.vulnStatus,
  );
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
  sleep: (ms: number) => Promise<unknown> = delay,
  targetCveIds: string[] = [],
  onNvdProgress?: (progress: { offset: number; total: number; records: number }) => Promise<void> | void,
): Promise<IngestResult> {
  const headers: Record<string, string> = {};
  const nvdInterval = Math.max(60000 / feed.rateLimitPerMin, feed.authType === 'API_KEY' ? 700 : 6500);
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
        await sleep(Math.max(nvdInterval, 2000 * (attempt + 1)));
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
      // Never retry earlier than the provider permits. Long cooldowns defer the
      // source to a later run instead of occupying this worker indefinitely.
      if (retryDelay > 60000)
        throw new Error(
          `NVD requested a ${Math.ceil(retryDelay / 1000)} second retry delay; defer to a later run`,
        );
      await sleep(Math.max(nvdInterval, retryDelay));
    }
    if (response.status === 304) {
      if (!conditional || !feed.etag) throw new Error('Feed returned an unexpected conditional response');
      return { data: undefined, etag: feed.etag };
    }
    if (response.status !== 200)
      throw new Error(
        response.status === 429
          ? 'Feed rate limit reached after retries; wait and run the pipeline again'
          : `Feed returned HTTP ${response.status}`,
      );
    const etag = typeof response.headers.etag === 'string' ? response.headers.etag : undefined;
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
    const withdrawals: NonNullable<IngestResult['withdrawals']> = [];
    let rawCount = 0;
    let expectedTotal: number | undefined;
    const seen = new Set<string>();
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
      if (data === undefined) throw new Error('NVD returned an unexpected conditional response');
      const page = data;
      if (
        !page ||
        !Array.isArray(page.vulnerabilities) ||
        page.vulnerabilities.length > 1000 ||
        offset + page.vulnerabilities.length > page.totalResults ||
        (expectedTotal !== undefined && page.totalResults !== expectedTotal) ||
        !Number.isInteger(page.totalResults) ||
        page.totalResults < 0 ||
        page.startIndex !== offset
      )
        throw new Error('Invalid NVD pagination response');
      if (page.totalResults > 50000) throw new Error('NVD window exceeds 50,000 records; reduce scope');
      expectedTotal = page.totalResults;
      for (const item of page.vulnerabilities) {
        const id = normalizeCveId(item?.cve?.id);
        if (!id || seen.has(id)) throw new Error('NVD returned an invalid or duplicate CVE');
        seen.add(id);
        if (item.cve?.vulnStatus === 'Rejected') {
          const cveId = normalizeCveId(item.cve.id);
          if (cveId) withdrawals.push({ cveId, modifiedDate: iso(item.cve.lastModified) });
          continue;
        }
        const cve = normalizeNvd(item, feed.id);
        if (cve) cves.push(cve);
      }
      rawCount += page.vulnerabilities.length;
      offset += page.vulnerabilities.length;
      await onNvdProgress?.({ offset, total: page.totalResults, records: rawCount });
      if (offset >= page.totalResults) break;
      if (!page.vulnerabilities.length) throw new Error('NVD pagination stopped before completion');
      await sleep(nvdInterval);
    }
    return { cves, count: rawCount, withdrawals };
  }
  if (feed.type === 'CISA_KEV') {
    const { data: rawData, etag } = await json(feed.url);
    if (rawData === undefined) return { cves: [], count: 0, notModified: true, etag };
    const data = z
      .object({
        count: z.number().int().min(0).max(50000).optional(),
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
    if (
      (data.count !== undefined && data.count !== data.vulnerabilities.length) ||
      new Set(data.vulnerabilities.map((v) => v.cveID)).size !== data.vulnerabilities.length
    )
      throw new Error('KEV catalog count mismatch or duplicate CVE');
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
    const scope = [...new Set(targetCveIds.map(normalizeCveId).filter((id): id is string => !!id))].sort();
    const batches: string[][] = [];
    for (const id of scope) {
      if (id.length > 1900) throw new Error('CVE identifier exceeds EPSS request limit');
      const batch = batches[batches.length - 1];
      if (!batch || batch.length >= 100 || [...batch, id].join(',').length > 1900) batches.push([id]);
      else batch.push(id);
    }
    let count = 0,
      requests = 0;
    for (const batch of batches) {
      const seen = new Set<string>();
      let expectedTotal: number | undefined;
      for (let offset = 0; ;) {
        if (requests++) await sleep(60000 / feed.rateLimitPerMin);
        const url = new URL(feed.url);
        // Do not inherit date/score filters: they could hide a requested score.
        url.search = '';
        url.searchParams.set('cve', batch.join(','));
        url.searchParams.set('offset', String(offset));
        url.searchParams.set('limit', '100');
        const { data: page } = await json(url.href, false);
        if (page === undefined) throw new Error('EPSS returned an incomplete conditional response');
        const rows = z
          .array(
            z.object({
              cve: z
                .string()
                .transform((id) => normalizeCveId(id))
                .refine((id) => !!id),
              epss: z.coerce.number().min(0).max(1),
              percentile: z.coerce.number().min(0).max(1),
            }),
          )
          .max(100)
          .parse(page.data);
        const total = Number(page.total);
        if (
          !Number.isInteger(total) ||
          total < 0 ||
          total > batch.length ||
          (expectedTotal !== undefined && total !== expectedTotal) ||
          (page.offset !== undefined && Number(page.offset) !== offset)
        )
          throw new Error('Invalid EPSS pagination response');
        expectedTotal = total;
        for (const row of rows) {
          if (!batch.includes(row.cve!) || seen.has(row.cve!))
            throw new Error('EPSS returned an unexpected or duplicate CVE');
          seen.add(row.cve!);
          epss[row.cve!] = { score: row.epss, percentile: row.percentile };
        }
        count += rows.length;
        offset += rows.length;
        if (offset > total) throw new Error('EPSS response exceeds declared total');
        if (offset === total) break;
        if (!rows.length) throw new Error('EPSS pagination stopped before completion');
      }
    }
    return { cves: [], epss, epssScope: scope, count };
  }
  if (feed.type === 'OPENCVE_API') {
    if (feed.authType !== 'BEARER') throw new Error('OpenCVE API v2 requires an organization Bearer token');
    const end = new Date();
    const start = new Date(end.getTime() - Math.min(scopeHours, 2880) * 3600000);
    const base = new URL(feed.url);
    const listUrl = new URL(base);
    listUrl.search = '';
    const listPath = listUrl.pathname.replace(/\/$/, '');
    if (!listPath.endsWith('/cves')) throw new Error('OpenCVE endpoint must end in /api/v2/cves');
    const records = new Map<string, any>();
    let next: string | null = listUrl.href;
    const visited = new Set<string>();
    for (let pageNo = 0; next; pageNo++) {
      if (pageNo >= 100) throw new Error('OpenCVE query exceeds 10,000 records; reduce ingestion window');
      const pageUrl = new URL(next);
      if (pageUrl.origin !== listUrl.origin || pageUrl.pathname !== listUrl.pathname || visited.has(pageUrl.href))
        throw new Error('OpenCVE returned an invalid pagination URL');
      visited.add(pageUrl.href);
      pageUrl.searchParams.set('page_size', '100');
      pageUrl.searchParams.set('q', `updated>=${start.toISOString().slice(0, 10)} AND updated<=${end.toISOString().slice(0, 10)}`);
      const { data: page } = await json(pageUrl.href, false, { timeoutMs: 25000, maxResponseBytes: 4 * 1024 * 1024 }, true);
      if (!page || !Array.isArray(page.results) || !Number.isInteger(page.count) || page.count < page.results.length)
        throw new Error('Invalid OpenCVE pagination response');
      for (const row of page.results) {
        const id = normalizeCveId(row?.cve_id);
        if (!id || typeof row.updated_at !== 'string' || !Number.isFinite(Date.parse(row.updated_at)))
          throw new Error('OpenCVE returned a malformed CVE record');
        const updated = Date.parse(row.updated_at);
        if (updated >= start.getTime() && updated <= end.getTime()) {
          const previous = records.get(id);
          if (!previous || updated > Date.parse(previous.updated_at)) records.set(id, row);
        }
      }
      next = typeof page.next === 'string' && page.next ? page.next : null;
      if (records.size > 500) throw new Error('OpenCVE window exceeds 500 CVEs; reduce ingestion window');
      if (next) await sleep(Math.max(1000, 60000 / feed.rateLimitPerMin));
    }
    const cves: NormalizedCVE[] = [];
    let requests = 0;
    for (const [id] of records) {
      if (requests++) await sleep(Math.max(1000, 60000 / feed.rateLimitPerMin));
      const detailUrl = new URL(`${listPath}/${encodeURIComponent(id)}`, listUrl.origin);
      detailUrl.searchParams.set('include', 'nvd_cpe_configurations');
      const { data } = await json(detailUrl.href, false, { timeoutMs: 25000, maxResponseBytes: 4 * 1024 * 1024 }, true);
      if (!data || normalizeCveId(data.cve_id) !== id) throw new Error('OpenCVE detail response did not match requested CVE');
      const cve = normalizeOpenCve(data, feed.id);
      if (Date.parse(cve.modifiedDate) >= start.getTime() && Date.parse(cve.modifiedDate) <= end.getTime()) cves.push(cve);
    }
    return { cves, count: cves.length };
  }
  if (feed.type === 'VULNCHECK_KEV') {
    if (feed.authType !== 'BEARER') throw new Error('VulnCheck KEV requires a Bearer API token');
    const url = new URL(feed.url);
    if (!url.pathname.replace(/\/$/, '').endsWith('/v3/index/vulncheck-kev'))
      throw new Error('VulnCheck endpoint must target /v3/index/vulncheck-kev');
    const exploited: Record<string, true> = {};
    const seenRecords = new Set<string>();
    let cursor: string | undefined;
    let count = 0;
    for (let pageNo = 0; pageNo < 100; pageNo++) {
      const pageUrl = new URL(url);
      pageUrl.searchParams.set('limit', '300');
      if (cursor) pageUrl.searchParams.set('cursor', cursor);
      else pageUrl.searchParams.set('start_cursor', '');
      const { data: page } = await json(pageUrl.href, false, { timeoutMs: 30000, maxResponseBytes: 8 * 1024 * 1024 }, true);
      if (!page || !Array.isArray(page.data)) throw new Error('Invalid VulnCheck KEV response');
      for (const row of page.data) {
        const record = row?.source || row;
        if (!Array.isArray(record?.cve)) throw new Error('VulnCheck KEV record has no CVE identifiers');
        for (const rawId of record.cve) {
          const id = normalizeCveId(rawId);
          if (!id) throw new Error('VulnCheck KEV returned an invalid CVE identifier');
          exploited[id] = true;
        }
        const key = String(row?.id || record?.date_added || JSON.stringify(record.cve));
        if (seenRecords.has(key)) throw new Error('VulnCheck KEV returned a duplicate record');
        seenRecords.add(key);
        count++;
      }
      const nextCursor = page._meta?.next_cursor;
      if (typeof nextCursor !== 'string' || !nextCursor) break;
      if (nextCursor === cursor) throw new Error('VulnCheck KEV cursor did not advance');
      cursor = nextCursor;
      if (pageNo === 99) throw new Error('VulnCheck KEV pagination exceeded 30,000 records');
      await sleep(Math.max(1000, 60000 / feed.rateLimitPerMin));
    }
    return { cves: [], exploited, count };
  }
  if (feed.type === 'JSON_SEARCH_API') {
    const { data, etag } = await json(feed.url);
    if (data === undefined) return { cves: [], count: 0, notModified: true, etag };
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
