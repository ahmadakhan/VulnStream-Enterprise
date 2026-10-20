import type { ThreatFeed, NormalizedCVE } from '../src/types';
import type { Requester } from './network';
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
  // Missing risk information is not replaced with an invented score.
  if (!metric) return null;
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
  const score = metric.baseScore;
  return cveSchema.parse({
    cveId: cve.id,
    title: description.slice(0, 500),
    description,
    publishedDate: iso(cve.published),
    modifiedDate: iso(cve.lastModified),
    cvss: {
      version: metric.version === '4.0' ? '4.0' : metric.version === '2.0' ? '2.0' : '3.1',
      score,
      vector: metric.vectorString || '',
      severity: score >= 9 ? 'CRITICAL' : score >= 7 ? 'HIGH' : score >= 4 ? 'MEDIUM' : 'LOW',
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
  const json = async (url: string) => {
    const response = await request(url, { headers });
    if (response.status !== 200) throw new Error(`Feed returned HTTP ${response.status}`);
    try {
      return JSON.parse(response.body);
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
      const page = await json(url.href);
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
      .parse(await json(feed.url));
    return {
      cves: [],
      count: data.vulnerabilities.length,
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
      const page = await json(url.href);
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
    const cves = z
      .array(cveSchema)
      .max(10000)
      .parse(await json(feed.url));
    // Generic feeds may assert VEX, but unsigned claims cannot suppress alerts.
    return { cves: cves.map((c) => ({ ...c, vex: undefined, sourceFeeds: [feed.id] })), count: cves.length };
  }
  throw new Error(`Unsupported feed adapter: ${feed.type}`);
}
