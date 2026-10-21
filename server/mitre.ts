import type { NormalizedCVE, ThreatFeed } from '../src/types';
import type { Requester } from './network';
import type { IngestResult } from './ingestion';
import { cveSchema } from './validation';
import { normalizeCveId } from '../src/utils/deduplicator';
import { parseCPE23 } from '../src/utils/cpeMatcher';
import { z } from 'zod';

export const MITRE_DELTA_URL = 'https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json';
const timestamp = (value: unknown): string => {
  if (typeof value !== 'string' || !Number.isFinite(Date.parse(value))) throw new Error('Invalid CVE record date');
  return new Date(value).toISOString();
};

/** CVE JSON version rules can include exclusions and custom version schemes.
 * Retain CNA product criteria as review candidates, never assert automatic applicability. */
export function normalizeMitre(record: any, feedId: string): NormalizedCVE | null {
  if (record?.dataType !== 'CVE_RECORD' || !/^5\./.test(record.dataVersion || '')) throw new Error('Expected a CVE JSON 5 record');
  const meta = record.cveMetadata;
  const id = normalizeCveId(meta?.cveId);
  if (!id) throw new Error('Invalid MITRE CVE identifier');
  if (meta.state === 'REJECTED') return null;
  if (meta.state !== 'PUBLISHED' || !record.containers?.cna) throw new Error('Expected a published CVE record');
  const cna = record.containers.cna;
  const containers = [cna, ...(record.containers.adp || [])];
  const metrics = containers.flatMap(c => c.metrics || []);
  const metric = metrics.map(m => m.cvssV4_0).find(Boolean) || metrics.map(m => m.cvssV3_1 || m.cvssV3_0).find(Boolean) || metrics.map(m => m.cvssV2_0).find(Boolean);
  const score = metric?.baseScore ?? 0;
  const descriptions = cna.descriptions || [];
  const description = descriptions.find((d: any) => /^en(?:-|$)/i.test(d.lang))?.value || descriptions[0]?.value || cna.title || id;
  const affected = containers.flatMap(c => c.affected || []);
  const cpes = [...new Set<string>(affected.flatMap(a => (a.cpes || []).filter((c: unknown) => typeof c === 'string' && parseCPE23(c).isValid)))];
  // Include explicit CNA product names for review-only text matching when CPEs are absent.
  const productNames = affected.map(a => [a.vendor, a.product].filter((v: unknown) => typeof v === 'string').join(' ')).filter(Boolean).join('; ');
  const references = containers.flatMap(c => c.references || []);
  const reference = references.find(r => typeof r.url === 'string' && /^https:\/\//.test(r.url));
  return cveSchema.parse({
    cveId: id, title: String(cna.title || description).slice(0, 500),
    description: `${description}${productNames ? `\nCNA affected products: ${productNames}` : ''}`.slice(0, 30000),
    publishedDate: timestamp(meta.datePublished), modifiedDate: timestamp(meta.dateUpdated || meta.datePublished),
    cvss: { version: !metric ? 'UNKNOWN' : metric.version === '4.0' ? '4.0' : metric.version === '2.0' ? '2.0' : '3.1',
      score, vector: metric?.vectorString || '', severity: !metric ? 'UNKNOWN' : score >= 9 ? 'CRITICAL' : score >= 7 ? 'HIGH' : score >= 4 ? 'MEDIUM' : 'LOW' },
    cwe: [...new Set(containers.flatMap(c => (c.problemTypes || []).flatMap((p: any) => (p.descriptions || []).map((d: any) => d.cweId).filter((id: unknown) => typeof id === 'string'))))].slice(0, 100),
    cpeMatches: cpes, applicabilityRequiresReview: true, sourceFeeds: [feedId],
    epss: { score: 0, percentile: 0 }, cisaKev: { isKev: false }, exploitStatus: 'None',
    remediation: { patchUrl: '', vendorAdvisoryRef: reference?.url || '', immediateActions: [], workarounds: [], rollbackPlan: '', stepByStep: [] },
  });
}

export async function ingestMitre(feed: ThreatFeed, scopeHours: number, request: Requester, sleep: (ms: number) => Promise<unknown>): Promise<IngestResult> {
  if (feed.url !== MITRE_DELTA_URL || feed.authType !== 'NONE') throw new Error('MITRE CVE requires the official cvelistV5 deltaLog.json endpoint without authentication');
  const readJson = async (url: string, maxResponseBytes: number) => {
    const response = await request(url, { timeoutMs: 60000, maxResponseBytes });
    if (response.status !== 200) throw new Error(`MITRE CVE returned HTTP ${response.status}`);
    try { return JSON.parse(response.body); } catch { throw new Error('MITRE CVE returned invalid JSON'); }
  };
  // The upstream rolling delta log covers at most 30 days; it is not a full historical dump.
  const end = Date.now(), start = end - Math.min(scopeHours, 720) * 3600000;
  const changes = z.array(z.object({
    fetchTime: z.string(),
    new: z.array(z.object({ cveId: z.string(), dateUpdated: z.string() })),
    updated: z.array(z.object({ cveId: z.string(), dateUpdated: z.string() })),
    error: z.array(z.unknown()).optional(),
  })).min(1).max(20000).parse(await readJson(feed.url, 64 * 1024 * 1024));
  const ids = new Set<string>();
  const warnings: string[] = [];
  if (scopeHours > 720) warnings.push('MITRE incremental history is limited to 30 days; older CVEs require a historical import');
  for (const entry of changes) {
    const fetched = Date.parse(timestamp(entry.fetchTime));
    if (fetched >= start && fetched <= end && entry.error?.length) throw new Error('MITRE delta log reports upstream record errors; retry later');
    for (const row of [...entry.new, ...entry.updated]) {
      const updated = Date.parse(timestamp(row.dateUpdated));
      const id = normalizeCveId(row.cveId);
      if (!id) throw new Error('MITRE delta log contains an invalid CVE identifier');
      if (updated >= start && updated <= end) ids.add(id);
    }
  }
  if (ids.size > 5000) throw new Error('MITRE window exceeds 5,000 unique CVEs; reduce ingestion scope');
  const cves: NormalizedCVE[] = [], withdrawals: NonNullable<IngestResult['withdrawals']> = [];
  let count = 0;
  for (const id of [...ids].sort()) {
    if (count) await sleep(60000 / feed.rateLimitPerMin);
    const [, year, sequence] = id.split('-');
    // Construct paths from validated IDs; never follow URLs supplied inside feed content.
    const bucket = `${sequence.slice(0, -3)}xxx`;
    const url = `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/${year}/${bucket}/${id}.json`;
    const record = await readJson(url, 4 * 1024 * 1024);
    if (normalizeCveId(record?.cveMetadata?.cveId) !== id) throw new Error('MITRE response did not match requested CVE');
    const cve = normalizeMitre(record, feed.id);
    if (cve) cves.push(cve);
    else withdrawals.push({ cveId: id, modifiedDate: timestamp(record.cveMetadata.dateUpdated) });
    count++;
  }
  return { cves, withdrawals, count, warnings };
}
