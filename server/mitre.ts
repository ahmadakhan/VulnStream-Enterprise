import type { NormalizedCVE, ThreatFeed } from '../src/types';
import type { Requester } from './network';
import type { IngestResult } from './ingestion';
import { cveSchema } from './validation';
import { normalizeCveId } from '../src/utils/deduplicator';
import { parseCPE23 } from '../src/utils/cpeMatcher';
import { z } from 'zod';
import { ingestionWindow, recentRevisions, type IngestionState } from './ingestionState';

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

export async function ingestMitre(feed: ThreatFeed, scopeHours: number, request: Requester, sleep: (ms: number) => Promise<unknown>, state: IngestionState = {}): Promise<IngestResult> {
  if (feed.url !== MITRE_DELTA_URL || feed.authType !== 'NONE') throw new Error('MITRE CVE requires the official cvelistV5 deltaLog.json endpoint without authentication');
  const index = await request(feed.url, { timeoutMs: 60000, maxResponseBytes: 64 * 1024 * 1024,
    headers: state.indexEtag ? { 'If-None-Match': state.indexEtag } : {} });
  if (index.status === 304 && state.indexEtag) return { cves: [], count: 0, notModified: true, syncState: state };
  if (index.status !== 200) throw new Error(`MITRE CVE returned HTTP ${index.status}`);
  const parse = (body: string) => { try { return JSON.parse(body); } catch { throw new Error('MITRE CVE returned invalid JSON'); } };
  const { start, end } = ingestionWindow(scopeHours, state);
  const changes = z.array(z.object({
    fetchTime: z.string(),
    new: z.array(z.object({ cveId: z.string(), dateUpdated: z.string() })),
    updated: z.array(z.object({ cveId: z.string(), dateUpdated: z.string() })),
    error: z.array(z.unknown()).optional(),
  })).min(1).max(20000).parse(parse(index.body));
  const revisions = recentRevisions(state.revisions || {}, start);
  const ids = new Set<string>();
  const warnings: string[] = [];
  if (scopeHours > 720 && !state.cursor) warnings.push('MITRE incremental history is limited to 30 days; older CVEs require a historical import');
  const fetchTimes = changes.map(entry => Date.parse(timestamp(entry.fetchTime)));
  const newestFetch = Math.max(...fetchTimes), oldestFetch = Math.min(...fetchTimes);
  if (state.cursor && Date.parse(state.cursor) < oldestFetch - 3600000)
    throw new Error('MITRE checkpoint predates available delta history; historical recovery is required');
  for (const entry of changes) {
    const fetched = Date.parse(timestamp(entry.fetchTime));
    if (fetched >= start.getTime() && fetched <= end.getTime() && entry.error?.length) throw new Error('MITRE delta log reports upstream record errors; retry later');
    for (const row of [...entry.new, ...entry.updated]) {
      const updated = Date.parse(timestamp(row.dateUpdated));
      const id = normalizeCveId(row.cveId);
      if (!id) throw new Error('MITRE delta log contains an invalid CVE identifier');
      if (updated >= start.getTime() && updated <= end.getTime() && !(Date.parse(revisions[id] || '') >= updated)) ids.add(id);
    }
  }
  if (ids.size > 5000) throw new Error('MITRE window exceeds 5,000 unique CVEs; reduce ingestion scope');
  const cves: NormalizedCVE[] = [], withdrawals: NonNullable<IngestResult['withdrawals']> = [];
  const sorted = [...ids].sort();
  let next = 0, gate = Promise.resolve(), first = true, stopped = false;
  // Overlap network latency while spacing ALL starts, including across workers.
  const pace = () => {
    const ready = gate.then(async () => { if (!first) await sleep(60000 / feed.rateLimitPerMin); first = false; });
    gate = ready.catch(() => {});
    return ready;
  };
  const worker = async () => {
    while (next < sorted.length && !stopped) {
      const id = sorted[next++];
      await pace();
      if (stopped) return;
      const [, year, sequence] = id.split('-');
      const bucket = `${sequence.slice(0, -3)}xxx`;
      // Never follow URLs supplied inside feed content.
      const url = `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/${year}/${bucket}/${id}.json`;
      const response = await request(url, { timeoutMs: 60000, maxResponseBytes: 4 * 1024 * 1024 });
      if (response.status !== 200) throw new Error(`MITRE CVE returned HTTP ${response.status}`);
      const record = parse(response.body);
      if (normalizeCveId(record?.cveMetadata?.cveId) !== id) throw new Error('MITRE response did not match requested CVE');
      const cve = normalizeMitre(record, feed.id);
      const modified = timestamp(record.cveMetadata.dateUpdated || record.cveMetadata.datePublished);
      if (cve) cves.push(cve);
      else withdrawals.push({ cveId: id, modifiedDate: modified });
      revisions[id] = modified;
    }
  };
  const workers = await Promise.allSettled(Array.from({ length: Math.min(3, sorted.length) }, async () => {
    try { await worker(); } catch (error) { stopped = true; throw error; }
  }));
  const failed = workers.find(result => result.status === 'rejected');
  if (failed?.status === 'rejected') throw failed.reason;
  // Do not advance beyond the latest published index, or install its validator
  // until this run has fully consumed it (important during multi-day catch-up).
  const cursor = new Date(Math.max(Date.parse(state.cursor || '') || 0, Math.min(end.getTime(), newestFetch))).toISOString();
  return { cves: cves.sort((a, b) => a.cveId.localeCompare(b.cveId)), withdrawals, count: sorted.length, warnings,
    syncState: { cursor, hasMore: end.getTime() < newestFetch, revisions, indexEtag: end.getTime() >= newestFetch && typeof index.headers.etag === 'string' ? index.headers.etag : undefined } };
}
