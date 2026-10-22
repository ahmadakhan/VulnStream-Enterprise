import type { NormalizedCVE, ThreatFeed } from '../src/types';
import type { Requester } from './network';
import { getIngestionWindowStart, type IngestContext, type IngestResult } from './ingestion';
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

export async function ingestMitre(
  feed: ThreatFeed,
  scopeHours: number,
  request: Requester,
  sleep: (ms: number) => Promise<unknown>,
  context: IngestContext = {},
): Promise<IngestResult> {
  if (feed.url !== MITRE_DELTA_URL || feed.authType !== 'NONE') throw new Error('MITRE CVE requires the official cvelistV5 deltaLog.json endpoint without authentication');
  const readJson = async (url: string, maxResponseBytes: number) => {
    const response = await request(url, { timeoutMs: 60000, maxResponseBytes });
    if (response.status !== 200) throw new Error(`MITRE CVE returned HTTP ${response.status}`);
    try { return JSON.parse(response.body); } catch { throw new Error('MITRE CVE returned invalid JSON'); }
  };
  // The upstream rolling delta log covers at most 30 days; it is not a full historical dump.
  const end = new Date();
  const start = getIngestionWindowStart(end, scopeHours, context.checkpoint, 720);
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
    if (fetched >= start.getTime() && fetched <= end.getTime() && entry.error?.length) throw new Error('MITRE delta log reports upstream record errors; retry later');
    for (const row of [...entry.new, ...entry.updated]) {
      const updated = Date.parse(timestamp(row.dateUpdated));
      const id = normalizeCveId(row.cveId);
      if (!id) throw new Error('MITRE delta log contains an invalid CVE identifier');
      if (updated >= start.getTime() && updated <= end.getTime()) {
        const knownTimes = [context.knownCveModifiedAt?.get(id), context.knownWithdrawalAt?.get(id)]
          .map((value) => Date.parse(value || ''))
          .filter(Number.isFinite);
        const known = knownTimes.length ? Math.max(...knownTimes) : NaN;
        if (!Number.isFinite(known) || updated > known) ids.add(id);
      }
    }
  }
  if (ids.size > 5000) throw new Error('MITRE window exceeds 5,000 unique CVEs; reduce ingestion scope');
  const cves: NormalizedCVE[] = [], withdrawals: NonNullable<IngestResult['withdrawals']> = [];
  const sortedIds = [...ids].sort();
  const records = new Array<NormalizedCVE | null>(sortedIds.length);
  const rejected: NonNullable<IngestResult['withdrawals']> = [];
  let nextIndex = 0;
  let nextRequestAt = Date.now();
  const concurrency = Math.min(4, sortedIds.length);
  const interval = 60000 / feed.rateLimitPerMin;
  const worker = async () => {
    while (true) {
      const index = nextIndex++;
      if (index >= sortedIds.length) return;
      const wait = Math.max(0, nextRequestAt - Date.now());
      nextRequestAt = Math.max(Date.now(), nextRequestAt) + interval;
      if (wait) await sleep(wait);
      const id = sortedIds[index];
      const [, year, sequence] = id.split('-');
      // Construct paths from validated IDs; never follow URLs supplied inside feed content.
      const bucket = `${sequence.slice(0, -3)}xxx`;
      const url = `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/${year}/${bucket}/${id}.json`;
      const record = await readJson(url, 4 * 1024 * 1024);
      if (normalizeCveId(record?.cveMetadata?.cveId) !== id)
        throw new Error('MITRE response did not match requested CVE');
      const cve = normalizeMitre(record, feed.id);
      records[index] = cve;
      if (!cve) rejected.push({ cveId: id, modifiedDate: timestamp(record.cveMetadata.dateUpdated) });
    }
  };
  const settled = await Promise.allSettled(Array.from({ length: concurrency }, worker));
  const failed = settled.find((result) => result.status === 'rejected');
  if (failed?.status === 'rejected') throw failed.reason;
  for (const record of records) if (record) cves.push(record);
  withdrawals.push(...rejected);
  const checkpointCovered = !context.checkpoint || end.getTime() - Date.parse(context.checkpoint) <= 30 * 24 * 3600000;
  if (!checkpointCovered)
    warnings.push('Saved MITRE checkpoint is older than the rolling 30-day delta log; a source re-baseline is required and the checkpoint was not advanced');
  return { cves, withdrawals, count: sortedIds.length, warnings, ...(checkpointCovered ? { sourceCheckpoint: end.toISOString() } : {}) };
}
