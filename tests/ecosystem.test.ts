import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ingestFeed, normalizeNvd } from '../server/ingestion';
import { loadConfig } from '../server/config';
import { mergeCveRecords } from '../src/utils/deduplicator';
import { matchesWatchlistItem } from '../src/utils/cpeMatcher';
import { runVulnerabilityPipeline } from '../src/engine/pipelineEngine';
import { DEFAULT_SETTINGS } from '../shared/state';
import { cveSchema } from '../server/validation';
import type { NormalizedCVE, ThreatFeed, WatchListItem } from '../src/types';

const config = loadConfig({
  NODE_ENV: 'test',
  DATABASE_URL: 'postgres://unused',
  APP_ORIGIN: 'http://localhost',
  ENCRYPTION_KEY: Buffer.alloc(32, 1).toString('base64'),
});
const cpe = (version: string) => `cpe:2.3:a:example:widget:${version}:*:*:*:*:*:*:*`;
const feed = (type: ThreatFeed['type']): ThreatFeed => ({
  id: 'test-feed',
  name: 'Test source',
  type,
  url: 'https://example.com/data?date=2020-01-01',
  authType: 'NONE',
  rateLimitPerMin: 10,
  enabled: true,
  healthStatus: 'UNTESTED',
  lastSync: null,
  latencyMs: 0,
  itemCountLastRun: 0,
  ssrfValidated: false,
  vendorSeed: false,
});
const nvd = (status = 'Analyzed') => ({
  cve: {
    id: 'CVE-2026-12345',
    vulnStatus: status,
    published: '2026-01-01T00:00:00Z',
    lastModified: '2026-10-20T00:00:00Z',
    descriptions: [{ lang: 'en', value: 'Example widget issue' }],
    configurations: [{ nodes: [{ operator: 'OR', cpeMatch: [{ vulnerable: true, criteria: cpe('1.0') }] }] }],
  },
});
const cve = () => normalizeNvd(nvd(), 'source-a')!;
test('normalized feed remediation links reject executable URL schemes', () => {
  const record = cve();
  assert.throws(() =>
    cveSchema.parse({
      ...record,
      remediation: { ...record.remediation, vendorAdvisoryRef: 'javascript:alert(1)' },
    }),
  );
  assert.equal(
    cveSchema.parse({
      ...record,
      remediation: { ...record.remediation, patchUrl: 'https://example.com/patch' },
    }).remediation.patchUrl,
    'https://example.com/patch',
  );
});
const asset: WatchListItem = {
  id: 'asset',
  vendor: 'example',
  product: 'widget',
  cpes: [cpe('1.0')],
  assetTag: 'TEST',
  ownerGroup: 'test',
  active: true,
  createdAt: '2026-01-01T00:00:00Z',
};

test('unknown constrained inventory fields require review; later confirmed evidence wins', () => {
  for (const criteria of [cpe('1.0'), cpe('*').replace(':*:*:*:*:*:*:*', ':*:*:*:*:windows:*:*')]) {
    const finding = runVulnerabilityPipeline(
      [],
      [{ ...cve(), cpeMatches: [criteria], cpeMatchDetails: undefined }],
      [{ ...asset, cpes: [cpe('*')] }],
      [],
      [],
      { ...DEFAULT_SETTINGS, scopeHours: 0 },
    ).newFindings[0];
    assert.equal(finding?.notificationStatus, 'REVIEW_REQUIRED');
  }
  const direct = matchesWatchlistItem([cpe('*'), cpe('1.0')], 'example', 'widget', [cpe('1.0')], '', '');
  assert.equal(direct.confidence, 90);
  assert.equal(direct.applicabilityRequiresReview, false);
  const record = {
    ...cve(),
    cpeMatchDetails: [
      { criteria: cpe('*').replace(':*:*:*:*:*:*:*', ':*:*:*:*:windows:*:*') },
      { criteria: cpe('1.0') },
    ],
  };
  const finding = runVulnerabilityPipeline([], [record], [asset], [], [], {
    ...DEFAULT_SETTINGS,
    scopeHours: 0,
  }).newFindings[0];
  assert.equal(finding.notificationStatus, 'QUEUED_FOR_DISPATCH');
});

test('equal-revision conflicts merge deterministically and cannot auto-dispatch', () => {
  const first = cve(),
    second: NormalizedCVE = {
      ...cve(),
      title: 'Other revision',
      sourceFeeds: ['source-b'],
      cpeMatches: [cpe('2.0')],
      cpeMatchDetails: [{ criteria: cpe('2.0') }],
    };
  const a = [...mergeCveRecords([first, second]).values()];
  const b = [...mergeCveRecords([second, first]).values()];
  assert.deepEqual(a, b);
  assert.equal(a[0].applicabilityRequiresReview, true);
  assert.deepEqual(a[0].sourceFeeds, ['source-a', 'source-b']);
  assert.equal(mergeCveRecords([{ ...first, cveId: ' cve-2026-12345 ' }, first]).size, 1);
});

test('NVD retains provisional analysis as review-only and reports withdrawals', async () => {
  assert.equal(normalizeNvd(nvd('Awaiting Analysis'), 'nvd')?.applicabilityRequiresReview, true);
  const result = await ingestFeed(
    feed('NVD_API'),
    24,
    async () => ({
      status: 200,
      headers: {},
      body: JSON.stringify({ startIndex: 0, totalResults: 1, vulnerabilities: [nvd('Rejected')] }),
    }),
    config,
  );
  assert.equal(result.cves.length, 0);
  assert.deepEqual(result.withdrawals, [
    { cveId: 'CVE-2026-12345', modifiedDate: '2026-10-20T00:00:00.000Z' },
  ]);
});

test('EPSS fetches only requested inventory CVEs in bounded batches', async () => {
  const ids = Array.from({ length: 205 }, (_, index) => `CVE-2026-${10000 + index}`);
  let calls = 0;
  const result = await ingestFeed(
    feed('EPSS_API'),
    24,
    async (value, options) => {
      calls++;
      const url = new URL(value),
        requested = url.searchParams.get('cve')!.split(',');
      assert.ok(url.searchParams.get('cve')!.length <= 2000);
      assert.ok(requested.length <= 100);
      assert.equal(url.searchParams.has('date'), false);
      assert.equal(options?.headers?.['If-None-Match'], undefined);
      return {
        status: 200,
        headers: {},
        body: JSON.stringify({
          total: requested.length,
          offset: 0,
          data: requested.map((id) => ({ cve: id, epss: '0.7', percentile: '0.9' })),
        }),
      };
    },
    config,
    async () => {},
    ids,
  );
  assert.equal(calls, 3);
  assert.equal(result.count, 205);
  assert.deepEqual(result.epssScope, ids);
  await ingestFeed(
    feed('EPSS_API'),
    24,
    async () => {
      throw new Error('Empty scope must not request the full corpus');
    },
    config,
  );
});

test('EPSS rejects unexpected records instead of declaring a partial snapshot complete', async () => {
  await assert.rejects(
    ingestFeed(
      feed('EPSS_API'),
      24,
      async () => ({
        status: 200,
        headers: {},
        body: JSON.stringify({ total: 1, data: [{ cve: 'CVE-2026-99999', epss: 0.1, percentile: 0.2 }] }),
      }),
      config,
      async () => {},
      ['CVE-2026-12345'],
    ),
    /unexpected/,
  );
});

test('long NVD Retry-After defers instead of retrying before the allowed time', async () => {
  let calls = 0;
  await assert.rejects(
    ingestFeed(
      feed('NVD_API'),
      24,
      async () => {
        calls++;
        return { status: 429, headers: { 'retry-after': '120' }, body: '' };
      },
      config,
      async () => {
        throw new Error('Must defer');
      },
    ),
    /120 second retry delay/,
  );
  assert.equal(calls, 1);
});
