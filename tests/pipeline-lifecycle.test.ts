import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID, randomBytes } from 'node:crypto';
import { createPool, migrate, transaction, put, list, get } from '../server/db';
import { queueRun, processPipeline } from '../server/pipeline';
import { deliverNext } from '../server/delivery';
import { loadConfig } from '../server/config';
import { DEFAULT_SETTINGS } from '../shared/state';
import type { Finding, NormalizedCVE, WatchListItem } from '../src/types';
const database = process.env.TEST_DATABASE_URL;
const cpe = (version: string) => `cpe:2.3:a:example:widget:${version}:*:*:*:*:*:*:*`;
const asset = (version = '1.5'): WatchListItem => ({
  id: 'asset',
  vendor: 'example',
  product: 'widget',
  cpes: [cpe(version)],
  assetTag: 'TEST',
  ownerGroup: 'test',
  active: true,
  createdAt: new Date().toISOString(),
});
const vulnerability = (): NormalizedCVE => ({
  cveId: 'CVE-2026-98001',
  title: 'Lifecycle fixture',
  description: 'Test only',
  publishedDate: new Date().toISOString(),
  modifiedDate: new Date().toISOString(),
  cvss: { version: '3.1', score: 8, vector: '', severity: 'HIGH' },
  cwe: [],
  cpeMatches: [cpe('*')],
  versionRange: { versionEndExcluding: '2.0' },
  sourceFeeds: [],
  epss: { score: 0, percentile: 0 },
  cisaKev: { isKev: false },
  exploitStatus: 'None',
  remediation: {
    patchUrl: '',
    vendorAdvisoryRef: '',
    immediateActions: [],
    workarounds: [],
    rollbackPlan: '',
    stepByStep: [],
  },
});
test('pipeline reconciles inventory and protects queued deliveries', { skip: !database }, async (t) => {
  const base = createPool(database!),
    schema = 'lifecycle_' + randomUUID().replaceAll('-', '');
  await base.query(`CREATE SCHEMA ${schema}`);
  const url = new URL(database!);
  url.searchParams.set('options', `-c search_path=${schema}`);
  const pool = createPool(url.href),
    config = loadConfig({
      NODE_ENV: 'test',
      DATABASE_URL: url.href,
      APP_ORIGIN: 'http://localhost',
      ENCRYPTION_KEY: randomBytes(32).toString('base64'),
    });
  const request = async () => {
    throw new Error('No network expected');
  };
  const run = async () => {
    await queueRun(pool, 24, 'test');
    await processPipeline(pool, config, request);
  };
  const save = (kind: string, id: string, value: unknown) =>
    transaction(pool, (db) => put(db, kind, id, value));
  const reset = async () => {
    await pool.query('DELETE FROM records; DELETE FROM outbox');
    await save('settings', 'main', { ...DEFAULT_SETTINGS, autoDispatchEnabled: false });
  };
  try {
    await migrate(pool);
    await t.test('new inventory is matched against older cached CVEs', async () => {
      await reset();
      const cve = vulnerability();
      cve.publishedDate = cve.modifiedDate = '2020-01-01T00:00:00Z';
      await save('cveData', cve.cveId, cve);
      await save('watchlist', 'asset', asset());
      await run();
      assert.equal((await list(pool, 'findings')).length, 1);
    });
    await t.test('review findings promote after inventory correction and retain stable IDs', async () => {
      await reset();
      const cve = vulnerability();
      await save('cveData', cve.cveId, cve);
      await save('watchlist', 'asset', asset('*'));
      await run();
      const first = (await list<Finding>(pool, 'findings'))[0];
      assert.equal(first.notificationStatus, 'REVIEW_REQUIRED');
      await save('watchlist', 'asset', asset());
      await run();
      const next = (await list<Finding>(pool, 'findings'))[0];
      assert.equal(next.id, first.id);
      assert.equal(next.notificationStatus, 'QUEUED_FOR_DISPATCH');
      await save('findings', next.id, { ...next, status: 'FALSE_POSITIVE' });
      await run();
      assert.equal((await list(pool, 'findings')).length, 1);
      assert.equal((await get<Finding>(pool, 'findings', next.id))?.status, 'FALSE_POSITIVE');
    });
    await t.test('patched or removed inventory cannot retain pending applicability', async () => {
      await reset();
      const cve = vulnerability();
      await save('cveData', cve.cveId, cve);
      await save('watchlist', 'asset', asset());
      await run();
      await save('watchlist', 'asset', asset('2.0'));
      await run();
      assert.equal((await list<Finding>(pool, 'findings'))[0].notificationStatus, 'NOT_APPLICABLE');
      await save('watchlist', 'asset', asset());
      await run();
      assert.equal((await list<Finding>(pool, 'findings'))[0].notificationStatus, 'QUEUED_FOR_DISPATCH');
      await pool.query("DELETE FROM records WHERE kind='watchlist'");
      await run();
      assert.equal((await list<Finding>(pool, 'findings'))[0].notificationStatus, 'NOT_APPLICABLE');
    });
    await t.test('changed CVE applicability and enrichment refresh existing findings', async () => {
      await reset();
      const cve = vulnerability();
      await save('cveData', cve.cveId, cve);
      await save('watchlist', 'asset', asset());
      await run();
      await save('cveData', cve.cveId, {
        ...cve,
        applicabilityRequiresReview: true,
        epss: { score: 0.9, percentile: 0.99 },
      });
      await run();
      const finding = (await list<Finding>(pool, 'findings'))[0];
      assert.equal(finding.notificationStatus, 'REVIEW_REQUIRED');
      assert.equal(finding.cve.epss.score, 0.9);
    });
    await t.test(
      'delivery rechecks current inventory before sending an already queued advisory',
      async () => {
        await reset();
        await save('settings', 'main', { ...DEFAULT_SETTINGS, autoDispatchEnabled: true });
        await save('recipients', 'recipient', {
          id: 'recipient',
          name: 'test',
          email: 'test@example.invalid',
          role: 'test',
          subscriptionTier: 'ALL_SEVERITIES',
          enabled: true,
          deliverySuccessRate: 0,
        });
        const cve = vulnerability();
        await save('cveData', cve.cveId, cve);
        await save('watchlist', 'asset', asset());
        await save('watchlist', 'asset-2', {
          ...asset(),
          id: 'asset-2',
          assetTag: 'TEST-SECOND',
        });
        await run();
        assert.equal(
          (await pool.query("SELECT count(*)::int AS count FROM outbox WHERE status='QUEUED'")).rows[0].count,
          1,
        );
        const execution = (await list<any>(pool, 'executions'))[0];
        assert.equal(execution.scopeHours, 24);
        assert.equal(execution.stats.notificationsQueued, 1);
        assert.equal(execution.stats.advisoriesQueued, 1);
        assert.deepEqual(
          execution.phases.map((phase: any) => phase.name),
          ['Feed ingestion', 'Structured correlation', 'Delivery queue'],
        );
        await save('watchlist', 'asset', asset('2.0'));
        let calls = 0;
        await deliverNext(pool, config, request, async () => {
          calls++;
          return 'must-not-send';
        });
        assert.equal(calls, 0);
        assert.equal((await pool.query('SELECT status FROM outbox')).rows[0].status, 'FAILED');
        // A wholly blocked, never-accepted bundle can be rebuilt once applicable again.
        await save('watchlist', 'asset', asset());
        await run();
        assert.equal(
          (await pool.query("SELECT count(*)::int AS count FROM outbox WHERE status='QUEUED'")).rows[0].count,
          1,
        );
        await deliverNext(pool, config, request, async () => {
          calls++;
          return 'accepted-current';
        });
        assert.equal(calls, 1);
        await run();
        assert.equal(
          (await pool.query("SELECT count(*)::int AS count FROM outbox WHERE status='QUEUED'")).rows[0].count,
          0,
        );
      },
    );
    await t.test('feed circuit breaker cools down and allows a recovery probe', async () => {
      await reset();
      await save('feeds', 'cooling-feed', {
        id: 'cooling-feed',
        name: 'Cooling test feed',
        type: 'JSON_SEARCH_API',
        url: 'https://8.8.8.8/feed',
        authType: 'NONE',
        rateLimitPerMin: 60,
        enabled: true,
        healthStatus: 'DOWN',
        lastSync: null,
        latencyMs: 0,
        vendorSeed: false,
        itemCountLastRun: 0,
        ssrfValidated: false,
        consecutiveFailures: 5,
        circuitOpenUntil: new Date(Date.now() + 60_000).toISOString(),
      });
      let calls = 0;
      const probe = async () => {
        calls++;
        return { status: 200, body: '[]', headers: {} };
      };
      await queueRun(pool, 24, 'test');
      await processPipeline(pool, config, probe);
      assert.equal(calls, 0);
      assert.equal((await get<any>(pool, 'feeds', 'cooling-feed')).consecutiveFailures, 5);

      await save('feeds', 'cooling-feed', {
        ...(await get<any>(pool, 'feeds', 'cooling-feed')),
        circuitOpenUntil: new Date(Date.now() - 1000).toISOString(),
      });
      await queueRun(pool, 24, 'test');
      await processPipeline(pool, config, probe);
      const recovered = await get<any>(pool, 'feeds', 'cooling-feed');
      assert.equal(calls, 1);
      assert.equal(recovered.healthStatus, 'HEALTHY');
      assert.equal(recovered.consecutiveFailures, 0);
      assert.equal(recovered.circuitOpenUntil, null);
    });
    await t.test('complete KEV and EPSS snapshots clear stale enrichment', async () => {
      await reset();
      const cve = vulnerability();
      cve.cisaKev = {
        isKev: true,
        dateAdded: '2026-01-01',
        dueDate: '2026-02-01',
        requiredAction: 'Patch now',
      };
      cve.epss = { score: 0.9, percentile: 0.99 };
      await save('cveData', cve.cveId, cve);
      await save('feeds', 'kev-feed', {
        id: 'kev-feed',
        name: 'KEV test',
        type: 'CISA_KEV',
        url: 'https://8.8.8.8/kev',
        authType: 'NONE',
        rateLimitPerMin: 60,
        enabled: true,
        healthStatus: 'UNTESTED',
        lastSync: null,
        latencyMs: 0,
        vendorSeed: false,
        itemCountLastRun: 0,
        ssrfValidated: false,
      });
      await save('feeds', 'epss-feed', {
        id: 'epss-feed',
        name: 'EPSS test',
        type: 'EPSS_API',
        url: 'https://8.8.8.8/epss',
        authType: 'NONE',
        rateLimitPerMin: 60,
        enabled: true,
        healthStatus: 'UNTESTED',
        lastSync: null,
        latencyMs: 0,
        vendorSeed: false,
        itemCountLastRun: 0,
        ssrfValidated: false,
      });
      await queueRun(pool, 24, 'test');
      await processPipeline(pool, config, async (url) => ({
        status: 200,
        body: url.endsWith('/kev') ? '{"vulnerabilities":[]}' : '{"total":0,"data":[]}',
        headers: {},
      }));
      const refreshed = await get<NormalizedCVE>(pool, 'cveData', cve.cveId);
      assert.deepEqual(refreshed?.cisaKev, { isKev: false });
      assert.deepEqual(refreshed?.epss, { score: 0, percentile: 0 });
    });
  } finally {
    await pool.end();
    await base.query(`DROP SCHEMA ${schema} CASCADE`);
    await base.end();
  }
});
