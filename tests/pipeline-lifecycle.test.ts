import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID, randomBytes } from 'node:crypto';
import { createPool, migrate, transaction, put, putMany, list, get } from '../server/db.ts';
import { queueRun, processPipeline, stopRun } from '../server/pipeline';
import { deliverNext, queueAdvisory } from '../server/delivery';
import { loadConfig } from '../server/config.ts';
import { DEFAULT_SETTINGS } from '../shared/state.ts';
import { MITRE_DELTA_URL } from '../server/mitre';
import { mitreRecord, mitreDelta } from './fixtures/mitre';
import { applyCommand } from '../server/commands.ts';
import type { AliasEntry, Finding, NormalizedCVE, WatchListItem } from '../src/types/index.ts';
import { deriveInventoryAliases } from '../src/utils/aliasLifecycle.ts';
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
    await t.test('incremental checkpoints commit atomically, survive failures, and reset after source changes', async () => {
      await reset();
      await save('settings', 'main', { ...DEFAULT_SETTINGS, schedulerEnabled: false });
      const source = { id: 'incremental', name: 'NVD incremental', type: 'NVD_API', url: 'https://example.com/nvd', authType: 'NONE', rateLimitPerMin: 600, enabled: true };
      await save('feeds', source.id, source);
      let requestedStart = '', requestedEnd = '';
      const success = async (raw: string) => {
        const url = new URL(raw);
        requestedStart = url.searchParams.get('lastModStartDate')!;
        requestedEnd = url.searchParams.get('lastModEndDate')!;
        return { status: 200, headers: {}, body: JSON.stringify({ startIndex: 0, totalResults: 0, vulnerabilities: [] }) };
      };
      await queueRun(pool, 2880, 'test');
      await processPipeline(pool, config, success);
      assert.ok(Date.parse(requestedEnd) - Date.parse(requestedStart) <= 86400000);
      const first = await get<any>(pool, 'feedCursors', source.id);
      assert.equal(first.cursor, requestedEnd);
      await queueRun(pool, 24, 'test');
      await processPipeline(pool, config, success);
      assert.equal(Date.parse(requestedStart), Date.parse(first.cursor) - 600000);
      const committed = await get<any>(pool, 'feedCursors', source.id);
      await queueRun(pool, 24, 'test');
      await processPipeline(pool, config, async () => { throw new Error('Upstream unavailable'); });
      assert.deepEqual(await get(pool, 'feedCursors', source.id), committed);
      await transaction(pool, db => applyCommand(db, config, { action: 'feed.save', id: source.id, data: { ...source, url: 'https://example.com/new-nvd' }, actor: 'test' }));
      await queueRun(pool, 2880, 'test');
      await processPipeline(pool, config, success);
      assert.ok(Date.parse(requestedEnd) - Date.parse(requestedStart) >= 86399000);
      assert.notEqual((await get<any>(pool, 'feedCursors', source.id)).fingerprint, committed.fingerprint);
    });
    await t.test('disabled scheduler leaves catch-up work queued until scheduling is enabled', async () => {
      await reset();
      await save('settings', 'main', { ...DEFAULT_SETTINGS, schedulerEnabled: false });
      const source = { id: 'catchup', name: 'NVD catch-up', type: 'NVD_API', url: 'https://example.com/nvd', authType: 'NONE', rateLimitPerMin: 600, enabled: true };
      await save('feeds', source.id, source);
      const windows: Array<{ start: number; end: number }> = [];
      const request = async (raw: string) => {
        const url = new URL(raw);
        windows.push({
          start: Date.parse(url.searchParams.get('lastModStartDate')!),
          end: Date.parse(url.searchParams.get('lastModEndDate')!),
        });
        return { status: 200, headers: {}, body: JSON.stringify({ startIndex: 0, totalResults: 0, vulnerabilities: [] }) };
      };
      await queueRun(pool, 24, 'test');
      await processPipeline(pool, config, request);
      const cursor = await get<any>(pool, 'feedCursors', source.id);
      const old = Date.now() - 72 * 3600000;
      await save('feedCursors', source.id, { ...cursor, cursor: new Date(old).toISOString(), hasMore: true });
      assert.equal(await processPipeline(pool, config, request), false);
      assert.equal((await get<any>(pool, 'feedCursors', source.id)).cursor, new Date(old).toISOString());
      await save('settings', 'main', { ...DEFAULT_SETTINGS, schedulerEnabled: true });
      windows.length = 0;
      assert.equal(await processPipeline(pool, config, request), true);
      // A single run may consume several consecutive catch-up windows, but each
      // individual provider request must remain bounded to one day.
      assert.ok(windows.length > 0);
      for (const window of windows) assert.ok(window.end - window.start <= 86400000);
      const next = await get<any>(pool, 'feedCursors', source.id);
      assert.ok(Date.parse(next.cursor) > old);
      assert.ok(Date.parse(next.cursor) >= Date.now() - 60000);
      assert.equal(next.hasMore, false);
      await save('feeds', source.id, { ...source, enabled: false });
      assert.equal(await processPipeline(pool, config, request), false);
    });
    await t.test('MITRE CVE and overlapping feeds persist one CVE and stable inventory findings across runs', async () => {
      await reset();
      await save('watchlist', 'asset', asset());
      const date = new Date(Date.now() - 1000).toISOString();
      const common = { authType: 'NONE', enabled: true, rateLimitPerMin: 600 };
      await save('feeds', 'mitre', { ...common, id: 'mitre', name: 'MITRE CVE', type: 'MITRE_CVE', url: MITRE_DELTA_URL });
      await save('feeds', 'nvd', { ...common, id: 'nvd', name: 'NVD', type: 'NVD_API', url: 'https://example.com/nvd' });
      const sourceRequest = async (url: string) => {
        const data = url === MITRE_DELTA_URL ? mitreDelta(undefined, date)
          : url.startsWith('https://raw.githubusercontent.com/') ? mitreRecord(undefined, date)
          : { startIndex: 0, totalResults: 1, vulnerabilities: [{ cve: {
              id: 'CVE-2026-98001', published: date, lastModified: date, vulnStatus: 'Analyzed',
              descriptions: [{ lang: 'en', value: 'Example widget vulnerability' }],
              configurations: [{ nodes: [{ cpeMatch: [{ vulnerable: true, criteria: cpe('*') }] }] }],
            } }] };
        return { status: 200, body: JSON.stringify(data), headers: {} };
      };
      await queueRun(pool, 24, 'test');
      await processPipeline(pool, config, sourceRequest);
      const cves = await list<NormalizedCVE>(pool, 'cveData');
      assert.equal(cves.length, 1);
      assert.deepEqual(cves[0].sourceFeeds, ['mitre', 'nvd']);
      const first = await list<Finding>(pool, 'findings');
      assert.equal(first.length, 1);
      await queueRun(pool, 24, 'test');
      await processPipeline(pool, config, sourceRequest);
      assert.equal((await list(pool, 'cveData')).length, 1);
      const second = await list<Finding>(pool, 'findings');
      assert.equal(second.length, 1);
      assert.equal(second[0].id, first[0].id);
      assert.equal((await get<any>(pool, 'feeds', 'mitre')).healthStatus, 'HEALTHY');
    });
    await t.test('configured advisory prefix reaches queued email subjects and bodies automatically', async () => {
      await reset();
      await save('settings', 'main', { ...DEFAULT_SETTINGS, advisoryPrefix: 'SECURITY-', autoDispatchEnabled: true });
      await save('watchlist', 'asset', asset());
      await save('cveData', vulnerability().cveId, vulnerability());
      await save('recipients', 'rec', { id: 'rec', name: 'Test', email: 'test@example.invalid', enabled: true, subscriptionTier: 'ALL_SEVERITIES' });
      await run();
      const jobs = (await pool.query('SELECT payload,advisory_id FROM outbox')).rows;
      assert.equal(jobs.length, 1);
      assert.match(jobs[0].advisory_id, /^SECURITY-/);
      assert.ok(jobs[0].payload.subject.startsWith(`[${jobs[0].advisory_id}] [HIGH]`));
      assert.ok(jobs[0].payload.text.includes(`Advisory ID: ${jobs[0].advisory_id}`));
      assert.ok(jobs[0].payload.html.includes(jobs[0].advisory_id));
    });
    await t.test('timed out source recovers without the scheduler being enabled', async () => {
      await reset();
      await save('settings', 'main', { ...DEFAULT_SETTINGS, schedulerEnabled: false, autoDispatchEnabled: false });
      await save('feeds', 'recover-feed', {
        id: 'recover-feed', name: 'Recovery test', type: 'JSON_SEARCH_API',
        url: 'https://example.com/feed', enabled: true, authType: 'NONE',
        rateLimitPerMin: 60, recoveryDelayMinutes: 1,
      });
      await queueRun(pool, 24, 'test');
      await processPipeline(pool, config, async () => { throw new Error('Outbound request timed out'); });
      const failed = await get<any>(pool, 'feeds', 'recover-feed');
      assert.equal(failed.healthStatus, 'DOWN');
      assert.ok(Date.parse(failed.circuitOpenUntil) > Date.now());
      assert.equal(await processPipeline(pool, config, request), false);
      await save('feeds', failed.id, { ...failed, circuitOpenUntil: new Date(Date.now() - 1000).toISOString() });
      assert.equal(await processPipeline(pool, config, async () => ({ status: 200, body: '[]', headers: {} })), true);
      const recovered = await get<any>(pool, 'feeds', failed.id);
      assert.equal(recovered.healthStatus, 'HEALTHY');
      assert.equal(recovered.consecutiveFailures, 0);
      assert.equal(recovered.circuitOpenUntil, null);
    });
    await t.test('concurrent queue requests create one execution and one worker owns ingestion', async () => {
      await reset();
      const queued = await Promise.all(Array.from({ length: 8 }, () => queueRun(pool, 24, 'test')));
      assert.equal(new Set(queued.map(run => run.id)).size, 1);
      await save('feeds', 'single-worker', {
        id: 'single-worker', name: 'Single worker', type: 'JSON_SEARCH_API', url: 'https://example.com/feed',
        enabled: true, authType: 'NONE', rateLimitPerMin: 60,
      });
      let calls = 0;
      await Promise.all(Array.from({ length: 3 }, () => processPipeline(pool, config, async () => {
        calls++;
        await new Promise(resolve => setTimeout(resolve, 50));
        return { status: 200, body: '[]', headers: {} };
      })));
      assert.equal(calls, 1);
    });
    await t.test('EPSS without applicable inventory clears overdue recovery instead of repeatedly queuing', async () => {
      await reset();
      await save('settings', 'main', { ...DEFAULT_SETTINGS, schedulerEnabled: false });
      await save('feeds', 'empty-epss', {
        id: 'empty-epss', name: 'EPSS', type: 'EPSS_API', url: 'https://example.com/epss',
        enabled: true, authType: 'NONE', rateLimitPerMin: 60, healthStatus: 'DOWN',
        consecutiveFailures: 1, circuitOpenUntil: new Date(Date.now() - 1000).toISOString(),
      });
      assert.equal(await processPipeline(pool, config, request), true);
      const source = await get<any>(pool, 'feeds', 'empty-epss');
      assert.equal(source.circuitOpenUntil, null);
      assert.equal(source.consecutiveFailures, 0);
      assert.equal(source.healthStatus, 'UNTESTED');
      assert.equal(await processPipeline(pool, config, request), false);
    });
    await t.test('source duration budget discards late responses and schedules recovery', async () => {
      await reset();
      await save('feeds', 'slow-feed', {
        id: 'slow-feed', name: 'Slow source', type: 'JSON_SEARCH_API', url: 'https://example.com/feed',
        enabled: true, authType: 'NONE', rateLimitPerMin: 60,
      });
      await queueRun(pool, 24, 'test');
      await processPipeline(pool, { ...config, FEED_MAX_DURATION_SECONDS: 1 }, async (_url, options) => {
        assert.ok(options!.timeoutMs! <= 1000);
        await new Promise(resolve => setTimeout(resolve, 1100));
        return { status: 200, body: JSON.stringify([vulnerability()]), headers: {} };
      });
      const source = await get<any>(pool, 'feeds', 'slow-feed');
      assert.equal(source.healthStatus, 'DOWN');
      assert.match(source.errorLog, /duration limit/);
      assert.equal((await list(pool, 'cveData')).length, 0);
      assert.ok(source.circuitOpenUntil);
    });
    await t.test('lost worker lock prevents commit and the next worker recovers the run', async () => {
      await reset();
      await save('feeds', 'lock-loss', {
        id: 'lock-loss', name: 'Lock loss', type: 'JSON_SEARCH_API', url: 'https://example.com/feed',
        enabled: true, authType: 'NONE', rateLimitPerMin: 60,
      });
      const queued = await queueRun(pool, 24, 'test');
      await assert.rejects(processPipeline(pool, config, async () => {
        // Two-int advisory locks are exposed as classid/objid in pg_locks;
        // scope the termination to this schema so parallel test databases and
        // other deployments sharing the cluster are not affected.
        await pool.query(`SELECT pg_terminate_backend(pid) FROM pg_locks
          WHERE locktype='advisory' AND classid=800003 AND objsubid=2
            AND objid=hashtext(COALESCE(current_schema(), current_database())) AND granted`);
        await new Promise(resolve => setTimeout(resolve, 50));
        return { status: 200, body: JSON.stringify([vulnerability()]), headers: {} };
      }), /lock connection/);
      assert.equal((await list(pool, 'cveData')).length, 0);
      assert.equal(await processPipeline(pool, config, async () => ({ status: 200, body: '[]', headers: {} })), true);
      const recovered = await get<any>(pool, 'executions', queued.id);
      assert.equal(recovered.status, 'COMPLETED');
      assert.ok(recovered.logs.some((line: string) => line.includes('Recovered interrupted worker')));
    });
    await t.test('queued stop is idempotent and never runs', async () => {
      await reset();
      const queued = await queueRun(pool, 24, 'test');
      assert.equal((await stopRun(pool, queued.id, 'test')).status, 'CANCELLED');
      assert.equal((await stopRun(pool, queued.id, 'test')).status, 'CANCELLED');
      assert.equal(await processPipeline(pool, config, request), false);
    });
    await t.test('stop during network retrieval discards results and releases worker lock', async () => {
      await reset();
      await save('feeds', 'stop-feed', {
        id: 'stop-feed',
        name: 'Stop test',
        type: 'JSON_SEARCH_API',
        url: 'https://example.com/feed',
        enabled: true,
        authType: 'NONE',
        rateLimitPerMin: 60,
      });
      const queued = await queueRun(pool, 24, 'test');
      await processPipeline(pool, config, async () => {
        const live = await get<any>(pool, 'executions', queued.id);
        assert.equal(live.phases[0].status, 'RUNNING');
        assert.equal(live.phases[1].status, 'PENDING');
        await stopRun(pool, queued.id, 'test');
        return { status: 200, body: JSON.stringify([vulnerability()]), headers: {} };
      });
      const stopped = await get<any>(pool, 'executions', queued.id);
      assert.equal(stopped.status, 'CANCELLED');
      assert.ok(stopped.stopRequestedAt);
      assert.equal(await get(pool, 'feedCursors', 'stop-feed'), undefined);
      assert.equal((await list(pool, 'cveData')).length, 0);
      assert.equal((await list(pool, 'findings')).length, 0);
      assert.equal((await pool.query('SELECT count(*) FROM outbox')).rows[0].count, '0');
      await save('feeds', 'stop-feed', { id: 'stop-feed', enabled: false });
      await run();
      assert.ok((await list<any>(pool, 'executions')).some((e) => e.status === 'COMPLETED'));
    });
    await t.test('large bulk writes stay below parameter limits and preserve unchanged rows', async () => {
      await reset();
      const rows = Array.from({ length: 22000 }, (_, id) => ({ id: String(id), data: { value: id } }));
      await transaction(pool, (db) => putMany(db, 'bulk-test', [...rows, { id: '0', data: { value: -1 } }]));
      assert.equal(
        (await pool.query("SELECT count(*)::int AS n FROM records WHERE kind='bulk-test'")).rows[0].n,
        22000,
      );
      assert.deepEqual(await get(pool, 'bulk-test', '0'), { value: -1 });
      await pool.query("UPDATE records SET updated_at='2000-01-01T00:00:00Z' WHERE kind='bulk-test' AND id='0'");
      await transaction(pool, (db) => putMany(db, 'bulk-test', [{ id: '0', data: { value: -1 } }]));
      assert.equal(
        (
          await pool.query("SELECT updated_at FROM records WHERE kind='bulk-test' AND id='0'")
        ).rows[0].updated_at.toISOString(),
        '2000-01-01T00:00:00.000Z',
      );
    });
    await t.test('new inventory is matched against older cached CVEs', async () => {
      await reset();
      const cve = vulnerability();
      cve.publishedDate = cve.modifiedDate = '2020-01-01T00:00:00Z';
      await save('cveData', cve.cveId, cve);
      await save('watchlist', 'asset', asset());
      await run();
      assert.equal((await list(pool, 'findings')).length, 1);
    });
    await t.test('repeated bulk inventory imports preserve asset and finding identities', async () => {
      await reset();
      const { id: _id, createdAt: _created, ...item } = asset();
      const importItems = () =>
        transaction(pool, (db) =>
          applyCommand(db, config, { action: 'asset.import', data: [item, item], actor: 'test' }),
        );
      assert.equal((await importItems()).imported, 1);
      const first = (await list<WatchListItem>(pool, 'watchlist'))[0];
      await save('cveData', vulnerability().cveId, vulnerability());
      await run();
      const finding = (await list<Finding>(pool, 'findings'))[0];
      await importItems();
      await run();
      assert.equal((await list<WatchListItem>(pool, 'watchlist')).length, 1);
      assert.equal((await list<WatchListItem>(pool, 'watchlist'))[0].id, first.id);
      assert.equal((await list<Finding>(pool, 'findings')).length, 1);
      assert.equal((await list<Finding>(pool, 'findings'))[0].id, finding.id);
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
          ['Feed ingestion', 'Normalize & deduplicate', 'Product matching', 'Delivery queue'],
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
    await t.test(
      'retention of the threat cache does not permanently block a queued advisory',
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
        await run();
        assert.equal(
          (await pool.query("SELECT count(*)::int AS count FROM outbox WHERE status='QUEUED'")).rows[0]
            .count,
          1,
        );
        // The retention policy may remove the regenerable cache record while a
        // manually reviewed advisory is still waiting to be delivered.
        await pool.query("DELETE FROM records WHERE kind='cveData' AND id=$1", [cve.cveId]);
        let calls = 0;
        await deliverNext(pool, config, request, async () => {
          calls++;
          return 'accepted-from-finding-snapshot';
        });
        assert.equal(calls, 1);
        assert.equal((await pool.query('SELECT status FROM outbox')).rows[0].status, 'ACCEPTED');
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
    await t.test('unchanged KEV snapshots enrich later CVEs and invalidate on source edits', async () => {
      await reset();
      const cve = vulnerability();
      const source = {
        id: 'kev',
        name: 'KEV',
        type: 'CISA_KEV',
        url: 'https://example.com/kev',
        authType: 'NONE',
        enabled: true,
        rateLimitPerMin: 60,
      };
      await save('feeds', 'kev', source);
      await queueRun(pool, 24, 'test');
      await processPipeline(pool, config, async (_, options) => {
        assert.equal(options?.headers?.['If-None-Match'], undefined);
        return {
          status: 200,
          headers: { etag: '"catalog-1"' },
          body: JSON.stringify({
            vulnerabilities: [
              {
                cveID: cve.cveId,
                dateAdded: '2026-01-01',
                dueDate: '2026-02-01',
                requiredAction: 'Patch',
                knownRansomwareCampaignUse: 'Unknown',
              },
            ],
          }),
        };
      });
      await save('cveData', cve.cveId, cve);
      await queueRun(pool, 24, 'test');
      await processPipeline(pool, config, async (_, options) => {
        assert.equal(options?.headers?.['If-None-Match'], '"catalog-1"');
        return { status: 304, headers: {}, body: '' };
      });
      assert.equal((await get<NormalizedCVE>(pool, 'cveData', cve.cveId))?.cisaKev.isKev, true);
      await save('feeds', 'kev', {
        ...(await get<any>(pool, 'feeds', 'kev')),
        url: 'https://example.com/other',
      });
      await queueRun(pool, 24, 'test');
      await processPipeline(pool, config, async (_, options) => {
        assert.equal(options?.headers?.['If-None-Match'], undefined);
        return { status: 200, headers: {}, body: '{"vulnerabilities":[]}' };
      });
      assert.equal((await get<NormalizedCVE>(pool, 'cveData', cve.cveId))?.cisaKev.isKev, false);
      assert.equal((await get<any>(pool, 'feeds', 'kev')).etag, undefined);
    });
    await t.test('renamed assets invalidate queued rendered systems and rebuild once', async () => {
      await reset();
      await save('settings', 'main', { ...DEFAULT_SETTINGS, autoDispatchEnabled: true });
      await save('watchlist', 'asset', asset());
      await save('cveData', vulnerability().cveId, vulnerability());
      await save('recipients', 'rec', {
        id: 'rec',
        name: 'Test',
        email: 'test@example.invalid',
        enabled: true,
        subscriptionTier: 'ALL_SEVERITIES',
      });
      await run();
      await save('watchlist', 'asset', { ...asset(), assetTag: 'RENAMED' });
      // Correlation may refresh stored findings before old queued payload is checked.
      await run();
      let sent = 0;
      await deliverNext(pool, config, request, async () => {
        sent++;
        return 'must-not-send';
      });
      assert.equal(sent, 0);
      await run();
      await deliverNext(pool, config, request, async (job) => {
        assert.match(job.payload.text, /RENAMED/);
        sent++;
        return 'accepted';
      });
      assert.equal(sent, 1);
      await run();
      assert.equal(
        (await pool.query("SELECT count(*)::int AS n FROM outbox WHERE status='QUEUED'")).rows[0].n,
        0,
      );
    });
    await t.test('interleaved dispatches count each CVE dispatch only once', async () => {
      await reset();
      await save('settings', 'main', { ...DEFAULT_SETTINGS, autoDispatchEnabled: true });
      await save('watchlist', 'asset', asset());
      await save('cveData', vulnerability().cveId, vulnerability());
      await save('recipients', 'rec', {
        id: 'rec',
        name: 'Test',
        email: 'test@example.invalid',
        enabled: true,
        subscriptionTier: 'ALL_SEVERITIES',
      });
      await run();
      const advisory = (await list<any>(pool, 'advisories'))[0];
      const findings = await list<Finding>(pool, 'findings');
      await deliverNext(pool, config, request, async () => 'accepted-a');
      await transaction(pool, (db) => queueAdvisory(db, advisory, findings, undefined, 'dispatch-b'));
      await deliverNext(pool, config, request, async () => 'accepted-b');
      await save('recipients', 'rec-2', {
        id: 'rec-2',
        name: 'Second',
        email: 'second@example.invalid',
        enabled: true,
        subscriptionTier: 'ALL_SEVERITIES',
      });
      await transaction(pool, (db) => queueAdvisory(db, advisory, findings));
      await deliverNext(pool, config, request, async () => 'accepted-a-second');
      assert.equal((await get<any>(pool, 'alertedCves', vulnerability().cveId)).dispatchCount, 2);
      assert.equal((await list(pool, 'alertDispatches')).length, 2);
    });
    await t.test('feed credential rotation resets validator, health history and cooldown', async () => {
      await reset();
      const data = {
        name: 'Rotated source',
        type: 'JSON_SEARCH_API',
        url: 'https://example.com/feed',
        authType: 'API_KEY',
        authSecretKey: 'new-secret',
        rateLimitPerMin: 60,
        enabled: true,
      };
      await save('feeds', 'rotated', {
        ...data,
        id: 'rotated',
        etag: 'old-etag',
        lastSync: '2026-01-01T00:00:00Z',
        itemCountLastRun: 12,
        consecutiveFailures: 5,
        circuitOpenUntil: '2099-01-01T00:00:00Z',
      });
      await transaction(pool, (db) =>
        applyCommand(db, config, { action: 'feed.save', id: 'rotated', data, actor: 'test' }),
      );
      const saved = await get<any>(pool, 'feeds', 'rotated');
      assert.equal(saved.etag, undefined);
      assert.equal(saved.lastSync, null);
      assert.equal(saved.itemCountLastRun, 0);
      assert.equal(saved.consecutiveFailures, 0);
      assert.equal(saved.circuitOpenUntil, null);
      await transaction(pool, (db) =>
        applyCommand(db, config, {
          action: 'feed.import',
          data: [{ ...data, id: 'rotated', etag: 'invented', lastSync: '2026-01-01T00:00:00Z' }],
          actor: 'test',
        }),
      );
      const imported = await get<any>(pool, 'feeds', 'rotated');
      assert.equal(imported.etag, undefined);
      assert.equal(imported.lastSync, null);
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
      await save('watchlist', 'asset', asset());
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
    await t.test('same-run CVEs receive targeted EPSS enrichment before dispatch', async () => {
      await reset();
      await save('watchlist', 'asset', asset());
      const baseFeed = {
        name: 'Test',
        authType: 'NONE',
        rateLimitPerMin: 60,
        enabled: true,
        consecutiveFailures: 0,
      };
      await save('feeds', 'json', {
        ...baseFeed,
        id: 'json',
        type: 'JSON_SEARCH_API',
        url: 'https://8.8.8.8/cves',
      });
      await save('feeds', 'epss', { ...baseFeed, id: 'epss', type: 'EPSS_API', url: 'https://8.8.8.8/epss' });
      const targeted: string[] = [];
      await queueRun(pool, 24, 'test');
      await processPipeline(pool, config, async (value) => {
        const url = new URL(value);
        if (url.pathname === '/cves')
          return { status: 200, headers: {}, body: JSON.stringify([vulnerability()]) };
        targeted.push(url.searchParams.get('cve')!);
        return {
          status: 200,
          headers: {},
          body: JSON.stringify({
            total: 1,
            data: [{ cve: vulnerability().cveId, epss: '0.8', percentile: '0.95' }],
          }),
        };
      });
      assert.deepEqual(targeted, [vulnerability().cveId]);
      assert.equal((await list<Finding>(pool, 'findings'))[0].cve.epss.score, 0.8);
    });
    await t.test(
      'responses from sources changed during ingestion cannot overwrite health or cache',
      async () => {
        await reset();
        const source = {
          id: 'changed',
          name: 'Test',
          type: 'JSON_SEARCH_API',
          url: 'https://8.8.8.8/old',
          authType: 'NONE',
          rateLimitPerMin: 60,
          enabled: true,
          healthStatus: 'UNTESTED',
        };
        await save('feeds', source.id, source);
        await queueRun(pool, 24, 'test');
        await processPipeline(pool, config, async () => {
          await save('feeds', source.id, { ...source, url: 'https://8.8.8.8/new' });
          return { status: 200, headers: {}, body: JSON.stringify([vulnerability()]) };
        });
        assert.equal((await list(pool, 'cveData')).length, 0);
        assert.equal((await get<any>(pool, 'feeds', source.id)).healthStatus, 'UNTESTED');
        assert.ok(
          (await list<any>(pool, 'executions'))[0].logs.some((line: string) =>
            line.includes('obsolete response ignored'),
          ),
        );
      },
    );
    await t.test('notification bundles obey severity and KEV subscriptions without cross-talk', async () => {
      await reset();
      await save('settings', 'main', { ...DEFAULT_SETTINGS, autoDispatchEnabled: true });
      await save('watchlist', 'asset', asset());
      const high = vulnerability(),
        low = {
          ...vulnerability(),
          cveId: 'CVE-2026-98002',
          cvss: { ...vulnerability().cvss, severity: 'LOW', score: 2 },
        };
      high.cisaKev = { isKev: true };
      await save('cveData', high.cveId, high);
      await save('cveData', low.cveId, low);
      for (const tier of ['ALL_SEVERITIES', 'CRITICAL_HIGH_ONLY', 'CISA_KEV_ONLY'])
        await save('recipients', tier, {
          id: tier,
          name: tier,
          email: `${tier.toLowerCase()}@example.invalid`,
          enabled: true,
          subscriptionTier: tier,
        });
      await run();
      const jobs = (await pool.query('SELECT target_id,payload FROM outbox')).rows;
      assert.equal(jobs.length, 4);
      for (const job of jobs.filter((job) => job.target_id !== 'ALL_SEVERITIES'))
        assert.deepEqual(job.payload.cveIds, [high.cveId]);
      while (await deliverNext(pool, config, request, async () => 'mock-accepted')) {
        /* Drain only mock transports. */
      }
      await run();
      assert.equal((await pool.query('SELECT count(*)::int AS n FROM outbox')).rows[0].n, 4);
    });
    await t.test('queued delivery rechecks changed recipient subscriptions', async () => {
      await reset();
      await save('settings', 'main', { ...DEFAULT_SETTINGS, autoDispatchEnabled: true });
      await save('watchlist', 'asset', asset());
      await save('cveData', vulnerability().cveId, vulnerability());
      const recipient = {
        id: 'rec',
        name: 'Test',
        email: 'test@example.invalid',
        enabled: true,
        subscriptionTier: 'ALL_SEVERITIES',
      };
      await save('recipients', recipient.id, recipient);
      await run();
      await save('recipients', recipient.id, { ...recipient, subscriptionTier: 'CISA_KEV_ONLY' });
      let transports = 0;
      await deliverNext(pool, config, request, async () => {
        transports++;
        return 'must-not-send';
      });
      assert.equal(transports, 0);
      assert.equal((await pool.query('SELECT status FROM outbox')).rows[0].status, 'FAILED');
    });
    await t.test(
      'queued payloads cannot send stale CVE severity or remediation after an update',
      async () => {
        await reset();
        await save('settings', 'main', { ...DEFAULT_SETTINGS, autoDispatchEnabled: true });
        await save('watchlist', 'asset', asset());
        const cve = vulnerability();
        await save('cveData', cve.cveId, cve);
        await save('recipients', 'rec', {
          id: 'rec',
          name: 'Test',
          email: 'test@example.invalid',
          enabled: true,
          subscriptionTier: 'ALL_SEVERITIES',
        });
        await run();
        await save('cveData', cve.cveId, {
          ...cve,
          remediation: { ...cve.remediation, immediateActions: ['Updated vendor action'] },
        });
        let transports = 0;
        await deliverNext(pool, config, request, async () => {
          transports++;
          return 'must-not-send';
        });
        assert.equal(transports, 0);
        assert.equal((await pool.query('SELECT status FROM outbox')).rows[0].status, 'FAILED');
        await run();
        assert.equal(
          (await pool.query("SELECT count(*)::int AS n FROM outbox WHERE status='QUEUED'")).rows[0].n,
          1,
        );
      },
    );
    await t.test(
      'legacy queued payloads without revision evidence are rebuilt before transport',
      async () => {
        await reset();
        await save('settings', 'main', { ...DEFAULT_SETTINGS, autoDispatchEnabled: true });
        await save('watchlist', 'asset', asset());
        await save('cveData', vulnerability().cveId, vulnerability());
        await save('recipients', 'rec', {
          id: 'rec',
          name: 'Test',
          email: 'test@example.invalid',
          enabled: true,
          subscriptionTier: 'ALL_SEVERITIES',
        });
        await run();
        await pool.query("UPDATE outbox SET payload=payload-'cveRevisions'");
        let transports = 0;
        await deliverNext(pool, config, request, async () => {
          transports++;
          return 'must-not-send';
        });
        assert.equal(transports, 0);
        await run();
        assert.equal(
          (await pool.query("SELECT count(*)::int AS n FROM outbox WHERE status='QUEUED'")).rows[0].n,
          1,
        );
      },
    );
    await t.test('NVD withdrawals invalidate cached findings and block older feed resurrection', async () => {
      await reset();
      await save('watchlist', 'asset', asset());
      const original = { ...vulnerability(), modifiedDate: '2026-01-01T00:00:00Z' };
      await save('cveData', original.cveId, original);
      await run();
      const source = {
        id: 'nvd',
        name: 'NVD test',
        type: 'NVD_API',
        url: 'https://8.8.8.8/nvd',
        authType: 'NONE',
        rateLimitPerMin: 60,
        enabled: true,
      };
      await save('feeds', source.id, source);
      await queueRun(pool, 24, 'test');
      await processPipeline(pool, config, async () => ({
        status: 200,
        headers: {},
        body: JSON.stringify({
          totalResults: 1,
          startIndex: 0,
          vulnerabilities: [
            { cve: { id: original.cveId, lastModified: '2026-02-01T00:00:00Z', vulnStatus: 'Rejected' } },
          ],
        }),
      }));
      assert.equal(await get(pool, 'cveData', original.cveId), undefined);
      assert.equal((await list<Finding>(pool, 'findings'))[0].notificationStatus, 'NOT_APPLICABLE');
      await assert.rejects(
        transaction(pool, (db) =>
          applyCommand(db, config, { action: 'cve.save', data: original, actor: 'test' }),
        ),
        /withdrawn/,
      );
      await save('feeds', source.id, { ...source, type: 'JSON_SEARCH_API' });
      await queueRun(pool, 24, 'test');
      await processPipeline(pool, config, async () => ({
        status: 200,
        headers: {},
        body: JSON.stringify([original]),
      }));
      assert.equal(await get(pool, 'cveData', original.cveId), undefined);
    });
    await t.test('alias promotion freezes a learned relation and revocation tombstones it', async () => {
      await reset();
      const createdAt = new Date().toISOString();
      const auto: AliasEntry = {
        id: 'auto:vendor:acme corp',
        scope: 'VENDOR',
        canonical: 'acme corp',
        aliases: ['acme_inc'],
        source: 'AUTO',
        provenance: 'INVENTORY',
        createdAt,
        firstSeenAt: createdAt,
        lastSeenAt: createdAt,
        expiresAt: new Date(Date.parse(createdAt) + 86400000).toISOString(),
      };
      await save('aliases', auto.id, auto);
      await transaction(pool, (db) =>
        applyCommand(db, config, { action: 'alias.promote', id: auto.id, actor: 'test' }),
      );
      const promoted = await get<AliasEntry>(pool, 'aliases', auto.id);
      assert.equal(promoted?.source, 'MANUAL');
      assert.equal(promoted?.provenance, 'OPERATOR');
      assert.equal(promoted?.expiresAt, undefined);
      assert.deepEqual(promoted?.aliases, ['acme_inc']);

      const product: AliasEntry = {
        id: 'auto:product:widget pro',
        scope: 'PRODUCT',
        canonical: 'widget pro',
        aliases: ['widget_pro'],
        source: 'AUTO',
        provenance: 'INVENTORY',
        createdAt,
        firstSeenAt: createdAt,
        lastSeenAt: createdAt,
        expiresAt: new Date(Date.parse(createdAt) + 86400000).toISOString(),
      };
      await save('aliases', product.id, product);
      await transaction(pool, (db) =>
        applyCommand(db, config, { action: 'alias.revoke', id: product.id, actor: 'test' }),
      );
      assert.equal(await get(pool, 'aliases', product.id), undefined);
      const tombstone = await get<AliasEntry>(pool, 'aliases', `revoked:${product.id}`);
      assert.equal(tombstone?.source, 'REVOKED');
      assert.deepEqual(tombstone?.aliases, []);
      assert.deepEqual(tombstone?.revokedAliases, ['widget_pro']);

      // The revocation blocks re-learning while the promoted row is preserved
      // as an operator decision.
      const persisted = await list<AliasEntry>(pool, 'aliases');
      assert.deepEqual(
        deriveInventoryAliases(
          [
            {
              vendor: 'Acme Corp',
              product: 'Widget Pro',
              cpes: ['cpe:2.3:a:acme_inc:widget_pro:1.0:*:*:*:*:*:*:*'],
              active: true,
            },
          ],
          persisted,
        ),
        [],
      );
    });
  } finally {
    await pool.end();
    await base.query(`DROP SCHEMA ${schema} CASCADE`);
    await base.end();
  }
});
