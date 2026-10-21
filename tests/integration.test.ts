import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID, createHmac } from 'node:crypto';
import supertest from 'supertest';
import { createPool, migrate, transaction, get, list, put } from '../server/db';
import { createApp } from '../server/app';
import { createUser } from '../server/auth';
import { loadConfig } from '../server/config';
import { decrypt, encrypt, passwordHash, checkPassword } from '../server/secrets';
import { publicAddress, resolvePublic, type Requester } from '../server/network';
import { normalizeNvd } from '../server/ingestion';
import { ingestFeed } from '../server/ingestion';
import { processPipeline, queueRun } from '../server/pipeline';
import { deliverNext } from '../server/delivery';
import { verifyAuditChain } from '../src/utils/cryptoChain';
import { DEFAULT_SETTINGS } from '../shared/state';
import type { NormalizedCVE, Finding, Advisory, WebhookEndpoint } from '../src/types';
const database = process.env.TEST_DATABASE_URL;
const key = randomBytes(32).toString('base64');
const config = loadConfig({
  NODE_ENV: 'test',
  DATABASE_URL: database || 'postgres://unused',
  APP_ORIGIN: 'http://localhost',
  ENCRYPTION_KEY: key,
  EGRESS_ALLOWED_HOSTS: '8.8.8.8',
  WORKER_ENABLED: 'false',
});
const password = 'Integration-test-password-2026!';
const cpe = (version: string) => `cpe:2.3:a:example:widget:${version}:*:*:*:*:*:*:*`;
function fixture(): NormalizedCVE {
  return {
    cveId: 'CVE-2026-12345',
    title: 'Widget test vulnerability',
    description: 'Test fixture',
    publishedDate: new Date().toISOString(),
    modifiedDate: new Date().toISOString(),
    cvss: { version: '3.1', score: 9.8, vector: '', severity: 'CRITICAL' },
    cwe: [],
    cpeMatches: [cpe('*')],
    versionRange: { versionEndExcluding: '2.0' },
    sourceFeeds: ['operator-import'],
    epss: { score: 0.5, percentile: 0.9 },
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
  };
}
test('configuration rejects absent secrets and insecure production origin', () => {
  assert.throws(() => loadConfig({}), /./);
  assert.throws(
    () =>
      loadConfig({
        ...Object.fromEntries(Object.entries(config).map(([k, v]) => [k, String(v)])),
        NODE_ENV: 'production',
      }),
    /HTTPS/,
  );
});
test('encryption authenticates ciphertext and its record context', () => {
  const secret = encrypt('private-value', key, 'record:1');
  assert.equal(decrypt(secret, key, 'record:1'), 'private-value');
  assert.throws(() => decrypt(secret, key, 'record:2'));
  assert.throws(() => decrypt(secret.replace(/.$/, 'x'), key, 'record:1'));
});
test('password hashes are salted and verify only the correct password', async () => {
  const hash = await passwordHash(password);
  assert.equal(await checkPassword(password, hash), true);
  assert.equal(await checkPassword('wrong', hash), false);
  assert.notEqual(hash, await passwordHash(password));
});
test('outbound DNS screening rejects private, mapped and mixed resolutions', async () => {
  for (const ip of [
    '127.0.0.1',
    '::1',
    '::ffff:127.0.0.1',
    '10.1.2.3',
    '169.254.169.254',
    '100.64.1.2',
    'fc00::1',
    '192.0.2.1',
  ])
    assert.equal(publicAddress(ip), false, ip);
  assert.equal(publicAddress('8.8.8.8'), true);
  await assert.rejects(
    resolvePublic(new URL('https://example.com'), ['example.com'], (async () => [
      { address: '8.8.8.8', family: 4 },
      { address: '10.0.0.1', family: 4 },
    ]) as any),
    /non-public/,
  );
  await assert.rejects(resolvePublic(new URL('https://8.8.8.8'), []), /allow|EGRESS/);
  await assert.rejects(resolvePublic(new URL('http://8.8.8.8'), ['8.8.8.8']), /HTTPS/);
});
test('NVD normalization preserves per-CPE ranges and does not flatten AND conditions', () => {
  const input = {
    cve: {
      id: 'CVE-2026-12345',
      vulnStatus: 'Analyzed',
      published: '2026-10-20T01:00:00',
      lastModified: '2026-10-20T01:00:00',
      descriptions: [{ lang: 'en', value: 'Test' }],
      metrics: { cvssMetricV31: [{ cvssData: { version: '3.1', baseScore: 9.8, vectorString: '' } }] },
      configurations: [
        {
          nodes: [
            {
              operator: 'OR',
              cpeMatch: [{ vulnerable: true, criteria: cpe('*'), versionEndExcluding: '2.0' }],
            },
          ],
        },
      ],
    },
  };
  assert.equal(normalizeNvd(input, 'source')?.cpeMatchDetails?.[0].range?.versionEndExcluding, '2.0');
  input.cve.configurations[0].nodes[0].operator = 'AND';
  assert.equal(normalizeNvd(input, 'source')?.applicabilityRequiresReview, true);
  assert.equal(normalizeNvd(input, 'source')?.cpeMatches.length, 1);
});
test('unscored NVD vulnerabilities remain matchable without inventing a severity', () => {
  const input = {
    cve: {
      id: 'CVE-2026-12345',
      vulnStatus: 'Analyzed',
      published: '2026-10-20T01:00:00Z',
      lastModified: '2026-10-20T01:00:00Z',
      descriptions: [{ lang: 'en', value: 'Unscored vulnerability' }],
      metrics: {},
      configurations: [{ nodes: [{ operator: 'OR', cpeMatch: [{ vulnerable: true, criteria: cpe('*') }] }] }],
    },
  };
  const normalized = normalizeNvd(input, 'nvd');
  assert.equal(normalized?.cvss.version, 'UNKNOWN');
  assert.equal(normalized?.cvss.severity, 'UNKNOWN');
  assert.equal(normalized?.cvss.score, 0);
  assert.equal(normalized?.cpeMatches.length, 1);
});
test('NVD uses bounded large-page requests and honors rate-limit retries', async () => {
  const headers: Record<string, string>[] = [];
  const requestLimits: { timeoutMs?: number; socketTimeoutMs?: number; maxResponseBytes?: number }[] = [];
  const feed = {
    id: 'nvd',
    name: 'NVD',
    type: 'NVD_API' as const,
    url: 'https://services.nvd.nist.gov/rest/json/cves/2.0',
    authType: 'NONE' as const,
    authSecretKey: '',
    rateLimitPerMin: 10,
    enabled: true,
    healthStatus: 'UNTESTED' as const,
    lastSync: null,
    latencyMs: 0,
    vendorSeed: true,
    itemCountLastRun: 0,
    ssrfValidated: false,
    etag: 'stale-page-etag',
  };
  await ingestFeed(
    feed,
    24,
    async (_url, options) => {
      headers.push(options?.headers || {});
      requestLimits.push({
        timeoutMs: options?.timeoutMs,
        socketTimeoutMs: options?.socketTimeoutMs,
        maxResponseBytes: options?.maxResponseBytes,
      });
      return {
        status: 200,
        body: JSON.stringify({ vulnerabilities: [], totalResults: 0, startIndex: 0 }),
        headers: {},
      };
    },
    config,
  );
  assert.equal(headers.length, 1);
  assert.equal(headers[0]['If-None-Match'], undefined);
  assert.deepEqual(requestLimits, [
    { timeoutMs: 60000, socketTimeoutMs: 30000, maxResponseBytes: 16 * 1024 * 1024 },
  ]);

  const retryDelays: number[] = [];
  let retryCalls = 0;
  await ingestFeed(
    feed,
    24,
    async () => {
      retryCalls++;
      return retryCalls === 1
        ? { status: 429, body: '', headers: { 'retry-after': '2' } }
        : {
            status: 200,
            body: JSON.stringify({ vulnerabilities: [], totalResults: 0, startIndex: 0 }),
            headers: {},
          };
    },
    config,
    async <T = void>(ms = 0, value?: T): Promise<T> => {
      retryDelays.push(ms);
      return value as T;
    },
  );
  assert.equal(retryCalls, 2);
  assert.deepEqual(retryDelays, [6500]);

  const timeoutDelays: number[] = [];
  let timeoutCalls = 0;
  await ingestFeed(
    feed,
    24,
    async () => {
      timeoutCalls++;
      if (timeoutCalls === 1) throw new Error('Outbound request timed out');
      return {
        status: 200,
        body: JSON.stringify({ vulnerabilities: [], totalResults: 0, startIndex: 0 }),
        headers: {},
      };
    },
    config,
    async <T = void>(ms = 0, value?: T): Promise<T> => {
      timeoutDelays.push(ms);
      return value as T;
    },
  );
  assert.equal(timeoutCalls, 2);
  assert.deepEqual(timeoutDelays, [6500]);
});

test('PostgreSQL API, auth, pipeline, durable delivery and recovery', { skip: !database }, async (t) => {
  const base = createPool(database!);
  const schema = 'test_' + randomUUID().replaceAll('-', '');
  await base.query(`CREATE SCHEMA ${schema}`);
  const url = new URL(database!);
  url.searchParams.set('options', `-c search_path=${schema}`);
  const pool = createPool(url.href);
  let capturedBody = '',
    capturedHeaders: Record<string, string> = {},
    responseStatus = 200,
    responseBody = '[]';
  const requester: Requester = async (_url, options) => {
    capturedBody = options?.body || '';
    capturedHeaders = options?.headers || {};
    return { status: responseStatus, body: responseBody, headers: {} };
  };
  try {
    await migrate(pool);
    await migrate(pool);
    await createUser(pool, 'admin', password, 'ADMIN');
    await createUser(pool, 'operator', password, 'OPERATOR');
    await createUser(pool, 'viewer', password, 'VIEWER');
    const app = createApp(pool, config, requester),
      admin = supertest.agent(app),
      viewer = supertest.agent(app),
      operator = supertest.agent(app);
    const login = async (agent: ReturnType<typeof supertest.agent>, username: string) => {
      const r = await agent.post('/api/login').set('Origin', config.APP_ORIGIN).send({ username, password });
      assert.equal(r.status, 200, JSON.stringify(r.body));
      return r.body.csrfToken as string;
    };
    const csrf = await login(admin, 'admin'),
      viewCsrf = await login(viewer, 'viewer'),
      opCsrf = await login(operator, 'operator');
    const post = (route: string, data: any = {}) =>
      admin.post(route).set('Origin', config.APP_ORIGIN).set('x-csrf-token', csrf).send(data);
    const command = (action: string, data?: any, id?: string) => post('/api/commands', { action, data, id });
    await t.test('unauthenticated reads, CSRF and foreign origins are rejected', async () => {
      assert.equal((await supertest(app).get('/api/state')).status, 401);
      assert.equal(
        (
          await admin
            .post('/api/commands')
            .set('Origin', config.APP_ORIGIN)
            .send({ action: 'asset.delete', id: 'x' })
        ).status,
        403,
      );
      assert.equal(
        (
          await admin
            .post('/api/commands')
            .set('Origin', 'https://evil.test')
            .set('x-csrf-token', csrf)
            .send({})
        ).status,
        403,
      );
      const response = await admin.get('/api/state');
      assert.equal(response.status, 200);
      assert.match(response.headers['content-security-policy'], /script-src 'self'/);
      assert.equal(response.headers['cache-control'], 'no-store');
      assert.equal(response.body.watchlist.length, 0);
    });
    await t.test('pipeline stop enforces authentication, CSRF and operator roles', async () => {
      const path = '/api/pipeline/missing/stop';
      assert.equal((await supertest(app).post(path).set('Origin', config.APP_ORIGIN).send({})).status, 401);
      assert.equal((await admin.post(path).set('Origin', config.APP_ORIGIN).send({})).status, 403);
      assert.equal(
        (await viewer.post(path).set('Origin', config.APP_ORIGIN).set('x-csrf-token', viewCsrf).send({}))
          .status,
        403,
      );
      assert.equal(
        (await operator.post(path).set('Origin', config.APP_ORIGIN).set('x-csrf-token', opCsrf).send({}))
          .status,
        404,
      );
    });
    await t.test('roles enforce write and administration boundaries', async () => {
      assert.equal(
        (
          await viewer
            .post('/api/pipeline')
            .set('Origin', config.APP_ORIGIN)
            .set('x-csrf-token', viewCsrf)
            .send({})
        ).status,
        403,
      );
      assert.equal(
        (
          await operator
            .post('/api/commands')
            .set('Origin', config.APP_ORIGIN)
            .set('x-csrf-token', opCsrf)
            .send({ action: 'settings.save', data: { schedulerEnabled: true } })
        ).status,
        403,
      );
      assert.equal((await operator.get('/api/users')).status, 403);
    });
    await t.test('validation rejects malformed data and unsupported feed adapters', async () => {
      assert.equal((await command('asset.import', [null])).status, 400);
      assert.equal((await command('feed.save', { url: 'http://127.0.0.1' })).status, 400);
      const bad = await command('settings.save', {
        ssrfProtection: { blockPrivateIps: false, blockLoopback: true, allowRedirects: false },
      });
      assert.equal(bad.status, 400);
      const feed = await command('feed.save', {
        name: 'unsupported',
        type: 'RSS_ATOM',
        url: 'https://8.8.8.8',
        authType: 'NONE',
        rateLimitPerMin: 1,
        enabled: false,
      });
      assert.equal(feed.status, 400);
    });
    await t.test('records persist and feed secrets are encrypted and redacted', async () => {
      assert.equal(
        (
          await command('feed.save', {
            name: 'fixture',
            type: 'JSON_SEARCH_API',
            url: 'https://8.8.8.8/feed',
            authType: 'API_KEY',
            authSecretKey: 'fixture-secret',
            rateLimitPerMin: 10,
            enabled: false,
          })
        ).status,
        200,
      );
      const saved = (await list<any>(pool, 'feeds'))[0];
      assert.notEqual(saved.authSecretKey, 'fixture-secret');
      assert.equal(decrypt(saved.authSecretKey, key, `feed:${saved.id}`), 'fixture-secret');
      const snapshot = (await admin.get('/api/state')).body;
      assert.equal(snapshot.feeds[0].authSecretKey, undefined);
      const edit = {
        name: saved.name,
        type: saved.type,
        url: saved.url + '-changed',
        authType: saved.authType,
        rateLimitPerMin: 10,
        enabled: false,
      };
      assert.equal((await command('feed.save', edit, saved.id)).status, 200);
      assert.equal((await get<any>(pool, 'feeds', saved.id)).authSecretKey, '');
      assert.equal(
        (await command('feed.save', { ...edit, authSecretKey: 'fixture-secret' }, saved.id)).status,
        200,
      );

      assert.equal((await supertest(createApp(pool, config, requester)).get('/ready')).status, 200);
    });
    await t.test(
      'pipeline creates a pending advisory and outbox atomically; reruns do not duplicate',
      async () => {
        assert.equal(
          (
            await command('asset.save', {
              vendor: 'example',
              product: 'widget',
              cpes: [cpe('1.0')],
              assetTag: 'asset-one',
              ownerGroup: 'test',
              active: true,
            })
          ).status,
          200,
        );
        assert.equal((await command('cve.save', fixture())).status, 200);
        assert.equal(
          (
            await command('recipient.save', {
              name: 'Recipient',
              email: 'test@example.com',
              role: 'SOC',
              subscriptionTier: 'ALL_SEVERITIES',
              enabled: true,
            })
          ).status,
          200,
        );
        assert.equal((await command('settings.save', { autoDispatchEnabled: true })).status, 200);
        const run = await post('/api/pipeline', {});
        assert.equal(run.status, 202);
        assert.equal(run.body.status, 'QUEUED');
        await processPipeline(pool, config, requester);
        const snapshot = (await admin.get('/api/state')).body;
        assert.equal(snapshot.findings.length, 1);
        assert.equal(snapshot.advisories.length, 1);
        assert.equal(snapshot.advisories[0].deliveryStatus, 'PENDING');
        assert.equal(snapshot.emailLogs[0].status, 'QUEUED');
        assert.equal(snapshot.alertedCves.length, 0);
        await queueRun(pool, 24, 'test');
        await processPipeline(pool, config, requester);
        assert.equal((await pool.query('SELECT count(*)::int AS count FROM outbox')).rows[0].count, 1);
      },
    );
    await t.test(
      'failed transport retries durably, acceptance is recorded without claiming inbox delivery',
      async () => {
        await deliverNext(pool, config, requester, async () => {
          throw new Error('temporary transport outage');
        });
        assert.equal((await list<any>(pool, 'emailLogs'))[0].status, 'RETRYING');
        await pool.query("UPDATE outbox SET next_attempt=now() WHERE status='QUEUED'");
        await deliverNext(pool, config, requester, async () => '<provider-message-id>');
        const snapshot = (await admin.get('/api/state')).body;
        assert.equal(snapshot.emailLogs[0].status, 'ACCEPTED');
        assert.equal(snapshot.advisories[0].deliveryStatus, 'ACCEPTED');
        assert.equal(snapshot.alertedCves[0].dispatchCount, 1);
      },
    );
    await t.test('webhook signs timestamp and exact body; nonretryable rejection is terminal', async () => {
      assert.equal(
        (
          await command('webhook.save', {
            name: 'test-hook',
            url: 'https://8.8.8.8/hook',
            provider: 'GENERIC_HMAC',
            secretToken: 'webhook-fixture-secret-at-least-32-characters',
            enabled: true,
            events: ['ALL'],
          })
        ).status,
        200,
      );
      const hook = (await list<WebhookEndpoint>(pool, 'webhooks'))[0];
      assert.notEqual(hook.url, 'https://8.8.8.8/hook');
      assert.equal((await post(`/api/webhooks/${hook.id}/test`)).status, 202);
      await deliverNext(pool, config, requester, async () => 'unused');
      assert.equal(
        capturedHeaders['x-vulnstream-signature'],
        'sha256=' +
          createHmac('sha256', 'webhook-fixture-secret-at-least-32-characters')
            .update(`${capturedHeaders['x-vulnstream-timestamp']}.${capturedBody}`)
            .digest('hex'),
      );
      responseStatus = 400;
      await post(`/api/webhooks/${hook.id}/test`);
      await deliverNext(pool, config, requester, async () => 'unused');
      assert.equal((await list<any>(pool, 'webhookLogs'))[0].status, 'FAILED');
      responseStatus = 200;
    });
    await t.test('running pipeline recovers after crash and audit is content-verifiable', async () => {
      const queued = await queueRun(pool, 24, 'test');
      await transaction(pool, (db) => put(db, 'executions', queued.id, { ...queued, status: 'RUNNING' }));
      await processPipeline(pool, config, requester);
      assert.equal((await get<any>(pool, 'executions', queued.id)).status, 'COMPLETED');
      const logs = (await admin.get('/api/state')).body.auditLogs;
      assert.equal(verifyAuditChain(logs), true);
      await assert.rejects(
        pool.query('UPDATE audit SET data=data || \'{"event":"tamper"}\'::jsonb'),
        /append-only/,
      );
    });
    await t.test(
      'live adapter data is persisted; feed failure is recorded instead of invented success',
      async () => {
        const feed = (await list<any>(pool, 'feeds'))[0];
        await command('feed.toggle', undefined, feed.id);
        responseBody = JSON.stringify([{ ...fixture(), cveId: 'CVE-2026-23456' }]);
        await queueRun(pool, 24, 'test');
        await processPipeline(pool, config, requester);
        assert.ok(await get(pool, 'cveData', 'CVE-2026-23456'));
        assert.equal((await get<any>(pool, 'feeds', feed.id)).healthStatus, 'HEALTHY');
        responseStatus = 503;
        const failed = await queueRun(pool, 24, 'test');
        await processPipeline(pool, config, requester);
        assert.equal((await get<any>(pool, 'executions', failed.id)).status, 'FAILED');
        assert.equal((await get<any>(pool, 'feeds', feed.id)).healthStatus, 'DOWN');
        responseStatus = 200;
        responseBody = '[]';
        await command('feed.toggle', undefined, feed.id);
      },
    );
    await t.test(
      'disabled recipients prevent queued delivery and concurrent workers claim distinct jobs',
      async () => {
        const recipient = (await list<any>(pool, 'recipients'))[0];
        await command('recipient.toggle', undefined, recipient.id);
        let mailCalls = 0;
        await Promise.all([
          deliverNext(pool, config, requester, async () => {
            mailCalls++;
            return 'unexpected';
          }),
          deliverNext(pool, config, requester, async () => {
            mailCalls++;
            return 'unexpected';
          }),
        ]);
        assert.equal(mailCalls, 0);
      },
    );
    await t.test('password change revokes all sessions; expired sessions fail closed', async () => {
      const changed = await post('/api/password', {
        currentPassword: password,
        newPassword: password + 'changed',
      });
      assert.equal(changed.status, 200);
      assert.equal((await admin.get('/api/state')).status, 401);
      await pool.query("UPDATE sessions SET expires_at=now()-interval '1 second'");
      assert.equal((await viewer.get('/api/state')).status, 401);
    });
    await t.test('login throttling is stored in PostgreSQL', async () => {
      for (let i = 0; i < 5; i++)
        assert.equal(
          (
            await supertest(app)
              .post('/api/login')
              .set('Origin', config.APP_ORIGIN)
              .send({ username: 'unknown', password: 'wrong' })
          ).status,
          401,
        );
      assert.equal(
        (
          await supertest(app)
            .post('/api/login')
            .set('Origin', config.APP_ORIGIN)
            .send({ username: 'unknown', password: 'wrong' })
        ).status,
        429,
      );
    });
  } finally {
    await pool.end();
    await base.query(`DROP SCHEMA ${schema} CASCADE`);
    await base.end();
  }
});
