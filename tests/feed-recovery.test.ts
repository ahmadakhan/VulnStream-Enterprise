import { test } from 'node:test';
import assert from 'node:assert/strict';
import { recoveryAt, recoveryDue } from '../server/feedRecovery';
import { feedSchema } from '../server/validation';
import { ingestFeed } from '../server/ingestion';
import type { ThreatFeed } from '../src/types';
import { loadConfig } from '../server/config';
const feed = { id: 'source', name: 'Source', type: 'JSON_SEARCH_API', url: 'https://example.com/feed', authType: 'NONE', rateLimitPerMin: 60, enabled: true, healthStatus: 'DOWN', recoveryDelayMinutes: 2 } as ThreatFeed;
test('failed sources recover at their persisted deadline and back off to one hour', () => {
  const now = Date.now();
  const deadline = recoveryAt(feed, 1, now);
  assert.equal(Date.parse(deadline), now + 120000);
  assert.equal(recoveryDue({ ...feed, circuitOpenUntil: deadline }, now), false);
  assert.equal(recoveryDue({ ...feed, circuitOpenUntil: deadline }, now + 120000), true);
  assert.equal(recoveryDue({ ...feed, enabled: false, circuitOpenUntil: deadline }, now + 120000), false);
  assert.equal(recoveryDue({ ...feed, healthStatus: 'HEALTHY', circuitOpenUntil: deadline }, now + 120000), false);
  assert.equal(Date.parse(recoveryAt(feed, 100, now)), now + 3600000);
});
test('feed settings validate bounds and retain legacy timeout behavior', () => {
  assert.equal(feedSchema.parse(feed).requestTimeoutSeconds, undefined);
  assert.equal(feedSchema.safeParse({ ...feed, requestTimeoutSeconds: 0 }).success, false);
  assert.equal(feedSchema.safeParse({ ...feed, recoveryDelayMinutes: 61 }).success, false);
});
test('custom timeout is used and a previously timed out source can ingest again', async () => {
  const config = loadConfig({ NODE_ENV: 'test', DATABASE_URL: 'postgres://unused', APP_ORIGIN: 'http://localhost', ENCRYPTION_KEY: Buffer.alloc(32, 1).toString('base64') });
  let fail = true;
  const request = async (_url: string, options: any) => {
    assert.equal(options.timeoutMs, 45000);
    assert.equal(options.socketTimeoutMs, 45000);
    if (fail) throw new Error('Outbound request timed out');
    return { status: 200, body: '[]', headers: {} };
  };
  const source = { ...feed, requestTimeoutSeconds: 45 };
  await assert.rejects(ingestFeed(source, 24, request, config), /timed out/);
  fail = false;
  assert.equal((await ingestFeed(source, 24, request, config)).count, 0);
});
