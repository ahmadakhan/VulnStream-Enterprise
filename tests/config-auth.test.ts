import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readCookie, requireRole } from '../server/auth.ts';
import { loadConfig } from '../server/config.ts';
import type { Request, Response } from 'express';

const baseEnv = {
  NODE_ENV: 'test',
  DATABASE_URL: 'postgres://user:pass@127.0.0.1:5432/db',
  APP_ORIGIN: 'http://127.0.0.1:8080',
  ENCRYPTION_KEY: 'QUJDREVGR0hJSktMTU5PUFFSU1QxMjM0NTY3ODkwMTI=',
};

const runRole = (roles: Parameters<typeof requireRole>, operator?: { role: string }) => {
  let error: unknown;
  let passed = false;
  const middleware = requireRole(...roles);
  middleware(
    { operator } as unknown as Request,
    {} as Response,
    ((nextError?: unknown) => {
      error = nextError;
      passed = !nextError;
    }) as never,
  );
  return { error, passed };
};

test('cookie parsing matches the exact cookie name and ignores prefix shadows', () => {
  assert.equal(readCookie('vulnstream=real-token', 'vulnstream'), 'real-token');
  assert.equal(
    readCookie('vulnstream_attacker=shadow; vulnstream=real-token', 'vulnstream'),
    'real-token',
  );
  assert.equal(readCookie('other=value; vulnstream=', 'vulnstream'), '');
  assert.equal(readCookie('vulnstream=first; vulnstream=second', 'vulnstream'), 'first');
  assert.equal(readCookie(undefined, 'vulnstream'), '');
  assert.equal(readCookie('malformed; =empty; vulnstream=ok', 'vulnstream'), 'ok');
});

test('requireRole fails closed when authentication middleware did not run', () => {
  const missing = runRole(['ADMIN']);
  assert.equal(missing.passed, false);
  assert.equal((missing.error as { status?: number }).status, 401);

  const denied = runRole(['ADMIN'], { role: 'VIEWER' });
  assert.equal(denied.passed, false);
  assert.equal((denied.error as { status?: number }).status, 403);

  const allowed = runRole(['ADMIN', 'OPERATOR'], { role: 'OPERATOR' });
  assert.equal(allowed.passed, true);
  assert.equal(allowed.error, undefined);
});

test('configuration rejects malformed database URLs and trust-all proxy settings', () => {
  assert.throws(() => loadConfig({ ...baseEnv, DATABASE_URL: 'not-a-url' }), /DATABASE_URL/);
  assert.throws(
    () => loadConfig({ ...baseEnv, DATABASE_URL: 'mysql://127.0.0.1/db' }),
    /DATABASE_URL/,
  );
  for (const trust of ['*', 'true', '0.0.0.0/0', '::/0']) {
    assert.throws(
      () => loadConfig({ ...baseEnv, TRUST_PROXY: trust }),
      /TRUST_PROXY/,
      `trust proxy ${trust} must be rejected`,
    );
  }
  assert.equal(loadConfig({ ...baseEnv, TRUST_PROXY: 'loopback,10.0.0.0/8' }).TRUST_PROXY, 'loopback,10.0.0.0/8');
  assert.equal(loadConfig(baseEnv).TRUST_PROXY, '');
});
