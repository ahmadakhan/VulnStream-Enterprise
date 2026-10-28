import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import supertest from 'supertest';
import pg from 'pg';
import { z } from 'zod';
import { createApp } from '../server/app.ts';
import { createUser } from '../server/auth.ts';
import { loadConfig } from '../server/config.ts';
import { createPool, migrate } from '../server/db.ts';
import { describeError, describeFailureSummary } from '../server/events.ts';

/**
 * Operator delivery actions driven by a URL parameter, and the failure label
 * written to the operational event log.
 *
 * Both defects were found by clicking through the running application. A
 * malformed delivery id in the address bar answered every email action with
 * `500 Server operation failed` and wrote an incident-log entry, because the
 * value went straight into a uuid column parameter. Each such request also
 * created its own event message, drowning the log the message column exists to
 * make searchable.
 */

async function withDatabase<T>(fn: (pool: pg.Pool) => Promise<T>): Promise<T | null> {
  if (!process.env.TEST_DATABASE_URL) return null;
  const master = createPool(process.env.TEST_DATABASE_URL);
  const schema = `delivery_ops_${randomBytes(10).toString('hex')}`;
  let pool: pg.Pool | undefined;
  try {
    await master.query(`CREATE SCHEMA ${schema}`);
    pool = new pg.Pool({
      connectionString: process.env.TEST_DATABASE_URL,
      options: `-c search_path=${schema}`,
      max: 4,
      connectionTimeoutMillis: 3000,
    });
    await migrate(pool);
    return await fn(pool);
  } finally {
    await pool?.end();
    await master.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    await master.end();
  }
}

async function adminAgent(pool: pg.Pool) {
  const config = loadConfig({
    ...process.env,
    DATABASE_URL: process.env.TEST_DATABASE_URL,
    APP_ORIGIN: 'http://127.0.0.1:3998',
    ENCRYPTION_KEY: randomBytes(32).toString('base64'),
    WORKER_ENABLED: 'false',
  });
  await createUser(pool, 'delivery-admin', 'Disposable-delivery-test-password-2026!', 'ADMIN');
  const app = createApp(pool, config, async () => ({ status: 200, headers: {}, body: '[]' }));
  const agent = supertest.agent(app);
  const login = await agent
    .post('/api/login')
    .set('Origin', config.APP_ORIGIN)
    .send({ username: 'delivery-admin', password: 'Disposable-delivery-test-password-2026!' });
  assert.equal(login.status, 200);
  return { agent, csrf: login.body.csrfToken as string, origin: config.APP_ORIGIN };
}

test(
  'a malformed delivery id is a client error on every delivery action, never a 500',
  { skip: !process.env.TEST_DATABASE_URL },
  async () => {
    const outcome = await withDatabase(async (pool) => {
      const { agent, csrf, origin } = await adminAgent(pool);
      const send = (method: 'post' | 'delete', path: string) =>
        agent[method](path).set('Origin', origin).set('x-csrf-token', csrf).send({});
      const cases = [
        ['post', '/api/email/not-a-uuid/approve'],
        ['post', '/api/email/not-a-uuid/reject'],
        ['post', '/api/email/not-a-uuid/retry'],
        ['delete', '/api/email/not-a-uuid'],
      ] as const;
      for (const [method, path] of cases) {
        const response = await send(method, path);
        assert.ok(response.status < 500, `${method.toUpperCase()} ${path} returned ${response.status}`);
        assert.equal(response.status, 400, `${method.toUpperCase()} ${path} → ${response.status}`);
        assert.match(String(response.body.error), /Invalid identifier/);
      }
      // A well-formed but unknown id keeps its existing "nothing to act on"
      // contract, so the guard did not swallow the normal path.
      assert.equal((await send('post', `/api/email/${randomUUID()}/approve`)).status, 409);
      assert.equal((await send('delete', `/api/email/${randomUUID()}`)).status, 409);
      // None of the rejected requests may look like an incident.
      const incidents = await pool.query(
        "SELECT count(*)::int AS count FROM operational_events WHERE code='http.request_failed'",
      );
      assert.equal(incidents.rows[0].count, 0, 'a client error must not be recorded as a server failure');
    });
    assert.notEqual(outcome, null);
  },
);

test(
  'an operator id that is not a uuid is a 400, and a valid one still updates the operator',
  { skip: !process.env.TEST_DATABASE_URL },
  async () => {
    const outcome = await withDatabase(async (pool) => {
      const { agent, csrf, origin } = await adminAgent(pool);
      const malformed = await agent
        .patch('/api/users/not-a-uuid')
        .set('Origin', origin)
        .set('x-csrf-token', csrf)
        .send({ role: 'VIEWER', disabled: false });
      assert.equal(malformed.status, 400);

      const created = await agent
        .post('/api/users')
        .set('Origin', origin)
        .set('x-csrf-token', csrf)
        .send({ username: 'viewer-one', password: 'Disposable-viewer-password-2026!', role: 'VIEWER' });
      assert.equal(created.status, 201);
      const viewer = (await pool.query("SELECT id FROM users WHERE username='viewer-one'")).rows[0];
      const updated = await agent
        .patch(`/api/users/${viewer.id}`)
        .set('Origin', origin)
        .set('x-csrf-token', csrf)
        .send({ role: 'OPERATOR', disabled: false });
       assert.equal(updated.status, 200);
     });
     assert.notEqual(outcome, null);
   },
);

test(
  'an operator id that is not a uuid is a 400, and a valid one is deleted from the workspace',
  { skip: !process.env.TEST_DATABASE_URL },
  async () => {
    const outcome = await withDatabase(async (pool) => {
      const { agent, csrf, origin } = await adminAgent(pool);
      const malformed = await agent
        .delete('/api/users/not-a-uuid')
        .set('Origin', origin)
        .set('x-csrf-token', csrf)
        .send({});
      assert.equal(malformed.status, 400);

      const created = await agent
        .post('/api/users')
        .set('Origin', origin)
        .set('x-csrf-token', csrf)
        .send({ username: 'viewer-two', password: 'Disposable-viewer-password-2026!', role: 'VIEWER' });
      assert.equal(created.status, 201);
      const viewer = (await pool.query("SELECT id FROM users WHERE username='viewer-two'")).rows[0];
      const deleted = await agent
        .delete(`/api/users/${viewer.id}`)
        .set('Origin', origin)
        .set('x-csrf-token', csrf)
        .send({});
      assert.equal(deleted.status, 200);
      const remaining = await pool.query("SELECT id FROM users WHERE username='viewer-two'");
      assert.equal(remaining.rowCount, 0);

      // An administrator cannot delete their own account.
      const adminRow = (await pool.query("SELECT id FROM users WHERE username='delivery-admin'")).rows[0];
      const selfDelete = await agent
        .delete(`/api/users/${adminRow.id}`)
        .set('Origin', origin)
        .set('x-csrf-token', csrf)
        .send({});
      assert.equal(selfDelete.status, 400);
      // The actor account must still exist.
      const stillThere = await pool.query("SELECT id FROM users WHERE username='delivery-admin'");
      assert.equal(stillThere.rowCount, 1);
    });
    assert.notEqual(outcome, null);
  },
);

test('the event-log failure label is a stable summary, not the error text', () => {
  const databaseError = Object.assign(new Error('invalid input syntax for type uuid: "not-a-uuid"'), {
    code: '22P02',
    name: 'error',
  });
  assert.equal(describeFailureSummary(databaseError), 'error');
  // The label must not vary with the caller-supplied value in the message.
  const other = Object.assign(new Error('invalid input syntax for type uuid: "x"'), { code: '22P02', name: 'error' });
  assert.equal(describeFailureSummary(databaseError), describeFailureSummary(other));

  const validation = z.uuid().safeParse('nope');
  assert.equal(validation.success, false);
  assert.equal(describeFailureSummary(validation.error), 'Validation failed');
  assert.equal(describeFailureSummary('a string'), 'Request failed');
  assert.equal(describeFailureSummary(new RangeError('boom')), 'RangeError');
  // The full message still reaches the event context, where it is not indexed
  // and not rendered as the row title.
  assert.match(String(describeError(databaseError).error), /not-a-uuid/);
});
