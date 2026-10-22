import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import supertest from 'supertest';
import { DEFAULT_EMAIL_CONFIG } from '../shared/state.ts';
import { EmailProviderError, sendProviderEmail } from '../server/emailProviders.ts';
import { createMailSender, deliverNext, type Job } from '../server/delivery';
import { createPool, migrate, get, list } from '../server/db.ts';
import { createApp } from '../server/app';
import { createUser } from '../server/auth';
import { loadConfig } from '../server/config.ts';
import { decrypt } from '../server/secrets.ts';
import type { EmailConfiguration, EmailDeliveryLog } from '../src/types/index.ts';

const token = 'test-provider-token';
const job: Job = {
  id: randomUUID(),
  dedupe_key: 'test',
  channel: 'email',
  target_id: 'test',
  advisory_id: 'TEST',
  attempts: 1,
  lock_token: 'test',
  payload: {
    recipientEmail: 'recipient@example.invalid',
    subject: 'Security notice',
    text: 'Test text',
    html: '<p>Test text</p>',
    cveIds: [],
  },
};
const configuration = (provider: EmailConfiguration['provider']): EmailConfiguration => ({
  ...DEFAULT_EMAIL_CONFIG,
  provider,
  fromEmail: 'security@example.invalid',
  fromName: 'Security',
  mailgunDomain: 'mg.example.invalid',
});

test('provider requests preserve recipients and body and validate native acceptance contracts', async (t) => {
  for (const provider of ['MAILGUN', 'MAILTRAP', 'SENDGRID', 'POSTMARK'] as const) {
    await t.test(provider, async () => {
      const config = configuration(provider);
      const result = await sendProviderEmail(config, token, job, async (url, options) => {
        assert.equal(options?.method, 'POST');
        assert.ok(options.body?.includes(job.payload.subject));
        assert.ok(options.body?.includes(job.payload.recipientEmail!));
        assert.ok(options.body?.includes(job.id));
        assert.ok(!options.body?.includes(token));
        const headers = options.headers!;
        if (provider === 'MAILGUN') {
          assert.equal(url, 'https://api.mailgun.net/v3/mg.example.invalid/messages');
          assert.equal(headers.Authorization, `Basic ${Buffer.from(`api:${token}`).toString('base64')}`);
          assert.match(headers['content-type'], /^multipart\/form-data; boundary=/);
          assert.match(options.body!, /name="text"\r\n\r\nTest text/);
          return { status: 200, headers: {}, body: JSON.stringify({ id: 'accepted-id' }) };
        }
        const payload = JSON.parse(options.body!);
        if (provider === 'POSTMARK') {
          assert.equal(url, 'https://api.postmarkapp.com/email');
          assert.equal(headers['X-Postmark-Server-Token'], token);
          assert.equal(headers.Authorization, undefined);
          assert.equal(payload.MessageStream, 'outbound');
          return {
            status: 200,
            headers: {},
            body: JSON.stringify({ ErrorCode: 0, MessageID: 'accepted-id' }),
          };
        }
        assert.equal(headers.Authorization, `Bearer ${token}`);
        if (provider === 'SENDGRID') {
          assert.equal(url, 'https://api.sendgrid.com/v3/mail/send');
          assert.equal(payload.personalizations[0].to[0].email, job.payload.recipientEmail);
          assert.deepEqual(
            payload.content.map((entry: any) => entry.type),
            ['text/plain', 'text/html'],
          );
          return { status: 202, headers: { 'x-message-id': 'accepted-id' }, body: '' };
        }
        assert.equal(url, 'https://send.api.mailtrap.io/api/send');
        assert.equal(payload.to[0].email, job.payload.recipientEmail);
        return {
          status: 200,
          headers: {},
          body: JSON.stringify({ success: true, message_ids: ['accepted-id'] }),
        };
      });
      assert.equal(result, 'accepted-id');
    });
  }
});
test('region and sandbox settings select the correct fixed endpoints', async () => {
  await sendProviderEmail({ ...configuration('MAILGUN'), mailgunRegion: 'EU' }, token, job, async (url) => {
    assert.match(url, /^https:\/\/api\.eu\.mailgun\.net\//);
    return { status: 200, headers: {}, body: '{"id":"eu-id"}' };
  });
  await sendProviderEmail(
    { ...configuration('MAILTRAP'), mailtrapMode: 'SANDBOX', mailtrapInboxId: '12345' },
    token,
    job,
    async (url) => {
      assert.equal(url, 'https://sandbox.api.mailtrap.io/api/send/12345');
      return { status: 200, headers: {}, body: '{"success":true,"message_ids":["sandbox-id"]}' };
    },
  );
});
test('HTTP failures honor Retry-After and never expose provider bodies or tokens', async () => {
  const before = Date.now();
  await assert.rejects(
    sendProviderEmail(configuration('MAILTRAP'), token, job, async () => ({
      status: 429,
      headers: { 'retry-after': '120' },
      body: `secret ${token}`,
    })),
    (error: any) => {
      assert.ok(error instanceof EmailProviderError);
      assert.equal(error.status, 429);
      assert.ok(error.retryAt >= before + 120000);
      assert.ok(!error.message.includes(token));
      return true;
    },
  );
  for (const body of ['not-json', '{}', '{"ErrorCode":406,"Message":"suppressed"}'])
    await assert.rejects(
      sendProviderEmail(configuration('POSTMARK'), token, job, async () => ({
        status: 200,
        headers: {},
        body,
      })),
      EmailProviderError,
    );
});

test(
  'email configuration is admin-only, encrypted, redacted, persisted, and used by the outbox',
  { skip: !process.env.TEST_DATABASE_URL },
  async () => {
    const schema = `email_${randomBytes(6).toString('hex')}`;
    const base = createPool(process.env.TEST_DATABASE_URL!);
    await base.query(`CREATE SCHEMA ${schema}`);
    const url = new URL(process.env.TEST_DATABASE_URL!);
    url.searchParams.set('options', `-c search_path=${schema}`);
    const config = loadConfig({
      NODE_ENV: 'test',
      DATABASE_URL: url.href,
      APP_ORIGIN: 'http://localhost',
      ENCRYPTION_KEY: randomBytes(32).toString('base64'),
      WORKER_ENABLED: 'false',
    });
    const pool = createPool(url.href);
    try {
      await migrate(pool);
      const password = 'Disposable-test-password-2026!';
      await createUser(pool, 'email-admin', password, 'ADMIN');
      await createUser(pool, 'email-operator', password, 'OPERATOR');
      const request = async (endpoint: string, options?: any) => {
        assert.equal(endpoint, 'https://api.sendgrid.com/v3/mail/send');
        assert.equal(options.headers.Authorization, `Bearer ${token}`);
        return { status: 202, headers: { 'x-message-id': 'outbox-accepted-id' }, body: '' };
      };
      const app = createApp(pool, config, request);
      const admin = supertest.agent(app),
        operator = supertest.agent(app);
      const login = async (agent: typeof admin, username: string) =>
        (await agent.post('/api/login').set('Origin', config.APP_ORIGIN).send({ username, password })).body
          .csrfToken;
      const csrf = await login(admin, 'email-admin'),
        operatorCsrf = await login(operator, 'email-operator');
      const command = (data: any) =>
        admin
          .post('/api/commands')
          .set('Origin', config.APP_ORIGIN)
          .set('x-csrf-token', csrf)
          .send({ action: 'email.configure', data });
      const settings = { ...configuration('SENDGRID'), apiKey: token };
      assert.equal(
        (
          await operator
            .post('/api/commands')
            .set('Origin', config.APP_ORIGIN)
            .set('x-csrf-token', operatorCsrf)
            .send({ action: 'email.configure', data: settings })
        ).status,
        403,
      );
      assert.equal((await command(settings)).status, 200);
      const stored = await get<EmailConfiguration>(pool, 'emailConfig', 'main');
      assert.ok(stored);
      assert.notEqual(stored.apiKey, token);
      assert.equal(decrypt(stored.apiKey, config.ENCRYPTION_KEY, 'email-provider:SENDGRID'), token);
      const snapshot = (await admin.get('/api/state')).body;
      assert.equal(snapshot.emailConfig.apiKey, '');
      assert.equal(snapshot.emailConfig.hasApiKey, true);
      assert.ok(!JSON.stringify(snapshot).includes(token));
      assert.equal((await command({ ...settings, apiKey: '' })).status, 200);
      assert.equal((await get<EmailConfiguration>(pool, 'emailConfig', 'main'))?.apiKey, stored.apiKey);
      assert.equal((await command({ ...settings, provider: 'POSTMARK', apiKey: '' })).status, 400);
      assert.equal((await command({ ...settings, fromName: 'Injected\r\nHeader' })).status, 400);
      const queued = await admin
        .post('/api/test-email')
        .set('Origin', config.APP_ORIGIN)
        .set('x-csrf-token', csrf)
        .send({ email: job.payload.recipientEmail });
      assert.equal(queued.status, 202);
      const queuedPayload = (await pool.query('SELECT payload FROM outbox')).rows[0].payload;
      assert.match(queuedPayload.subject, /^\[ADV-TEST\]/);
      assert.match(queuedPayload.text, /Advisory ID: ADV-TEST/);
      assert.match(queuedPayload.html, /ADV-TEST/);
      assert.ok(!queuedPayload.html.includes('{{advisory_id}}'));
      assert.equal(await deliverNext(pool, config, request, createMailSender(config, pool, request)), true);
      const logs = await list<EmailDeliveryLog>(pool, 'emailLogs');
      assert.equal(logs.length, 1);
      assert.equal(logs[0].provider, 'SendGrid');
      assert.equal(logs[0].status, 'ACCEPTED');
      assert.equal(
        (await pool.query('SELECT provider_id FROM outbox')).rows[0].provider_id,
        'outbox-accepted-id',
      );
      await admin
        .post('/api/test-email')
        .set('Origin', config.APP_ORIGIN)
        .set('x-csrf-token', csrf)
        .send({ email: job.payload.recipientEmail });
      const limited = async () => ({
        status: 429,
        headers: { 'retry-after': '180' },
        body: 'provider details are private',
      });
      const before = Date.now();
      assert.equal(await deliverNext(pool, config, limited, createMailSender(config, pool, limited)), true);
      const retry = (
        await pool.query("SELECT id,next_attempt,status,error FROM outbox WHERE status='QUEUED'")
      ).rows[0];
      assert.ok(retry);
      assert.ok(retry.next_attempt.getTime() >= before + 180000);
      assert.match(retry.error, /SendGrid.*429/);
      assert.ok(!retry.error.includes('provider details'));
      await pool.query('UPDATE outbox SET next_attempt=now() WHERE id=$1', [retry.id]);
      const rejected = async () => ({ status: 401, headers: {}, body: 'unauthorized' });
      await deliverNext(pool, config, rejected, createMailSender(config, pool, rejected));
      assert.equal(
        (await pool.query('SELECT status FROM outbox WHERE id=$1', [retry.id])).rows[0].status,
        'FAILED',
      );
      assert.equal((await get<EmailDeliveryLog>(pool, 'emailLogs', retry.id))?.provider, 'SendGrid');
    } finally {
      await pool.end();
      await base.query(`DROP SCHEMA ${schema} CASCADE`);
      await base.end();
    }
  },
);
