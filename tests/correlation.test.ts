import supertest from 'supertest';
import { createApp } from '../server/app.ts';
import { createUser } from '../server/auth.ts';
import { loadConfig } from '../server/config.ts';
import { CorrelationRuntime } from '../server/correlation/runtime.ts';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, readdir, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable, Writable } from 'node:stream';
import pg from 'pg';
import { AdvisoryInputSchema } from '../server/correlation/validation.ts';
import { evaluateVersion } from '../server/correlation/version.ts';
import { advisoryRecords, AdvisoryStreamProcessor } from '../server/correlation/stream.ts';
import { extractText } from '../server/correlation/extraction.ts';
import { CorrelationTelemetry } from '../server/correlation/telemetry.ts';
import { DeadLetterQueue } from '../server/correlation/deadLetter.ts';
import { AdvisoryIngestor } from '../server/correlation/ingest.ts';
import { PipelineSupervisor } from '../server/correlation/supervisor.ts';
import { createPool, migrate } from '../server/db.ts';
import { decrypt } from '../server/secrets.ts';
const silent = () =>
  new CorrelationTelemetry(
    new Writable({
      write(_chunk, _encoding, callback) {
        callback();
      },
    }),
  );
const key = randomBytes(32).toString('base64');
const advisory = (overrides: Record<string, unknown> = {}) => ({
  title: 'Kubernetes vulnerability actively exploited',
  content: 'An unpatched zero-day vulnerability affects k8s.',
  url: 'https://example.org/security/1',
  ...overrides,
});

test('correlation boundary rejects oversized input, credential URLs and unknown fields', () => {
  assert.equal(AdvisoryInputSchema.safeParse(advisory()).success, true);
  for (const raw of [
    advisory({ title: 'x'.repeat(201) }),
    advisory({ content: 'x'.repeat(50001) }),
    advisory({ url: 'https://user:secret@example.org/' }),
    advisory({ url: 'javascript:alert(1)' }),
    advisory({ injected: 'value' }),
  ])
    assert.equal(AdvisoryInputSchema.safeParse(raw).success, false);
  assert.equal(AdvisoryInputSchema.parse(advisory({ title: '  trimmed  ' })).title, 'trimmed');
});
test('version ranges preserve release candidates and refuse vendor backport coercion', () => {
  assert.equal(evaluateVersion('1.9', '>=1.0 <2.0'), 'AFFECTED');
  assert.equal(evaluateVersion('2.0.0', '<2.0'), 'UNAFFECTED');
  assert.equal(evaluateVersion('2.0.0-rc.1', '>=2.0.0-rc.1 <2.0.0'), 'AFFECTED');
  assert.equal(evaluateVersion('1.2.3-0ubuntu0.22.04.1', '<2.0'), 'REVIEW');
  assert.equal(evaluateVersion('1.2.3-8.el8_6', '<2.0'), 'REVIEW');
  assert.equal(evaluateVersion('1.2.3+vendor.patch', '<2.0'), 'REVIEW');
  assert.equal(evaluateVersion('1.2.3', '*'), 'REVIEW');
  assert.equal(evaluateVersion('2.4.41-2', '<2.4.41'), 'REVIEW');
  assert.equal(evaluateVersion('2.4.41-2', '>=2.0.0 <2.4.41'), 'REVIEW');
  assert.equal(evaluateVersion('1.0.0-rc.1', '<1.0.0'), 'AFFECTED');
  assert.equal(evaluateVersion('1.0.0-beta', '<1.0.0'), 'AFFECTED');
  assert.equal(evaluateVersion('1.0.0-preview.2', '<1.0.0'), 'AFFECTED');
});
test('NDJSON framing survives arbitrary UTF-8 splits and bounds malformed giant frames', async () => {
  const payload = Buffer.from(JSON.stringify(advisory({ title: 'Kubernetes 漏洞' })) + '\n');
  const decoded: unknown[] = [];
  for await (const item of advisoryRecords(
    Readable.from(
      [...payload].map((byte) => Buffer.from([byte])),
      { objectMode: false },
    ),
  ))
    decoded.push(item);
  assert.equal((decoded[0] as { title: string }).title, 'Kubernetes 漏洞');
  const frames = [];
  for await (const item of advisoryRecords(
    Readable.from([Buffer.from('x'.repeat(300000) + '\n' + JSON.stringify(advisory()))], {
      objectMode: false,
    }),
  ))
    frames.push(item);
  assert.equal(frames.length, 2);
  assert.deepEqual(frames[0], { invalidFrame: 'OVERSIZED_NDJSON' });
});
test('extraction uses an isolated worker and routes CVE-free exploitation to review', async () => {
  const telemetry = silent();
  const early = await extractText('k8s zero-day vulnerability actively exploited', telemetry, randomUUID());
  assert.equal(early.zeroDay, true);
  const ranged = await extractText('k8s versions before 2.0 vulnerability', telemetry, randomUUID());
  assert.deepEqual(ranged.ranges, [{ productPhrase: 'k8s', range: '<2.0' }]);
  const published = await extractText(
    'CVE-2026-12345 vulnerability actively exploited',
    telemetry,
    randomUUID(),
  );
  assert.equal(published.zeroDay, false);
  assert.deepEqual(published.cveIds, ['CVE-2026-12345']);
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(extractText('text', telemetry, randomUUID(), controller.signal));
});
test('dead-letter fallback encrypts payload before filesystem persistence', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'correlation-dlq-'));
  try {
    const queue = new DeadLetterQueue(directory, key, silent());
    await queue.capture(
      { secret: 'sensitive-customer-value' },
      'VALIDATION_FAILED',
      randomUUID(),
      {} as pg.Pool,
    );
    const files = await readdir(directory);
    assert.equal(files.length, 1);
    const stored = await readFile(join(directory, files[0]), 'utf8');
    assert.equal(stored.includes('sensitive-customer-value'), false);
    const letter = JSON.parse(stored);
    assert.equal(
      JSON.parse(decrypt(letter.encryptedPayload, key, 'correlation-dlq')).secret,
      'sensitive-customer-value',
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
test('telemetry persistence drains only the entries of the committing advisory', async () => {
  // The buffer is shared by every in-flight ingest in the worker. Draining all
  // of it on one commit silently discards (and misattributes) the logs of other
  // concurrent advisories.
  const telemetry = silent();
  const A = randomUUID();
  const B = randomUUID();
  telemetry.log('INFO', 'advisory.a.first', { trackingId: A });
  telemetry.log('INFO', 'advisory.b.first', { trackingId: B });
  telemetry.log('INFO', 'advisory.a.second', { trackingId: A });
  const inserted: unknown[][] = [];
  const client = {
    query: async (sql: string, values?: unknown[]) => {
      if (/INSERT INTO operational_events/.test(sql)) inserted.push(values ?? []);
      return { rows: [], rowCount: 0 };
    },
  } as unknown as import('pg').PoolClient;
  await telemetry.persistBeforeCommit(client, A);
  assert.equal(inserted.length, 1);
  // 15 bound parameters per entry, two entries for advisory a.
  assert.equal(inserted[0].length, 30);
  // Advisory b's entry survives for its own commit.
  assert.deepEqual(
    telemetry.logs.map((entry) => entry.event),
    ['advisory.b.first'],
    "another advisory's telemetry must stay buffered",
  );
});
test('a full dead-letter spool must not silently discard the advisory', async () => {
  // The spool exists to guarantee a failed advisory is never lost. When it is
  // full, throwing loses the very record it was meant to protect; the caller
  // then reports a rejection instead of DEAD_LETTER and the stream aborts.
  const directory = await mkdtemp(join(tmpdir(), 'correlation-dlq-full-'));
  try {
    const queue = new DeadLetterQueue(directory, key, silent());
    // Fill the spool to its documented ceiling (file i is the (i+1)th letter).
    for (let i = 0; i < 255; i++)
      await queue.capture({ i }, 'VALIDATION_FAILED', randomUUID(), {} as pg.Pool);
    assert.equal(await queue.capture({ i: 255 }, 'VALIDATION_FAILED', randomUUID(), {} as pg.Pool), 'SPOOLED');
    const outcome = await queue.capture({ overflow: true }, 'VALIDATION_FAILED', randomUUID(), {} as pg.Pool);
    assert.equal(
      outcome,
      'capacity',
      'a full spool must be reported so the caller can use the database fallback',
    );
    // Exactly the ceiling, no partial writes left behind.
    const files = (await readdir(directory)).filter((f) => f.endsWith('.json'));
    assert.equal(files.length, 256);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test(
  'native correlation transactions, schema coexistence and stream concurrency',
  { skip: !process.env.TEST_DATABASE_URL },
  async () => {
    const master = createPool(process.env.TEST_DATABASE_URL!);
    const schema = `correlation_test_${randomBytes(12).toString('hex')}`;
    const directory = await mkdtemp(join(tmpdir(), 'correlation-integration-'));
    let pool: pg.Pool | undefined;
    try {
      await master.query(`CREATE SCHEMA ${schema}`);
      pool = new pg.Pool({
        connectionString: process.env.TEST_DATABASE_URL,
        options: `-c search_path=${schema}`,
        max: 6,
        connectionTimeoutMillis: 2000,
      });
      await migrate(pool);
      await migrate(pool);
      const telemetry = silent();
      const queue = new DeadLetterQueue(directory, key, telemetry);
      const ingestor = new AdvisoryIngestor(telemetry, queue);
      const assetId = randomUUID();
      await pool.query(
        `INSERT INTO assets(id,vendor,product,version,purl) VALUES($1,'kubernetes','kubernetes','1.28.0','pkg:generic/kubernetes@1.28.0')`,
        [assetId],
      );
      const results = await Promise.all(
        Array.from({ length: 8 }, () => ingestor.processIncomingAdvisory(advisory(), pool!)),
      );
      assert.equal(results.filter((result) => result === 'PROCESSED').length, 1);
      assert.equal((await pool.query('SELECT * FROM unstructured_advisories')).rowCount, 1);
      assert.equal((await pool.query('SELECT * FROM correlation_matches')).rows[0].confidence, 'MEDIUM');
      await ingestor.processIncomingAdvisory(
        advisory({ url: 'https://example.org/security/exact', purls: ['pkg:generic/kubernetes@1.28.0'] }),
        pool,
      );
      assert.equal(
        (await pool.query("SELECT * FROM correlation_matches WHERE confidence='HIGH'")).rowCount,
        1,
      );
      await ingestor.processIncomingAdvisory(
        advisory({
          url: 'https://example.org/security/backport',
          entities: [{ vendor: 'kubernetes', product: 'kubernetes', affectedRange: '<1.0.0' }],
        }),
        pool,
      );
      // Explicit structured range excludes the asset; alias text must not override it.
      assert.equal(
        (
          await pool.query(
            `SELECT m.* FROM correlation_matches m JOIN unstructured_advisories a ON a.id=m.advisory_id WHERE a.url='https://example.org/security/backport'`,
          )
        ).rowCount,
        0,
      );
      await ingestor.processIncomingAdvisory(
        advisory({
          url: 'https://example.org/security/unmapped',
          title: 'Unpatched zero-day vulnerability actively exploited',
          content: 'Unidentified software exploitation in the wild.',
        }),
        pool,
      );
      assert.equal(
        (
          await pool.query(
            `SELECT b.* FROM low_confidence_review_buffer b JOIN unstructured_advisories a ON a.id=b.advisory_id WHERE a.url='https://example.org/security/unmapped'`,
          )
        ).rowCount,
        1,
      );
      const retryEngine = new (await import('../server/correlation/engine.ts')).TextCorrelationEngine();
      const correlate = retryEngine.correlate.bind(retryEngine);
      let attempts = 0;
      retryEngine.correlate = async (...args) => {
        if (++attempts === 1) throw Object.assign(new Error('serialization retry'), { code: '40001' });
        return correlate(...args);
      };
      const retryIngestor = new AdvisoryIngestor(telemetry, queue, retryEngine);
      assert.equal(
        await retryIngestor.processIncomingAdvisory(advisory({ url: 'https://example.org/retry' }), pool),
        'PROCESSED',
      );
      assert.equal(attempts, 2);
      assert.equal(
        (await pool.query("SELECT id FROM unstructured_advisories WHERE url='https://example.org/retry'"))
          .rowCount,
        1,
      );
      await ingestor.processIncomingAdvisory({ poison: 'customer-secret' }, pool);
      await queue.flush(pool);
      assert.equal((await pool.query('SELECT * FROM correlation_dead_letters')).rowCount, 1);
      assert.equal(JSON.stringify(telemetry.logs).includes('customer-secret'), false);
      const supervisor = new PipelineSupervisor(pool, ingestor);
      await pool.query('UPDATE correlation_policy SET concurrency_limit=8 WHERE id=1');
      supervisor.setConcurrency(8);
      supervisor.memoryPercent = () => 90;
      await supervisor.check();
      assert.equal(supervisor.health, 'DEGRADED_BACKPRESSURE');
      assert.equal(supervisor.concurrencyLimit, 4);
      supervisor.memoryPercent = () => 50;
      await supervisor.check();
      assert.equal(supervisor.health, 'HEALTHY');
      assert.equal(supervisor.concurrencyLimit, 8);
      supervisor.setConcurrency(2);
      const processor = new AdvisoryStreamProcessor(supervisor);
      let max = 0;
      const original = ingestor.processIncomingAdvisory.bind(ingestor);
      ingestor.processIncomingAdvisory = async (...args) => {
        max = Math.max(max, supervisor.active.size);
        return original(...args);
      };
      await Promise.all(
        [1, 2].map((stream) =>
          processor.processAdvisoryStream(
            Readable.from(
              Array.from({ length: 4 }, (_, i) =>
                advisory({ url: `https://example.org/stream/${stream}/${i}` }),
              ),
            ),
            4,
            pool!,
          ),
        ),
      );
      assert.ok(max <= 2, `Global worker ceiling exceeded: ${max}`);
      await supervisor.stop();
      const config = loadConfig({
        NODE_ENV: 'test',
        DATABASE_URL: process.env.TEST_DATABASE_URL,
        APP_ORIGIN: 'http://localhost',
      METRICS_TOKEN: 'test-metrics-token-with-at-least-32-characters',
        ENCRYPTION_KEY: key,
        WORKER_ENABLED: 'false',
      });
      await createUser(pool, 'native-admin', 'Disposable-native-test-password-2026!', 'ADMIN');
      const runtime = new CorrelationRuntime(pool, key, directory);
      const app = createApp(pool, config, async () => ({ status: 200, headers: {}, body: '[]' }), {
        correlation: runtime,
      });
      const agent = supertest.agent(app);
      const login = await agent
        .post('/api/login')
        .set('Origin', config.APP_ORIGIN)
        .send({ username: 'native-admin', password: 'Disposable-native-test-password-2026!' });
      assert.equal(login.status, 200);
      const csrf = login.body.csrfToken as string;
      assert.equal((await agent.get('/api/correlation')).status, 200);
      assert.equal((await agent.get('/metrics')).status,401);
      const metrics=await agent.get('/metrics').set('Authorization','Bearer '+config.METRICS_TOKEN);
      assert.equal(metrics.status,200);
      assert.match(metrics.text,/vulnstream_correlation_items_total/);
      assert.equal((await agent.get('/api/correlation/workflows')).status,200);

      assert.equal(
        (await agent.post('/api/correlation/concurrency').set('Origin', config.APP_ORIGIN).send({ limit: 3 }))
          .status,
        403,
      );
      assert.equal(
        (
          await agent
            .post('/api/correlation/concurrency')
            .set('Origin', config.APP_ORIGIN)
            .set('x-csrf-token', csrf)
            .send({ limit: 3 })
        ).status,
        200,
      );
      const accepted = await agent
        .post('/api/correlation/ingest')
        .set('Origin', config.APP_ORIGIN)
        .set('x-csrf-token', csrf)
        .send({
          ndjson: JSON.stringify(advisory({ url: 'https://example.org/durable-api' })) + '\n{invalid json}',
        });
      assert.equal(accepted.status, 202);
      assert.equal(accepted.body.queued, 2);
      assert.equal((await pool.query('SELECT * FROM correlation_pending')).rowCount, 2);
      // Existing product/CVE simulator keeps its original contract with the new runtime attached.
      const legacy = await agent
        .post('/api/correlation/simulate')
        .set('Origin', config.APP_ORIGIN)
        .set('x-csrf-token', csrf)
        .send({ vendor: 'kubernetes', product: 'kubernetes' });
      assert.equal(legacy.status, 200);
    } finally {
      await pool?.end();
      await master.query(`DROP SCHEMA ${schema} CASCADE`);
      await master.end();
      await rm(directory, { recursive: true, force: true });
    }
  },
);

test(
  'owner-managed inventory columns and rows survive migration unchanged',
  { skip: !process.env.TEST_DATABASE_URL },
  async () => {
    const master = createPool(process.env.TEST_DATABASE_URL!);
    const schema = 'correlation_owner_' + randomBytes(12).toString('hex');
    let pool: pg.Pool | undefined;
    try {
      await master.query(`CREATE SCHEMA ${schema}`);
      pool = new pg.Pool({
        connectionString: process.env.TEST_DATABASE_URL,
        options: `-c search_path=${schema}`,
      });
      await pool.query(
        `CREATE TABLE assets(id uuid PRIMARY KEY,vendor text,product text,version text,cpe_23 text,purl text,owner_tag text DEFAULT 'untouched')`,
      );
      await pool.query("INSERT INTO assets(id,vendor,product) VALUES($1,'owner','inventory')", [
        randomUUID(),
      ]);
      const before = (
        await pool.query(
          "SELECT column_name,data_type,column_default,is_nullable FROM information_schema.columns WHERE table_schema=$1 AND table_name='assets' ORDER BY ordinal_position",
          [schema],
        )
      ).rows;
      const rows = (await pool.query('SELECT * FROM assets')).rows;
      await migrate(pool);
      assert.deepEqual(
        (
          await pool.query(
            "SELECT column_name,data_type,column_default,is_nullable FROM information_schema.columns WHERE table_schema=$1 AND table_name='assets' ORDER BY ordinal_position",
            [schema],
          )
        ).rows,
        before,
      );
      assert.deepEqual((await pool.query('SELECT * FROM assets')).rows, rows);
    } finally {
      await pool?.end();
      await master.query(`DROP SCHEMA ${schema} CASCADE`);
      await master.end();
    }
  },
);
test(
  'telemetry rows carry the durable clock retention and the event reader use',
  { skip: !process.env.TEST_DATABASE_URL },
  async () => {
    const master = createPool(process.env.TEST_DATABASE_URL!);
    const schema = 'correlation_clock_' + randomBytes(12).toString('hex');
    let pool: pg.Pool | undefined;
    try {
      await master.query(`CREATE SCHEMA ${schema}`);
      pool = new pg.Pool({
        connectionString: process.env.TEST_DATABASE_URL,
        options: `-c search_path=${schema}`,
        max: 2,
      });
      await migrate(pool);
      const telemetry = silent();
      const trackingId = randomUUID();
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        telemetry.log('INFO', 'ingestion.started', { trackingId });
        await telemetry.persistBeforeCommit(client, trackingId);
        await client.query('COMMIT');
      } finally {
        client.release();
      }
      // The pipeline shape supplies neither clock.
      await pool.query(
        "INSERT INTO operational_events(category,level,code,message) VALUES('PIPELINE','INFO','pipeline.started','x')",
      );
      const rows = (
        await pool.query<{ occurred_at: Date | null; timestamp: Date | null }>(
          'SELECT occurred_at,"timestamp" FROM operational_events',
        )
      ).rows;
      assert.equal(rows.length, 2);
      for (const row of rows) {
        // occurred_at NULL is the defect: retention filters on it and the event
        // reader reports it, so such a row is both unreadable and immortal.
        assert.ok(row.occurred_at, 'every row must carry the durable clock');
        assert.ok(row.timestamp, 'every row must carry a telemetry clock');
      }
      // Retention as the sweeper performs it: it must match the rows.
      const swept = await pool.query(
        "DELETE FROM operational_events WHERE occurred_at < now() + interval '1 second'",
      );
      assert.equal(swept.rowCount, 2, 'retention must be able to see telemetry rows');
      // A caller cannot persist two contradictory clocks: timestamp wins, so
      // ordering and retention always agree.
      await pool.query(
        `INSERT INTO operational_events(category,level,code,message,"timestamp",occurred_at)
         VALUES('PIPELINE','INFO','x','x',now()-interval '1 hour',now())`,
      );
      const reconciled = (
        await pool.query<{ occurred_at: Date; timestamp: Date }>(
          "SELECT occurred_at,\"timestamp\" FROM operational_events WHERE code='x'",
        )
      ).rows[0];
      assert.equal(
        reconciled.occurred_at.getTime(),
        reconciled.timestamp.getTime(),
        'the durable clock must be derived from the telemetry clock',
      );
      // A deliberate correction to the durable clock must take effect and be
      // mirrored. An earlier version of the trigger reset it back to timestamp,
      // so the UPDATE reported success while changing nothing.
      const corrected = (
        await pool.query<{ occurred_at: Date; timestamp: Date }>(
          `UPDATE operational_events SET occurred_at = occurred_at - interval '1 day'
           WHERE code='x' RETURNING occurred_at,"timestamp"`,
        )
      ).rows[0];
      assert.ok(
        Date.now() - corrected.occurred_at.getTime() > 20 * 3600_000,
        'a maintenance correction to occurred_at must stick',
      );
      assert.equal(
        corrected.occurred_at.getTime(),
        corrected.timestamp.getTime(),
        'both clocks must move together',
      );
      // An unrelated column update must not touch either clock.
      const untouched = (
        await pool.query<{ occurred_at: Date }>(
          "UPDATE operational_events SET message='x2' WHERE code='x' RETURNING occurred_at",
        )
      ).rows[0];
      assert.equal(untouched.occurred_at.getTime(), corrected.occurred_at.getTime());
    } finally {
      await pool?.end();
      await master.query(`DROP SCHEMA ${schema} CASCADE`);
      await master.end();
    }
  },
);
