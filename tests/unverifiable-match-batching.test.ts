import { test } from 'node:test';
import assert from 'node:assert/strict';
import pg from 'pg';
import { randomBytes } from 'node:crypto';
import { createPool, migrate } from '../server/db.ts';
import { queueUnverifiableMatchNotification } from '../server/delivery.ts';
import type { Finding, EmailRecipient } from '../src/types/index.ts';

interface OutboxRow {
  id: string;
  dedupe_key: string;
  advisory_id: string;
  payload: Record<string, unknown>;
}

const url = process.env.TEST_DATABASE_URL ?? '';
async function withDatabase<T>(fn: (pool: pg.Pool) => Promise<T>): Promise<T | null> {
  if (!url) return null;
  const master = createPool(url);
  const schema = `unverifiable_${randomBytes(10).toString('hex')}`;
  let pool: pg.Pool | undefined;
  try {
    await master.query(`CREATE SCHEMA ${schema}`);
    pool = new pg.Pool({ connectionString: url, options: `-c search_path=${schema}`, max: 4 });
    await migrate(pool);
    return await fn(pool);
  } finally {
    await pool?.end();
    await master.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    await master.end();
  }
}

const finding = (cveId: string, id: string, assetName: string, vendor?: string, product?: string): Finding =>
  ({
    id,
    cveId,
    matchedAssetId: id,
    matchedAssetName: assetName,
    matchedAssetVendor: vendor,
    matchedAssetProduct: product,
    matchedCpe: `cpe:2.3:a:${vendor}:${product}:*:*:*:*:*:*:*:*`,
    matchingMethod: 'exact',
    matchingEvidence: `Evidence for ${cveId} on ${assetName}`,
    confidence: 0,
    notificationStatus: 'REVIEW_REQUIRED',
    status: 'MONITORED',
    autoDispatchedAt: null,
    advisoryId: null,
    cve: {
      cveId,
      title: cveId,
      description: 'desc',
      publishedDate: '2026-01-01T00:00:00Z',
      modifiedDate: '2026-01-01T00:00:00Z',
      cvss: { version: '3.1', score: 7.5, vector: 'AV:N/AC:L', severity: 'HIGH' },
      cwe: [],
      cpeMatches: [],
      epss: { score: 0, percentile: 0 },
      cisaKev: { inKev: false, dueDate: null, cveNotes: '' },
      exploitStatus: 'None',
      remediation: { play: [], nextSteps: [] },
      sourceFeeds: [],
    },
    timeline: [],
  }) as unknown as Finding;

const recipient = (id: string, email: string, group: 'SECURITY_TEAM' | 'EVERYONE'): EmailRecipient => ({
  id,
  name: email,
  email,
  role: 'admin',
  deliveryGroup: group,
  subscriptionTier: 'ALL_SEVERITIES',
  enabled: true,
  deliverySuccessRate: 1,
});

test('unverifiable matches are batched into a single combined email per recipient', async () => {
  const outcome = await withDatabase(async (pool) => {
    const findings: Finding[] = [
      finding('CVE-2026-10001', 'f1', 'server-1', 'acme', 'widget'),
      finding('CVE-2026-10002', 'f2', 'server-2', 'acme', 'gadget'),
      finding('CVE-2026-10003', 'f3', 'server-3'),
    ];
    const recipients: EmailRecipient[] = [
      recipient('r1', 'sec-1@example.com', 'SECURITY_TEAM'),
      recipient('r2', 'sec-2@example.com', 'SECURITY_TEAM'),
    ];

    // One queued notification per recipient, NOT one per finding.
    const queued = await queueUnverifiableMatchNotification(pool, findings, recipients);
    assert.equal(queued, 2, 'one combined email per recipient');

    const rows = await pool.query<OutboxRow>(
      `SELECT id, dedupe_key, advisory_id, payload FROM outbox WHERE advisory_id LIKE 'UNVERIFIABLE:%' ORDER BY target_id`,
    );
    assert.equal(rows.rowCount, 2, 'exactly two combined jobs enqueued');

    for (const row of rows.rows) {
      const payload = row.payload as {
        subject: string;
        cveIds: string[];
        unverifiableMatch: { findings: unknown[]; cveIds: string[] };
        findingRevisions: Record<string, string>;
        contentRevision: string;
      };
      assert.equal(payload.unverifiableMatch.findings.length, 3, 'each email carries all findings');
      assert.deepEqual(payload.cveIds, ['CVE-2026-10001', 'CVE-2026-10002', 'CVE-2026-10003']);
      assert.equal(payload.subject, '[Threat intelligence] for Review - Unverifiable matches (3 findings)');
      assert.equal(Object.keys(payload.findingRevisions).length, 3, 'findingRevisions covers every finding');
      assert.ok(row.dedupe_key, 'dedupe key populated');
    }

    // A re-queue of the identical batch dedupes against the existing jobs instead
    // of producing duplicates (ON CONFLICT no-ops on non-FAILED rows).
    const requeued = await queueUnverifiableMatchNotification(pool, findings, recipients);
    assert.equal(requeued, 0, 'identical batch does not re-queue');
    const after = await pool.query(
      `SELECT count(*)::int AS n FROM outbox WHERE advisory_id LIKE 'UNVERIFIABLE:%'`,
    );
    assert.equal(after.rows[0].n, 2, 'no additional jobs after re-queue');
    return true;
  });
  assert.ok(outcome, 'database-backed test ran');
});
