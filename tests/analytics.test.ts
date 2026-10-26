import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { createPool, migrate, put, transaction } from '../server/db';
import { computeThreatAnalytics, buildDateClause, computeTimelineBucket } from '../server/analytics';
import { INITIAL_NORMALIZED_CVES } from './fixtures/seedData';
import type { NormalizedCVE } from '../src/types/index.ts';

const database = process.env.TEST_DATABASE_URL;

function cveForAnalytics(overrides: Partial<NormalizedCVE> = {}): NormalizedCVE {
  return {
    ...INITIAL_NORMALIZED_CVES[0],
    cveId: overrides.cveId || `CVE-ANALYTICS-${randomUUID().slice(0, 8)}`,
    ...overrides,
  };
}

test('buildDateClause returns empty string for all-time range', () => {
  assert.equal(buildDateClause('all'), '');
});

test('buildDateClause returns date filter for bounded ranges', () => {
  assert.ok(buildDateClause('7d').includes('days'), '7d should include days interval');
  assert.ok(buildDateClause('30d').includes('30'), '30d should include 30');
  assert.ok(buildDateClause('90d').includes('90'), '90d should include 90');
  assert.ok(buildDateClause('365d').includes('365'), '365d should include 365');
});

test('computeTimelineBucket maps ranges to correct bucket types', () => {
  assert.equal(computeTimelineBucket('7d'), 'day');
  assert.equal(computeTimelineBucket('30d'), 'day');
  assert.equal(computeTimelineBucket('90d'), 'week');
  assert.equal(computeTimelineBucket('365d'), 'month');
  assert.equal(computeTimelineBucket('all'), 'month');
});

test('computeThreatAnalytics aggregates CVE data correctly', { skip: !database }, async () => {
  const base = createPool(database!);
  const schema = 'test_' + randomUUID().replaceAll('-', '');
  await base.query(`CREATE SCHEMA "${schema}"`);
  const url = new URL(database!);
  url.searchParams.set('options', `-c search_path=${schema}`);
  const pool = createPool(url.href);

  try {
    await migrate(pool);

    const criticalCve = cveForAnalytics({
      cveId: 'CVE-2024-ANALYTICS-001',
      publishedDate: '2026-10-10T10:00:00Z',
      cvss: { version: '3.1', score: 9.8, vector: 'CVSS:3.1/AV:N', severity: 'CRITICAL' },
      cisaKev: { isKev: true, dateAdded: '2026-10-10', dueDate: '2026-10-17', requiredAction: 'test' },
      exploitStatus: 'Active Weaponized',
      cpeMatches: ['cpe:2.3:a:microsoft:windows_10:*:*:*:*:*:*:*:*'],
    });

    const highCve = cveForAnalytics({
      cveId: 'CVE-2024-ANALYTICS-002',
      publishedDate: '2026-10-11T10:00:00Z',
      cvss: { version: '3.1', score: 7.5, vector: 'CVSS:3.1/AV:N', severity: 'HIGH' },
      cisaKev: { isKev: false },
      exploitStatus: 'POC Available',
      cpeMatches: ['cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*'],
    });

    const lowCve = cveForAnalytics({
      cveId: 'CVE-2024-ANALYTICS-003',
      publishedDate: '2026-09-01T10:00:00Z',
      cvss: { version: '3.1', score: 3.5, vector: 'CVSS:3.1/AV:L', severity: 'LOW' },
      cisaKev: { isKev: false },
      exploitStatus: 'None',
      cpeMatches: ['cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*'],
    });

    await transaction(pool, async (db) => {
      for (const cve of [criticalCve, highCve, lowCve]) {
        await put(db, 'cveData', cve.cveId, cve);
      }
    });

    const result = await computeThreatAnalytics(pool, 'all', 10);

    assert.equal(result.totalCves, 3, 'should count all 3 CVEs');
    assert.equal(result.kevCount, 1, 'should count 1 KEV CVE');
    assert.equal(result.severityDistribution.critical, 1);
    assert.equal(result.severityDistribution.high, 1);
    assert.equal(result.severityDistribution.low, 1);
    assert.equal(result.exploitStatusDistribution.activeWeaponized, 1);
    assert.equal(result.exploitStatusDistribution.pocAvailable, 1);
    assert.equal(result.exploitStatusDistribution.none, 1);
    assert.ok(result.topVendors.length > 0, 'should have vendor data');
    assert.ok(result.timeline.length >= 1, 'should have timeline data');
    assert.ok(result.cvssScoreHistogram.length === 5, 'should have 5 CVSS score bins');
    assert.ok(result.generatedAt, 'should have a generation timestamp');
  } finally {
    await pool.end();
    await base.query(`DROP SCHEMA "${schema}" CASCADE`);
    await base.end();
  }
});

test('computeThreatAnalytics handles empty database', { skip: !database }, async () => {
  const base = createPool(database!);
  const schema = 'test_' + randomUUID().replaceAll('-', '');
  await base.query(`CREATE SCHEMA "${schema}"`);
  const url = new URL(database!);
  url.searchParams.set('options', `-c search_path=${schema}`);
  const pool = createPool(url.href);

  try {
    await migrate(pool);

    const result = await computeThreatAnalytics(pool, '30d');

    assert.equal(result.totalCves, 0);
    assert.equal(result.kevCount, 0);
    assert.deepEqual(result.timeline, []);
    assert.equal(result.severityDistribution.critical, 0);
    assert.equal(result.topVendors.length, 0);
  } finally {
    await pool.end();
    await base.query(`DROP SCHEMA "${schema}" CASCADE`);
    await base.end();
  }
});

test('computeThreatAnalytics respects timeline range filter', { skip: !database }, async () => {
  const base = createPool(database!);
  const schema = 'test_' + randomUUID().replaceAll('-', '');
  await base.query(`CREATE SCHEMA "${schema}"`);
  const url = new URL(database!);
  url.searchParams.set('options', `-c search_path=${schema}`);
  const pool = createPool(url.href);

  try {
    await migrate(pool);

    const oldDateCve = cveForAnalytics({
      cveId: 'CVE-2020-OLD',
      publishedDate: '2020-01-01T00:00:00Z',
      cvss: { version: '3.1', score: 5.0, vector: '', severity: 'MEDIUM' },
      cisaKev: { isKev: false },
      exploitStatus: 'None',
      cpeMatches: ['cpe:2.3:a:test:product:*:*:*:*:*:*:*:*'],
    });

    const recentCve = cveForAnalytics({
      cveId: 'CVE-2026-RECENT',
      publishedDate: new Date().toISOString(),
      cvss: { version: '3.1', score: 8.0, vector: '', severity: 'HIGH' },
      cisaKev: { isKev: false },
      exploitStatus: 'None',
      cpeMatches: ['cpe:2.3:a:test:product2:*:*:*:*:*:*:*'],
    });

    await transaction(pool, async (db) => {
      for (const cve of [oldDateCve, recentCve]) {
        await put(db, 'cveData', cve.cveId, cve);
      }
    });

    const result7d = await computeThreatAnalytics(pool, '7d');
    const resultAll = await computeThreatAnalytics(pool, 'all');

    assert.equal(result7d.totalCves, 1, '7-day range should only see the recent CVE');
    assert.equal(result7d.timeline.length, 1, 'should have one timeline bucket for the recent CVE');
    assert.equal(resultAll.totalCves, 2, 'all-time should see both CVEs');
  } finally {
    await pool.end();
    await base.query(`DROP SCHEMA "${schema}" CASCADE`);
    await base.end();
  }
});
