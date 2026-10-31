import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import os from 'node:os';
import fs from 'node:fs';

import { CronDataProvider, runScheduledTraining } from '../server/ml/train/cron.ts';
import type { Db } from '../server/db.ts';
import type { Pool as pgPool } from 'pg';

const tmpDir = () => join(os.tmpdir(), `ml-cron-test-${Math.random().toString(36).slice(2)}`);

/** Minimal mock Db that matches SQL against patterns and returns canned rows. */
function createMockDb(rowsByQuery: Record<string, { rows: unknown[] }>): Db {
  const query = async (sql: string, _params?: unknown[]) => {
    for (const [pattern, result] of Object.entries(rowsByQuery)) {
      if (sql.includes(pattern)) return result;
    }
    return { rows: [] };
  };
  return { query, release: () => undefined } as unknown as Db;
}

/** Mock pool that returns our mock client on connect(). */
function createMockPool(client: ReturnType<typeof createMockDb>) {
  return {
    connect: async () => client,
    end: async () => undefined,
    query: client.query,
  };
}

describe('CronDataProvider', () => {
  it('collectCpeStrings parses matched_cpe from results', async () => {
    const db = createMockDb({
      'correlation_matches': {
        rows: [
          { matched_cpe: 'cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*' },
          { matched_cpe: 'cpe:2.3:a:microsoft:windows_10:*:*:*:*:*:*:*:*' },
        ],
      },
    });
    const provider = new CronDataProvider();
    const result = await provider.collectCpeStrings(db);
    assert.equal(result.length, 2);
    assert.ok(result[0].startsWith('cpe:2.3'));
  });

  it('collectCpeStrings handles empty results', async () => {
    const db = createMockDb({});
    const provider = new CronDataProvider();
    const result = await provider.collectCpeStrings(db);
    assert.equal(result.length, 0);
  });

  it('collectTelemetry maps columns to MetricFeatures', async () => {
    const db = createMockDb({
      'correlation_telemetry': {
        rows: [
          {
            memory_percent: 50,
            active_workers: 4,
            concurrency_limit: 10,
            latency_ms: 100,
            dead_letters: 0,
            pending_claims: 3,
            items_per_second: 100,
            pool_waiting: 2,
          },
        ],
      },
    });
    const provider = new CronDataProvider();
    const result = await provider.collectTelemetry(db);
    assert.equal(result.length, 1);
    assert.equal(result[0].memoryPercent, 50);
    assert.equal(result[0].activeWorkers, 4);
    assert.equal(result[0].concurrencyLimit, 10);
  });

  it('collectDispatchOutcomes classifies TRUE_POSITIVE vs FALSE_POSITIVE', async () => {
    const db = createMockDb({
      'FROM correlation_matches': {
        rows: [
          { confidence: 95, notification_status: 'QUEUED_FOR_DISPATCH', status: 'PATCHED', cve_id: 'CVE-2024-1' },
          { confidence: 92, notification_status: 'QUEUED_FOR_DISPATCH', status: 'FALSE_POSITIVE', cve_id: 'CVE-2024-2' },
          { confidence: 50, notification_status: 'REVIEW_REQUIRED', status: 'MONITORED', cve_id: 'CVE-2024-3' },
        ],
      },
    });
    const provider = new CronDataProvider();
    const result = await provider.collectDispatchOutcomes(db);
    assert.equal(result.length, 3);
    assert.equal(result[0].dispatched, true);
    assert.equal(result[0].foundTruePositive, true);
    assert.equal(result[1].foundTruePositive, false);
    assert.equal(result[1].wasFalsePositive, true);
    assert.equal(result[2].dispatched, false);
  });

  it('collectCalibrationPairs maps to credibility score + actionable', async () => {
    const db = createMockDb({
      'credibility_score IS NOT NULL': {
        rows: [
          { credibility_score: 85, status: 'PATCHED' },
          { credibility_score: 30, status: 'FALSE_POSITIVE' },
          { credibility_score: 70, status: 'MONITORED' },
        ],
      },
    });
    const provider = new CronDataProvider();
    const result = await provider.collectCalibrationPairs(db);
    assert.equal(result.length, 3);
    assert.equal(result[0].credibilityScore, 85);
    assert.equal(result[0].isActionable, true);
    assert.equal(result[1].isActionable, false);
    assert.equal(result[2].isActionable, false);
  });

  it('collectDeliveryOutcomes from email and webhook channels', async () => {
    const db = createMockDb({
      'channel = \'email\'': {
        rows: [
          { provider: 'postmark', attempt: 1, delay_ms: 300000, succeeded: true, is_rate_limited: false, is_permanent_failure: false },
        ],
      },
      'channel = \'webhook\'': {
        rows: [
          { provider: 'webhook', attempt: 2, delay_ms: 600000, succeeded: true, is_rate_limited: false, is_permanent_failure: false },
        ],
      },
    });
    const provider = new CronDataProvider();
    const result = await provider.collectDeliveryOutcomes(db);
    assert.equal(result.length, 2);
    assert.equal(result[0].provider, 'postmark');
    assert.equal(result[1].provider, 'webhook');
  });

  it('collectRemediationFindings maps to RemediationFeatures', async () => {
    const db = createMockDb({
      'remediation_playbooks': {
        rows: [
          {
            cvss_score: 8.5,
            epss_score: 0.7,
            cisa_kev: true,
            days_since_published: 5,
            source_feed_weight: 40,
            has_version_evidence: true,
            cwe_risk_level: 2,
            exploit_status: 3,
            patch_url: 'https://example.com',
            vendor_advisory_ref: 'https://example.com/advisory',
            has_workarounds: true,
            has_immediate_actions: false,
            has_rollback_plan: true,
            has_step_by_step: false,
          },
        ],
      },
    });
    const provider = new CronDataProvider();
    const result = await provider.collectRemediationFindings(db);
    assert.equal(result.length, 1);
    assert.equal(result[0].features.cvssScore, 8.5);
    assert.equal(result[0].features.cisaKev, true);
    assert.ok(result[0].playbook.patch_url);
    assert.equal(result[0].playbook.immediate_actions, undefined);
  });

  it('collectAll returns TrainingDataSources with all fields', async () => {
    const db = createMockDb({
      'correlation_matches': { rows: [{ matched_cpe: 'cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*' }] },
      'correlation_telemetry': { rows: [{ memory_percent: 50, active_workers: 4, concurrency_limit: 10, latency_ms: 100, dead_letters: 0, pending_claims: 3, items_per_second: 100, pool_waiting: 2 }] },
      'FROM correlation_matches': { rows: [] },
      'credibility_score IS NOT NULL': { rows: [] },
      'channel = \'email\'': { rows: [] },
      'channel = \'webhook\'': { rows: [] },
      'remediation_playbooks': { rows: [] },
    });
    const provider = new CronDataProvider();
    const result = await provider.collectAll(db);
    assert.ok(result.cpeStrings);
    assert.ok(result.telemetryHistory);
    assert.ok(result.dispatchOutcomes);
    assert.ok(result.reviewOutcomeHistory);
    assert.ok(result.calibrationPairs);
    assert.ok(result.deliveryOutcomes);
    assert.ok(result.remediationFindings);
  });
});

describe('runScheduledTraining', () => {
  it('skips models when database has no training data', async () => {
    const mockDb = createMockDb({});
    const mockPool = createMockPool(mockDb);
    const dir = tmpDir();

    const summary = await runScheduledTraining(mockPool as unknown as pgPool, {
      directory: dir,
      lookbackDays: 1,
    });

    assert.equal(summary.summary.total, 7);
    assert.equal(summary.summary.skipped, 7);
    assert.equal(summary.summary.trained, 0);
    assert.equal(summary.summary.failed, 0);

    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('trains CPE validity gate with real data', async () => {
    const mockDb = createMockDb({
      'correlation_matches': {
        rows: [
          ...Array.from({ length: 100 }, (_, i) => ({
            matched_cpe: `cpe:2.3:a:vendor${i}:product${i}:1.0:*:*:*:*:*:*:*`,
          })),
          ...Array.from({ length: 100 }, (_, i) => ({
            matched_cpe: `garbage-${i}`,
          })),
        ],
      },
    });
    const mockPool = createMockPool(mockDb);
    const dir = tmpDir();

    const summary = await runScheduledTraining(mockPool as unknown as pgPool, {
      directory: dir,
      lookbackDays: 30,
    });

    const cpeResult = summary.results.find((r) => r.modelId === 'cpe-validity-gate')!;
    assert.equal(cpeResult.status, 'trained');
    assert.ok(cpeResult.validation.passed);
    assert.ok(cpeResult.saved);

    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('handles training failures gracefully (does not throw)', async () => {
    const mockDb = createMockDb({});
    const mockPool = createMockPool(mockDb);
    const dir = tmpDir();

    const summary =       await runScheduledTraining(mockPool as unknown as pgPool, { directory: dir });

    assert.equal(summary.summary.total, 7);
    assert.equal(summary.summary.failed, 0);

    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('logs results to console', async () => {
    const mockDb = createMockDb({});
    const mockPool = createMockPool(mockDb);
    const dir = tmpDir();

    const logs: string[] = [];
    const origLog = console.log;
    console.log = (...args: unknown[]) => { logs.push(args.join(' ')); };

    try {
      await runScheduledTraining(mockPool as unknown as pgPool, { directory: dir });
      assert.ok(logs.length > 0, 'Expected console.log to be called');
      assert.ok(logs.some((l) => l.includes('[ML Training]')), 'Expected ML Training log line');
    } finally {
      console.log = origLog;
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
