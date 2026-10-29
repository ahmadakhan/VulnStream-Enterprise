import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  DEFAULT_DAILY_DIGEST_CUSTOMIZATION,
  renderDailyDigest,
  renderDailyFindingSummary,
  renderDailyHealthReport,
} from '../src/utils/templateCompiler.ts';
import type { DailyDigestParts, DigestFinding, DigestHealth } from '../src/utils/templateCompiler.ts';

// These are the exact keys DailyDigestView dereferences on
// `dailyDigestCustomization` when rendering the typography/color tool panels.
// The crash "can't access property canvasBg, dailyDigestCustomization is
// undefined" recurred whenever any of these was missing from the fallback
// config, so this set is the regression boundary.
const UI_COLOR_KEYS = ['canvasBg', 'cardBg', 'headerBg', 'accentColor', 'fontFamily', 'headingColor'] as const;

const FINDINGS: DigestFinding[] = [
  { cveId: 'CVE-2026-0001', severity: 'CRITICAL', assetName: 'edge-router-01', vendor: 'VendorX' },
  { cveId: 'CVE-2026-0002', severity: 'CRITICAL', assetName: 'auth-service' },
  { cveId: 'CVE-2026-0003', severity: 'HIGH', assetName: 'portal-web' },
];

const HEALTH: DigestHealth = {
  database: 'connected',
  databaseLatencyMs: 12,
  workerStatus: 'HEALTHY',
  workerHeartbeatAgeSeconds: 4,
  nextScheduledAttempt: '2026-10-30T09:00:00.000Z',
  backlog: [
    { status: 'QUEUED', count: 0 },
    { status: 'ACCEPTED', count: 12 },
  ],
  checkedAt: '2026-10-29T08:00:00.000Z',
};

test('DEFAULT_DAILY_DIGEST_CUSTOMIZATION defines every color/style the digest UI reads', () => {
  for (const key of UI_COLOR_KEYS) {
    assert.ok(
      DEFAULT_DAILY_DIGEST_CUSTOMIZATION[key],
      `daily digest default is missing the "${key}" value the UI dereferences`,
    );
  }
});

test('renderDailyFindingSummary returns HTML containing each finding CVE', () => {
  const html = renderDailyFindingSummary(FINDINGS, DEFAULT_DAILY_DIGEST_CUSTOMIZATION);
  assert.equal(typeof html, 'string');
  assert.ok(html.length > 0);
  assert.ok(html.includes('CVE-2026-0001'));
  assert.ok(html.includes('CVE-2026-0003'));
});

test('renderDailyFindingSummary reports "no findings" when the list is empty', () => {
  const html = renderDailyFindingSummary([], DEFAULT_DAILY_DIGEST_CUSTOMIZATION);
  assert.ok(html.includes('No findings'));
});

test('renderDailyHealthReport returns HTML containing the database status', () => {
  const html = renderDailyHealthReport(HEALTH, DEFAULT_DAILY_DIGEST_CUSTOMIZATION);
  assert.equal(typeof html, 'string');
  assert.ok(html.length > 0);
  assert.ok(html.includes('connected'));
});

test('renderDailyDigest embeds the findings summary and the health report', () => {
  const parts: DailyDigestParts = {
    advisory_id: 'DAILY-2026-0001',
    advisory_title: 'Daily Vulnerability Digest',
    dispatch_date: '2026-10-29T10:00:00.000Z',
    severity: 'HIGH',
    finding_count: FINDINGS.length,
    severity_counts: '2 critical, 1 high',
    findings_summary: renderDailyFindingSummary(FINDINGS, DEFAULT_DAILY_DIGEST_CUSTOMIZATION),
    health_report: renderDailyHealthReport(HEALTH, DEFAULT_DAILY_DIGEST_CUSTOMIZATION),
    recipient_name: 'Team',
  };
  const html = renderDailyDigest(DEFAULT_DAILY_DIGEST_CUSTOMIZATION, parts);
  assert.equal(typeof html, 'string');
  assert.ok(html.includes('CVE-2026-0001'), 'digest embeds the findings summary');
  assert.ok(html.includes('connected'), 'digest embeds the health report');
  assert.ok(html.includes('Daily Vulnerability Digest'), 'digest embeds the advisory title');
});
