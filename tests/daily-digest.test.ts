import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  DEFAULT_DAILY_DIGEST_CUSTOMIZATION,
  renderDailyDigest,
  renderDailyFindingSummary,
  renderDailyHealthReport,
} from '../src/utils/templateCompiler.ts';
import type { DailyDigestParts, DigestFinding, DigestHealth } from '../src/utils/templateCompiler.ts';

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

const PARTS: DailyDigestParts = {
  advisory_id: 'DAILY-2026-10-29',
  advisory_title: 'Daily Vulnerability Digest',
  dispatch_date: '2026-10-29T10:00:00.000Z',
  severity: 'HIGH',
  finding_count: FINDINGS.length,
  severity_counts: '2 critical, 1 high',
  findings_summary: renderDailyFindingSummary(FINDINGS, DEFAULT_DAILY_DIGEST_CUSTOMIZATION),
  health_report: renderDailyHealthReport(HEALTH, DEFAULT_DAILY_DIGEST_CUSTOMIZATION),
  recipient_name: 'Team',
  critical_count: 2,
  high_count: 1,
  asset_count: 3,
  executive_summary:
    'A total of <strong>3 vulnerabilities</strong> were identified during the latest monitoring cycle, including <strong>2 Critical</strong> and <strong>1 High</strong> severity findings. Immediate review and remediation of critical vulnerabilities is recommended in accordance with established vulnerability management procedures and organizational SLAs.',
  report_generated: '29 October 2026 | 22:48 GMT+4',
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

test('renderDailyFindingSummary groups findings by severity with count headers', () => {
  const html = renderDailyFindingSummary(FINDINGS, DEFAULT_DAILY_DIGEST_CUSTOMIZATION);
  assert.ok(html.includes('CRITICAL (2)'));
  assert.ok(html.includes('HIGH (1)'));
  assert.ok(html.includes('edge-router-01 (VendorX)'));
  assert.ok(html.includes('auth-service'));
  assert.ok(html.includes('portal-web'));
});

test('renderDailyHealthReport returns HTML containing the database status', () => {
  const html = renderDailyHealthReport(HEALTH, DEFAULT_DAILY_DIGEST_CUSTOMIZATION);
  assert.equal(typeof html, 'string');
  assert.ok(html.length > 0);
  assert.ok(html.includes('Operational'));
  assert.ok(html.includes('12 ms'));
});

test('renderDailyHealthReport renders Platform Health Status table rows', () => {
  const html = renderDailyHealthReport(HEALTH, DEFAULT_DAILY_DIGEST_CUSTOMIZATION);
  assert.ok(html.includes('Platform Connectivity'));
  assert.ok(html.includes('Operational (12 ms)'));
  assert.ok(html.includes('Healthy'));
  assert.ok(html.includes('Delivery Queue'));
  assert.ok(html.includes('0 Pending | 12 Processed'));
});

test('renderDailyHealthReport returns empty string when health is null', () => {
  const html = renderDailyHealthReport(null, DEFAULT_DAILY_DIGEST_CUSTOMIZATION);
  assert.equal(html, '');
});

test('renderDailyDigest embeds the findings summary and the health report', () => {
  const html = renderDailyDigest(DEFAULT_DAILY_DIGEST_CUSTOMIZATION, PARTS);
  assert.equal(typeof html, 'string');
  assert.ok(html.includes('CVE-2026-0001'), 'digest embeds the findings summary');
  assert.ok(html.includes('Operational (12 ms)'), 'digest embeds the health report');
  assert.ok(html.includes('Daily Vulnerability Digest'), 'digest embeds the title');
});

test('renderDailyDigest populates KPI counts exactly', () => {
  const html = renderDailyDigest(DEFAULT_DAILY_DIGEST_CUSTOMIZATION, PARTS);
  assert.ok(html.includes('Total Findings:</strong> 3'));
  assert.ok(html.includes('Critical:</strong> 2'));
  assert.ok(html.includes('High:</strong> 1'));
  assert.ok(html.includes('ASSETS'));
  assert.ok(html.includes('>3<'), 'asset count KPI shows 3');
});

test('renderDailyDigest embeds executive summary and report generated date', () => {
  const html = renderDailyDigest(DEFAULT_DAILY_DIGEST_CUSTOMIZATION, PARTS);
  assert.ok(html.includes('Report Generated: 29 October 2026 | 22:48 GMT+4'));
  assert.ok(html.includes('Vulnerability Overview'));
  assert.ok(html.includes('<strong>3 vulnerabilities</strong>'));
  assert.ok(html.includes('<strong>2 Critical</strong>'));
});

test('renderDailyDigest contains no leftover template placeholders', () => {
  const html = renderDailyDigest(DEFAULT_DAILY_DIGEST_CUSTOMIZATION, PARTS);
  assert.ok(!html.includes('{{'), 'no unreplaced placeholders remain');
});
