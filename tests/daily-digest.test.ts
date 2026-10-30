import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  DEFAULT_DAILY_DIGEST_CUSTOMIZATION,
  renderDailyDigest,
  renderDailyFindingSummary,
  renderDailyHealthReport,
  digestSeveritySummary,
  digestSeverityKpi,
} from '../src/utils/templateCompiler.ts';
import type { DailyDigestParts, DigestFinding, DigestHealth } from '../src/utils/templateCompiler.ts';

const UI_COLOR_KEYS = ['canvasBg', 'cardBg', 'headerBg', 'accentColor', 'fontFamily', 'headingColor'] as const;

const FINDINGS: DigestFinding[] = [
  { cveId: 'CVE-2026-0001', severity: 'CRITICAL', assetName: 'edge-router-01', vendor: 'VendorX', sourceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2026-0001' },
  { cveId: 'CVE-2026-0002', severity: 'CRITICAL', assetName: 'auth-service', sourceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2026-0002' },
  { cveId: 'CVE-2026-0003', severity: 'HIGH', assetName: 'portal-web', sourceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2026-0003' },
  { cveId: 'CVE-2026-0004', severity: 'MEDIUM', assetName: 'internal-api', sourceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2026-0004' },
  { cveId: 'CVE-2026-0005', severity: 'LOW', assetName: 'monitoring-agent', sourceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2026-0005' },
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
  systemUptime: '187 Days 14 Hours',
  systemUptimePercentage: 99.98,
};

const PARTS: DailyDigestParts = {
  advisory_id: 'DAILY-2026-10-29',
  advisory_title: 'Daily Vulnerability Digest',
  dispatch_date: '2026-10-29T10:00:00.000Z',
  severity: 'HIGH',
  finding_count: FINDINGS.length,
  severity_counts: '2 critical, 1 high, 1 medium, 1 low',
  findings_summary: renderDailyFindingSummary(FINDINGS, DEFAULT_DAILY_DIGEST_CUSTOMIZATION),
  health_report: renderDailyHealthReport(HEALTH, DEFAULT_DAILY_DIGEST_CUSTOMIZATION),
  recipient_name: 'Team',
  critical_count: 2,
  high_count: 1,
  medium_count: 1,
  low_count: 1,
  asset_count: 5,
  executive_summary:
    'A total of <strong>5 vulnerabilities</strong> were identified during the latest monitoring cycle, including <strong>2 Critical</strong>, <strong>1 High</strong>, <strong>1 Medium</strong>, and <strong>1 Low</strong> severity findings across monitored assets. Immediate remediation of critical findings is recommended while medium and low severity items should be addressed according to established risk treatment and vulnerability management procedures.',
  report_generated: '29 October 2026 | 22:48 GMT+4',
  critical_summary: digestSeveritySummary('CRITICAL', 2, DEFAULT_DAILY_DIGEST_CUSTOMIZATION),
  high_summary: digestSeveritySummary('HIGH', 1, DEFAULT_DAILY_DIGEST_CUSTOMIZATION),
  medium_summary: digestSeveritySummary('MEDIUM', 1, DEFAULT_DAILY_DIGEST_CUSTOMIZATION),
  low_summary: digestSeveritySummary('LOW', 1, DEFAULT_DAILY_DIGEST_CUSTOMIZATION),
  critical_kpi: digestSeverityKpi('CRITICAL', 2, DEFAULT_DAILY_DIGEST_CUSTOMIZATION),
  high_kpi: digestSeverityKpi('HIGH', 1, DEFAULT_DAILY_DIGEST_CUSTOMIZATION),
  medium_kpi: digestSeverityKpi('MEDIUM', 1, DEFAULT_DAILY_DIGEST_CUSTOMIZATION),
  low_kpi: digestSeverityKpi('LOW', 1, DEFAULT_DAILY_DIGEST_CUSTOMIZATION),
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
  assert.ok(html.includes('CVE-2026-0004'));
  assert.ok(html.includes('CVE-2026-0005'));
});

test('renderDailyFindingSummary reports "no findings" when the list is empty', () => {
  const html = renderDailyFindingSummary([], DEFAULT_DAILY_DIGEST_CUSTOMIZATION);
  assert.ok(html.includes('No findings'));
});

test('renderDailyFindingSummary groups findings by severity with count headers', () => {
  const html = renderDailyFindingSummary(FINDINGS, DEFAULT_DAILY_DIGEST_CUSTOMIZATION);
  assert.ok(html.includes('CRITICAL (2)'));
  assert.ok(html.includes('HIGH (1)'));
  assert.ok(html.includes('MEDIUM (1)'));
  assert.ok(html.includes('LOW (1)'));
  assert.ok(html.includes('edge-router-01 (VendorX)'));
  assert.ok(html.includes('auth-service'));
  assert.ok(html.includes('portal-web'));
  assert.ok(html.includes('internal-api'));
  assert.ok(html.includes('monitoring-agent'));
});

test('renderDailyFindingSummary renders each CVE as a link to its source', () => {
  const html = renderDailyFindingSummary(FINDINGS, DEFAULT_DAILY_DIGEST_CUSTOMIZATION);
  assert.ok(
    html.includes('href="https://nvd.nist.gov/vuln/detail/CVE-2026-0001"'),
    'CVE links to its source URL',
  );
  assert.ok(
    html.includes('href="https://nvd.nist.gov/vuln/detail/CVE-2026-0005"'),
    'CVE links to its source URL',
  );
  assert.ok(!html.includes('Hello'), 'greeting text removed');
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
  assert.ok(html.includes('CRITICAL (2)'), 'findings summary shows critical count');
  assert.ok(html.includes('CRITICAL'), 'KPI dashboard shows critical label');
  assert.ok(html.includes('CRITICAL'), 'severity header present');
  assert.ok(html.includes('ASSETS'));
});

test('renderDailyDigest embeds executive summary and report generated date', () => {
  const html = renderDailyDigest(DEFAULT_DAILY_DIGEST_CUSTOMIZATION, PARTS);
  assert.ok(html.includes('Report Generated: 29 October 2026 | 22:48 GMT+4'));
  assert.ok(html.includes('Vulnerability Overview'));
  assert.ok(html.includes('<strong>5 vulnerabilities</strong>'));
  assert.ok(html.includes('<strong>2 Critical</strong>'));
  assert.ok(html.includes('<strong>1 High</strong>'));
  assert.ok(html.includes('<strong>1 Medium</strong>'));
  assert.ok(html.includes('<strong>1 Low</strong>'));
});

test('renderDailyHealthReport renders System Uptime row', () => {
  const html = renderDailyHealthReport(HEALTH, DEFAULT_DAILY_DIGEST_CUSTOMIZATION);
  assert.ok(html.includes('System Uptime'));
  assert.ok(html.includes('99.98%'));
  assert.ok(html.includes('187 Days 14 Hours'));
});

test('renderDailyDigest contains no leftover template placeholders', () => {
  const html = renderDailyDigest(DEFAULT_DAILY_DIGEST_CUSTOMIZATION, PARTS);
  assert.ok(!html.includes('{{'), 'no unreplaced placeholders remain');
});

test('renderDailyDigest omits zero-count severity sections', () => {
  const zeroParts: DailyDigestParts = {
    ...PARTS,
    medium_count: 0,
    low_count: 0,
    medium_summary: '',
    low_summary: '',
    medium_kpi: '',
    low_kpi: '',
  };
  const html = renderDailyDigest(DEFAULT_DAILY_DIGEST_CUSTOMIZATION, zeroParts);
  assert.ok(!html.includes('Medium:</strong>'), 'zero-count medium summary not rendered');
  assert.ok(!html.includes('Low:</strong>'), 'zero-count low summary not rendered');
  assert.ok(!html.includes('MEDIUM (0)'), 'zero-count medium findings not rendered');
  assert.ok(!html.includes('LOW (0)'), 'zero-count low findings not rendered');
  assert.ok(!html.includes('{{'), 'no unreplaced placeholders');
});
