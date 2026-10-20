import { generateCPE23 } from '../src/utils/cpeMatcher';
import { buildStrictCpe23 } from '../src/data/vendorCatalog';
import type { NormalizedCVE, WatchListItem } from '../src/types';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { matchCPE, matchPurl, matchesWatchlistItem, parseCPE23 } from '../src/utils/cpeMatcher';
import { compareVersions } from '../src/utils/versionComparator';
import { quickHash, generateHmacSignature } from '../src/utils/cryptoChain';
import { runVulnerabilityPipeline, validateSsrfSafety } from '../src/engine/pipelineEngine';
import {
  INITIAL_NORMALIZED_CVES,
  INITIAL_WATCHLIST,
  INITIAL_SETTINGS,
  INITIAL_FEEDS,
} from './fixtures/seedData';

const cpe = (version: string, product = 'widget') => `cpe:2.3:a:vendor:${product}:${version}:*:*:*:*:*:*:*`;
test('CPE rejects malformed names and substring component matches', () => {
  assert.equal(parseCPE23('cpe:2.3:a:vendor').isValid, false);
  assert.equal(matchCPE(cpe('1.2'), cpe('1.20')).matched, false);
  assert.equal(matchCPE(cpe('1', 'widget'), cpe('1', 'widget_server')).matched, false);
});
test('CPE applies start-only ranges', () => {
  assert.equal(matchCPE(cpe('1'), cpe('*'), { versionStartIncluding: '2' }).matched, false);
});
test('fallback cannot override a known version exclusion', () => {
  assert.equal(
    matchesWatchlistItem([cpe('3')], 'vendor', 'widget', [cpe('*')], 'vendor widget', '', {
      versionEndExcluding: '2',
    }).matched,
    false,
  );
});
test('PURL matches exact identity and specified version', () => {
  assert.equal(matchPurl('pkg:npm/express-extra@1', 'pkg:npm/express'), false);
  assert.equal(matchPurl('pkg:npm/express@5', 'pkg:npm/express@4'), false);
  assert.equal(matchPurl('pkg:npm/express@5', 'pkg:npm/express'), true);
});
test('SemVer build metadata does not change precedence', () => {
  assert.equal(compareVersions('1.2.3+build.1', '1.2.3+build.2'), 0);
});
test('hash and HMAC match independent crypto implementations', () => {
  assert.equal(quickHash('audit'), createHash('sha256').update('audit').digest('hex'));
  assert.equal(
    generateHmacSignature('payload', 'secret'),
    'sha256=' + createHmac('sha256', 'secret').update('payload').digest('hex'),
  );
});
for (const url of [
  'http://[::ffff:127.0.0.1]',
  'http://[fc00::1]',
  'http://localhost.',
  'http://100.64.0.1',
]) {
  test(`URL screening rejects ${url}`, () => assert.equal(validateSsrfSafety(url).safe, false));
}
function fixture() {
  const cve: NormalizedCVE = {
    ...structuredClone(INITIAL_NORMALIZED_CVES[0]),
    cveId: ' cve-2026-12345 ',
    cpeMatches: [cpe('*')],
    versionRange: undefined,
    purls: undefined,
    vex: undefined,
  };
  const asset: WatchListItem = {
    ...structuredClone(INITIAL_WATCHLIST[0]),
    id: 'asset-test',
    vendor: 'vendor',
    product: 'widget',
    cpes: [cpe('1')],
    purls: undefined,
    active: true,
  };
  const settings = { ...structuredClone(INITIAL_SETTINGS), scopeHours: 0, autoDispatchEnabled: true };
  return { cve, asset, settings };
}
test('unsigned VEX cannot silently suppress a verified product match', () => {
  const { cve, asset, settings } = fixture();
  cve.vex = { status: 'not_affected' };
  const result = runVulnerabilityPipeline(INITIAL_FEEDS, [cve], [asset], [], [], settings);
  assert.equal(result.newFindings.length, 1);
  assert.equal(result.newAdvisories.length, 0);
  assert.equal(result.newEmailLogs.length, 0);
  assert.equal(result.newFindings[0].notificationStatus, 'QUEUED_FOR_DISPATCH');
});
test('correlation canonicalizes output without fabricating delivery or mutating prior alerts', () => {
  const { cve, asset, settings } = fixture();
  const prior = [
    {
      cveId: 'CVE-2026-12345',
      firstAlertedAt: '',
      lastAlertedAt: '',
      advisoryId: 'old',
      recipientEmails: [],
      status: 'DISPATCHED' as const,
      dispatchCount: 1,
    },
  ];
  const before = structuredClone(prior);
  const result = runVulnerabilityPipeline(
    INITIAL_FEEDS,
    [cve],
    [asset, { ...asset, id: 'second' }],
    prior,
    [],
    settings,
  );
  assert.equal(result.newFindings[0].cveId, 'CVE-2026-12345');
  assert.deepEqual(prior, before);
  assert.equal(result.updatedAlertedCves.length, 1);
  assert.equal(result.updatedAlertedCves[0].dispatchCount, 1);
  assert.equal(result.newEmailLogs.length, 0);
});

import { chainAuditLogs, verifyAuditChain } from '../src/utils/cryptoChain';
import { INITIAL_AUDIT_LOGS } from './fixtures/seedData';
import { compileCustomizedTemplate, DEFAULT_TEMPLATE_CUSTOMIZATION } from '../src/utils/templateCompiler';
test('audit verification detects changed content and reordered records', () => {
  const logs = chainAuditLogs(INITIAL_AUDIT_LOGS);
  assert.equal(verifyAuditChain(logs), true);
  const changed = structuredClone(logs);
  changed[0].details += 'tampered';
  assert.equal(verifyAuditChain(changed), false);
  assert.equal(verifyAuditChain([...logs].reverse()), false);
  const appended = chainAuditLogs([{ ...logs[0], id: 'new-log' }], logs[0].hash);
  assert.equal(verifyAuditChain([...appended, ...logs]), true);
});
test('customization escapes markup and rejects CSS breakout', () => {
  const html = compileCustomizedTemplate({
    ...DEFAULT_TEMPLATE_CUSTOMIZATION,
    badgeStampText: '<img src=x onerror=alert(1)>',
    canvasBg: '</style><script>evil()</script>',
    borderRadius: '0; background:url(https://evil.test)',
  });
  assert.ok(!html.includes('<img src=x'));
  assert.ok(html.includes('&lt;img'));
  assert.ok(!html.includes('<script>'));
  assert.ok(!html.includes('evil.test'));
});
test('valid public endpoints and matching CPE still work', () => {
  assert.equal(validateSsrfSafety('https://example.com/feed').safe, true);
  assert.equal(validateSsrfSafety('https://[2606:4700:4700::1111]/').safe, true);
  assert.equal(
    matchCPE(cpe('1.2.3'), cpe('*'), { versionStartIncluding: '1', versionEndExcluding: '2' }).matched,
    true,
  );
});
test('pipeline rerun is idempotent and emitted audit content verifies', () => {
  const { cve, asset, settings } = fixture();
  const first = runVulnerabilityPipeline(INITIAL_FEEDS, [cve, cve], [asset], [], [], settings);
  assert.equal(first.newFindings.length, 1);
  assert.equal(first.execution.stats.inRunDuplicatesDropped, 1);
  assert.equal(verifyAuditChain([...first.newAuditLogs].reverse()), true);
  const second = runVulnerabilityPipeline(
    INITIAL_FEEDS,
    [cve],
    [asset],
    first.updatedAlertedCves,
    first.newFindings,
    settings,
  );
  assert.equal(second.newFindings.length, 0);
  assert.equal(second.newAdvisories.length, 0);
});

import { csvCell } from '../src/utils/csv';
test('CSV escapes quotes, delimiters, and formula prefixes', () => {
  assert.equal(csvCell('=1+1'), '"\'=1+1"');
  assert.equal(csvCell('a,"b"'), '"a,""b"""');
  assert.equal(csvCell('\t=1+1'), '"\'\t=1+1"');
});
test('PURL cannot bypass an explicit version exclusion', () => {
  assert.equal(
    matchesWatchlistItem(
      [],
      'vendor',
      'widget',
      [],
      '',
      '',
      { versionEndExcluding: '2' },
      ['pkg:npm/widget@3'],
      ['pkg:npm/widget'],
    ).matched,
    false,
  );
});

test('unsupported package version ordering requires review before dispatch', () => {
  const { cve, asset, settings } = fixture();
  asset.cpes = [];
  asset.purls = ['pkg:npm/widget@1.0-beta'];
  cve.cpeMatches = [];
  cve.purls = ['pkg:npm/widget'];
  cve.versionRange = { versionEndExcluding: '2.0' };
  const result = runVulnerabilityPipeline([], [cve], [asset], [], [], settings);
  assert.equal(result.newFindings.length, 1);
  assert.equal(result.newFindings[0].notificationStatus, 'REVIEW_REQUIRED');
});

test('strict CPE does not equate different products through marketing aliases', () => {
  assert.equal(
    matchCPE(
      'cpe:2.3:a:paloaltonetworks:globalprotect:6.0:*:*:*:*:*:*:*',
      'cpe:2.3:a:paloaltonetworks:pan_os:*:*:*:*:*:*:*:*',
    ).matched,
    false,
  );
});
test('empty per-CPE details fall back to supplied CPE matches', () => {
  const { cve, asset, settings } = fixture();
  cve.cpeMatchDetails = [];
  assert.equal(runVulnerabilityPipeline([], [cve], [asset], [], [], settings).newFindings.length, 1);
});
test('package without installed version produces a review finding for a ranged vulnerability', () => {
  const { cve, asset, settings } = fixture();
  asset.cpes = [];
  asset.purls = ['pkg:npm/widget'];
  cve.cpeMatches = [];
  cve.purls = ['pkg:npm/widget'];
  cve.versionRange = { versionEndExcluding: '2.0' };
  const result = runVulnerabilityPipeline([], [cve], [asset], [], [], settings);
  assert.equal(result.newFindings.length, 1);
  assert.equal(result.newFindings[0].notificationStatus, 'REVIEW_REQUIRED');
});
test('unknown architecture cannot confirm an architecture-specific vulnerability', () => {
  const { cve, asset, settings } = fixture();
  cve.cpeMatches = ['cpe:2.3:a:vendor:widget:*:*:*:*:*:*:arm64:*'];
  const result = runVulnerabilityPipeline([], [cve], [asset], [], [], settings);
  assert.equal(result.newFindings.length, 1);
  assert.equal(result.newFindings[0].notificationStatus, 'REVIEW_REQUIRED');
});

test('inventory CPE builders preserve hyphens in canonical product identifiers', () => {
  for (const build of [generateCPE23, buildStrictCpe23]) {
    assert.equal(parseCPE23(build('o','paloaltonetworks','pan-os','10.2.3')).product,'pan-os');
  }
});
