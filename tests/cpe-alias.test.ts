import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildAliasMap,
  matchCPE,
  matchesWatchlistItem,
  matchVendorWithAliases,
} from '../src/utils/cpeMatcher.ts';
import { runVulnerabilityPipeline } from '../src/engine/pipelineEngine.ts';
import { DEFAULT_SETTINGS } from '../shared/state.ts';
import { INITIAL_NORMALIZED_CVES } from './fixtures/seedData';
import type { WatchListItem } from '../src/types/index.ts';

const cpe = (vendor: string, product: string, version = '*') =>
  `cpe:2.3:a:${vendor}:${product}:${version}:*:*:*:*:*:*:*`;

const aliases = {
  vendorAliases: { example: ['example_corp'] },
  productAliases: { widget: ['widget_pro'] },
};

test('structured CPE alias matching is symmetric in both operand orders', () => {
  const left = cpe('example', 'widget', '1.5');
  const right = cpe('example_corp', 'widget_pro', '1.5');

  const forward = matchCPE(left, right, undefined, aliases);
  const reverse = matchCPE(right, left, undefined, aliases);

  assert.equal(forward.matched, true);
  assert.equal(forward.viaAlias, true);
  assert.equal(reverse.matched, true);
  assert.equal(reverse.viaAlias, true);
});

test('strict CPE matching stays closed when alias maps are omitted', () => {
  const left = cpe('example', 'widget', '1.5');
  const right = cpe('example_corp', 'widget_pro', '1.5');

  assert.equal(matchCPE(left, right).matched, false);
  assert.equal(matchCPE(right, left).matched, false);
});

test('exact structured identifiers are authoritative and not flagged as alias matches', () => {
  const result = matchCPE(
    cpe('example', 'widget', '1.5'),
    cpe('example', 'widget', '1.5'),
    undefined,
    aliases,
  );
  assert.equal(result.matched, true);
  assert.equal(result.viaAlias, false);
});

test('an alias cannot bridge a genuinely different product', () => {
  assert.equal(
    matchCPE(
      cpe('example', 'widget', '1.5'),
      cpe('example_corp', 'gateway', '1.5'),
      undefined,
      aliases,
    ).matched,
    false,
  );
});

test('alias-resolved matches stay below auto-dispatch confidence and require review', () => {
  const result = matchesWatchlistItem(
    [cpe('example', 'widget', '1.5')],
    'example',
    'widget',
    [cpe('example_corp', 'widget_pro', '*')],
    'unrelated advisory title',
    'unrelated advisory body',
    undefined,
    undefined,
    undefined,
    undefined,
    undefined,
    true,
    aliases.vendorAliases,
    aliases.productAliases,
  );
  assert.equal(result.matched, true);
  assert.equal(result.method, 'VENDOR_PRODUCT_ALIAS');
  assert.equal(result.confidence, 85);
  assert.ok(result.confidence < 90, 'alias evidence must stay below auto-dispatch threshold');
});

test('operator alias keys cannot pollute object prototypes', () => {
  const custom = JSON.parse('{"__proto__":["polluted"]}') as Record<string, string[]>;
  assert.equal(matchVendorWithAliases('__proto__', 'polluted', custom), true);
  assert.equal(({} as Record<string, unknown>).polluted, undefined);

  const map = buildAliasMap(
    [{ scope: 'VENDOR', canonical: '__proto__', aliases: ['polluted'] }],
    'VENDOR',
  );
  assert.equal(Object.getPrototypeOf(map), null);
  assert.equal(Object.prototype.hasOwnProperty.call(map, '__proto__'), true);
  assert.deepEqual(map['__proto__'], ['polluted']);
  assert.equal(({} as Record<string, unknown>).polluted, undefined);
});

test('punctuation-only product variants reach the pipeline candidate prefilter', () => {
  // The matcher treats `widget_pro` and `widget-pro` as the same identity by
  // normalizing punctuation. The candidate index must index that normalized key
  // too, or the pair is dropped before the matcher can run.
  const record = {
    ...structuredClone(INITIAL_NORMALIZED_CVES[0]),
    cveId: 'CVE-2026-70003',
    cpeMatches: [cpe('example', 'widget-pro', '1.5')],
    cpeMatchDetails: [{ criteria: cpe('example', 'widget-pro', '1.5') }],
    versionRange: undefined,
    purls: undefined,
    vex: undefined,
    vexStatements: [],
    sourceFeeds: [],
    exploitationSources: [],
    cisaKev: { isKev: false },
    exploitStatus: 'None' as const,
    applicabilityRequiresReview: false,
  };
  const asset: WatchListItem = {
    id: 'asset-punctuation',
    vendor: 'example',
    product: 'widget_pro',
    version: '1.5',
    cpes: [cpe('example', 'widget_pro', '1.5')],
    assetTag: 'WIDGET-01',
    ownerGroup: 'test',
    active: true,
    createdAt: '2026-10-25T00:00:00.000Z',
  };

  const finding = runVulnerabilityPipeline([], [record], [asset], [], [], {
    ...DEFAULT_SETTINGS,
    scopeHours: 0,
  }).newFindings[0];

  assert.ok(finding, 'a punctuation-only product variant must reach the matcher');
  assert.equal(finding.matchingMethod, 'VENDOR_PRODUCT_ALIAS');
  assert.equal(finding.notificationStatus, 'REVIEW_REQUIRED');
});

test('built-in vendor aliases reach the pipeline candidate prefilter', () => {
  const vendorCpe = cpe('msft', 'windows_server_2022', '1.0');
  const record = {
    ...structuredClone(INITIAL_NORMALIZED_CVES[0]),
    cveId: 'CVE-2026-70002',
    cpeMatches: [vendorCpe],
    cpeMatchDetails: [{ criteria: vendorCpe }],
    versionRange: undefined,
    purls: undefined,
    vex: undefined,
    vexStatements: [],
    sourceFeeds: [],
    exploitationSources: [],
    cisaKev: { isKev: false },
    exploitStatus: 'None' as const,
    applicabilityRequiresReview: false,
  };
  const asset: WatchListItem = {
    id: 'asset-ms',
    vendor: 'microsoft',
    product: 'windows_server_2022',
    version: '1.0',
    cpes: [cpe('microsoft', 'windows_server_2022', '1.0')],
    assetTag: 'MS-01',
    ownerGroup: 'test',
    active: true,
    createdAt: '2026-10-25T00:00:00.000Z',
  };

  const finding = runVulnerabilityPipeline([], [record], [asset], [], [], {
    ...DEFAULT_SETTINGS,
    scopeHours: 0,
  }).newFindings[0];

  assert.ok(finding, 'a built-in alias pair must reach the matcher');
  assert.equal(finding.matchingMethod, 'VENDOR_PRODUCT_ALIAS');
  assert.equal(finding.notificationStatus, 'REVIEW_REQUIRED');
});
