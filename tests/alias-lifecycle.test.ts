import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  autoAliasId,
  deriveCorrelationAliases,
  deriveInventoryAliases,
  reconcileAutoAliases,
} from '../src/utils/aliasLifecycle.ts';
import { matchesWatchlistItem } from '../src/utils/cpeMatcher.ts';
import type { AliasEntry, Finding, WatchListItem } from '../src/types/index.ts';

const cpe = (vendor: string, product: string, version = '*') =>
  `cpe:2.3:a:${vendor}:${product}:${version}:*:*:*:*:*:*:*`;

const asset = (overrides: Partial<WatchListItem> = {}): WatchListItem => ({
  id: 'asset-auto',
  vendor: 'Acme Corporation',
  product: 'Widget Pro',
  version: '1.0',
  cpes: [cpe('acme', 'widget_pro', '1.0')],
  purls: [],
  assetTag: 'AUTO-01',
  ownerGroup: 'Security',
  active: true,
  createdAt: '2026-10-26T00:00:00Z',
  ...overrides,
});

test('inventory/CPE spelling variants become automatic aliases', () => {
  const derived = deriveInventoryAliases([asset()]);
  assert.deepEqual(
    derived.map(({ scope, canonical, aliases }) => ({ scope, canonical, aliases })),
    [{ scope: 'VENDOR', canonical: 'acme corporation', aliases: ['acme'] }],
  );
  assert.equal(derived[0].id, autoAliasId('VENDOR', 'acme corporation'));
  assert.equal(derived[0].source, 'AUTO');
});

test('an unrelated CPE identity is never learned as an alias', () => {
  // A misconfigured asset must not teach the matcher that Microsoft and Linux
  // are alternate spellings of the same vendor.
  assert.deepEqual(
    deriveInventoryAliases([
      asset({ vendor: 'Microsoft', product: 'Windows', cpes: [cpe('linux', 'linux_kernel')] }),
    ]),
    [],
  );
});

test('automatic aliases are added and removed without touching operator rows', () => {
  const manual: AliasEntry = {
    id: 'manual-1',
    scope: 'VENDOR',
    canonical: 'acme',
    aliases: ['acme-inc'],
    createdAt: '2026-01-01T00:00:00Z',
    source: 'MANUAL',
  };
  const first = reconcileAutoAliases([manual], deriveInventoryAliases([asset()]));
  assert.equal(first.added.length, 1);
  assert.equal(first.updated.length, 0);
  assert.equal(first.removed.length, 0);
  assert.ok(first.aliases.some((entry) => entry.id === manual.id));
  assert.ok(first.aliases.some((entry) => entry.source === 'AUTO'));

  // The asset disappears/its CPE becomes generic: the derived relation is no
  // longer supported, so the next reconciliation removes only the auto row.
  const second = reconcileAutoAliases(
    first.aliases,
    deriveInventoryAliases([asset({ cpes: ['cpe:2.3:a:*:*:*:*:*:*:*:*:*:*'] })]),
  );
  assert.equal(second.removed.length, 1);
  assert.deepEqual(
    second.aliases.map((entry) => entry.id),
    [manual.id],
  );
});

test('correlation evidence can teach an alias and loses it when rejected', () => {
  const finding = {
    cveId: 'CVE-2026-90001',
    matchedAssetId: 'asset-auto',
    matchingMethod: 'VENDOR_PRODUCT_FALLBACK',
    notificationStatus: 'REVIEW_REQUIRED',
    status: 'MONITORED',
    cve: {
      cveId: 'CVE-2026-90001',
      cpeMatches: [cpe('acme_corp', 'widget_pro', '1.0')],
    },
  } as unknown as Finding;

  const learned = deriveCorrelationAliases([finding], [asset()]);
  assert.deepEqual(
    learned.map(({ scope, canonical, aliases }) => ({ scope, canonical, aliases })),
    [{ scope: 'VENDOR', canonical: 'acme corporation', aliases: ['acme_corp'] }],
  );

  const rejected = { ...finding, status: 'FALSE_POSITIVE' as const };
  assert.deepEqual(deriveCorrelationAliases([rejected], [asset()]), []);

  // Remediation does not disprove the naming relation: the finding remains a
  // valid source until it ages out of retention.
  const resolved = { ...finding, status: 'RESOLVED' as const };
  assert.equal(deriveCorrelationAliases([resolved], [asset()]).length, 1);

  const strict = { ...finding, matchingMethod: 'STRICT_CPE' as const };
  assert.deepEqual(deriveCorrelationAliases([strict], [asset()]), []);
});

test('a generic inventory CPE is constrained by the inventory product', () => {
  const generic = 'cpe:2.3:a:*:*:*:*:*:*:*:*:*:*';
  const advisory = cpe('acme', 'widget', '1.0');
  const sameProduct = matchesWatchlistItem(
    [generic],
    'acme',
    'widget',
    [advisory],
    'unrelated title',
    'unrelated body',
  );
  assert.equal(sameProduct.matched, true);
  assert.equal(sameProduct.applicabilityRequiresReview, true);
  assert.ok(sameProduct.confidence < 90);

  const otherProduct = matchesWatchlistItem(
    [generic],
    'acme',
    'gadget',
    [advisory],
    'unrelated title',
    'unrelated body',
  );
  assert.equal(otherProduct.matched, false);
});

test('a CPE mismatch can still correlate on vendor and product', () => {
  const result = matchesWatchlistItem(
    [cpe('other', 'different', '*')],
    'acme',
    'widget',
    [cpe('acme', 'widget', '*')],
    'unrelated title',
    'unrelated body',
  );
  assert.equal(result.matched, true);
  assert.ok(['VENDOR_PRODUCT_ALIAS', 'VENDOR_PRODUCT_FALLBACK'].includes(result.method));
  assert.ok(result.confidence < 90, 'looser correlation must stay review-only');
});

test('the fallback still cannot override an explicit CPE version mismatch', () => {
  assert.equal(
    matchesWatchlistItem(
      [cpe('acme', 'widget', '3.0')],
      'acme',
      'widget',
      [cpe('acme', 'widget', '1.0')],
      'unrelated title',
      'unrelated body',
    ).matched,
    false,
  );
});

test('a PURL mismatch remains authoritative over a vendor/product text match', () => {
  assert.equal(
    matchesWatchlistItem(
      [],
      'acme',
      'widget',
      [],
      'Acme Widget vulnerability',
      'Acme Widget is affected',
      undefined,
      ['pkg:npm/acme-widget@1.0.0'],
      ['pkg:npm/other-package@1.0.0'],
    ).matched,
    false,
  );
});
