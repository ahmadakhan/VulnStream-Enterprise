import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { WatchListItem } from '../src/types/index.ts';
import { editedWatchlistCpe, orderWatchlist } from '../src/utils/watchlist.ts';

const item = (id: string, createdAt: string, product = 'widget'): WatchListItem => ({
  id,
  vendor: 'example',
  product,
  cpes: [`cpe:2.3:a:example:${product}:1.0:*:*:*:*:*:*:*`],
  assetTag: id,
  ownerGroup: 'test',
  active: true,
  createdAt,
});

test('editing inventory data does not change its created-time order', () => {
  const older = item('older', '2026-01-01T00:00:00.000Z');
  const newer = item('newer', '2026-02-01T00:00:00.000Z');
  const edited = { ...older, product: 'renamed', createdAt: older.createdAt };

  assert.deepEqual(orderWatchlist([edited, newer]).map((asset) => asset.id), ['newer', 'older']);
});

test('editing the product field generates and saves a matching CPE', () => {
  const asset = item('asset', '2026-01-01T00:00:00.000Z');
  const cpe = editedWatchlistCpe(asset, {
    cpeExpression: asset.cpes[0],
    vendor: 'example',
    product: 'widget-enterprise',
    part: 'a',
    version: '1.0',
    targetHw: '*',
  });

  assert.equal(cpe, 'cpe:2.3:a:example:widget-enterprise:1.0:*:*:*:*:*:*:*');
});

test('editing the CPE expression directly preserves that expression', () => {
  const asset = item('asset', '2026-01-01T00:00:00.000Z');
  const cpe = 'cpe:2.3:o:example:widget:2.0:*:*:*:*:*:*:*';

  assert.equal(editedWatchlistCpe(asset, {
    cpeExpression: cpe,
    vendor: 'example',
    product: 'widget',
    part: 'a',
    version: '1.0',
    targetHw: '*',
  }), cpe);
});
