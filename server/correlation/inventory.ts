import type { Db } from '../db.ts';
import type { WatchListItem } from '../../src/types/index.ts';
import { parseCPE23 } from '../../src/utils/cpeMatcher.ts';
/** Called in the same transaction as every inventory mutation. No owner row is rewritten. */
export async function syncCorrelationAsset(db: Db, asset: WatchListItem): Promise<void> {
  const parsed = asset.cpes.map(parseCPE23).filter((cpe) => cpe.isValid);
  const primary = parsed[0];
  const version =
    asset.version || (primary && !['*', '-'].includes(primary.version) ? primary.version : null);
  await db.query(
    `INSERT INTO correlation_managed_assets(record_id,vendor,product,version,cpes,purls,active)
    VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(record_id) DO UPDATE SET
    vendor=EXCLUDED.vendor,product=EXCLUDED.product,version=EXCLUDED.version,
    cpes=EXCLUDED.cpes,purls=EXCLUDED.purls,active=EXCLUDED.active,updated_at=now()`,
    [
      asset.id,
      primary?.vendor || asset.vendor.toLowerCase(),
      primary?.product || asset.product.toLowerCase(),
      version,
      [...new Set(asset.cpes)].sort(),
      [...new Set(asset.purls || [])].sort(),
      asset.active,
    ],
  );
}
export async function backfillCorrelationInventory(db: Db): Promise<number> {
  // Keyset pagination keeps inventory bootstrapping independent of inventory size.
  let cursor = '',
    count = 0;
  for (;;) {
    const rows = await db.query<{ id: string; data: WatchListItem }>(
      "SELECT id,data FROM records WHERE kind='watchlist' AND id>$1 ORDER BY id LIMIT 200 FOR UPDATE",
      [cursor],
    );
    if (!rows.rowCount) return count;
    for (const row of rows.rows) {
      await syncCorrelationAsset(db, row.data);
      count++;
    }
    cursor = rows.rows[rows.rows.length - 1].id;
  }
}
