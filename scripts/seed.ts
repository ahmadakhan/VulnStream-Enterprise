import { z } from 'zod';
import { loadConfig } from '../server/config';
import { createPool, transaction } from '../server/db';
import { applyCommand } from '../server/commands';
import { INITIAL_FEEDS, INITIAL_WATCHLIST } from '../tests/fixtures/seedData';

const config = loadConfig();
const pool = createPool(config.DATABASE_URL);

/** Map the fixture feeds onto the shared import command payload. */
const feedPayload = INITIAL_FEEDS.map((feed) => ({
  id: feed.id,
  name: feed.name,
  type: feed.type,
  url: feed.url,
  authType: feed.authType,
  authSecretKey: feed.authSecretKey,
  rateLimitPerMin: feed.rateLimitPerMin,
  enabled: feed.enabled,
  vendorSeed: feed.vendorSeed ?? true,
  lastSync: feed.lastSync,
  etag: feed.etag,
  itemCountLastRun: feed.itemCountLastRun,
  latencyMs: feed.latencyMs,
}));

try {
  await transaction(pool, async (db) => {
    // Feeds go through the same validated command path the API uses, so a
    // misconfigured feed fails loudly here instead of landing in the database.
    await applyCommand(db, config, {
      action: 'feed.import',
      data: feedPayload,
      actor: 'seed-script',
    });

    for (const item of INITIAL_WATCHLIST) {
      await applyCommand(db, config, {
        action: 'asset.save',
        id: item.id,
        data: {
          vendor: item.vendor,
          product: item.product,
          version: item.version,
          cpes: item.cpes,
          purls: item.purls,
          targetHw: item.targetHw,
          assetTag: item.assetTag,
          ownerGroup: item.ownerGroup,
          active: item.active,
          notes: item.notes,
        },
        actor: 'seed-script',
      });
    }
  });

  console.log('Seed data applied: Threat Feed Sources and Monitored Product Inventory only.');
} catch (e) {
  if (e instanceof z.ZodError) {
    console.error('Seed failed: feed configuration is invalid.');
    for (const issue of e.issues)
      console.error(`  - ${issue.path.join('.') || '(root)'}: ${issue.message}`);
    process.exitCode = 1;
  } else {
    console.error('Seed failed:', e);
    process.exitCode = 1;
  }
} finally {
  await pool.end();
}
