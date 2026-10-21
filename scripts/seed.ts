import { z } from 'zod';
import { loadConfig } from '../server/config';
import { createPool, get, transaction } from '../server/db';
import { applyCommand } from '../server/commands';
import { RECOMMENDED_FEEDS } from '../server/recommendedFeeds';
import { INITIAL_WATCHLIST } from '../tests/fixtures/seedData';

const config = loadConfig();
const pool = createPool(config.DATABASE_URL);

/** Only seed adapters whose response contracts are implemented and verified. */
const feedPayload = [
  {
    id: 'feed-nvd',
    name: 'NVD CVE API 2.0',
    type: 'NVD_API' as const,
    url: 'https://services.nvd.nist.gov/rest/json/cves/2.0',
    authType: 'NONE' as const,
    rateLimitPerMin: 10,
    enabled: true,
    vendorSeed: true,
  },
  {
    id: 'feed-cisa-kev',
    name: 'CISA Known Exploited Vulnerabilities Catalog',
    type: 'CISA_KEV' as const,
    url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    authType: 'NONE' as const,
    rateLimitPerMin: 120,
    enabled: true,
    vendorSeed: true,
  },
  {
    id: 'feed-epss',
    name: 'FIRST Exploit Prediction Scoring System',
    type: 'EPSS_API' as const,
    url: 'https://api.first.org/data/v1/epss',
    authType: 'NONE' as const,
    rateLimitPerMin: 240,
    enabled: true,
    vendorSeed: true,
  },
  ...RECOMMENDED_FEEDS,
];

try {
  await transaction(pool, async (db) => {
    // These legacy seed URLs return vendor-specific advisory documents, not the
    // normalized-CVE array required by JSON_SEARCH_API. Disable them until a
    // source-specific, schema-validated adapter is configured.
    for (const id of ['feed-msrc', 'feed-paloalto']) {
      const legacy = await get<{ enabled: boolean }>(db, 'feeds', id);
      if (legacy?.enabled)
        await applyCommand(db, config, { action: 'feed.toggle', id, actor: 'seed-script' });
    }
    // Feeds go through the same validated command path the API uses, so a
    // misconfigured feed fails loudly here instead of landing in the database.
    await applyCommand(db, config, {
      action: 'feed.import',
      data: feedPayload,
      actor: 'seed-script',
    });

    // The watchlist is upserted by its stable fixture id so that repeated
    // seeding refreshes existing rows instead of failing with "not found"
    // or orphaning the findings that reference those asset ids.
    await applyCommand(db, config, {
      action: 'watchlist.import',
      data: INITIAL_WATCHLIST.map((item) => ({
        id: item.id,
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
        exposure: item.exposure,
        createdAt: item.createdAt,
      })),
      actor: 'seed-script',
    });
  });

  console.log('Seed data applied: Threat Feed Sources and Monitored Product Inventory only.');
} catch (e) {
  if (e instanceof z.ZodError) {
    console.error('Seed failed: feed configuration is invalid.');
    for (const issue of e.issues) console.error(`  - ${issue.path.join('.') || '(root)'}: ${issue.message}`);
    process.exitCode = 1;
  } else {
    console.error('Seed failed:', e);
    process.exitCode = 1;
  }
} finally {
  await pool.end();
}
