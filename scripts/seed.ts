import { loadConfig } from '../server/config';
import { createPool, put, transaction } from '../server/db';
import { encrypt } from '../server/secrets';
import { INITIAL_FEEDS, INITIAL_WATCHLIST } from '../tests/fixtures/seedData';

const config = loadConfig();
const pool = createPool(config.DATABASE_URL);

const encryptFeedKey = (feed: (typeof INITIAL_FEEDS)[number]) =>
  feed.authSecretKey ? encrypt(feed.authSecretKey, config.ENCRYPTION_KEY, `feed:${feed.id}`) : '';

try {
  await transaction(pool, async (db) => {
    for (const feed of INITIAL_FEEDS) {
      await put(db, 'feeds', feed.id, {
        ...feed,
        authSecretKey: encryptFeedKey(feed),
        healthStatus: 'UNTESTED' as const,
        ssrfValidated: true,
        latencyMs: 0,
      });
    }

    for (const item of INITIAL_WATCHLIST) {
      await put(db, 'watchlist', item.id, item);
    }
  });

  console.log('Seed data applied: Threat Feed Sources and Monitored Product Inventory only.');
} catch (e) {
  console.error('Seed failed:', e);
} finally {
  await pool.end();
}
