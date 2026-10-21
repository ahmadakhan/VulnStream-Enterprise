import { loadConfig } from '../server/config';
import { createPool, put, transaction } from '../server/db';
import { encrypt } from '../server/secrets';
import { DEFAULT_TEMPLATE_CUSTOMIZATION } from '../src/utils/templateCompiler';
import {
  INITIAL_FEEDS,
  INITIAL_WATCHLIST,
  INITIAL_NORMALIZED_CVES,
  INITIAL_FINDINGS,
  INITIAL_ADVISORIES,
  INITIAL_ALERTED_CVES,
  INITIAL_RECIPIENTS,
  INITIAL_WEBHOOKS,
  INITIAL_WEBHOOK_LOGS,
  INITIAL_EMAIL_LOGS,
  INITIAL_AUDIT_LOGS,
  INITIAL_SETTINGS,
  INITIAL_ADVISORY_TEMPLATE,
} from '../tests/fixtures/seedData';

const config = loadConfig();
const pool = createPool(config.DATABASE_URL);

const encryptFeedKey = (feed: (typeof INITIAL_FEEDS)[0]) =>
  feed.authSecretKey ? encrypt(feed.authSecretKey, config.ENCRYPTION_KEY, `feed:${feed.id}`) : '';

const encryptWebhookUrl = (hook: (typeof INITIAL_WEBHOOKS)[number]) =>
  encrypt(hook.url, config.ENCRYPTION_KEY, `webhook-url:${hook.id}`);

const encryptWebhookToken = (hook: (typeof INITIAL_WEBHOOKS)[number]) =>
  encrypt(hook.secretToken, config.ENCRYPTION_KEY, `webhook:${hook.id}`);

try {
  await transaction(pool, async (db) => {
    await put(db, 'settings', 'main', INITIAL_SETTINGS);
    await put(db, 'template', 'main', {
      templateCustomization: DEFAULT_TEMPLATE_CUSTOMIZATION,
      advisoryTemplate: INITIAL_ADVISORY_TEMPLATE,
    });

    for (const feed of INITIAL_FEEDS) {
      await put(db, 'feeds', feed.id, { ...feed, authSecretKey: encryptFeedKey(feed) });
    }

    for (const item of INITIAL_WATCHLIST) {
      await put(db, 'watchlist', item.id, item);
    }

    for (const cve of INITIAL_NORMALIZED_CVES) {
      await put(db, 'cveData', cve.cveId, cve);
    }

    for (const finding of INITIAL_FINDINGS) {
      await put(db, 'findings', finding.id, finding);
    }

    for (const advisory of INITIAL_ADVISORIES) {
      await put(db, 'advisories', advisory.id, advisory);
    }

    for (const acv of INITIAL_ALERTED_CVES) {
      await put(db, 'alertedCves', acv.cveId, acv);
    }

    for (const recipient of INITIAL_RECIPIENTS) {
      await put(db, 'recipients', recipient.id, recipient);
    }

    for (const hook of INITIAL_WEBHOOKS) {
      await put(db, 'webhooks', hook.id, {
        ...hook,
        url: encryptWebhookUrl(hook),
        secretToken: encryptWebhookToken(hook),
      });
    }

    for (const log of INITIAL_WEBHOOK_LOGS) {
      await put(db, 'webhookLogs', log.id, log);
    }

    for (const log of INITIAL_EMAIL_LOGS) {
      await put(db, 'emailLogs', log.id, log);
    }

    const orderedLogs = [...INITIAL_AUDIT_LOGS].sort(
      (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime(),
    );
    for (const log of orderedLogs) {
      await db.query('INSERT INTO audit(data) VALUES($1)', [JSON.stringify(log)]);
    }

    await db.query(
      "INSERT INTO scheduler_state(id,last_run,heartbeat) VALUES(1,now(),now()) ON CONFLICT(id) DO UPDATE SET last_run=now(),heartbeat=now()",
    );
  });

  console.log('Seed data applied.');
} catch (e) {
  console.error('Seed failed:', e);
} finally {
  await pool.end();
}
