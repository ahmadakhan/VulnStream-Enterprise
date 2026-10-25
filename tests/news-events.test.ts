import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { parseSyndication } from '../server/rss';
import { matchIntelligence, mergeArticles } from '../src/utils/intelligenceMatcher';
import { redactEventContext, writeEvent, readEvents } from '../server/events';
import { createPool, migrate, put, state } from '../server/db.ts';
import { queueRun, processPipeline } from '../server/pipeline';
import { loadConfig } from '../server/config.ts';
import type { WatchListItem, NormalizedCVE, Finding, IntelligenceArticle } from '../src/types/index.ts';
const now = new Date('2026-10-21T12:00:00Z');
const rss = (items: string) => `<rss version="2.0"><channel><title>Security</title>${items}</channel></rss>`;
const item = (
  url = 'https://example.com/story?utm_source=test',
  description = 'Acme Widget CVE-2026-12345 cve-2026-12345',
) =>
  `<item><title>Acme Widget vulnerability</title><link>${url.replaceAll('&', '&amp;')}</link><pubDate>Wed, 21 Oct 2026 10:00:00 GMT</pubDate><description>${description}</description></item>`;
const articles = () => parseSyndication(rss(item()), 'news', 24, now).articles;
const asset: WatchListItem = {
  id: 'asset',
  vendor: 'acme',
  product: 'widget',
  version: '2',
  cpes: [],
  assetTag: 'Production',
  ownerGroup: 'Security',
  active: true,
  createdAt: now.toISOString(),
};
test('RSS scopes ingestion, normalizes references and deduplicates tracked URLs', () => {
  const result = parseSyndication(
    rss(
      item() +
        item('https://example.com/story#fragment') +
        item('https://example.com/old').replace('21 Oct', '01 Oct') +
        '<item><title>No date</title></item>',
    ),
    'news',
    24,
    now,
  );
  assert.equal(result.articles.length, 1);
  assert.deepEqual(result.articles[0].cveIds, ['CVE-2026-12345']);
  assert.equal(result.articles[0].url, 'https://example.com/story');
  assert.equal(result.warnings.length, 1);
});
test('Atom handles alternate links and rejects HTML, entities and future timestamps', () => {
  const xml =
    '<feed xmlns="http://www.w3.org/2005/Atom"><entry><title>Acme Widget</title><link rel="alternate" href="https://example.com/atom"/><updated>2026-10-21T10:00:00Z</updated><summary>CVE-2026-12345</summary></entry></feed>';
  assert.equal(parseSyndication(xml, 'atom', 24, now).articles.length, 1);
  assert.equal(parseSyndication(xml, 'atom', 24, new Date('2026-10-20')).articles.length, 0);
  assert.throws(() => parseSyndication('<html/>', 'x', 24), /Expected/);
  assert.throws(
    () => parseSyndication('<!DOCTYPE rss [<!ENTITY x SYSTEM "file:///etc/passwd">]><rss/>', 'x', 24),
    /declarations/,
  );
  assert.throws(() => parseSyndication('<rss>', 'x', 24), /valid XML/);
  assert.throws(() =>
    parseSyndication('<rss>' + '<nested>'.repeat(100) + '</nested>'.repeat(100) + '</rss>', 'x', 24),
  );
});
test('numeric entities cannot emit lone UTF-16 surrogates', () => {
  const xml = rss(
    '<item><title>Acme &#xD800; Widget &#x1F600;</title><link>https://example.com/story</link><pubDate>Wed, 21 Oct 2026 10:00:00 GMT</pubDate><description>CVE-2026-12345</description></item>',
  );
  const [article] = parseSyndication(xml, 'news', 24, now).articles;
  assert.ok(article);
  assert.ok(
    !/[\uD800-\uDFFF]/u.test(article.title),
    'a lone surrogate must never reach normalized article text',
  );
  assert.match(article.title, /😀/, 'valid astral-plane references must still decode');
});
test('cross-feed evidence deduplicates by URL and CVE/product without producing findings', () => {
  const news = articles();
  const other = { ...news[0], id: 'other', url: 'https://example.org/report', sourceFeeds: ['other'] };
  const merged = mergeArticles([...news, { ...news[0], sourceFeeds: ['second'] }, other]);
  assert.equal(merged.length, 2);
  assert.deepEqual(merged.find((a) => a.id === news[0].id)!.sourceFeeds, ['news', 'second']);
  const matches = matchIntelligence(merged, [asset], []);
  assert.equal(matches.length, 1);
  assert.equal(matches[0].articleIds.length, 2);
  assert.equal(matches[0].status, 'REVIEW_REQUIRED');
  assert.equal(matchIntelligence(news, [{ ...asset, vendor: 'unrelated' }], []).length, 0);
  assert.equal(matchIntelligence(news, [{ ...asset, product: 'wid' }], []).length, 0);
  assert.equal(matchIntelligence(news, [{ ...asset, active: false }], []).length, 0);
});
test('structured exclusions and operator resolutions cannot be overridden by article mentions', () => {
  const corpus = [
    { cveId: 'CVE-2026-12345', cpeMatches: ['cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*'] } as NormalizedCVE,
  ];
  assert.equal(matchIntelligence(articles(), [asset], [], corpus).length, 0);
  const finding = {
    id: 'finding',
    cveId: 'CVE-2026-12345',
    matchedAssetId: asset.id,
    status: 'OPEN',
    notificationStatus: 'QUEUED_FOR_DISPATCH',
  } as unknown as Finding;
  assert.equal(matchIntelligence(articles(), [asset], [finding], corpus)[0].status, 'CORROBORATED');
  for (const status of ['RESOLVED', 'FALSE_POSITIVE', 'PATCH_APPLIED'])
    assert.equal(
      matchIntelligence(articles(), [asset], [{ ...finding, status } as Finding], corpus).length,
      0,
    );
  assert.equal(
    matchIntelligence(articles(), [asset], [{ ...finding, notificationStatus: 'REVIEW_REQUIRED' }], corpus)[0]
      .status,
    'REVIEW_REQUIRED',
  );
  for (const notificationStatus of ['NOT_APPLICABLE', 'SUPPRESSED_VEX_NOT_AFFECTED'] as const)
    assert.equal(
      matchIntelligence(
        articles(),
        [asset],
        [{ ...finding, notificationStatus } as Finding],
        corpus,
      )[0].status,
      'REVIEW_REQUIRED',
      `${notificationStatus} must not become corroborated by a news mention`,
    );
});
test('event context redacts credentials recursively and bounds arbitrary values', () => {
  assert.deepEqual(
    redactEventContext({ nested: { apiKey: 'private', password: 'private', ok: 1 }, body: 'private' }),
    { nested: { apiKey: '[redacted]', password: '[redacted]', ok: 1 }, body: '[redacted]' },
  );
  assert.equal((redactEventContext({ value: 'x'.repeat(3000) }) as any).value.length, 2000);
});
test(
  'PostgreSQL news ingestion stays idempotent; events paginate and validate filters',
  { skip: !process.env.TEST_DATABASE_URL },
  async () => {
    const base = createPool(process.env.TEST_DATABASE_URL!);
    const schema = 'news_' + randomUUID().replaceAll('-', '');
    await base.query(`CREATE SCHEMA ${schema}`);
    const url = new URL(process.env.TEST_DATABASE_URL!);
    url.searchParams.set('options', `-c search_path=${schema}`);
    const pool = createPool(url.href);
    try {
      await migrate(pool);
      await migrate(pool);
      await put(pool, 'watchlist', asset.id, asset);
      await put(pool, 'feeds', 'news', {
        id: 'news',
        name: 'News',
        enabled: true,
        type: 'RSS_ATOM',
        url: 'https://example.com/feed',
        authType: 'NONE',
        rateLimit: 60,
        healthStatus: 'UNTESTED',
      });
      const config = loadConfig({
        NODE_ENV: 'test',
        DATABASE_URL: url.href,
        APP_ORIGIN: 'http://localhost',
        ENCRYPTION_KEY: Buffer.alloc(32, 1).toString('base64'),
        EGRESS_ALLOWED_HOSTS: 'example.com',
        WORKER_ENABLED: 'false',
      });
      const xml = rss(item()).replaceAll('Wed, 21 Oct 2026 10:00:00 GMT', new Date().toUTCString());
      for (let i = 0; i < 2; i++) {
        await queueRun(pool, 24, 'test');
        await processPipeline(pool, config, async () => ({ status: 200, body: xml, headers: {} }));
      }
      const snapshot = await state(pool);
      assert.equal(snapshot.intelligenceArticles.length, 1);
      assert.equal(snapshot.intelligenceMatches.length, 1);
      assert.equal(snapshot.cveData.length, 0);
      assert.equal(snapshot.findings.length, 0);
      assert.equal((await pool.query('SELECT count(*) FROM outbox')).rows[0].count, '0');
      await writeEvent(pool, {
        category: 'SYSTEM',
        code: 'test.marker',
        message: 'searchable marker',
        context: { token: 'secret' },
      });
      const first = await readEvents(pool, { limit: 1 });
      assert.equal(first.events.length, 1);
      assert.ok(first.nextCursor);
      assert.equal(first.events[0].context.token, '[redacted]');
      const next = await readEvents(pool, { before: first.nextCursor, limit: 1 });
      assert.notEqual(next.events[0].id, first.events[0].id);
      assert.equal((await readEvents(pool, { q: 'searchable', category: 'SYSTEM' })).events.length, 1);
      assert.ok((await readEvents(pool, { category: 'MATCHING' })).events.length >= 2);
      await assert.rejects(readEvents(pool, { before: '9999999999999999999' }));
    } finally {
      await pool.end();
      await base.query(`DROP SCHEMA ${schema} CASCADE`);
      await base.end();
    }
  },
);
test('large legitimate RSS archives are bounded but filtered by scope instead of failing at 500 entries', () => {
  const oldItem = item('https://example.com/old', 'Historical advisory '.repeat(30)).replace('21 Oct', '01 Oct');
  const xml = rss(oldItem.repeat(5103) + item('https://example.com/current'));
  assert.ok(Buffer.byteLength(xml) > 2 * 1024 * 1024);
  const parsed = parseSyndication(xml, 'msrc-sized', 24, now);
  assert.equal(parsed.articles.length, 1);
  assert.equal(parsed.articles[0].url, 'https://example.com/current');
  assert.throws(() => parseSyndication('x'.repeat(8 * 1024 * 1024 + 1), 'oversized', 24), /8 MiB/);
  assert.throws(() => parseSyndication(rss('<item/>'.repeat(10001)), 'too-many', 24), /10,000 entries/);
});

test('custom vendor aliases from the Alias Thesaurus reach news matching', () => {
  // Article says "Acme Corp" but inventory uses the CPE identifier "acmecorp".
  // Without the custom alias, no match. With it, vendor is found.
  const article = {
    id: 'alias-vendor-1',
    title: 'Acme Corp product hit by critical RCE',
    summary: 'The Acme Corp widget server is vulnerable.',
    url: 'https://example.com/acme',
    publishedDate: '2026-10-01T00:00:00Z',
    modifiedDate: '2026-10-01T00:00:00Z',
    cveIds: ['CVE-2026-9001'],
    sourceFeeds: ['test'],
  };
  const asset: WatchListItem = {
    id: 'asset-alias-test',
    assetTag: 'Widget Server',
    vendor: 'acmecorp',
    product: 'widget',
    version: '3.0',
    cpes: [],
    purls: [],
    active: true,
    ownerGroup: 'Test',
    targetHw: '*',
    createdAt: '2026-01-01T00:00:00Z',
  };
  // No match without alias
  assert.equal(matchIntelligence([article], [asset], []).length, 0);
  // Match once we supply the custom vendor alias
  const matches = matchIntelligence([article], [asset], [], [], { acmecorp: ['acme corp'] });
  assert.equal(matches.length, 1);
  assert.equal(matches[0].status, 'REVIEW_REQUIRED');
  assert.equal(matches[0].assetId, 'asset-alias-test');
});

test('custom product aliases from the Alias Thesaurus reach news matching', () => {
  // Article uses a marketing name "xenon gateway" — inventory records the product
  // by its CPE identifier "xgateway". The vendor is explicitly named in both.
  const article = {
    id: 'alias-product-1',
    title: 'Critical RCE in acmecorp Xenon Gateway',
    summary: 'The acmecorp Xenon Gateway appliance is affected by CVE-2026-5555.',
    url: 'https://example.com/xenon',
    publishedDate: '2026-10-01T00:00:00Z',
    modifiedDate: '2026-10-01T00:00:00Z',
    cveIds: [],
    sourceFeeds: ['test'],
  };
  const asset: WatchListItem = {
    id: 'asset-product-alias-test',
    assetTag: 'Gateway Appliance',
    vendor: 'acmecorp',
    product: 'xgateway',
    version: '3.0',
    cpes: [],
    purls: [],
    active: true,
    ownerGroup: 'Test',
    targetHw: '*',
    createdAt: '2026-01-01T00:00:00Z',
  };
  // Vendor matches literally ('acmecorp'); product 'xgateway' does NOT appear in article.
  assert.equal(matchIntelligence([article], [asset], [], [], {}, {}).length, 0);
  // Once we alias xgateway → 'xenon gateway', the product is found in the article.
  const matches = matchIntelligence([article], [asset], [], [], {}, { xgateway: ['xenon gateway'] });
  assert.equal(matches.length, 1);
  assert.equal(matches[0].status, 'REVIEW_REQUIRED');
});

test('built-in vendor aliases still work after custom-alias merge', () => {
  // 'palo alto networks' is a built-in alias for 'paloaltonetworks'.
  // Adding a custom alias for an unrelated vendor must not break this.
  const article = {
    id: 'builtin-alias-preserved',
    title: 'Palo Alto Networks firewall vulnerability',
    summary: 'A critical vulnerability affects Palo Alto Networks pan os products.',
    url: 'https://example.com/pan',
    publishedDate: '2026-10-01T00:00:00Z',
    modifiedDate: '2026-10-01T00:00:00Z',
    cveIds: ['CVE-2026-9002'],
    sourceFeeds: ['test'],
  };
  const asset: WatchListItem = {
    id: 'asset-pan',
    assetTag: 'Firewall',
    vendor: 'paloaltonetworks',
    product: 'pan os',
    version: '10.2',
    cpes: [],
    purls: [],
    active: true,
    ownerGroup: 'Ops',
    targetHw: '*',
    createdAt: '2026-01-01T00:00:00Z',
  };
  // Should match via the built-in alias even when custom aliases are supplied
  const matches = matchIntelligence(
    [article],
    [asset],
    [],
    [],
    { acmecorp: ['acme corp'] }, // unrelated custom alias
  );
  assert.equal(matches.length, 1);
  assert.equal(matches[0].assetId, 'asset-pan');
});

test('CVE-less article without urgency language is not misclassified as zero-day', () => {
  const routine: IntelligenceArticle = {
    id: 'routine-feature-1',
    url: 'https://example.com/feature',
    title: 'Acme Widget quarterly feature update',
    summary: 'The Acme Widget platform receives a routine maintenance update.',
    publishedDate: '2026-10-01T00:00:00Z',
    modifiedDate: '2026-10-01T00:00:00Z',
    cveIds: [],
    sourceFeeds: ['test'],
    zeroDay: false,
  };
  const matches = matchIntelligence([routine], [asset], []);
  assert.equal(matches.length, 1);
  assert.equal(matches[0].status, 'REVIEW_REQUIRED');
  assert.equal(matches[0].zeroDay, false);
});

test('zero-day flag clears once a merged record carries a CVE ID', () => {
  const preCve: IntelligenceArticle = {
    id: 'zeroday-cve-later',
    url: 'https://example.com/story',
    title: 'Acme Widget zero-day exploit in the wild',
    summary: 'Acme Widget is being actively exploited in the wild without a patch.',
    publishedDate: '2026-10-01T00:00:00Z',
    modifiedDate: '2026-10-01T00:00:00Z',
    cveIds: [],
    sourceFeeds: ['feed1'],
    zeroDay: true,
  };
  const postCve: IntelligenceArticle = {
    ...preCve,
    modifiedDate: '2026-10-02T00:00:00Z',
    cveIds: ['CVE-2026-12345'],
    sourceFeeds: ['feed2'],
    zeroDay: false,
  };
  const merged = mergeArticles([preCve, postCve]);
  assert.equal(merged.length, 1);
  assert.deepEqual(merged[0].cveIds, ['CVE-2026-12345']);
  assert.equal(merged[0].zeroDay, false);

  // Zero-day persists when no CVE ID is ever attached.
  const stillZero = mergeArticles([
    preCve,
    { ...preCve, modifiedDate: '2026-10-02T00:00:00Z', sourceFeeds: ['feed2'] },
  ]);
  assert.equal(stillZero[0].zeroDay, true);
  assert.equal(stillZero[0].cveIds.length, 0);
});
