import { XMLParser, XMLValidator } from 'fast-xml-parser';
import { createHash } from 'node:crypto';
import type { IntelligenceArticle } from '../src/types/index.ts';

export const RSS_MAX_BYTES = 8 * 1024 * 1024;
export const RSS_MAX_ENTRIES = 10000;

export function canonicalArticleUrl(value: string): string | null {
  try {
    const url = new URL(value);
    if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password) return null;
    url.hash = '';
    for (const key of [...url.searchParams.keys()])
      if (/^utm_|^(fbclid|gclid|mc_cid|mc_eid)$/i.test(key)) url.searchParams.delete(key);
    url.searchParams.sort();
    return url.href;
  } catch {
    return null;
  }
}
const array = (value: any): any[] => (value == null ? [] : Array.isArray(value) ? value : [value]);
const string = (value: any): string =>
  typeof value === 'string'
    ? value
    : typeof value === 'number'
      ? String(value)
      : string(value?.['#text'] ?? '');
const decode = (value: string) =>
  value.replace(/&(amp|lt|gt|quot|apos|#\d{1,7}|#x[0-9a-f]{1,6});/gi, (whole, entity: string) => {
    const known: Record<string, string> = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" };
    if (known[entity.toLowerCase()]) return known[entity.toLowerCase()];
    const code = entity[1]?.toLowerCase() === 'x' ? parseInt(entity.slice(2), 16) : Number(entity.slice(1));
    return code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : whole;
  });
function plain(value: string) {
  return decode(value)
    .replace(/<(script|style)\b[^>]*>[\s\S]*?<\/\1>/gi, ' ')
    .replace(/<[^>]*>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}
export function parseSyndication(
  xml: string,
  sourceId: string,
  scopeHours: number,
  now = new Date(),
): {
  articles: IntelligenceArticle[];
  warnings: string[];
} {
  if (Buffer.byteLength(xml) > RSS_MAX_BYTES) throw new Error('RSS/Atom feed exceeds 8 MiB');
  if (/<!\s*(DOCTYPE|ENTITY)/i.test(xml))
    throw new Error('RSS/Atom document type and entity declarations are not permitted');
  if (XMLValidator.validate(xml) !== true) throw new Error('Feed is not valid XML');
  const parsed = new XMLParser({
    ignoreAttributes: false,
    parseTagValue: false,
    parseAttributeValue: false,
    processEntities: false,
    maxNestedTags: 64,
    trimValues: true,
  }).parse(xml);
  if (!parsed.rss?.channel && !parsed.feed && !parsed['rdf:RDF'])
    throw new Error('Expected an RSS or Atom feed, not an HTML page');
  const rows = parsed.feed
    ? array(parsed.feed.entry)
    : parsed.rss
      ? array(parsed.rss.channel.item)
      : array(parsed['rdf:RDF'].item);
  if (rows.length > RSS_MAX_ENTRIES) throw new Error('RSS/Atom feed exceeds 10,000 entries');
  const records = new Map<string, IntelligenceArticle>(),
    warnings: string[] = [];
  let invalid = 0;
  for (const row of rows) {
    const link =
      typeof row.link === 'string'
        ? row.link
        : array(row.link).find((entry) => !entry['@_rel'] || entry['@_rel'] === 'alternate')?.['@_href'];
    const url = canonicalArticleUrl(decode(string(link)));
    const title = plain(string(row.title)).slice(0, 500);
    const published = Date.parse(string(row.pubDate || row.published || row['dc:date'] || row.updated));
    const modified = Date.parse(string(row.updated || row['dc:date'] || row.pubDate || row.published));
    if (
      !url ||
      !title ||
      !Number.isFinite(published) ||
      !Number.isFinite(modified) ||
      published > now.getTime() ||
      modified > now.getTime()
    ) {
      invalid++;
      continue;
    }
    if (scopeHours > 0 && Math.max(published, modified) < now.getTime() - scopeHours * 3600000) continue;
    const full = plain(string(row['content:encoded'] || row.content || row.summary || row.description));
    // Summaries are context only; never infer that every CVE in a multi-product article affects every product.
    const cveIds = [
      ...new Set(
        (`${title} ${full} ${url}`.match(/\bCVE-\d{4}-\d{4,}\b/gi) || []).map((id) => id.toUpperCase()),
      ),
    ].sort();
    if (cveIds.length > 100) {
      invalid++;
      continue;
    }
    // Zero-day heuristic: articles without a CVE ID that mention exploitation,
    // zero-day, or in-the-wild activity are flagged for priority review.
    const zeroDay =
      cveIds.length === 0 &&
      /\b(zero[- ]?day|0[- ]?day|actively exploited|in the wild|unpatched|no (?:patch|fix|cve))\b/i.test(
        `${title} ${full}`,
      );
    const id = createHash('sha256').update(url).digest('hex');
    const article: IntelligenceArticle = {
      id,
      url,
      title,
      summary: full.slice(0, 1500),
      publishedDate: new Date(published).toISOString(),
      modifiedDate: new Date(modified).toISOString(),
      cveIds,
      sourceFeeds: [sourceId],
      zeroDay,
    };
    const old = records.get(id);
    if (
      !old ||
      modified > Date.parse(old.modifiedDate) ||
      (modified === Date.parse(old.modifiedDate) && JSON.stringify(article) > JSON.stringify(old))
    )
      records.set(id, article);
  }
  if (invalid)
    warnings.push(
      `${invalid} entries quarantined for missing/invalid URL, title, date, or excessive CVE references`,
    );
  return { articles: [...records.values()], warnings };
}
