import type { AdvisoryInput, ExtractedText } from './validation.ts';
import type { CorrelationMatch } from '../../shared/correlation.ts';
import { evaluateVersion, evaluateVersionDetailed } from './version.ts';
interface Asset {
  id: string;
  vendor: string;
  product: string;
  version: string | null;
  revision: string;
}
interface Entity {
  vendor: string;
  product: string;
  affectedRange?: string;
}
export type TimedQuery = <T extends import('pg').QueryResultRow>(
  sql: string,
  values?: unknown[],
) => Promise<import('pg').QueryResult<T>>;
const normalized = (s: string) =>
  s
    .toLowerCase()
    .replace(/[^a-z0-9_.+-]+/g, ' ')
    .trim();
export class TextCorrelationEngine {
  async correlate(
    input: AdvisoryInput,
    extracted: ExtractedText,
    query: TimedQuery,
  ): Promise<CorrelationMatch[]> {
    const matches = new Map<string, CorrelationMatch>();
    const add = (asset: Asset, confidence: CorrelationMatch['confidence'], reason: string) => {
      if (!matches.has(asset.id) && matches.size >= 1000) throw new Error('MATCH_FANOUT_LIMIT');
      const old = matches.get(asset.id);
      if (old && (old.confidence === 'HIGH' || (old.confidence === 'MEDIUM' && confidence === 'LOW'))) return;
      if (extracted.negated) {
        confidence = 'LOW';
        reason = 'Applicability negation or conflicting evidence requires review';
      }
      matches.set(asset.id, {
        assetId: asset.id,
        vendor: asset.vendor,
        product: asset.product,
        confidence,
        reason,
        assetRevision: asset.revision,
      });
    };
    if (input.cpes.length || input.purls.length) {
      const exact = await query<Asset>(
        `SELECT id,vendor,product,version,revision FROM correlation_asset_inventory
        WHERE (cpe_23 IS NOT NULL AND cpe_23=ANY($1::text[]))
           OR (purl IS NOT NULL AND purl=ANY($2::text[]))
           OR id IN (SELECT native_id FROM correlation_managed_assets WHERE active AND (cpes && $1::text[] OR purls && $2::text[])) LIMIT 1001`,
        [input.cpes, input.purls],
      );
      if (exact.rows.length > 1000) throw new Error('MATCH_FANOUT_LIMIT');
      for (const asset of exact.rows)
        add(asset, 'HIGH', 'Explicit structured CPE/PURL identity intersection');
    }
    // Generate bounded token n-grams, then indexed alias lookups. A generic product
    // substring must never join every asset mentioned elsewhere in an article.
    const STOPWORDS = new Set([
      'the','a','an','and','or','of','in','for','to','on','with','by','from','at','is','are','was','were',
      'this','that','it','as','be','has','have','had','not','no','but','its','their','our','new','other',
      'after','before','between','through','over','under','about','into','more','most','than','then',
      'exploit','exploits','vulnerability','vulnerabilities','security','attack','attacker','attackers',
      'flaw','flaws','bug','bugs','patch','patched','update','updates','zero','day','critical','remote',
      'code','execution','affected','versions','version','software','servers','server','systems','system',
      'users','user','researchers','researcher','reported','disclosed','fixed','issued','using','used',
      'which','while','when','who','also','been','being','could','would','should','may','might','will',
    ]);
    const tokens = extracted.text.trim().split(' ').slice(0, 20_000);
    const grams = new Set<string>();
    for (let i = 0; i < tokens.length; i++)
      for (let n = 1; n <= 4 && i + n <= tokens.length; n++) {
        // Every token in the gram must be a plausible identity token: a stopword
        // span ("a critical flaw in") or a single character can never be a
        // product alias, and admitting them lets one sensationalized article
        // saturate the 101-row alias budget with junk candidates.
        const span = tokens.slice(i, i + n);
        if (span.some((token) => STOPWORDS.has(token) || token.length < 2)) continue;
        grams.add(span.join(' '));
      }
    const aliases = await query<Entity & { alias: string }>(
      `SELECT alias,vendor,product FROM vendor_product_aliases
      WHERE lower(alias)=ANY($1::text[]) LIMIT 101`,
      [[...grams]],
    );
    if (aliases.rows.length > 100) throw new Error('ENTITY_FANOUT_LIMIT');
    const entities: Entity[] = [...input.entities];
    const distinctEntityCount = new Set(
      aliases.rows.map((row) => `${row.vendor.toLowerCase()}:${row.product.toLowerCase()}`),
    ).size;
    const pushedEntities = new Set<string>();
    for (const alias of aliases.rows) {
      // An explicit range is authoritative; a versionless alias must never
      // resurrect a product excluded by that range.
      if (
        input.entities.some(
          (entity) =>
            entity.vendor === alias.vendor.toLowerCase() && entity.product === alias.product.toLowerCase(),
        )
      )
        continue;
      const entityKey = `${alias.vendor.toLowerCase()}:${alias.product.toLowerCase()}`;
      if (pushedEntities.has(entityKey)) continue;
      pushedEntities.add(entityKey);
      let affectedRange: string | undefined;
      // Only infer a range for an unambiguous single-product article, immediately
      // adjacent to its name. Multiple alias strings (e.g., "k8s" and
      // "kubernetes") that map to the same canonical entity still qualify — the
      // dedup above collapses them before the count check.
      if (distinctEntityCount === 1) {
        const phrase = normalized(alias.alias);
        const evidence = extracted.ranges.filter(
          (range) => range.productPhrase === phrase || range.productPhrase.endsWith(' ' + phrase),
        );
        if (evidence.length === 1) affectedRange = evidence[0].range;
      }
      entities.push({ vendor: alias.vendor, product: alias.product, affectedRange });
    }
    // Native vendor/product prose candidates use existing functional indexes.
    // Only exact phrases for both dimensions qualify, and only security prose.
    if (!entities.length && extracted.securitySignal) {
      const names = await query<Asset>(
        `SELECT id,vendor,product,version,revision FROM correlation_asset_inventory
        WHERE lower(vendor)=ANY($1::text[]) AND lower(product)=ANY($1::text[]) LIMIT 1001`,
        [[...grams]],
      );
      if (names.rows.length > 1000) throw new Error('MATCH_FANOUT_LIMIT');
      for (const asset of names.rows)
        add(asset, 'LOW', 'Vendor/product tokens present; contextual applicability requires review');
    }
    // One bounded inventory lookup for all entities avoids hundreds of sequential
    // queries and enforces the ceiling across products, not just per product.
    const assets = entities.length ? await query<Asset>(
      `SELECT id,vendor,product,version,revision FROM correlation_asset_inventory i
       WHERE EXISTS (SELECT 1 FROM jsonb_to_recordset($1::jsonb) AS e(vendor text,product text)
       WHERE lower(i.vendor)=e.vendor AND lower(i.product)=e.product) LIMIT 1001`,
      [JSON.stringify(entities.map(entity => ({vendor: entity.vendor.toLowerCase(), product: entity.product.toLowerCase()})))],
    ) : { rows: [] };
    if (assets.rows.length > 1000) throw new Error('MATCH_FANOUT_LIMIT');
    for (const entity of entities) {
      if (assets.rows.length > 1000) throw new Error('MATCH_FANOUT_LIMIT');
      for (const asset of assets.rows.filter(asset => asset.vendor?.toLowerCase() === entity.vendor.toLowerCase() && asset.product?.toLowerCase() === entity.product.toLowerCase())) {
        if (!entity.affectedRange) {
          add(
            asset,
            extracted.securitySignal ? 'MEDIUM' : 'LOW',
            'Exact canonical vendor/product; affected versions unspecified',
          );
          continue;
        }
        const verdict = evaluateVersionDetailed(asset.version, entity.affectedRange);
        if (verdict.verdict === 'AFFECTED')
          add(asset, 'HIGH', `Canonical entity and explicit affected version range satisfied (${verdict.provenance}:${verdict.comparator})`);
        else if (verdict.verdict === 'REVIEW')
          add(asset, 'LOW', `Version/backport ordering uncertain (${verdict.provenance}:${verdict.comparator}); vendor evidence required`);
      }
    }
    if (extracted.zeroDay && matches.size === 0)
      return [
        {
          assetId: '',
          vendor: '',
          product: '',
          confidence: 'LOW',
          reason: 'Security keyword density without published CVE; unverified early intelligence',
        },
      ];
    return [...matches.values()];
  }
}
