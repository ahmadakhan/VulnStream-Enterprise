import type { AliasEntry, Finding, NormalizedCVE, WatchListItem } from '../types/index.ts';
import {
  buildAliasMap,
  matchProductWithAliases,
  matchVendorWithAliases,
  parseCPE23,
} from './cpeMatcher.ts';

const AUTO_ALIAS_PREFIX = 'auto:';

/** Stable identity for an automatic alias row. The id only depends on the
 * scope and canonical name, so recomputing the same relation on a later run
 * updates the existing row instead of creating a duplicate. */
export function autoAliasId(scope: 'VENDOR' | 'PRODUCT', canonical: string): string {
  return `${AUTO_ALIAS_PREFIX}${scope.toLowerCase()}:${canonical.trim().toLowerCase()}`;
}

const isManual = (entry: AliasEntry) =>
  entry.source === 'MANUAL' ||
  (entry.source === undefined && !entry.id.startsWith(AUTO_ALIAS_PREFIX));

const mergeEntry = (target: Map<string, AliasEntry>, entry: AliasEntry) => {
  const key = autoAliasId(entry.scope, entry.canonical);
  const aliases = entry.aliases
    .map((alias) => alias.trim().toLowerCase())
    .filter((alias) => isSafeNameVariant(entry.canonical, alias));
  if (!aliases.length) return;
  const previous = target.get(key);
  if (!previous) {
    target.set(key, {
      ...entry,
      id: key,
      canonical: entry.canonical.trim().toLowerCase(),
      aliases: [...new Set(aliases)].sort(),
      source: 'AUTO',
    });
    return;
  }
  target.set(key, {
    ...previous,
    aliases: [...new Set([...previous.aliases, ...aliases])].sort(),
  });
};

const normalizeName = (value: string) => value.toLowerCase().replace(/[^a-z0-9]/g, '');

/**
 * Corporate/edition suffixes recognized when two names normalize differently
 * but share the same family name (for example `acme corp` and `acme_inc`).
 * Wholly different vendors/products are rejected by the base-name and prefix
 * checks below, so a misconfigured CPE cannot teach the engine that
 * `Microsoft` and `linux` are the same vendor. Arbitrary abbreviations still
 * require an operator alias or the reviewed built-in table.
 */
const SAFE_NAME_SUFFIXES = new Set(
  [
    'inc',
    'incorporated',
    'corp',
    'corporation',
    'co',
    'company',
    'ltd',
    'limited',
    'llc',
    'plc',
    'gmbh',
    'ag',
    'bv',
    'nv',
    'sa',
    'group',
    'holdings',
    'international',
    'global',
    'technologies',
    'technology',
    'software',
    'systems',
    'system',
    'networks',
    'network',
    'labs',
    'lab',
    'foundation',
    'project',
    'pro',
    'professional',
    'enterprise',
    'standard',
    'edition',
    'cloud',
    'suite',
    'platform',
    'appliance',
    'virtual',
    'client',
    'server',
    'app',
    'application',
  ].map(normalizeName),
);

/** True when the names share a family name after stripping common corporate or
 * edition suffixes, or one normalized name is a prefix of the other. */
function isSafeNameVariant(left: string, right: string): boolean {
  const a = normalizeName(left || '');
  const b = normalizeName(right || '');
  if (!a || !b || a === b) return false;

  const stripSuffix = (value: string) => {
    const suffixes = [...SAFE_NAME_SUFFIXES].sort((x, y) => y.length - x.length);
    for (const suffix of suffixes) {
      if (value.length > suffix.length && value.endsWith(suffix))
        return value.slice(0, -suffix.length);
    }
    return value;
  };
  const base = (value: string) => {
    let current = value;
    let changed = false;
    for (;;) {
      const next = stripSuffix(current);
      if (next === current) return { value: current, changed };
      current = next;
      changed = true;
    }
  };
  const leftBase = base(a);
  const rightBase = base(b);
  if ((leftBase.changed || rightBase.changed) && leftBase.value === rightBase.value)
    return leftBase.value.length >= 3;

  const [short, long] = a.length <= b.length ? [a, b] : [b, a];
  // A family name followed by an arbitrary edition/marketing token (for
  // example `widgetpro` -> `widgetprox`) is a reasonable automatic relation.
  // The prefix requirement still rejects wholly different vendors/products.
  return short.length >= 3 && long.startsWith(short);
}

/**
 * Derives the vendor/product aliases implied by an inventory record and its
 * own CPEs.
 *
 * The operator declares `vendor`/`product` and one or more CPEs for the same
 * asset, so when the CPE uses a different spelling (for example
 * `Acme Corp`/`Widget Pro` versus `acme`/`widget_pro`) that spelling is an
 * authoritative alias, not a guess from advisory prose. Keeping auto aliases
 * tied to inventory declarations is what makes the lifecycle safe: they can
 * be recomputed and removed deterministically when the inventory changes.
 *
 * Built-in and operator-managed aliases are consulted first so an auto row is
 * only created when the pair is not already resolvable.
 */
export function deriveInventoryAliases(
  assets: readonly Pick<WatchListItem, 'vendor' | 'product' | 'cpes' | 'active'>[],
  existing: readonly AliasEntry[] = [],
  now = new Date().toISOString(),
): AliasEntry[] {
  const manual = existing.filter(isManual);
  const vendorAliases = buildAliasMap(manual, 'VENDOR');
  const productAliases = buildAliasMap(manual, 'PRODUCT');
  const groups = new Map<string, AliasEntry>();

  for (const asset of assets) {
    if (asset.active === false) continue;
    const vendor = asset.vendor.trim().toLowerCase();
    const product = asset.product.trim().toLowerCase();
    for (const cpe of asset.cpes ?? []) {
      const parsed = parseCPE23(cpe);
      if (!parsed.isValid) continue;
      const cpeVendor = parsed.vendor;
      const cpeProduct = parsed.product;
      if (
        vendor &&
        !/[*?]/.test(cpeVendor) &&
        cpeVendor !== '-' &&
        !matchVendorWithAliases(vendor, cpeVendor, vendorAliases)
      )
        mergeEntry(groups, {
          id: autoAliasId('VENDOR', vendor),
          scope: 'VENDOR',
          canonical: vendor,
          aliases: [cpeVendor],
          createdAt: now,
        });
      if (
        product &&
        !/[*?]/.test(cpeProduct) &&
        cpeProduct !== '-' &&
        !matchProductWithAliases(product, cpeProduct, productAliases)
      )
        mergeEntry(groups, {
          id: autoAliasId('PRODUCT', product),
          scope: 'PRODUCT',
          canonical: product,
          aliases: [cpeProduct],
          createdAt: now,
        });
    }
  }

  return [...groups.values()].sort((a, b) => a.id.localeCompare(b.id));
}

/**
 * Derives aliases from correlations that actually survived this run.
 *
 * A vendor/product fallback or alias-resolved finding proves that the
 * inventory's declared identity and the advisory CPE describe the same
 * product even though their spellings differ. Learning that relation lets
 * later runs use the structured alias path (still review-only at 85%
 * confidence) instead of depending on advisory prose.
 */
export function deriveCorrelationAliases(
  findings: readonly Finding[],
  watchlist: readonly WatchListItem[],
  cveById?: ReadonlyMap<string, NormalizedCVE>,
  now = new Date().toISOString(),
): AliasEntry[] {
  const assets = new Map(watchlist.map((asset) => [asset.id, asset]));
  const groups = new Map<string, AliasEntry>();

  for (const finding of findings) {
    if (!['VENDOR_PRODUCT_ALIAS', 'VENDOR_PRODUCT_FALLBACK'].includes(finding.matchingMethod)) continue;
    // A stale/NOT_APPLICABLE or operator-rejected finding is not evidence that
    // the names are interchangeable. Only current correlations may teach the
    // thesaurus, and the next run removes rows that lose that support. A
    // remediated finding still proves the naming relation, so RESOLVED and
    // PATCH_APPLIED remain valid evidence; only a rejected ruling does not.
    if (finding.notificationStatus === 'NOT_APPLICABLE') continue;
    if (finding.notificationStatus === 'SUPPRESSED_VEX_NOT_AFFECTED') continue;
    if (finding.status === 'FALSE_POSITIVE') continue;
    const asset = assets.get(finding.matchedAssetId);
    if (!asset || asset.active === false) continue;
    const cve =
      cveById?.get(finding.cveId.toUpperCase()) ||
      cveById?.get(finding.cveId) ||
      finding.cve;
    if (!cve) continue;
    const criteria = cve.cpeMatchDetails?.length
      ? cve.cpeMatchDetails.map((detail) => detail.criteria)
      : cve.cpeMatches;
    for (const criterion of criteria ?? []) {
      const parsed = parseCPE23(criterion);
      if (!parsed.isValid) continue;
      const vendor = asset.vendor.trim().toLowerCase();
      const product = asset.product.trim().toLowerCase();
      if (
        vendor &&
        !/[*?]/.test(parsed.vendor) &&
        parsed.vendor !== '-' &&
        !matchVendorWithAliases(vendor, parsed.vendor)
      )
        mergeEntry(groups, {
          id: autoAliasId('VENDOR', vendor),
          scope: 'VENDOR',
          canonical: vendor,
          aliases: [parsed.vendor],
          createdAt: now,
        });
      if (
        product &&
        !/[*?]/.test(parsed.product) &&
        parsed.product !== '-' &&
        !matchProductWithAliases(product, parsed.product)
      )
        mergeEntry(groups, {
          id: autoAliasId('PRODUCT', product),
          scope: 'PRODUCT',
          canonical: product,
          aliases: [parsed.product],
          createdAt: now,
        });
    }
  }

  return [...groups.values()].sort((a, b) => a.id.localeCompare(b.id));
}

export interface AutoAliasReconciliation {
  /** Automatic rows that remain after reconciliation. */
  entries: AliasEntry[];
  /** Rows to insert or update. */
  upserts: AliasEntry[];
  /** Ids of automatic rows that are no longer supported. */
  removals: string[];
  /** Complete alias list after reconciliation (manual rows + automatic rows). */
  aliases: AliasEntry[];
  added: AliasEntry[];
  updated: AliasEntry[];
  removed: AliasEntry[];
}

/**
 * Reconciles persisted auto aliases against the aliases implied by the current
 * inventory and correlation evidence. Manual rows are never changed. Updated
 * auto rows keep their original `createdAt` so the operator can see when the
 * relation was learned.
 */
export function reconcileAutoAliases(
  existing: readonly AliasEntry[],
  desired: readonly AliasEntry[],
  now = new Date().toISOString(),
): AutoAliasReconciliation {
  const manual = existing.filter(isManual);
  const remainingAuto = new Map(
    existing
      .filter((entry) => !isManual(entry))
      .map((entry) => [autoAliasId(entry.scope, entry.canonical), entry]),
  );
  const desiredById = new Map<string, AliasEntry>();
  for (const entry of desired) mergeEntry(desiredById, entry);

  const added: AliasEntry[] = [];
  const updated: AliasEntry[] = [];
  const entries: AliasEntry[] = [];

  for (const entry of desiredById.values()) {
    const previous = remainingAuto.get(entry.id);
    if (!previous) {
      const created = { ...entry, createdAt: entry.createdAt || now };
      added.push(created);
      entries.push(created);
      continue;
    }
    remainingAuto.delete(entry.id);
    const merged: AliasEntry = {
      ...previous,
      ...entry,
      createdAt: previous.createdAt || entry.createdAt || now,
    };
    const changed =
      previous.scope !== merged.scope ||
      previous.canonical !== merged.canonical ||
      previous.source !== merged.source ||
      previous.notes !== merged.notes ||
      previous.aliases.length !== merged.aliases.length ||
      previous.aliases.some((alias, index) => alias !== merged.aliases[index]);
    if (changed) {
      updated.push(merged);
      entries.push(merged);
    } else entries.push(previous);
  }

  const removed = [...remainingAuto.values()];
  return {
    entries,
    upserts: [...added, ...updated],
    removals: removed.map((entry) => entry.id),
    aliases: [...manual, ...entries],
    added,
    updated,
    removed,
  };
}
