/**
 * Enterprise CPE 2.3 Strict Component Matcher, SemVer Range Evaluator & PURL Matcher
 * Spec: NIST IR 7695 & Package URL (purl-spec)
 */

import { NvdVersionRange, canCompareRange, isVersionInNvdRange } from './versionComparator.ts';

export interface ParsedCPE {
  prefix: string; // cpe:2.3
  part: string; // a, o, h
  vendor: string;
  product: string;
  version: string;
  update: string;
  edition: string;
  language: string;
  swEdition: string;
  targetSw: string;
  targetHw: string;
  other: string;
  raw: string;
  isValid: boolean;
}

const cpeCache = new Map<string, ParsedCPE>();
const MAX_CPE_CACHE_SIZE = 10000;

export function parseCPE23(cpeString: string): ParsedCPE {
  if (!cpeString || typeof cpeString !== 'string') {
    return createEmptyCPE(cpeString, false);
  }

  const cached = cpeCache.get(cpeString);
  if (cached) return cached;

  const trimmed = cpeString.trim();
  if (!trimmed.startsWith('cpe:2.3:')) {
    const empty = createEmptyCPE(trimmed, false);
    if (cpeCache.size >= MAX_CPE_CACHE_SIZE) {
      const first = cpeCache.keys().next().value;
      if (first !== undefined) cpeCache.delete(first);
    }
    cpeCache.set(cpeString, empty);
    return empty;
  }

  const tokens = splitCpeTokens(trimmed.slice(8));

  if (
    tokens.length !== 11 ||
    !['a', 'o', 'h', '*', '-'].includes(tokens[0]) ||
    tokens.some((token) => !token || /(?<!\\)(?:\\\\)*\\$/.test(token))
  ) {
    const empty = createEmptyCPE(trimmed, false);
    if (cpeCache.size >= MAX_CPE_CACHE_SIZE) {
      const first = cpeCache.keys().next().value;
      if (first !== undefined) cpeCache.delete(first);
    }
    cpeCache.set(cpeString, empty);
    return empty;
  }

  const result: ParsedCPE = {
    prefix: 'cpe:2.3',
    part: tokens[0]?.toLowerCase() || '*',
    vendor: tokens[1]?.toLowerCase() || '*',
    product: tokens[2]?.toLowerCase() || '*',
    version: tokens[3]?.toLowerCase() || '*',
    update: tokens[4]?.toLowerCase() || '*',
    edition: tokens[5]?.toLowerCase() || '*',
    language: tokens[6]?.toLowerCase() || '*',
    swEdition: tokens[7]?.toLowerCase() || '*',
    targetSw: tokens[8]?.toLowerCase() || '*',
    targetHw: tokens[9]?.toLowerCase() || '*',
    other: tokens[10]?.toLowerCase() || '*',
    raw: trimmed,
    isValid: true,
  };

  if (cpeCache.size >= MAX_CPE_CACHE_SIZE) {
    const first = cpeCache.keys().next().value;
    if (first !== undefined) cpeCache.delete(first);
  }
  cpeCache.set(cpeString, result);
  return result;
}

function splitCpeTokens(str: string): string[] {
  const result: string[] = [];
  let current = '';
  let escaped = false;

  for (let i = 0; i < str.length; i++) {
    const char = str[i];
    if (escaped) {
      current += char;
      escaped = false;
    } else if (char === '\\') {
      escaped = true;
      current += char;
    } else if (char === ':') {
      result.push(current);
      current = '';
    } else {
      current += char;
    }
  }
  result.push(current);
  return result;
}

function createEmptyCPE(raw: string, isValid: boolean): ParsedCPE {
  return {
    prefix: 'cpe:2.3',
    part: '*',
    vendor: '*',
    product: '*',
    version: '*',
    update: '*',
    edition: '*',
    language: '*',
    swEdition: '*',
    targetSw: '*',
    targetHw: '*',
    other: '*',
    raw: raw || '',
    isValid,
  };
}

function cpeComponentPattern(value: string): { regex: RegExp; hasWildcard: boolean; literal: string } {
  let source = '';
  let literal = '';
  let escaped = false;
  let hasWildcard = false;
  let wildcardCount = 0;
  for (const char of value.toLowerCase()) {
    if (escaped) {
      source += char.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      literal += char;
      escaped = false;
    } else if (char === '\\') {
      escaped = true;
    } else if (char === '*') {
      wildcardCount++;
      if (wildcardCount > 10) {
        throw new Error('CPE component contains too many wildcards, potential ReDoS');
      }
      source += '.*';
      hasWildcard = true;
    } else if (char === '?') {
      wildcardCount++;
      if (wildcardCount > 10) {
        throw new Error('CPE component contains too many wildcards, potential ReDoS');
      }
      source += '.';
      hasWildcard = true;
    } else {
      source += char.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      literal += char;
    }
  }
  return { regex: new RegExp(`^${source}$`, 'i'), hasWildcard, literal };
}

type GlobToken = { type: 'star' } | { type: 'any' } | { type: 'literal'; value: string };

function globTokens(value: string): GlobToken[] {
  const tokens: GlobToken[] = [];
  let escaped = false;
  for (const char of value.toLowerCase()) {
    if (escaped) {
      tokens.push({ type: 'literal', value: char });
      escaped = false;
    } else if (char === '\\') {
      escaped = true;
    } else if (char === '*') {
      tokens.push({ type: 'star' });
    } else if (char === '?') {
      tokens.push({ type: 'any' });
    } else {
      tokens.push({ type: 'literal', value: char });
    }
  }
  return tokens;
}

/**
 * Decides whether two CPE component globs can describe the same concrete
 * value. A wildcard-versus-wildcard comparison cannot simply be accepted:
 * `2.*` and `1.*` are disjoint, while `1.*` and `1.2*` overlap. This is the
 * standard non-emptiness check for the intersection of two glob languages.
 */
function globIntersects(leftValue: string, rightValue: string): boolean {
  const left = globTokens(leftValue);
  const right = globTokens(rightValue);
  const memo = new Map<string, boolean>();
  const onlyStars = (tokens: GlobToken[], from: number) =>
    tokens.slice(from).every((token) => token.type === 'star');
  const visit = (i: number, j: number): boolean => {
    if (i === left.length && j === right.length) return true;
    if (i === left.length) return onlyStars(right, j);
    if (j === right.length) return onlyStars(left, i);
    const key = `${i}:${j}`;
    const cached = memo.get(key);
    if (cached !== undefined) return cached;
    const a = left[i],
      b = right[j];
    let result: boolean;
    if (a.type === 'star') {
      // The star can match the empty string, or consume whatever b[j] matches.
      result = visit(i + 1, j) || visit(i, j + 1);
    } else if (a.type === 'any') {
      result = b.type === 'star' ? visit(i, j + 1) || visit(i + 1, j) : visit(i + 1, j + 1);
    } else {
      result =
        b.type === 'star'
          ? visit(i, j + 1) || visit(i + 1, j)
          : b.type === 'any'
            ? visit(i + 1, j + 1)
            : a.value === b.value && visit(i + 1, j + 1);
    }
    memo.set(key, result);
    return result;
  };
  return visit(0, 0);
}

function matchComponent(assetAttr: string, vulnAttr: string): boolean {
  if (assetAttr === '*' || vulnAttr === '*') return true;
  if (assetAttr === '-' && vulnAttr === '-') return true;
  if (assetAttr === '-' || vulnAttr === '-') return false;

  const asset = cpeComponentPattern(assetAttr);
  const vuln = cpeComponentPattern(vulnAttr);
  if (asset.hasWildcard && vuln.hasWildcard) return globIntersects(assetAttr, vulnAttr);
  if (vuln.hasWildcard) return vuln.regex.test(asset.literal);
  if (asset.hasWildcard) return asset.regex.test(vuln.literal);
  return asset.literal === vuln.literal;
}

function hasUnescapedCpeWildcard(value: string): boolean {
  return value !== '*' && cpeComponentPattern(value).hasWildcard;
}

function escapeCpeToken(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/:/g, '\\:');
}

/** Inventory fields are operator-facing, so map them to the same component
 * conventions used by NVD CPEs before substituting them for a wildcard. */
function inventoryCpeToken(value: string): string {
  return escapeCpeToken(
    value
      .toLowerCase()
      .trim()
      .replace(/[^a-z0-9_.-]/g, '_'),
  );
}

function isGenericCpeComponent(value: string): boolean {
  return value === '*' || hasUnescapedCpeWildcard(value);
}

/**
 * Free text is the weakest matching path, so a substring test is not enough:
 * a two-letter vendor such as `os` or `ai` occurs inside `most`, `cost` and
 * `maintain`. Require each identity word to appear as a whole token, and treat
 * identities made only of very short words as too ambiguous for prose. Those
 * still match through strict CPE, alias or PURL evidence.
 */
const TEXT_IDENTITY_MIN_WORD = 3;
const textWordPatterns = new Map<string, RegExp>();
const MAX_TEXT_WORD_PATTERNS = 2000;

function textWordPattern(word: string): RegExp {
  const cached = textWordPatterns.get(word);
  if (cached) return cached;
  const escaped = word.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const pattern = new RegExp(`(?<![a-z0-9])${escaped}(?![a-z0-9])`);
  if (textWordPatterns.size >= MAX_TEXT_WORD_PATTERNS) textWordPatterns.clear();
  textWordPatterns.set(word, pattern);
  return pattern;
}

function containsIdentityWords(text: string, value: string): boolean {
  const words = value
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
  const significant = words.filter((word) => word.length >= TEXT_IDENTITY_MIN_WORD);
  // `os`, `ai`, `go` and `3m` are real names but not usable as prose evidence.
  if (!significant.length) return false;
  // Prefer the long words; for a multi-word identity that also contains short
  // tokens (for example `f5 big_ip`) keep the short ones so `f5` cannot be
  // dropped from its own name.
  const required = significant.length >= 2 || words.length === 1 ? significant : words;
  return required.every((word) => textWordPattern(word).test(text));
}

/**
 * Fixed CPE criteria that describe the platform rather than the product name.
 * Once two CPEs describe the same identity (directly or through the alias
 * thesaurus), a conflict here is an authoritative exclusion, not a spelling
 * difference.
 */
const CPE_PLATFORM_FIELDS = [
  'part',
  'update',
  'edition',
  'language',
  'swEdition',
  'targetSw',
  'targetHw',
  'other',
] as const;

function cpeCriterionConflict(asset: ParsedCPE, vuln: ParsedCPE): boolean {
  if (CPE_PLATFORM_FIELDS.some((field) => !matchComponent(asset[field], vuln[field]))) return true;
  return (
    asset.version !== '*' &&
    asset.version !== '-' &&
    vuln.version !== '*' &&
    vuln.version !== '-' &&
    !matchComponent(asset.version, vuln.version)
  );
}

/**
 * A CPE whose vendor or product is a wildcard is not evidence of either
 * identity: without help it intersects every advisory for the same part.
 * Resolve the wildcard side from the inventory's own vendor/product fields so
 * a generic inventory CPE matches the product it actually describes.
 */
function resolveGenericCpeIdentity(
  assetCpeStr: string,
  assetVendor: string,
  assetProduct: string,
): { cpe: string; inferred: boolean } {
  const parsed = parseCPE23(assetCpeStr);
  if (!parsed.isValid) return { cpe: assetCpeStr, inferred: false };

  const genericVendor = isGenericCpeComponent(parsed.vendor);
  const genericProduct = isGenericCpeComponent(parsed.product);
  if (!genericVendor && !genericProduct) return { cpe: assetCpeStr, inferred: false };

  let vendor = parsed.vendor;
  let product = parsed.product;
  let inferred = false;
  if (genericVendor && assetVendor.trim()) {
    vendor = inventoryCpeToken(assetVendor);
    inferred = true;
  }
  if (genericProduct && assetProduct.trim()) {
    product = inventoryCpeToken(assetProduct);
    inferred = true;
  }
  if (!inferred) return { cpe: assetCpeStr, inferred: false };

  const tokens = splitCpeTokens(parsed.raw.slice(8));
  tokens[1] = vendor;
  tokens[2] = product;
  return { cpe: `cpe:2.3:${tokens.join(':')}`, inferred: true };
}

export interface CpeAliasOptions {
  /** Passing either map enables symmetric alias resolution for structured CPEs. */
  vendorAliases?: Record<string, string[]>;
  productAliases?: Record<string, string[]>;
}

/**
 * Strict CPE 2.3 Component matching between watch-list asset CPE and vulnerability target CPE.
 *
 * Exact component equality is always evaluated first and remains authoritative.
 * When alias maps are supplied, a structured CPE pair whose vendor/product differ
 * only by a thesaurus entry is matched symmetrically and flagged `viaAlias` so
 * the caller can apply the lower alias confidence and review gate.
 */
export function matchCPE(
  assetCpeStr: string,
  vulnCpeStr: string,
  versionRange?: NvdVersionRange,
  aliases?: CpeAliasOptions,
  /**
   * The inventory entry does not assert a version (wildcard or missing). The
   * product identity still matches, but a version-constrained advisory criterion
   * cannot be proven, so the caller must treat the result as review evidence.
   */
  unverifiedVersion = false,
): { matched: boolean; viaAlias?: boolean; reason?: string; unverifiedVersion?: boolean } {
  const asset = parseCPE23(assetCpeStr);
  const vuln = parseCPE23(vulnCpeStr);

  if (!asset.isValid || !vuln.isValid) {
    return { matched: false, reason: 'Invalid CPE syntax' };
  }

  // Part match (application, os, hardware)
  if (!matchComponent(asset.part, vuln.part)) return { matched: false, reason: 'Part mismatch' };

  let viaAlias = false;

  // Exact structured identifiers win. Only an explicit alias map may broaden a
  // vendor/product comparison, and only in the symmetric thesaurus sense.
  if (!matchComponent(asset.vendor, vuln.vendor)) {
    if (!aliases || !matchVendorWithAliases(asset.vendor, vuln.vendor, aliases.vendorAliases))
      return { matched: false, reason: `Vendor mismatch (${asset.vendor} vs ${vuln.vendor})` };
    viaAlias = true;
  }

  // Do not equate separate products through marketing aliases unless the
  // operator/built-in thesaurus explicitly groups them.
  if (!matchComponent(asset.product, vuln.product)) {
    if (!aliases || !matchProductWithAliases(asset.product, vuln.product, aliases.productAliases))
      return { matched: false, reason: `Product mismatch (${asset.product} vs ${vuln.product})` };
    viaAlias = true;
  }

  // Architecture check if specified (e.g. x86_64 vs aarch64)
  if (asset.targetHw !== '*' && vuln.targetHw !== '*' && !matchComponent(asset.targetHw, vuln.targetHw)) {
    return { matched: false, reason: `Target architecture mismatch (${asset.targetHw} vs ${vuln.targetHw})` };
  }

  // Target SW check if specified (e.g. linux vs windows)
  if (asset.targetSw !== '*' && vuln.targetSw !== '*' && !matchComponent(asset.targetSw, vuln.targetSw)) {
    return { matched: false, reason: `Target OS/SW mismatch (${asset.targetSw} vs ${vuln.targetSw})` };
  }

  for (const field of ['update', 'edition', 'language', 'swEdition', 'other'] as const) {
    if (!matchComponent(asset[field], vuln[field])) return { matched: false, reason: `${field} mismatch` };
  }

  if (!matchComponent(asset.version, vuln.version) && !unverifiedVersion)
    return { matched: false, reason: 'Version token mismatch' };

  // An unasserted inventory version is reported as unverified, never as agreement.
  if (unverifiedVersion) return { matched: true, viaAlias, unverifiedVersion: true };

  // Version matching: If explicit NVD version interval provided, evaluate interval
  if (
    versionRange &&
    (versionRange.versionStartIncluding ||
      versionRange.versionStartExcluding ||
      versionRange.versionEndExcluding ||
      versionRange.versionEndIncluding)
  ) {
    const rangeCheck = isVersionInNvdRange(asset.version, versionRange);
    if (!rangeCheck.inRange) {
      return { matched: false, reason: rangeCheck.reason };
    }
  } else {
    // Standard component matching
    if (!matchComponent(asset.version, vuln.version))
      return { matched: false, reason: 'Version token mismatch' };
  }

  return { matched: true, viaAlias };
}

/**
 * Enterprise Alias & Synonym Thesaurus.
 * These built-in tables are the code-reviewed baseline and are never mutated
 * at runtime. Operator-managed custom aliases (the "Alias Thesaurus" admin
 * page) are stored separately and merged on top at match time by
 * matchVendorWithAliases/matchProductWithAliases — see their `customAliases`
 * parameter. Exported so the admin UI can display the built-in baseline
 * alongside what operators have added.
 */
export const DEFAULT_VENDOR_ALIASES: Record<string, string[]> = {
  microsoft: ['msft', 'windows'],
  paloaltonetworks: ['palo_alto', 'panw', 'paloalto', 'unit42'],
  fortinet: ['fortiguard', 'fortios', 'fortinet_technologies'],
  cisco: ['cisco_systems', 'cisco-systems'],
  vmware: ['broadcom', 'esxi', 'vmware_inc'],
  apache: ['apache_software_foundation', 'httpd'],
  f5: ['f5_networks', 'f5-networks', 'f5_inc'],
  kubernetes: ['k8s'],
  openssl: ['openssl_project', 'openssl-org'],
  nginx: ['f5_nginx', 'nginx_inc'],
  docker: ['moby', 'docker_inc'],
  linux: ['linux_kernel', 'kernel'],
  postgresql: ['postgres', 'postgresql_global_development_group'],
  hashicorp: ['hashicorp_inc'],
};

export const DEFAULT_PRODUCT_ALIASES: Record<string, string[]> = {
  http_server: ['httpd', 'apache2', 'apache_http_server'],
  // GlobalProtect is Palo Alto's separate VPN client product, not a spelling
  // variant of PAN-OS (the firewall OS) — the two have independent CVE
  // histories, so they must not be aliased together. 'panos' is kept: it is
  // only a formatting variant of the same pan_os product string.
  pan_os: ['panos'],
  fortios: ['forti_os', 'fortigate'],
  ios_xe: ['ios-xe', 'cisco_ios_xe'],
  windows_server_2022: ['windows_server', 'win_server_2022'],
  esxi: ['esx', 'vsphere_esxi'],
  big_ip: ['bigip', 'big-ip_access_policy_manager'],
  log4j_core: ['log4j', 'log4j-core'],
  express: ['expressjs'],
};

const normalizeAliasToken = (value: string) => value.toLowerCase().replace(/[^a-z0-9]/g, '');

/**
 * Returns every spelling in the alias group that contains `value`.
 *
 * Candidate prefilters (the in-process inventory index and the PostgreSQL
 * version index) must expand exactly like the matcher. Expanding only
 * operator-managed aliases would exclude built-in pairs such as
 * `microsoft`/`msft` before `matchVendorWithAliases` ever sees them, silently
 * dropping a finding that the matcher considers valid.
 */
export function aliasGroupKeys(
  value: string,
  base: Record<string, string[]>,
  custom: Record<string, string[]> = {},
): string[] {
  const target = normalizeAliasToken(value);
  if (!target) return [];
  const keys = new Set<string>();
  for (const [canonical, aliases] of Object.entries(mergeAliasTables(base, custom))) {
    const group = [canonical, ...aliases];
    if (!group.some((entry) => normalizeAliasToken(entry) === target)) continue;
    for (const entry of group) keys.add(entry.toLowerCase());
  }
  return [...keys];
}

/** Merges operator-managed additions onto the built-in baseline. Custom
 * entries only ever ADD aliases to a canonical key (or introduce a new
 * canonical key); they cannot remove a built-in alias, so the reviewed
 * baseline can't be silently broken from the admin page. */
function mergeAliasTables(
  base: Record<string, string[]>,
  custom: Record<string, string[]>,
): Record<string, string[]> {
  if (!Object.keys(custom).length) return base;
  // A null prototype keeps operator-controlled keys such as `__proto__` as
  // ordinary data instead of invoking the prototype setter.
  const merged: Record<string, string[]> = Object.assign(Object.create(null), base);
  for (const [canonical, extra] of Object.entries(custom))
    merged[canonical] = [...new Set([...(merged[canonical] || []), ...extra])];
  return merged;
}

/** Converts persisted operator-managed alias rows into the canonical -> aliases[]
 * shape matchVendorWithAliases/matchProductWithAliases expect, scoped to one of
 * VENDOR/PRODUCT and merging any rows that repeat the same canonical key. */
export function buildAliasMap(
  entries: { scope: 'VENDOR' | 'PRODUCT'; canonical: string; aliases: string[] }[],
  scope: 'VENDOR' | 'PRODUCT',
): Record<string, string[]> {
  const map: Record<string, string[]> = Object.create(null);
  for (const entry of entries) {
    if (entry.scope !== scope) continue;
    const key = entry.canonical.toLowerCase().trim();
    map[key] = [...new Set([...(map[key] || []), ...entry.aliases.map((a) => a.toLowerCase().trim())])];
  }
  return map;
}

export function matchVendorWithAliases(
  assetVendor: string,
  vulnVendor: string,
  customAliases: Record<string, string[]> = {},
): boolean {
  if (matchComponent(assetVendor, vulnVendor)) return true;

  const a = assetVendor.toLowerCase().replace(/[^a-z0-9]/g, '');
  const v = vulnVendor.toLowerCase().replace(/[^a-z0-9]/g, '');

  if (a === v) return true;

  // Check aliases (built-in baseline + any operator-managed custom aliases)
  for (const [canonical, aliases] of Object.entries(
    mergeAliasTables(DEFAULT_VENDOR_ALIASES, customAliases),
  )) {
    const group = [canonical, ...aliases].map((s) => s.replace(/[^a-z0-9]/g, ''));
    if (group.includes(a) && group.includes(v)) return true;
  }

  return false;
}

export function matchProductWithAliases(
  assetProduct: string,
  vulnProduct: string,
  customAliases: Record<string, string[]> = {},
): boolean {
  if (matchComponent(assetProduct, vulnProduct)) return true;

  const a = assetProduct.toLowerCase().replace(/[^a-z0-9]/g, '');
  const v = vulnProduct.toLowerCase().replace(/[^a-z0-9]/g, '');

  if (a === v) return true;

  for (const [canonical, aliases] of Object.entries(
    mergeAliasTables(DEFAULT_PRODUCT_ALIASES, customAliases),
  )) {
    const group = [canonical, ...aliases].map((s) => s.replace(/[^a-z0-9]/g, ''));
    if (group.includes(a) && group.includes(v)) return true;
  }

  return false;
}

/**
 * Package URL (PURL) matcher e.g. pkg:npm/express@4.18.2
 */
export function matchPurl(assetPurl: string, vulnPurl: string): boolean {
  if (!assetPurl || !vulnPurl) return false;
  // Keep package names case-sensitive. Ignore neither version nor qualifiers.
  const parse = (value: string) => {
    const match = /^pkg:([a-z][a-z0-9.+-]*)\/([^?#]+)(\?[^#]*)?(#.*)?$/.exec(value.trim());
    if (!match) return null;
    const path = match[2];
    // A leading `@` is the npm scope, not a version delimiter. Only an `@`
    // after the package path is a version separator, so `pkg:npm/@scope/name`
    // keeps its full identity instead of becoming `npm/@scope/`.
    const at = path.lastIndexOf('@');
    const versionAt = at > path.indexOf('/') + 1 ? at : -1;
    return {
      identity: `${match[1]}/${versionAt > 0 ? path.slice(0, versionAt) : path}`,
      version: versionAt > 0 ? path.slice(versionAt + 1) : '',
      qualifiers: match[3] || '',
      subpath: match[4] || '',
    };
  };
  const a = parse(assetPurl),
    v = parse(vulnPurl);
  return (
    !!a &&
    !!v &&
    a.identity === v.identity &&
    (!v.version || a.version === v.version) &&
    a.qualifiers === v.qualifiers &&
    a.subpath === v.subpath
  );
}

export interface MatchResult {
  matched: boolean;
  method:
    | 'STRICT_CPE_INTERVAL'
    | 'STRICT_CPE'
    | 'PURL_EXACT'
    | 'VENDOR_PRODUCT_ALIAS'
    | 'VENDOR_PRODUCT_FALLBACK'
    | 'NONE';
  matchedCpe?: string;
  confidence: number; // 0 to 100
  evidence: string;
  suppressedByVex?: boolean;
  suppressedReason?: string;
  applicabilityRequiresReview?: boolean;
}

/**
 * Enterprise evaluation combining CPE 2.3 intervals, PURL, alias thesaurus, and de-noising
 */
export function matchesWatchlistItem(
  assetCpes: string[],
  assetVendor: string,
  assetProduct: string,
  vulnCpeMatches: string[],
  vulnTitle: string,
  vulnDescription: string,
  versionRange?: NvdVersionRange,
  assetPurls?: string[],
  vulnPurls?: string[],
  assetTargetHw?: string,
  vulnTargetHw?: string,
  evaluatePackages = true,
  customVendorAliases: Record<string, string[]> = {},
  customProductAliases: Record<string, string[]> = {},
  assetVersionInput?: string,
): MatchResult {
  let bestMatch: MatchResult | undefined;
  const retain = (candidate: MatchResult) => {
    if (!bestMatch || candidate.confidence > bestMatch.confidence) bestMatch = candidate;
  };
  // 1. Architecture De-noising check
  if (assetTargetHw && vulnTargetHw && assetTargetHw !== '*' && vulnTargetHw !== '*') {
    const hwA = assetTargetHw.toLowerCase();
    const hwV = vulnTargetHw.toLowerCase();
    if (hwA !== hwV) {
      return {
        matched: false,
        method: 'NONE',
        confidence: 0,
        evidence: `De-noised: Target architecture mismatch (${assetTargetHw} vs ${vulnTargetHw})`,
      };
    }
  }

  // 2. PURL Matching if present
  if (evaluatePackages && assetPurls && vulnPurls) {
    for (const ap of assetPurls) {
      for (const vp of vulnPurls) {
        const assetMain = ap.split(/[?#]/)[0];
        const atIdx = assetMain.lastIndexOf('@');
        const packageVersion = atIdx > assetMain.indexOf('/') + 1 ? assetMain.slice(atIdx + 1) : '';
        const hasVersion = atIdx > assetMain.indexOf('/') + 1;
        const vulnMain = vp.split(/[?#]/)[0];
        const vulnAtIdx = vulnMain.lastIndexOf('@');
        const vulnHasVersion = vulnAtIdx > vulnMain.indexOf('/') + 1;
        if (!matchPurl(ap, vp)) continue;
        if (versionRange && hasVersion && !isVersionInNvdRange(packageVersion, versionRange).inRange)
          continue;
        if (versionRange) {
          const verified = hasVersion && canCompareRange(packageVersion, versionRange);
          retain({
            matched: true,
            method: 'PURL_EXACT',
            confidence: verified ? 95 : 70,
            matchedCpe: ap,
            evidence: verified
              ? `Matched package dependency via PURL with verified version range: ${vp} (95% confidence)`
              : `Matched package name via PURL; installed version or range requires review: ${vp} (70% confidence)`,
            applicabilityRequiresReview: !verified,
          });
          continue;
        }
        // Without a range, a version-less advisory PURL only proves the package
        // identity. Treat it as review evidence rather than an exact correlation.
        const verified = hasVersion && vulnHasVersion;
        retain({
          matched: true,
          method: 'PURL_EXACT',
          confidence: verified ? 95 : 70,
          matchedCpe: ap,
          evidence: verified
            ? `Matched package dependency via PURL: ${vp} (95% confidence)`
            : `Matched package name via PURL without a version constraint; applicability requires review: ${vp} (70% confidence)`,
          applicabilityRequiresReview: !verified,
        });
      }
    }
  }

  // 3. Strict CPE 2.3 comparison with NVD version interval evaluation
  for (const rawAssetCpe of assetCpes) {
    // Wildcard vendor/product CPEs are resolved from inventory identity below,
    // and such inferred matches are review-only.
    const { cpe: assetCpe, inferred: genericIdentity } = resolveGenericCpeIdentity(
      rawAssetCpe,
      assetVendor,
      assetProduct,
    );
    for (const vulnCpe of vulnCpeMatches) {
      // An inventory CPE with a wildcard version (or none at all) asserts nothing
      // about the release. A version-constrained advisory criterion can therefore
      // only be a review candidate, never a confirmed match. Treating the wildcard
      // as agreement let an unversioned asset pass as an exact token match.
      const assetParsed = parseCPE23(assetCpe);
      const assetVersionUnasserted =
        assetParsed.isValid &&
        (!assetParsed.version || assetParsed.version === '*' || hasUnescapedCpeWildcard(assetParsed.version));
      const vulnParsed = parseCPE23(vulnCpe);
      const vulnConstrainsVersion =
        vulnParsed.isValid && vulnParsed.version !== '*' && vulnParsed.version !== '-' && !hasUnescapedCpeWildcard(vulnParsed.version);
      const matchRes = matchCPE(
        assetCpe,
        vulnCpe,
        versionRange,
        {
          vendorAliases: customVendorAliases,
          productAliases: customProductAliases,
        },
        assetVersionUnasserted && vulnConstrainsVersion,
      );
      if (matchRes.matched) {
        const asset = parseCPE23(assetCpe);
        const vuln = parseCPE23(vulnCpe);
        const rangeHasBounds = Boolean(versionRange && Object.values(versionRange).some(Boolean));
        const rangeNeedsReview = Boolean(
          rangeHasBounds &&
          (!asset.version || asset.version === '*' || !canCompareRange(asset.version, versionRange!)),
        );
        if (matchRes.viaAlias) {
          // A structured CPE pair resolved only through the thesaurus is a
          // product correlation, not a verified exact token match. Keep it
          // below the auto-dispatch threshold and require review when the
          // advisory constrains a version the inventory cannot prove.
          retain({
            matched: true,
            method: 'VENDOR_PRODUCT_ALIAS',
            confidence: 85,
            matchedCpe: vulnCpe,
            evidence: `Matched structured CPE through the symmetric alias thesaurus (${asset.vendor}/${asset.product} -> ${vuln.vendor}/${vuln.product}) (85% confidence)`,
            applicabilityRequiresReview: rangeNeedsReview || genericIdentity,
          });
          continue;
        }
        // An unknown inventory component cannot prove a constrained criterion,
        // including explicit versions, editions, target OS, language or updates.
        const contextNeedsReview =
          (
            [
              'part',
              'vendor',
              'product',
              'version',
              'update',
              'edition',
              'language',
              'swEdition',
              'targetSw',
              'targetHw',
              'other',
            ] as const
          ).some((field) => asset[field] === '*' && vuln[field] !== '*') ||
          (
            [
              'part',
              'vendor',
              'product',
              'version',
              'update',
              'edition',
              'language',
              'swEdition',
              'targetSw',
              'targetHw',
              'other',
            ] as const
          ).some((field) => hasUnescapedCpeWildcard(asset[field]));
        const requiresReview =
          rangeNeedsReview || contextNeedsReview || genericIdentity || Boolean(matchRes.unverifiedVersion);
        retain({
          matched: true,
          method: versionRange ? 'STRICT_CPE_INTERVAL' : 'STRICT_CPE',
          confidence: requiresReview ? 70 : versionRange ? 100 : 90,
          matchedCpe: vulnCpe,
          evidence: genericIdentity
            ? 'Matched CPE product identity inferred from the inventory record; confirm the generic CPE is intended (70% confidence)'
            : versionRange
              ? requiresReview
                ? 'Matched strict CPE 2.3 product identifiers; version or architecture applicability requires review'
                : `Matched strict CPE 2.3 component tokens + verified in version interval [< ${versionRange.versionEndExcluding || versionRange.versionEndIncluding}] (100% confidence)`
              : `Matched strict CPE 2.3 component tokens (90% confidence)`,
          applicabilityRequiresReview: requiresReview,
        });
      }
    }
  }

  if (bestMatch) return bestMatch;

  // Package identity is exact: a PURL-vs-PURL mismatch remains authoritative.
  // A CPE mismatch, by contrast, may only mean the two sides spell the same
  // vendor/product differently, which the alias and fallback steps below can
  // still resolve.
  if (assetPurls?.length && vulnPurls?.length) {
    return {
      matched: false,
      method: 'NONE',
      confidence: 0,
      evidence: 'Package identifiers did not match',
    };
  }

  // 4. Vendor / Product Alias Resolution
  const normVendor = assetVendor.toLowerCase().trim();
  const normProduct = assetProduct.toLowerCase().trim();
  // The alias path is the last structured option before free text. Evaluate the
  // advisory's version interval against the inventory version when one is known
  // so an alias cannot create a finding for an explicitly unaffected release.
  const assetVersion =
    (assetVersionInput || '').trim() ||
    assetCpes
      .map((cpe) => parseCPE23(cpe))
      .find((parsed) => parsed.isValid && parsed.version && parsed.version !== '*' && parsed.version !== '-')
      ?.version ||
    '';
  const rangeHasBounds = Boolean(versionRange && Object.values(versionRange).some(Boolean));

  // A CPE mismatch is only allowed to fall through when it concerns the
  // vendor/product names. If the structured identity is the same and a CPE
  // criterion explicitly excludes the inventory (version token, part,
  // architecture, target OS or another fixed field), that exclusion remains
  // authoritative. Otherwise a text fallback could re-admit a release the CPE
  // evidence already proved inapplicable.
  const sameStructuredIdentity = (asset: ParsedCPE, vuln: ParsedCPE) =>
    (matchComponent(asset.vendor, vuln.vendor) ||
      matchVendorWithAliases(asset.vendor, vuln.vendor, customVendorAliases)) &&
    (matchComponent(asset.product, vuln.product) ||
      matchProductWithAliases(asset.product, vuln.product, customProductAliases));
  const cpeIdentityExcluded = assetCpes.some((assetCpe) => {
    // Resolve a generic inventory CPE with the same inventory fields used by
    // the strict comparison so its version/platform cannot be attributed to an
    // unrelated advisory product.
    const asset = parseCPE23(
      resolveGenericCpeIdentity(assetCpe, assetVendor, assetProduct).cpe,
    );
    if (!asset.isValid) return false;
    return vulnCpeMatches.some((vulnCpe) => {
      const vuln = parseCPE23(vulnCpe);
      if (!vuln.isValid || !sameStructuredIdentity(asset, vuln)) return false;
      return cpeCriterionConflict(asset, vuln);
    });
  });
  if (assetCpes.length > 0 && cpeIdentityExcluded) {
    return {
      matched: false,
      method: 'NONE',
      confidence: 0,
      evidence: 'Structured CPE criteria explicitly excluded the inventory version or platform',
    };
  }

  const resolvedAssetCpes = assetCpes
    .map((cpe) => parseCPE23(resolveGenericCpeIdentity(cpe, assetVendor, assetProduct).cpe))
    .filter((parsed) => parsed.isValid);

  for (const vulnCpe of vulnCpeMatches) {
    const parsedVuln = parseCPE23(vulnCpe);
    if (parsedVuln.isValid) {
      if (
        matchVendorWithAliases(normVendor, parsedVuln.vendor, customVendorAliases) &&
        matchProductWithAliases(normProduct, parsedVuln.product, customProductAliases)
      ) {
        // An alias only broadens the vendor/product names. The remaining CPE
        // criteria (part, architecture, target OS, edition, language, update
        // and concrete version) stay authoritative on this path too, so a
        // Windows-only advisory cannot correlate a Linux asset merely because
        // the vendor spellings differ.
        if (
          resolvedAssetCpes.length > 0 &&
          !resolvedAssetCpes.some((asset) => !cpeCriterionConflict(asset, parsedVuln))
        )
          continue;
        let applicabilityRequiresReview = rangeHasBounds;
        let versionVerified = false;
        if (rangeHasBounds && versionRange && assetVersion) {
          if (canCompareRange(assetVersion, versionRange)) {
            if (!isVersionInNvdRange(assetVersion, versionRange).inRange) continue;
            versionVerified = true;
            applicabilityRequiresReview = false;
          }
        }
        return {
          matched: true,
          method: 'VENDOR_PRODUCT_ALIAS',
          confidence: 85,
          matchedCpe: vulnCpe,
          evidence: versionVerified
            ? `Resolved via Enterprise Alias Thesaurus (${normVendor}/${normProduct} -> ${parsedVuln.vendor}/${parsedVuln.product}); inventory version ${assetVersion} is inside the advisory range (85% confidence)`
            : `Resolved via Enterprise Alias Thesaurus (${normVendor}/${normProduct} -> ${parsedVuln.vendor}/${parsedVuln.product}) (85% confidence)`,
          applicabilityRequiresReview,
        };
      }
    }
  }

  // 5. Fallback Heuristic
  const fullText = `${vulnTitle} ${vulnDescription}`.toLowerCase();
  if (
    normVendor &&
    normProduct &&
    containsIdentityWords(fullText, normVendor) &&
    containsIdentityWords(fullText, normProduct)
  ) {
    // Do not let the text fallback re-admit a release that the advisory range
    // explicitly excludes when the inventory version is comparable.
    if (
      rangeHasBounds &&
      versionRange &&
      assetVersion &&
      canCompareRange(assetVersion, versionRange) &&
      !isVersionInNvdRange(assetVersion, versionRange).inRange
    )
      return { matched: false, method: 'NONE', confidence: 0, evidence: 'Version outside advisory range' };
    return {
      matched: true,
      method: 'VENDOR_PRODUCT_FALLBACK',
      confidence: 70,
      matchedCpe: assetCpes[0] || `cpe:2.3:a:${normVendor}:${normProduct}:*:*:*:*:*:*:*:*`,
      evidence: `Matched vendor "${normVendor}" and product "${normProduct}" in advisory text (70% confidence)`,
    };
  }

  return { matched: false, method: 'NONE', confidence: 0, evidence: 'No component or keyword correlation' };
}

export function generateCPE23(
  part: 'a' | 'o' | 'h',
  vendor: string,
  product: string,
  version: string = '*',
  targetHw: string = '*',
): string {
  const escape = (value: string) => value.replace(/\\/g, '\\\\').replace(/:/g, '\\:');
  const cleanPart = part || 'a';
  const cleanVendor = escape(
    (vendor || 'any')
      .toLowerCase()
      .trim()
      .replace(/[^a-z0-9_.-]/g, '_'),
  );
  const cleanProduct = escape(
    (product || 'any')
      .toLowerCase()
      .trim()
      .replace(/[^a-z0-9_.-]/g, '_'),
  );
  const cleanVersion = version && version !== '*' ? escape(version.trim()) : '*';
  const cleanHw = targetHw && targetHw !== '*' ? escape(targetHw.trim()) : '*';

  return `cpe:2.3:${cleanPart}:${cleanVendor}:${cleanProduct}:${cleanVersion}:*:*:*:*:*:${cleanHw}:*`;
}
