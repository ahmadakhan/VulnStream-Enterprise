/**
 * Enterprise CPE 2.3 Strict Component Matcher, SemVer Range Evaluator & PURL Matcher
 * Spec: NIST IR 7695 & Package URL (purl-spec)
 */

import { NvdVersionRange, isVersionInNvdRange } from './versionComparator';

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

export function parseCPE23(cpeString: string): ParsedCPE {
  if (!cpeString || typeof cpeString !== 'string') {
    return createEmptyCPE(cpeString, false);
  }

  const trimmed = cpeString.trim();
  if (!trimmed.startsWith('cpe:2.3:')) {
    return createEmptyCPE(trimmed, false);
  }

  const tokens = splitCpeTokens(trimmed.slice(8));

  if (
    tokens.length !== 11 ||
    !['a', 'o', 'h', '*', '-'].includes(tokens[0]) ||
    tokens.some((token) => !token || /(?<!\\)(?:\\\\)*\\$/.test(token))
  ) {
    return createEmptyCPE(trimmed, false);
  }

  return {
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

function matchComponent(assetAttr: string, vulnAttr: string): boolean {
  if (assetAttr === '*' || vulnAttr === '*') return true;
  if (assetAttr === '-' && vulnAttr === '-') return true;
  if (assetAttr === '-' || vulnAttr === '-') return false;

  const a = assetAttr.replace(/\\/g, '').toLowerCase();
  const v = vulnAttr.replace(/\\/g, '').toLowerCase();

  return a === v;
}

/**
 * Strict CPE 2.3 Component matching between watch-list asset CPE and vulnerability target CPE
 */
export function matchCPE(
  assetCpeStr: string,
  vulnCpeStr: string,
  versionRange?: NvdVersionRange,
): { matched: boolean; reason?: string } {
  const asset = parseCPE23(assetCpeStr);
  const vuln = parseCPE23(vulnCpeStr);

  if (!asset.isValid || !vuln.isValid) {
    return { matched: false, reason: 'Invalid CPE syntax' };
  }

  // Part match (application, os, hardware)
  if (!matchComponent(asset.part, vuln.part)) return { matched: false, reason: 'Part mismatch' };

  // Structured identifiers require exact components; aliases are only for catalog search.
  if (!matchComponent(asset.vendor, vuln.vendor)) {
    return { matched: false, reason: `Vendor mismatch (${asset.vendor} vs ${vuln.vendor})` };
  }

  // Do not equate separate products through marketing aliases.
  if (!matchComponent(asset.product, vuln.product)) {
    return { matched: false, reason: `Product mismatch (${asset.product} vs ${vuln.product})` };
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

  if (!matchComponent(asset.version, vuln.version))
    return { matched: false, reason: 'Version token mismatch' };

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

  return { matched: true };
}

/**
 * Enterprise Alias & Synonym Thesaurus
 */
const VENDOR_ALIASES: Record<string, string[]> = {
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

const PRODUCT_ALIASES: Record<string, string[]> = {
  http_server: ['httpd', 'apache2', 'apache_http_server'],
  pan_os: ['panos', 'globalprotect'],
  fortios: ['forti_os', 'fortigate'],
  ios_xe: ['ios-xe', 'cisco_ios_xe'],
  windows_server_2022: ['windows_server', 'win_server_2022'],
  esxi: ['esx', 'vsphere_esxi'],
  big_ip: ['bigip', 'big-ip_access_policy_manager'],
  log4j_core: ['log4j', 'log4j-core'],
  express: ['expressjs'],
};

export function matchVendorWithAliases(assetVendor: string, vulnVendor: string): boolean {
  if (matchComponent(assetVendor, vulnVendor)) return true;

  const a = assetVendor.toLowerCase().replace(/[^a-z0-9]/g, '');
  const v = vulnVendor.toLowerCase().replace(/[^a-z0-9]/g, '');

  if (a === v) return true;

  // Check aliases
  for (const [canonical, aliases] of Object.entries(VENDOR_ALIASES)) {
    const group = [canonical, ...aliases].map((s) => s.replace(/[^a-z0-9]/g, ''));
    if (group.includes(a) && group.includes(v)) return true;
  }

  return false;
}

export function matchProductWithAliases(assetProduct: string, vulnProduct: string): boolean {
  if (matchComponent(assetProduct, vulnProduct)) return true;

  const a = assetProduct.toLowerCase().replace(/[^a-z0-9]/g, '');
  const v = vulnProduct.toLowerCase().replace(/[^a-z0-9]/g, '');

  if (a === v) return true;

  for (const [canonical, aliases] of Object.entries(PRODUCT_ALIASES)) {
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
    const at = match[2].lastIndexOf('@');
    return {
      identity: `${match[1]}/${at > 0 ? match[2].slice(0, at) : match[2]}`,
      version: at > 0 ? match[2].slice(at + 1) : '',
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
): MatchResult {
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
  if (assetPurls && vulnPurls) {
    for (const ap of assetPurls) {
      for (const vp of vulnPurls) {
        const packageVersion = ap.split(/[?#]/)[0].split('@').pop();
        const hasVersion = ap.split(/[?#]/)[0].lastIndexOf('@') > ap.indexOf('/') + 1;
        if (
          matchPurl(ap, vp) &&
          (!versionRange || (hasVersion && isVersionInNvdRange(packageVersion!, versionRange).inRange))
        ) {
          return {
            matched: true,
            method: 'PURL_EXACT',
            confidence: 95,
            matchedCpe: ap,
            evidence: `Matched package dependency via PURL: ${vp} (95% confidence)`,
          };
        }
      }
    }
  }

  // 3. Strict CPE 2.3 comparison with NVD version interval evaluation
  for (const assetCpe of assetCpes) {
    for (const vulnCpe of vulnCpeMatches) {
      const matchRes = matchCPE(assetCpe, vulnCpe, versionRange);
      if (matchRes.matched) {
        return {
          matched: true,
          method: versionRange ? 'STRICT_CPE_INTERVAL' : 'STRICT_CPE',
          confidence: versionRange ? 100 : 90,
          matchedCpe: vulnCpe,
          evidence: versionRange
            ? `Matched strict CPE 2.3 component tokens + verified in version interval [< ${versionRange.versionEndExcluding || versionRange.versionEndIncluding}] (100% confidence)`
            : `Matched strict CPE 2.3 component tokens (90% confidence)`,
        };
      }
    }
  }

  // Structured identifiers are authoritative; do not undo exclusions with text heuristics.
  if ((assetCpes.length && vulnCpeMatches.length) || (assetPurls?.length && vulnPurls?.length)) {
    return {
      matched: false,
      method: 'NONE',
      confidence: 0,
      evidence: 'Structured identifiers did not match',
    };
  }

  // 4. Vendor / Product Alias Resolution
  const normVendor = assetVendor.toLowerCase().trim();
  const normProduct = assetProduct.toLowerCase().trim();

  for (const vulnCpe of vulnCpeMatches) {
    const parsedVuln = parseCPE23(vulnCpe);
    if (parsedVuln.isValid) {
      if (
        matchVendorWithAliases(normVendor, parsedVuln.vendor) &&
        matchProductWithAliases(normProduct, parsedVuln.product)
      ) {
        return {
          matched: true,
          method: 'VENDOR_PRODUCT_ALIAS',
          confidence: 85,
          matchedCpe: vulnCpe,
          evidence: `Resolved via Enterprise Alias Thesaurus (${normVendor}/${normProduct} -> ${parsedVuln.vendor}/${parsedVuln.product}) (85% confidence)`,
        };
      }
    }
  }

  // 5. Fallback Heuristic
  const fullText = `${vulnTitle} ${vulnDescription}`.toLowerCase();
  if (normVendor && normProduct && fullText.includes(normVendor) && fullText.includes(normProduct)) {
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
  const cleanPart = part || 'a';
  const cleanVendor = (vendor || 'any')
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9_.-]/g, '_');
  const cleanProduct = (product || 'any')
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9_.-]/g, '_');
  const cleanVersion = version && version !== '*' ? version.trim() : '*';
  const cleanHw = targetHw && targetHw !== '*' ? targetHw.trim() : '*';

  return `cpe:2.3:${cleanPart}:${cleanVendor}:${cleanProduct}:${cleanVersion}:*:*:*:*:*:${cleanHw}:*`;
}
