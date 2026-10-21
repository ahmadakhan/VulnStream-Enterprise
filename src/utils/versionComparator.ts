/**
 * Numeric version and supported vendor patch range comparison.
 * Unknown release ordering is retained as a review candidate rather than excluded.
 */

export interface NvdVersionRange {
  versionStartIncluding?: string;
  versionStartExcluding?: string;
  versionEndIncluding?: string;
  versionEndExcluding?: string;
}

/** Only these version families have defined ordering in this comparator. */
export function canCompareRange(version: string, range: NvdVersionRange): boolean {
  const supported = (value: string) =>
    /^[0-9]+(?:\.[0-9]+)*(?:-(?:h|p|patch|hotfix|sp|u|update|build|fix)[0-9]+)?$/.test(value);
  const values = [version, ...Object.values(range).filter((bound): bound is string => !!bound)];
  // Different vendor suffix families do not have a portable relative ordering.
  // Numeric conversion must also be exact before it can justify exclusion.
  return (
    values.every(
      (value) =>
        supported(value) && (value.match(/\d+/g) || []).every((token) => Number.isSafeInteger(Number(token))),
    ) && new Set(values.map((value) => /-([a-z]+)/.exec(value)?.[1]).filter(Boolean)).size <= 1
  );
}

interface ParsedVersion {
  numbers: number[];
  prerelease: string[];
  raw: string;
}

export function parseVersion(verStr: string): ParsedVersion {
  if (!verStr || verStr === '*' || verStr === '-') {
    return { numbers: [], prerelease: [], raw: verStr || '*' };
  }

  const clean = verStr.trim().toLowerCase().replace(/^[v]/, '');
  const [core, ...preParts] = clean.split('+')[0].split(/[-_]/);

  // Extract all digit tokens from core
  const numMatches = core.match(/\d+/g);
  const numbers = numMatches ? numMatches.map(Number) : [0];

  return {
    numbers,
    prerelease: preParts,
    raw: verStr,
  };
}

function isPostReleasePatchTag(tag: string): boolean {
  return /^(h\d+|p\d+|patch\d*|hotfix\d*|sp\d*|u\d*|update\d*|build\d*|fix\d*)/i.test(tag.trim());
}

/**
 * Returns:
 *  -1 if v1 < v2
 *   0 if v1 === v2
 *   1 if v1 > v2
 */
export function compareVersions(v1Str: string, v2Str: string): number {
  if (v1Str === v2Str) return 0;
  if (v1Str === '*' || v2Str === '*') return 0;

  const v1 = parseVersion(v1Str);
  const v2 = parseVersion(v2Str);

  const maxLen = Math.max(v1.numbers.length, v2.numbers.length);

  for (let i = 0; i < maxLen; i++) {
    const num1 = v1.numbers[i] || 0;
    const num2 = v2.numbers[i] || 0;

    if (num1 > num2) return 1;
    if (num1 < num2) return -1;
  }

  // Compare prerelease / post-release patch tags if core numbers match
  const p1 = v1.prerelease.join('-');
  const p2 = v2.prerelease.join('-');

  if (p1 === p2) return 0;

  // Handle post-release patch tags (e.g. 10.2.9-h1 is GREATER than 10.2.9)
  if (!p1 && p2) {
    return isPostReleasePatchTag(p2) ? -1 : 1;
  }
  if (p1 && !p2) {
    return isPostReleasePatchTag(p1) ? 1 : -1;
  }

  // Natural numeric comparison (so h10 > h9, patch12 > patch2)
  return p1.localeCompare(p2, undefined, { numeric: true, sensitivity: 'base' });
}

/**
 * Checks if deployed product version satisfies an NVD version criteria interval
 */
export function isVersionInNvdRange(
  deployedVersion: string,
  range: NvdVersionRange,
): { inRange: boolean; reason: string } {
  if (!deployedVersion || deployedVersion === '*') {
    return { inRange: true, reason: 'Wildcard version on asset matches all ranges' };
  }

  if (!canCompareRange(deployedVersion, range)) {
    return { inRange: true, reason: 'Version ordering is unsupported; applicability requires review' };
  }

  // 1. Check versionStartIncluding (>= start)
  if (range.versionStartIncluding) {
    if (compareVersions(deployedVersion, range.versionStartIncluding) < 0) {
      return {
        inRange: false,
        reason: `Deployed version ${deployedVersion} < start limit ${range.versionStartIncluding}`,
      };
    }
  }

  // 2. Check versionStartExcluding (> start)
  if (range.versionStartExcluding) {
    if (compareVersions(deployedVersion, range.versionStartExcluding) <= 0) {
      return {
        inRange: false,
        reason: `Deployed version ${deployedVersion} <= start exclusion limit ${range.versionStartExcluding}`,
      };
    }
  }

  // 3. Check versionEndIncluding (<= end)
  if (range.versionEndIncluding) {
    if (compareVersions(deployedVersion, range.versionEndIncluding) > 0) {
      return {
        inRange: false,
        reason: `Deployed version ${deployedVersion} > patched limit ${range.versionEndIncluding} (Already Patched)`,
      };
    }
  }

  // 4. Check versionEndExcluding (< end)
  if (range.versionEndExcluding) {
    if (compareVersions(deployedVersion, range.versionEndExcluding) >= 0) {
      return {
        inRange: false,
        reason: `Deployed version ${deployedVersion} >= fixed limit ${range.versionEndExcluding} (Already Patched)`,
      };
    }
  }

  return {
    inRange: true,
    reason: `Deployed version ${deployedVersion} is strictly within vulnerable interval [${range.versionStartIncluding || '*'}, ${range.versionEndExcluding || range.versionEndIncluding || '*'})`,
  };
}
