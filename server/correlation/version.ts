import semver from 'semver';

const PRERELEASE_TAG = /-(alpha|beta|rc|pre|preview)([.-][0-9]+)?$/i;

const isNamedPrerelease = (clean: string): boolean => PRERELEASE_TAG.test(clean);

/** Coerce only plain numeric releases. Never discard distribution/backport suffixes.
 * Only unambiguous, named prerelease tags (alpha, beta, rc, pre, preview, optionally
 * with a numeric ordinal) are accepted. A bare digit-only suffix (e.g., "2.4.41-2")
 * falls through to REVIEW, consistent with NVD-side comparator behavior. */
export function portableVersion(value: string): string | null {
  if (value.length > 100) return null;
  const clean = value.trim().replace(/^v/i, '');
  const valid = semver.valid(clean);
  if (valid) {
    if (clean.includes('+')) return null;
    if (clean.includes('-') && !isNamedPrerelease(clean)) return null;
    return valid;
  }
  if (!/^[0-9]{1,9}(\.[0-9]{1,9}){0,3}$/.test(clean)) return null;
  return clean;
}

/** Detect a distribution/backport suffix on an enterprise package version.
 * Examples: "1.2.3-ubuntu1~20.04.1", "2.4.41-el8", "10.3.2-MariaDB",
 * "1.8.0_392" (Java update ordinal). These versions carry vendor rebuild
 * numbering that no upstream range can resolve; comparing them against an
 * upstream bound silently produces wrong verdicts. */
export function distributionSuffix(value: string): string | null {
  const clean = value.trim().replace(/^v/i, '');
  if (isNamedPrerelease(clean)) return null;
  const debian = /^[0-9.]+(?::-[0-9.]+)?-([A-Za-z][A-Za-z0-9.+~]*)$/.exec(clean);
  if (debian) return debian[1];
  if (/^[0-9.]+_[0-9]+$/.test(clean)) return clean.split('_')[1];
  return null;
}

const VERSION_TOKEN = 'v?([0-9]{1,9}(?:\\.[0-9]{1,9}){0,3})';

function stripLeadingV(raw: string): string {
  return raw.replace(/^v?/i, '');
}

/**
 * Natural-language range phrases extracted from unstructured prose must be
 * translated before they reach the semver comparator. Advisory prose uses
 * bounds the strict grammar never covered:
 *   "patched before version 9.0.86"   -> vulnerable < 9.0.86
 *   "fixed in 4.2.1"                  -> vulnerable < 4.2.1
 *   "vulnerable between 2.1.0 and 2.3.4" -> >=2.1.0 <=2.3.4
 *   "versions 5.0 through 5.7"        -> >=5.0 <=5.7
 *   "up to and including 4.2.1"       -> <=4.2.1
 * Anything that cannot be translated unambiguously returns REVIEW, never a
 * silent identity fallback.
 */
export function naturalLanguageRange(prose: string): string | null {
  const text = prose.toLowerCase().replace(/\bversions?\b/g, ' ').replace(/\s+/g, ' ').trim();

  let m: RegExpExecArray | null;

  m = new RegExp(`(?:between|from) ${VERSION_TOKEN} (?:and|to|through|thru) ${VERSION_TOKEN}`).exec(text);
  if (m) {
    const low = stripLeadingV(m[1]);
    const high = stripLeadingV(m[2]);
    return `>=${low} <=${high}`;
  }

  m = new RegExp(`${VERSION_TOKEN} (?:through|to|thru) ${VERSION_TOKEN}`).exec(text);
  if (m) {
    const low = stripLeadingV(m[1]);
    const high = stripLeadingV(m[2]);
    return `>=${low} <=${high}`;
  }

  m = new RegExp(`(?:before|prior to|below|earlier than|at most) ${VERSION_TOKEN}`).exec(text);
  if (m) return `<${stripLeadingV(m[1])}`;

  m = new RegExp(`(?:patched|fixed|resolved|remediated|addressed) in ${VERSION_TOKEN}`).exec(text);
  if (m) return `<${stripLeadingV(m[1])}`;

  m = new RegExp(`(?:up to and including|through|up to) ${VERSION_TOKEN}`).exec(text);
  if (m) return `<=${stripLeadingV(m[1])}`;

  m = new RegExp(`^${VERSION_TOKEN} (?:and earlier|or older|or earlier|or below)$`).exec(text);
  if (m) return `<=${stripLeadingV(m[1])}`;

  m = new RegExp(`^${VERSION_TOKEN} (?:and later|or later|or newer|or above)$`).exec(text);
  if (m) return `>=${stripLeadingV(m[1])}`;

  return null;
}

function numericParts(version: string): number[] | null {
  const match = /^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?$/.exec(version.trim());
  if (!match) return null;
  return [1, 2, 3, 4].map((i) => (match[i] === undefined ? 0 : Number(match[i])));
}

function compareNumeric(version: string, bound: string): number {
  const a = numericParts(version);
  const b = numericParts(bound);
  if (!a || !b) return 0;
  for (let i = 0; i < 4; i++) {
    if (a[i] !== b[i]) return a[i] > b[i] ? 1 : -1;
  }
  return 0;
}

export interface VersionVerdict {
  verdict: 'AFFECTED' | 'UNAFFECTED' | 'REVIEW';
  provenance: 'semver' | 'numeric' | 'distro-backport' | 'unparseable' | 'empty';
  comparator: string;
}

/**
 * Evaluate whether a deployed version is affected by a range.
 *
 * Returns the verdict string directly for backward compatibility. Use
 * `evaluateVersionDetailed` when provenance metadata is required.
 *
 * includePrerelease: true is an explicit policy decision: a prerelease of the
 * next release (e.g., 1.0.0-rc.1 satisfies <1.0.0) is treated as vulnerable
 * because it is older than the stable release. This is recorded as policy, not
 * an incidental semver flag.
 */
export function evaluateVersion(
  version: string | null,
  range: string,
): 'AFFECTED' | 'UNAFFECTED' | 'REVIEW' {
  return evaluateVersionDetailed(version, range).verdict;
}

export function evaluateVersionDetailed(
  version: string | null,
  range: string,
): VersionVerdict {
  if (!version) return { verdict: 'REVIEW', provenance: 'empty', comparator: range };
  if (range.length > 200) return { verdict: 'REVIEW', provenance: 'unparseable', comparator: range };

  if (distributionSuffix(version)) {
    return {
      verdict: 'REVIEW',
      provenance: 'distro-backport',
      comparator: `distribution-suffix:${version}`,
    };
  }

  const effective = naturalLanguageRange(range) ?? range;
  const parsed = portableVersion(version);
  if (!parsed) return { verdict: 'REVIEW', provenance: 'unparseable', comparator: range };

  const terms = effective.trim().split(/\s+/);
  if (
    terms.length > 8 ||
    terms.some(
      (term) =>
        !/^(>=|<=|>|<|=)?v?[0-9]{1,9}(\.[0-9]{1,9}){0,3}(-[a-zA-Z0-9.-]{1,40})?$/i.test(term),
    )
  )
    return { verdict: 'REVIEW', provenance: 'unparseable', comparator: range };

  const normalized: string[] = [];
  for (const term of terms) {
    const match = /^(>=|<=|>|<|=)?(.*)$/.exec(term)!;
    const bound = portableVersion(match[2]);
    if (!bound) return { verdict: 'REVIEW', provenance: 'unparseable', comparator: range };
    normalized.push(`${match[1] || '='}${bound}`);
  }

  const semverRange = semver.validRange(normalized.join(' '));
  if (semverRange && semver.valid(parsed)) {
    return {
      verdict: semver.satisfies(parsed, semverRange, { includePrerelease: true })
        ? 'AFFECTED'
        : 'UNAFFECTED',
      provenance: 'semver',
      comparator: semverRange,
    };
  }

  if (numericParts(parsed) && normalized.every((t) => numericParts(t.replace(/^(>=|<=|>|<|=)?/, '')))) {
    let affected = true;
    for (const term of normalized) {
      const match = /^(>=|<=|>|<|=)?(.*)$/.exec(term)!;
      const op = match[1] || '=';
      const cmp = compareNumeric(parsed, match[2]);
      if (
        (op === '>' && !(cmp > 0)) ||
        (op === '>=' && !(cmp >= 0)) ||
        (op === '<' && !(cmp < 0)) ||
        (op === '<=' && !(cmp <= 0)) ||
        (op === '=' && cmp !== 0)
      ) {
        affected = false;
        break;
      }
    }
    return {
      verdict: affected ? 'AFFECTED' : 'UNAFFECTED',
      provenance: 'numeric',
      comparator: normalized.join(' '),
    };
  }

  return { verdict: 'REVIEW', provenance: 'unparseable', comparator: range };
}
