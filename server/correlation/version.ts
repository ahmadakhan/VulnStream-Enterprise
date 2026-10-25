import semver from 'semver';
/** Coerce only plain numeric releases. Never discard distribution/backport suffixes.
 * Only unambiguous, named prerelease tags (alpha, beta, rc, pre, preview, optionally
 * with a numeric ordinal) are accepted. A bare digit-only suffix (e.g., "2.4.41-2")
 * falls through to REVIEW, consistent with NVD-side comparator behavior. */
export function portableVersion(value: string): string | null {
  if (value.length > 100) return null;
  const clean = value.trim().replace(/^v/, '');
  const valid = semver.valid(clean);
  if (valid) {
    // Vendor build metadata can encode backports; an upstream range cannot resolve it.
    if (clean.includes('+')) return null;
    // Reject bare numeric-only prerelease suffixes (e.g., "2.4.41-2", "1.2.3-45")
    // Only accept named prerelease tags: alpha, beta, rc, pre, preview with optional numeric ordinal.
    if (clean.includes('-') && !/-((alpha|beta|rc|pre|preview)([.-][0-9]+)?)$/.test(clean))
      return null;
    return valid;
  }
  if (!/^[0-9]{1,9}(\.[0-9]{1,9}){0,2}$/.test(clean)) return null;
  return semver.coerce(clean)?.version ?? null;
}

/** Detect a distribution/backport suffix on an enterprise package version.
 * Examples: "1.2.3-ubuntu1~20.04.1", "2.4.41-el8", "10.3.2-MariaDB",
 * "1.8.0_392" (Java update ordinal). These versions carry vendor rebuild
 * numbering that no upstream range can resolve; comparing them against an
 * upstream bound silently produces wrong verdicts. */
export function distributionSuffix(value: string): string | null {
  const clean = value.trim().replace(/^v/i, '');
  // Named prerelease tags are upstream identifiers, not distribution rebuilds.
  if (/-(alpha|beta|rc|pre|preview)([.-][0-9]+)?$/.test(clean)) return null;
  // Debian/Ubuntu/RHEL style: 1.2.3-ubuntu1~20.04.1, 2.4.41-el8, 1:1.2.3-1
  const debian = /^[0-9.]+(?::-[0-9.]+)?-([A-Za-z][A-Za-z0-9.+~]*)$/.exec(clean);
  if (debian) return debian[1];
  // Java-style update ordinal: 1.8.0_392
  if (/^[0-9.]+_[0-9]+$/.test(clean)) return clean.split('_')[1];
  return null;
}

/**
 * Natural-language range phrases extracted from unstructured prose must be
 * translated before they reach the semver comparator. Advisory prose uses
 * bounds the strict grammar never covered:
 *   "patched before version 9.0.86"   -> vulnerable < 9.0.86
 *   "fixed in 4.2.1"                  -> vulnerable < 4.2.1
 *   "vulnerable between 2.1.0 and 2.3.4" -> >=2.1.0 <=2.3.4
 *   "versions 5.0 through 5.7"        -> >=5.0 <=5.7
 * Anything that cannot be translated unambiguously returns REVIEW, never a
 * silent identity fallback.
 */
export function naturalLanguageRange(prose: string): string | null {
  const text = prose.toLowerCase().replace(/\bversions?\b/g, ' ').replace(/\s+/g, ' ').trim();
  const V = 'v?([0-9]{1,9}(?:\\.[0-9]{1,9}){0,2})';
  let m: RegExpExecArray | null;
  // "before/prior to/below/earlier than X" — vulnerable strictly below X,
  // unless negated by "patched/fixed/resolved", which means the same bound.
  m = new RegExp(`(?:before|prior to|below|earlier than) ${V}`).exec(text);
  if (m) return `<${m[1]}`;
  m = new RegExp(`(?:patched|fixed|resolved|remediated) in ${V}`).exec(text);
  if (m) return `<${m[1]}`;
  // "between X and Y" / "from X through Y" — inclusive band.
  m = new RegExp(`(?:between|from) ${V} (?:and|to|through|thru) ${V}`).exec(text);
  if (m) {
    const low = semver.coerce(m[1]);
    const high = semver.coerce(m[2]);
    if (low && high) return `>=${low.version} <=${high.version}`;
  }
  // "X and earlier" / "X or older"
  m = new RegExp(`^${V} (?:and earlier|or older|or earlier|or below)$`).exec(text);
  if (m) return `<=${m[1]}`;
  // "X and later" / "X or newer" — vulnerability introduced in X.
  m = new RegExp(`^${V} (?:and later|or later|or newer|or above)$`).exec(text);
  if (m) return `>=${m[1]}`;
  return null;
}

export function evaluateVersion(version: string | null, range: string): 'AFFECTED' | 'UNAFFECTED' | 'REVIEW' {
  if (!version || range.length > 200) return 'REVIEW';
  // A backported distribution package must never be resolved against an
  // upstream bound: distro rebuilds patch without changing the upstream base
  // version, so both AFFECTED and UNAFFECTED verdicts would be fiction.
  if (distributionSuffix(version)) return 'REVIEW';
  // Accept either a comparator range or a natural-language advisory phrase.
  const effective = naturalLanguageRange(range) ?? range;
  const parsed = portableVersion(version);
  // Keep range grammar narrow. No implicit broad x-ranges, caret or tilde coercion.
  const terms = effective.trim().split(/\s+/);
  if (
    !parsed ||
    terms.length > 8 ||
    terms.some((term) => !/^(>=|<=|>|<|=)?v?[0-9]{1,9}(\.[0-9]{1,9}){0,2}(-[a-zA-Z0-9.-]{1,40})?$/.test(term))
  )
    return 'REVIEW';
  const normalized: string[] = [];
  for (const term of terms) {
    const match = /^(>=|<=|>|<|=)?(.*)$/.exec(term)!;
    const bound = portableVersion(match[2]);
    if (!bound) return 'REVIEW';
    normalized.push(`${match[1] || '='}${bound}`);
  }
  const valid = semver.validRange(normalized.join(' '));
  if (!valid) return 'REVIEW';
  return semver.satisfies(parsed, valid, { includePrerelease: true }) ? 'AFFECTED' : 'UNAFFECTED';
}
