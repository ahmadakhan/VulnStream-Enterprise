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
export function evaluateVersion(version: string | null, range: string): 'AFFECTED' | 'UNAFFECTED' | 'REVIEW' {
  if (!version || range.length > 200) return 'REVIEW';
  const parsed = portableVersion(version);
  // Keep range grammar narrow. No implicit broad x-ranges, caret or tilde coercion.
  const terms = range.trim().split(/\s+/);
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
