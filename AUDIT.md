# Repository audit — 20 October 2026

## Scope and outcome

Reviewed the supplied React/Vite application, matching and version utilities, pipeline, state management, template rendering, audit/export paths, dependencies, and deployment configuration. Verified all 14 navigation views render in a local browser. This is a source and local runtime audit, not a penetration test or certification of a deployed service. The directory has no Git metadata, so no commit/diff baseline was available.

The application is a browser simulation, not an enterprise backend. A persistent UI notice and corrected README now make that explicit. Existing sample telemetry and delivery records remain demo data. No external feed requests, emails, or webhooks were sent during verification.

## Verified fixes

| Area | Confirmed defect | Applied correction |
| --- | --- | --- |
| Matching | Truncated CPEs and component substrings accepted; start-only intervals ignored | Validate component count/part, exact component matching, check all interval bounds and additional CPE attributes |
| Matching | Text/alias fallback reversed explicit CPE version exclusions | Structured-identifier mismatches cannot fall through to heuristic matching |
| Package matching | Name prefixes and different explicit versions matched | Exact package identity, explicit version, qualifier and subpath comparison; enforce provided version range |
| Versions | SemVer build metadata changed precedence | Ignore `+metadata` in comparisons |
| Dispatch | VEX `not_affected` findings were dispatched and lost suppression state | Only queued, unsuppressed findings enter advisory generation |
| Pipeline | Canonicalized IDs were discarded; input alert objects mutated; notification count inflated per asset | Preserve canonical IDs, copy prior alerts, update registry once per CVE, emit one simulated email per advisory, add in-run finding keys |
| Advisory metadata | Noncritical findings always labeled HIGH; fabricated webhook count | Compute highest actual severity; count zero webhooks when none executed; UUID advisory identifiers |
| Cryptography | Repeated 32-bit hash advertised as SHA-256; fake HMAC | Use `@noble/hashes` SHA-256 and HMAC-SHA256, independently checked against Node crypto |
| Audit integrity | Verification ignored modified content; pipeline logs broke the chain order | Canonical hash serialization covers all record fields, consistent chaining across batches, content and link verification; reset validation state after log changes |
| URL screening | Mapped IPv6, unique-local IPv6, trailing-dot localhost and shared address space passed | Block these literals and other nonpublic address forms; validate edited feeds too |
| Templates | Custom text/CSS interpolated directly into HTML | Escape text and restrict color/border values; existing preview sandbox still disables scripts |
| CSV export | Formula prefixes and some delimiters/quotes were unescaped | Quote all fields and neutralize formula prefixes; encode the entire CSV payload |
| State/runtime | Overlapping pipeline calls, zero-hour override ignored, lock not cleared on exceptions | Synchronous running guard, explicit undefined check and finally cleanup; scheduler records rejected runs |
| Local state | Invalid storage shapes, unavailable theme storage and null bulk rows could crash | Defensive storage checks/default merging, guarded theme access, validate bulk row/string types |
| Credentials | Named credential fields persisted in plaintext | Omit feed auth secret, webhook secret and Mailgun API key from future storage writes |
| UI | Pagination could remain beyond the final page after deletion | Clamp the page when the result count shrinks |
| Toolchain | Copied Windows modules could not execute on Linux; incompatible esbuild peer | Reinstalled with `npm ci`; aligned esbuild with installed Vite's peer range |

## Validation evidence

- The initial 12 regression tests all failed against the original implementation and passed after fixes.
- Final `npm test`: **18 passed, 0 failed**. Includes matching boundaries, PURL exclusions, VEX, canonicalization, immutable inputs, rerun idempotency, independent cryptographic vectors, audit tampering, template injection and CSV escaping.
- `npm run lint`: passed (TypeScript; no separate ESLint configuration).
- `npm run build`: passed.
- `npm audit --json`: **0 reported vulnerabilities** at audit time; this is not a guarantee that dependencies contain no vulnerabilities.
- Browser smoke check: dashboard and all 13 other navigation views rendered, including the template iframe and the simulation notice. Production-preview pipeline simulation completed, returned its controls to idle, and the combined seed/pipeline audit chain verified successfully. Screenshot: [audit-verification.png](audit-verification.png). A context-module hot update required a reload during development; a clean reload rendered normally.

## Remaining limitations / production blockers

1. **No backend security boundary.** Login, password changes, CSRF, session expiry enforcement, encrypted secrets, database locking, durable workers and health probes are not implemented. The password form now explicitly reports validation only. A browser banner cannot substitute for these controls.
2. **No real ingestion or delivery.** Pipeline ingestion/enrichment timings and delivery statuses remain simulations. Recipient lists/counts are hardcoded in the engine; channel configuration does not route real notifications. Cached CVEs are processed independently of feed availability. Production requires actual adapters, recipient policy evaluation, durable outbox, retry semantics and provider acknowledgements.
3. **URL screening is not SSRF protection at connection time.** No DNS resolution is performed. A future backend must validate resolved addresses and redirects, pin connections appropriately and apply network egress policy. Do not use this browser validator as the sole server guard.
4. **Local audit chains have no trusted external anchor.** They detect changed retained records and broken links, but cannot prove provenance or prevent wholesale replacement/truncation. Seed logs are rehashed on initialization; they remain sample events, not historical evidence.
5. **Matching is intentionally limited.** This is not a complete NIST CPE/PURL implementation. Escaped wildcard patterns, package-ecosystem normalization and arbitrary vendor-version ordering need dedicated standards fixtures before production. Unknown versions do not establish verified affectedness. VEX statements are not authenticated or tied to deployment-specific provenance.
6. **Storage remains browser-local and untrusted.** Core findings/history reset on reload. Defensive shape checks are not a complete schema/migration layer. Credential-shaped URLs may still contain sensitive data; do not enter production secrets. Backend secret storage and access control are required.
7. **UI coverage is a smoke check.** Not every CRUD workflow, responsive viewport, screen-reader interaction or deployment environment was tested. No server/infrastructure source was supplied to audit.

These limitations require product/backend implementation rather than a verified local bug fix. The changes do not make the application production-ready.
