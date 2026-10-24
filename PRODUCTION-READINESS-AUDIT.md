# BA Threat Intel Enterprise — Production Readiness Audit

**Audit date:** 2026-10-24  
**Scope:** server, matching engine, pipeline, ingestion, delivery, authentication, validation, retention, and the affected React views.  
**Method:** static review of the full TypeScript surface, targeted regression tests, full unit + PostgreSQL integration runs, lint, production build, and dependency audit.

> This report supersedes the older `AUDIT.md`, `AUDIT-SUMMARY.md`, and `THREAT-INTELLIGENCE-AUDIT.md` for current readiness decisions. Those files were not treated as authoritative.

---

## 1. Verification result

| Check | Command | Result |
|---|---|---|
| Type check | `npm run lint` | Pass |
| Production build | `npm run build` | Pass (client + server) |
| Unit tests (no DB) | `npm test` | 118 tests, 114 pass, 4 skipped, 0 fail |
| Full tests (PostgreSQL) | `TEST_DATABASE_URL=… npm test` | **166 tests, 166 pass, 0 fail** |
| Dependency audit | `npm audit --omit=dev` | **0 vulnerabilities** |

The full PostgreSQL run is now deterministic. Before this pass it failed intermittently when test files ran in parallel because every test schema and every deployment sharing a database contended for the same long-held pipeline advisory lock. Test files now run serially (`package.json`).

---

## 2. Fixed in this pass

### P0 — Pipeline advisory lock was database-wide, not schema-scoped
**Files:** `server/db.ts:25`, `server/db.ts:32`, `server/db.ts:68`, `server/pipeline.ts:150`, `server/pipeline.ts:822`

`pg_advisory_lock(800003)` is scoped to the database. Two BA Threat Intel deployments sharing one PostgreSQL database (or parallel test schemas) blocked each other's pipelines for the whole run. A worker that could not acquire the lock returned `false`, leaving executions `RUNNING` and silently skipping ingestion.

The migration, state-transaction, and pipeline-worker locks now use the two-key form with `hashtext(COALESCE(current_schema(), current_database()))`. Same-schema workers still serialize; independent schemas no longer block each other. The lost-lock regression test now targets its own schema (`tests/pipeline-lifecycle.test.ts`).

### P0 — CPE wildcard-vs-wildcard matching produced false positives
**File:** `src/utils/cpeMatcher.ts:157-233`

Two wildcard components were always treated as matching. `2.*` therefore matched `1.*`, which can correlate an installed version to an unrelated vulnerable range. Added a memoized glob-intersection check (`globIntersects`) and regression coverage in `tests/audit.test.ts`.

### P0 — Version-less PURL matches auto-dispatch as exact correlations
**File:** `src/utils/cpeMatcher.ts:503-541`

A package-name-only PURL (`pkg:npm/widget`) was assigned 95% confidence even when neither side had a version, which is above the 90% auto-dispatch threshold. It now returns 70% and `applicabilityRequiresReview: true`; only a verified installed version or comparable range is 95%. Regression test: `tests/audit.test.ts` (“package-name-only PURL correlation requires review…”).

### P0 — News mentions could resurrect excluded findings
**File:** `src/utils/intelligenceMatcher.ts:69-79`

`NOT_APPLICABLE` and `SUPPRESSED_VEX_NOT_AFFECTED` findings could become `CORROBORATED` from a news article. Both states, plus `REVIEW_REQUIRED`, now remain review-only. Regression test: `tests/news-events.test.ts`.

### P1 — Delivery revalidation ignored operator-managed aliases
**File:** `server/delivery.ts:272-308`

A finding matched through an operator alias was re-evaluated without that alias and permanently rejected as “no longer applicable.” Revalidation now loads `VENDOR`/`PRODUCT` aliases and passes them to the pipeline.

### P1 — Retention of the threat cache permanently blocked queued advisories
**File:** `server/delivery.ts:282-293`

Retention may delete a regenerable `cveData` record while a manually reviewed advisory is still queued. Revalidation then found no CVE, marked every finding invalid, and failed the bundle permanently. Revalidation now falls back to the finding’s embedded, already-validated CVE snapshot. Regression test: `tests/pipeline-lifecycle.test.ts` (“retention of the threat cache does not permanently block a queued advisory”).

### P1 — Email secrets were reused after changing the destination
**File:** `server/commands.ts:198-234`

Changing a custom API endpoint or SMTP host/username while leaving the secret blank silently reused the old credential, which could send it to a different service or account. The secret is now reused only when the provider and destination/identity are unchanged; otherwise the operator must re-enter it (blank token returns `400`). Regression test: `tests/email-providers.test.ts`.

### P1 — Feed deletion left orphaned cursors and snapshots
**File:** `server/commands.ts:295-306`

Deleting a feed now removes its `feedCursors` and `feedSnapshots`, so a later feed with the same id cannot resume a stale checkpoint.

### P1 — Feed connectivity test trusted HTTP status alone
**File:** `server/app.ts:392-410`

A `200` HTML error page or truncated body was reported as `HEALTHY`. Non-RSS feeds now require a parseable JSON body; RSS/Atom is parsed with the hardened syndication parser.

### P1 — Cookie clearing did not match the `__Host-` cookie attributes
**File:** `server/app.ts:170-180`, `server/app.ts:208-216`

Logout and password change now clear the cookie with `path`, `secure`, `sameSite`, and `httpOnly` matching the original, so the `__Host-vulnstream` cookie is actually removed in production.

### P1 — Advisory status refresh could overwrite explicit exclusions
**File:** `server/app.ts:77-95`

`refreshAdvisoryDeliveryStatus` no longer rewrites findings in `NOT_APPLICABLE`, `SUPPRESSED_VEX_NOT_AFFECTED`, or `REVIEW_REQUIRED` states.

### P1 — Feed URL credential detection missed common key names
**File:** `server/validation.ts:27-35`

Query keys such as `key`, `access_key`, `private_key`, `credential`, and `sig` are now rejected; credentials must use the encrypted auth field.

### P2 — Strict inventory CPE builder emitted invalid CPEs for names with `:` or `\`
**File:** `src/data/vendorCatalog.ts:654-671`

`buildStrictCpe23` now escapes token delimiters. A product such as `gateway:edge` produces a valid, matchable CPE instead of a 12-token invalid string. Regression test: `tests/audit.test.ts` (“inventory CPE builder escapes token delimiters…”).

### P2 — Dependency vulnerability
**Files:** `package.json`, `package-lock.json`

`body-parser` 1.20.8 → 1.20.9 (via Express 4.22.3) resolves `GHSA-27r3-jxmh-p828`. `npm audit --omit=dev` now reports 0 vulnerabilities.

### P2 — Non-deterministic full test suite
**File:** `package.json`

`npm test` now uses `--test-concurrency=1`. Parallel PostgreSQL test files exhausted connections and the 15-second statement timeout, producing false failures in otherwise-correct pipeline tests.

---

## 3. Remaining findings (prioritized)

### P0 — `/api/state` returns the entire cache and history on every poll
**Files:** `server/db.ts:151-184`, `server/app.ts:271-272`, `src/context/AppContext.tsx:127-129`

`state()` loads every row for every array kind (`cveData`, `intelligenceArticles`, `findings`, `advisories`, `emailLogs`, `webhookLogs`, `executions`, plus 500 audit entries), and the client requests it every 10 seconds. For a 10k–50k CVE installation this is a multi-megabyte response, repeated serialization, and sustained database load.

**Recommendation before a large deployment:** add server-side pagination/filtering for `cveData`, `intelligenceArticles`, and delivery history, or a compact summary endpoint plus on-demand detail endpoints. Enable gzip compression as an interim mitigation. This is an architectural change and was deliberately not attempted in this audit pass.

### P1 — Hardcoded cleanup windows bypass the operator retention policy
**Files:** `server/main.ts:109-118`, `server/retention.ts:11-17`

The background cleanup still deletes `outbox` rows after 30 days and `operational_events` after 90 days regardless of `settings.retentionConfig`. The policy-managed retention covers `emailLogs`/`webhookLogs`/`executions`, so operators can believe a longer window is in force while the queue/event history is trimmed independently.

**Recommendation:** either route these through the retention policy or document them as fixed system windows in the UI.

### P1 — PURL-only inventory is evaluated against every CVE
**Files:** `src/engine/pipelineEngine.ts:86-118`

`assetsWithNoCpes` includes PURL-only assets and is added as a candidate for every CVE, and a CVE with no CPE criteria returns all active assets. Matching is still correct, but large package inventories make each pipeline run O(assets × CVEs).

**Recommendation:** index PURL-only assets by package name and add only the matching bucket per CVE.

### P1 — Retention scheduling is per process, not per deployment
**File:** `server/main.ts:85-108`

`lastRetention` is in memory. With multiple worker replicas, each replica schedules cleanup independently. The state transaction serializes the destructive work, so this is redundant work rather than data corruption, but it multiplies load and audit entries.

**Recommendation:** persist the last-run timestamp in `systemState`, or elect a single retention worker.

### P2 — Alias/fallback matches ignore the version range
**File:** `src/utils/cpeMatcher.ts:621-649`

The vendor/product alias fallback returns 85% confidence without evaluating the CVE version range. Because the auto-dispatch threshold is 90% (`src/engine/pipelineEngine.ts:186`), these findings are review-only and cannot auto-send; however, they can add noisy review items for products whose only evidence is the vendor/product name.

**Recommendation:** when the asset has a version, evaluate the range and mark `applicabilityRequiresReview` instead of silently ignoring it.

### P2 — A failed retention run waits a full interval
**File:** `server/main.ts:94-100`

`lastRetention` is set before `runRetention` completes. If cleanup throws, the next attempt waits `cleanupIntervalMinutes` (default 60). Manual cleanup via `/api/retention/run` remains available.

### P2 — Older audit documents are stale
**Files:** `AUDIT.md`, `AUDIT-SUMMARY.md`, `THREAT-INTELLIGENCE-AUDIT.md`

They describe behavior that has since changed and should be replaced by this report or explicitly marked historical.

---

## 4. Deployment checklist

- [ ] Set `NODE_ENV=production`, an HTTPS `APP_ORIGIN`, and a 32-byte base64 `ENCRYPTION_KEY`.
- [ ] Keep `EGRESS_ALLOWED_HOSTS` minimal; add only feed/provider hosts actually used.
- [ ] Run migrations before starting the worker (`schema_migrations` version 4 is required).
- [ ] Set `WORKER_ENABLED=true` only on the process that should run the pipeline, delivery loop, and retention.
- [ ] Configure a reverse proxy with TLS, request/response size limits, and timeouts above the 30-second API timeout.
- [ ] Decide the `/api/state` scaling strategy (pagination or summary endpoint) before loading a large CVE cache.
- [ ] Verify email/webhook providers from the UI (“Test All Feeds” for feeds; provider test actions for delivery) before enabling auto-dispatch.
- [ ] Keep retention disabled until the desired window and archive ceiling are reviewed; test a manual cleanup in staging first.
- [ ] Run `npm run lint`, `npm test` (with `TEST_DATABASE_URL`), `npm run build`, and `npm audit --omit=dev` in CI.

---

## 5. Notes on concurrent work

The working tree also contains operator-facing retention work (`server/retention.ts`, `tests/retention.test.ts`, `src/components/ArchiveRetentionView.tsx`, retention settings/types) and unrelated UI changes. They were verified by the full test/build run and were not reverted. The older audit documents were left in place to avoid deleting user-authored history.
