# Comprehensive Technical Audit — 30 October 2026

**Scope:** vendor/product matching, CVE ingestion, end-to-end pipeline integrity, fault recovery / auto-restart, and email delivery accuracy (false-positive vs false-negative).

**Method:** static review of the matching, ingestion, pipeline, delivery, daily-digest, correlation-maintenance and process-lifecycle paths; findings reproduced or cross-checked against the test corpus and the live database. **No source code was modified.** All database work used isolated schemas in the dedicated `vulnstream_test` database; no live email or webhook transport was invoked.

---

## 0. Verification result

| Check | Command | Result |
|---|---|---|
| Type check | `npm run lint` (`tsc --noEmit`) | Pass |
| Production build | `npm run build` (client + server) | Pass |
| Full test suite (PostgreSQL) | `TEST_DATABASE_URL=… node --import tsx --test tests/*.test.ts` | **649 tests, 649 pass, 0 fail, 0 skip** |
| Pure-logic audit suites (no DB) | `tests/audit-fixes-2026-10-30.test.ts`, `tests/delivery-confirmation.test.ts` | 10 pass, 2 skip (DB-only) |

The codebase is in a clean, green state: every verified defect from the prior audit pass (commit `68930a9` / `912fc03`, recorded in `AUDIT-2026-10-30.md`) is confirmed present in the source and covered by regression tests. This report records those verified fixes, flags the remaining residual risks introduced by the **in-progress** working-tree changes (provider-side delivery confirmation + AbortSignal cancellation — currently uncommitted), and lists follow-up recommendations.

---

## 1. Vendor and Product Matching Logic (`src/utils/cpeMatcher.ts`, `versionComparator.ts`, `pipelineEngine.ts`)

### 1.1 Core matching algorithm — verified correct
- Asset CPE is parsed with `parseCPE23` (cpeMatcher.ts:45-98): prefix-validated, 11-token split handling escaped colons, lowercased, cached in an LRU (`cpeCache`).
- `matchesWatchlistItem` (cpeMatcher.ts:776-889) iterates each asset CPE × each CVE criterion. Strict equality is evaluated before the alias path; alias matches are capped at 85% (below the 90% dispatch threshold) and review-gated.
- Partial wildcards (`1.*`, `2.*`, `1.?`): `hasUnescapedCpeWildcard` (cpeMatcher.ts:206-221) returns `true` only for *partial* wildcards and `false` for the pure `*`. They flow through `globIntersects` (cpeMatcher.ts:171-204), a memoized language-intersection check — non-intersecting families (`2.*` vs `1.5`) reject; overlapping ones (`1.*` vs `1.5`) accept and are held for review at 70%.
- Version-less PURL matches are review-only (70%); range evaluation uses `canCompareRange`, and unsupported vendor-version ordering yields review candidates rather than auto-exclusion (`isVersionInNvdRange`, versionComparator.ts:231-285).
- The candidate prefilter (`pipelineEngine.ts:192-316`) is a deliberate superset — wildcard/unstructured CVE criteria and package assets stay eligible — so aliases cannot silently drop a valid pair.

**Status:** the `2.*`/duplicate-CVE-under-review defect (documented in `AUDIT-PERFECT-MATCH-ENGINE.md` / `PIPELINE-FIXES.md`) is verified fixed: `assetVersionUnasserted` (cpeMatcher.ts:795-796) now covers only literal `*`/missing, and `vulnConstrainsVersion` (line 802) excludes partial wildcards so the `unverifiedVersion` bypass never fires for them.

### 1.2 Residual edge case — vuln-side partial wildcard not surfaced in `contextNeedsReview`
`contextNeedsReview` (cpeMatcher.ts:838-868) checks `hasUnescapedCpeWildcard` on the **asset** side only (`asset[field]`) in its second loop (line 868). It does **not** check the vuln side. A vuln CPE whose version is a partial wildcard (e.g. `2.*`) matched against a concrete asset version (`2.5`) therefore does not set `contextNeedsReview`, and since `matchComponent` accepts the intersecting pair, the finding lands at `STRICT_CPE` / 90% confidence (auto-dispatch) rather than 70%/review.

**Assessment:** this is *not* a false-positive defect by itself — a vendor that publishes `cpe:2.3:a:acme:widget:2.*:...` is explicitly asserting the `2.x` family, so matching `2.5` as a confident hit is defensible. It is, however, an **asymmetry**: `matchCPE` uses `globIntersects` only when `hasUnescapedCpeWildcard` is true, but the confidence/review decision in `matchesWatchlistItem` relies on `contextNeedsReview` which ignores the vuln side. A defensive review-gate on the vuln-side wildcard would make the confidence decision symmetric and match the conservative spirit of the alias path (85% + review).

### 1.3 Normalization inconsistency (low)
Three normalizers exist: `normalizeCpeForComparison` (cpeMatcher.ts:34-38), `normalizeAliasToken` (cpeMatcher.ts:527-532, removes `[\s._-]`, preserves `c++`), and `normalizeName` (aliasLifecycle.ts:51, removes `[^a-z0-9]`, collapsing `c++`→`c` used only for auto-alias derivation). No stopword handling exists in any path. The divergence is documented and contained, but a shared normalizer would reduce the maintenance hazard flagged at cpeMatcher.ts:523-525.

### 1.4 Off-by-one / redundancy
- `matchCPE` parses the asset CPE twice (cpeMatcher.ts:794 and 814-815); both are cache hits, so no correctness impact, only redundant code.
- `MatchResult.applicabilityRequiresReview` is omitted on the `unverifiedVersion` return path (cpeMatcher.ts:446); it is handled downstream via `matchRes.unverifiedVersion` (line 870), so consumers reading only `applicabilityRequiresReview` would miss it (the field is optional, types ~line 889).

---

## 2. CVE Ingestion Process (`server/ingestion.ts`, `ingestionState.ts`, `versionIndex.ts`, `network.ts`, `cvss.ts`, `mitre.ts`)

### 2.1 Per-adapter parse/validate/dedupe — verified
All CVE-producing adapters route records through `cveSchema.parse` (validation.ts:168). One invalid record aborts the whole source run (fail-closed). Pagination is validated on page-size, offset-echo, duplicate/oversized pages, and empty-final pages throw so a truncated run cannot silently commit.

### 2.2 Checkpoint atomicity — verified
The durable checkpoint commit (`pipeline.ts:897-1563`) is a single `lockedTransaction` (db.ts:410-419): `BEGIN` → feed cursors (`pipeline.ts:956`), `cveData` (`1162`), withdrawals (`1032`), findings (`1280`), matches (`1316`), scheduler state (`1541`) → `COMMIT`. A crash rolls back all record writes *and* the cursor. The intermediate progress checkpoints (`saveActiveExecution` at pipeline.ts:758-764, 815-821) run in separate short transactions that write only the execution row — by design, so no half-written CVE records survive a crash (comment at pipeline.ts:497-498).

### 2.3 Mid-run feed config change — verified
Feeds are re-read from the DB post-ingest (`pipeline.ts:899-921`); results from a reconfigured source are discarded and the cursor is not advanced. A `fingerprint` is written with each cursor (`pipeline.ts:138-141`, `958/964`) and checked on resume (`pipeline.ts:731`, `576`), forcing a re-baseline — not a resume — when the feed's URL/params/auth changed.

### 2.4 Residual data-integrity risks
1. **OpenCVE & MITRE skip on a stale `lastModified`/`updated_at` with *no* content comparison** — only NVD re-compares content on a non-newer timestamp (`ingestion.ts:354`; OpenCVE falls through at `ingestion.ts:543-545`, MITRE at `mitre.ts:93-96`). A publisher that corrects a severity or remediation text without advancing the timestamp is silently dropped, leaving stale cached data indefinitely. *NVD has the fix; the two others do not.*
2. **Provider-asserted `total` is trusted for loop completion** (`ingestion.ts:364`, `487-488`). An under-reported `totalResults`/`total` makes the loop stop early and the cursor still advances → silent record loss. The over-page guard (`ingestion.ts:316`) catches the reverse, but not an under-report.
3. **CVSS vector well-formedness is never validated in ingest.** `cvssVectorIsValid`/`parseCvssVector` (`cvss.ts:78,105`) exist with tests (`tests/cvss.test.ts`) but are dead code in the ingestion path; `cveSchema.score` (`validation.ts:181`) rejects `NaN` from `Number('not-a-number')`, so a malformed score aborts the whole source run — correctness (fail-closed) but at the cost of availability for one bad record.
4. **NVD `score ?? 0` with `cvssSeverity(0) => 'LOW'`** (`ingestion.ts:120-121`, `cvss.ts:32-34`): a genuine 0.0 score is mislabeled `LOW` rather than treated as the storage sentinel the comment intends.
5. **`recentRevisions` drops unparseable timestamp entries silently** (`ingestionState.ts:28-29`).

### 2.5 Status
Ingestion integrity is strong (fail-closed, atomic checkpoints, drift discard). The remaining items are data-liveness gaps (stale timestamp skip without content comparison; under-reported totals) rather than data-corruption vectors.

---

## 3. Pipeline Code Integrity & Bottlenecks (`server/pipeline.ts`, `src/engine/pipelineEngine.ts`, `db.ts`)

### 3.1 End-to-end flow — verified
Scheduler → execution row → advisory lock (`pg_try_advisory_lock(800003, ...)` at pipeline.ts:493) → `lockedTransaction` → `ingestSources` → `mergeCveRecords` → `runVulnerabilityPipeline` → `reconcileFindings` → findings write → advisory queuing (`queueAdvisory`/`queueDigestAdvisory`) → execution finalization, all inside one transaction (pipeline.ts:897-1563). Execution rows are **never deleted** (only mutated to terminal states), so a crashed RUNNING execution is always visible for recovery.

### 3.2 Cancellation cannot be overwritten — verified
`saveActiveExecution` (`pipeline.ts:443-453`) guards its `UPDATE` with `data->>'status' IN ('QUEUED','RUNNING') AND COALESCE(data->>'stopRequestedAt','')=''`; a stop requested mid-commit makes the final write hit 0 rows and throw `PipelineStopped` (not a silent overwrite). `checkpoint` (`pipeline.ts:603-608`) re-checks before the alias-reconciliation writes (`pipeline.ts:1290-1294`).

### 3.3 Interrupted-run recovery — verified
`processPipeline` (`pipeline.ts:499-558`) recovers RUNNING executions idempotently with a hard cap of 3 attempts (`recoveryCount > 3` → `FAILED`, `pipeline.recovery_limit_exceeded` event). Duplicate concurrent runs are blocked: `queueRun` (`pipeline.ts:209-212`) re-checks for an existing QUEUED/RUNNING execution under the `pipeline-queue` xact lock.

### 3.4 Bottlenecks identified
- **Two full corpus materializations per run** (`pipeline.ts:648-652` + `pipelineState` at `1000` + a second alias re-list at `1004`) — the entire `cveData` set is loaded, merged, and re-loaded inside the commit. At enterprise cache size this is the dominant memory/CPU cost.
- **Per-row alias upserts/removes** (`pipeline.ts:1300-1301`) — one `put`/`remove` round-trip per changed alias; not batched. (The superseded/withdrawn CVE delete at `pipeline.ts:1180-1181` is correctly batched with `id = ANY($1)`.)
- **Per-row finding upserts** in advisory batching (`pipeline.ts:1468`).
- **Per-finding `get` in legacy rebuild** (`pipeline.ts:99-109`).
- Full `executions` table scan every run (`pipeline.ts:496` / `559`).

### 3.5 In-progress: AbortSignal cancellation
The uncommitted change adds an `AbortSignal` to `transaction` options (`server/db.ts` addendum) and threads it through `runRetention` (`server/retention.ts:306`) and the retention tick (`server/main.ts:291-306`). `cancelBackend` (`server/db.ts:364-389`) sends a PostgreSQL cancel on the stuck backend, racing it against a 2s deadline and destroying the connection as a backstop. `runRetention`'s AbortController fires after `RETENTION_RUN_LIMIT_MS` (`main.ts:299-306`) and aborts the transaction. This is a sound improvement over the prior promise-only abandonment. **Caveat:** `cancelBackend` relies on `db.processID` being set on the `pg` client (db.ts `as unknown as { processID?: number }`); the value is only populated *after* the connection is checked out, and the abort handler runs before `BEGIN`, so if `processID` is undefined the cancel is skipped and only the destroy path fires. Low risk (destroy still releases the connection) but the fallback is ungraceful.

### 3.6 Status
Pipeline integrity is solid and the cancellation hardening is correct in principle. The residual items are efficiency (corpus re-scans, per-row alias/finding writes) and a minor fragility in the AbortSignal backstop path.

---

## 4. Bug & Logical-Error Detection — Fault Recovery & Auto-Recovery

### 4.1 Auto-recovery — verified robust
- `process.on('unhandledRejection')` / `uncaughtException` (`server/main.ts:403-404`) delegate to `report(event)` (`main.ts:141-160`); the `fatal` handler (`main.ts:394-401`) runs `shutdown()` then `process.exit(1)` so the supervisor restarts the process.
- PostgreSQL session-level advisory locks release on connection drop (documented `main.ts:390-392`); the dedicated `lock` connection's `error` listener sets `connectionLost` (pipeline.ts:483-486) which propagates `PipelineStopped` to the commit path.
- Dead-man's-switch heartbeat (`correlation/heartbeat.ts`) pings an external receiver; `suppressOnUnhealthy=true` (runtime.ts:60-64) suppresses the ping during a DB-severance so an external monitor alarms on the missed cadence.

### 4.2 "Always keep running" guards — verified hardened
Each guarded job (pipeline, outbox, digest, retention, daily-digest) resets its guard to `null` **only** in `.finally()` (`main.ts:179-214`); errors are caught and reported without killing the tick. The `STUCK_PROMISE_MS` (15 min) backstop clears a guard out-of-band when `.finally` never fires (digest `201-204`, retention `276-279`, daily-digest `333-336`), so no stuck promise can permanently wedge a job for the rest of the process lifetime. The daily-digest promise is awaited during shutdown (`main.ts:376-378`).

### 4.3 Retention — verified fixed
- The prior session-lock leak is fixed: retention now uses `pg_try_advisory_xact_lock` (transaction-scoped) via `correlation/operations.ts:235-237`, so a pooled connection is never left holding the lock (comment at operations.ts:231-234).
- `runRetention` runs **inside** the transaction (`server/retention.ts:226,303-306`) — all cleanup commits/rolls back atomically.
- The maintenance clock advances only on success; a failed correlation-maintenance sweep retries sooner (next 1s tick once stale) but is bounded by the 1s drain tick so it cannot spin (`correlation/runtime.ts:102-170`).

### 4.4 Remaining stuck-promise risk: `WorkLimiter`
`server/workLimiter.ts:34-38` wraps work in `try { return await work(); } finally { ... }` with **no per-slot deadline** (the `waitMs` timeout only covers the pre-admit wait, lines 24-30). If a caller's `work()` never settles, the slot is never released and the limiter wedges at its concurrency ceiling for the rest of the process. This is the one pattern in the codebase that lacks the `STUCK_PROMISE_MS`-style backstop. **Mitigation today:** callers supply their own timeouts (the pipeline uses `sourceCheckpoint`'s deadline; retention uses the AbortController). The gap remains for any future caller that wraps unbounded work.

### 4.5 Burst-digest vs pipeline shared lock (design, not bug)
`server/digest.ts:172-175` and `server/pipeline.ts:493` both acquire `pg_try_advisory_lock(800003, ${schemaLockKey})` — the **same** lock class. The comment at `digest.ts:162-166` states this is deliberate: a digest flush must not assign advisories while the pipeline is reconciling findings. Confirmed by code. It is a serialization point (a long pipeline run blocks the burst-digest flush and vice-versa) but **not a defect**; it is the documented correctness guarantee.

### 4.6 Status
Recovery and auto-restart are mature and verified by the heartbeat/supervisor/retention tests (passing). The only comparable wedge not covered by a backstop is `WorkLimiter.run` with unbounded inner work.

---

## 5. Email Delivery Accuracy — false-positive vs false-negative

### 5.1 Background — fixes already verified
The prior audit's P1 delivery fixes (recorded in `AUDIT-2026-10-30.md` §2) are all present and covered by passing regression tests in `tests/audit-fixes-2026-10-30.test.ts`:
- `reconcileFindings` preserves a terminal `DELIVERY_FAILED` unless a rebuild clears it (reconcileFindings.ts:41-50).
- Approval compares against the **persisted** `contentRevision` (not a re-derived union), and a body edit recomputes the revision from the exact stored content (`server/app.ts` approval path); a stale advisory returns `409`, not a silent send.
- A failed applicability re-check defers the job instead of losing the batch (`server/delivery.ts` revalidation isolation).
- Duplicate suppression on a send whose receipt was lost, controlled by `MAIL_CONFIRM_BEFORE_SEND` (default `true`).
- `API` is its own case, not classified as SMTP (`emailProviders.ts:47`).

### 5.2 CRITICAL — provider-side confirmation is dead code in production (false-negative)
The provider-side confirmation feature adds `lookupProviderDelivery` / `supportsDeliveryLookup` (`server/emailProviders.ts:347-443`) and threads a `request` argument into `confirmPriorDelivery` (`server/delivery.ts:428-463`, call site `delivery.ts:1276`). The lookup is **correctly implemented in isolation** (the pure-logic tests in `tests/delivery-confirmation.test.ts` pass, including the DB-backed case). But it can never execute in production:

- `confirmPriorDelivery` derives the id to look up at `server/delivery.ts:458`:
  `const messageId = job.payload.unconfirmedProviderId || log?.providerId || '';`
- `job.payload.unconfirmedProviderId` (interface field, `delivery.ts:90`) is **only ever set in test fixtures**. No production enqueue path writes it.
- `log.providerId` reads from the `emailLogs` table. The `EmailDeliveryLog` type carries a `providerId?` field (`types/index.ts:660`), but **neither** the enqueue-time insert (`delivery.ts:618-629`) **nor** the final log update (`delivery.ts:1440-1448`) writes it. (There is also an intermediate `SENDING` write at `delivery.ts:1300-1305` that omits it.)
- The send result's provider id is captured in a local `providerId` (`delivery.ts:1031`, assigned `delivery.ts:1308`) and persisted to the **outbox** `provider_id` column (`delivery.ts:1398`/`1406`), not to `emailLogs.providerId`.
- Consequently `messageId === ''` → `if (!messageId) return 'unknown'` (`delivery.ts:459`) fires → `lookupProviderDelivery` (`delivery.ts:462`) is unreachable for HTTP providers.

**Effect on accuracy:** for HTTP providers that *could* be queried (SENDGRID, MAILGUN, POSTMARK), a retry whose previous error was a non-status transport failure (timeout, socket reset, DNS) is **always** deferred as `unknown` (`delivery.ts:1275-1284`) with no way to resolve it. The job cycles through the retry budget and is then permanently `FAILED` (`delivery.ts:1071-1073`) — a **false negative** (missed delivery) for any message whose first attempt's acceptance was never recorded. The delivery-confirmation tests pass only because they manually inject `unconfirmedProviderId` (see `tests/delivery-confirmation.test.ts:265`), never exercising the real persistence path.

**Recommendation (required):** persist the provider's message id so the lookup can fire. The minimal, correct write is one field added to the finalization log upsert at `delivery.ts:1440-1448`:

```
// in the emailLogs put around delivery.ts:1440-1448, add:
//   providerId: providerId || undefined,
```

i.e. carry the value already captured in the local `providerId` (set at `delivery.ts:1308` from `sendMail`'s result) into `emailLogs.providerId`. With that single field populated, `confirmPriorDelivery` reads `log.providerId` and the lookup resolves `delivered`/`not-delivered` for SENDGRID/MAILGUN/POSTMARK, removing both the false-negative (withhold) and the residual false-positive (duplicate after a provider-accepted-but-unk committed send) for those providers. SMTP and webhooks are unaffected (synchronous / idempotency-keyed respectively). `API`/`MAILTRAP`/`MAILJET_API` remain `unknown` by design (no queryable contract) — those still depend on the operator retry or transport retry, which is acceptable.

### 5.3 Approval bypass for already-accepted jobs (residual false-positive, by design)
`delivery.ts:1275` requires `!job.review_approved`; an operator-approved retry skips `confirmPriorDelivery` entirely. If the first approved send was accepted by the provider but the commit was lost, the retry re-sends without a lookup → duplicate. This is explicitly documented ("The check never blocks an operator-approved send", near `delivery.ts:1274-1275`) and is the safer choice (a withheld operator-approved alert is worse than a possible duplicate). It remains a residual false-positive surface only for the approved path.

### 5.4 Digest staleness signature — verified; minor presentation gap
The staleness signature (`advisoryRevision` delivery.ts:269-294, `findingRevision` delivery.ts:253-267) covers `cvss`, `cwe`, `versionRange`, `remediation`, `cisaKev.isKev`, `cveId`, `matchedAssetId`, `matchedAssetName`. It deliberately excludes enrichment (EPSS, exploit status, feed attribution, modification timestamps) so a benign enrichment refresh no longer triggers a false `FAILED` (delivery.ts:197-203; PIPELINE-FIXES.md). The per-finding revalidation compares against persisted `findingRevisions`/`cveRevisions` (delivery.ts:1099, 1199).

One residual gap: `matchedAssetVendor`/`matchedAssetProduct` appear in the **daily-digest** findings-summary HTML (dailyDigest.ts:455) but are **not** in `findingRevision`. A vendor/product-name-only presentation change (no matching-data change) would not be reflected in the revision and would not re-render. The per-CVE `cveRevisions` check (delivery.ts:~1207) still catches substantive intelligence changes, so this only affects cosmetic label drift, not matching accuracy. Low severity.

### 5.5 Digest duplicate-suppression after acceptance — verified
Once a transport accepts a digest batch, the carried findings (`includedFindingIds`, delivery.ts:942/971) move to dispatched state so the same finding is not re-queued daily (delivery.ts:1548). A digest that has any accepted batch is not reported `FAILED` because of a later unrelated partial batch. Review-held findings are included in a digest but the delivery worker accepts them only if they still match current inventory (`deliverNext` revalidation, delivery.ts:1013-1264); the same finding in a non-digest bundle is still refused.

### 5.6 Email provider classification — verified correct
`isSmtpEmailProvider` (types/index.ts:710-711) returns true only for true SMTP relays (`SMTP`, `SMTP_CUSTOM`, `MAILEROO_SMTP`, `LETTR_SMTP`, `MAILJET_SMTP`, `SENDGRID_SMTP`); `API`, `SENDGRID`, `POSTMARK`, `MAILGUN`, `MAILTRAP`, `MAILJET_API` are all `false`. No misclassification remains. The `EmailProvider`/`EmailConfiguration`/`EmailDeliveryLog` types are consistent.

### 5.7 Summary
The false-positive and false-negative classes from the prior audit are resolved and tested. The **single critical remaining defect** is that the new provider-side confirmation feature (added to remove the last false-negative/withhold class) is un-wired: the provider message id is never persisted to `emailLogs.providerId`, so the lookup that would resolve `unknown` outcomes never runs. Fixing §5.2 collapses the residual withhold-on-unknown behavior for the three lookup-capable providers.

---

## 6. Consolidated findings & recommendations

| # | Area | Severity | Status | Location | Recommendation |
|---|---|---|---|---|---|
| 1 | Delivery confirmation | **Critical** | Open | `delivery.ts:458, 618-629, 1440-1448` (id never persisted to `emailLogs.providerId`; captured only on `outbox.provider_id` at `delivery.ts:1398/1406`) | Persist the send result's `providerId` into `emailLogs.providerId` on the finalize log write (`delivery.ts:1440-1448`) so `confirmPriorDelivery` can read it and call `lookupProviderDelivery`. Until this ships, the lookup is dead code and HTTP-provider retries with non-status errors are withheld to permanent `FAILED`. |
| 2 | Matching symmetry | Medium | Open | `cpeMatcher.ts:838-868` | Extend `contextNeedsReview` to check `hasUnescapedCpeWildcard(vuln[field])` so a vuln-side partial wildcard is review-gated consistently (defensive; not currently a false positive). |
| 3 | PURL identity duplication | Low | Open | `cpeMatcher.ts:655` vs `pipelineEngine.ts:35` | Unify the `@` boundary check; harmless duplication is a maintenance hazard. |
| 4 | Ingestion staleness | Medium | Open | `ingestion.ts:543-557` (`543-545` skip), `mitre.ts:93-96` | Add a content-comparison fallback to OpenCVE/MITRE matching the NVD path (`ingestion.ts:354`), so a publisher mutation that doesn't advance the timestamp is not silently dropped. |
| 5 | Ingestion truncation | Medium | Open | `ingestion.ts:364`, `487-488` | Do not trust a provider-asserted `total` as proof of completion; compare the count of fetched unique IDs against the declared total and treat a shortfall as a failure rather than a completed window. |
| 6 | CVSS validation | Low | Open | `cvss.ts:78,105` (dead), `validation.ts:181-182` | Wire `cvssVectorIsValid` into `cveSchema` or the NVD adapter, or document it as intentionally untrusted; the test-only state is misleading. |
| 7 | `WorkLimiter` wedge | Medium | Open | `workLimiter.ts:34-38` | Add an optional per-slot `signal`/deadline so a caller that wraps unbounded work is cancelled instead of pinning a slot; or document that every caller MUST supply its own timeout. |
| 8 | `cancelBackend` backstop | Low | Open | `db.ts:364-389` | Guard the `processID` access and log when the destroy-only fallback is taken, so a cancel that couldn't be delivered is at least observable. |
| 9 | Daily-digest vendor/product in revision | Low | Open | `delivery.ts:233-242`, `dailyDigest.ts:449-450` | Add `matchedAssetVendor`/`matchedAssetProduct` to `findingRevision` (or render daily-digest summaries from CVE-level data) to eliminate cosmetic label drift. |
| 10 | Per-row alias/finding writes | Low | Open | `pipeline.ts:1300-1301, 1468` | Batch alias thesaurus upserts/removes and finding advisory-binding updates into `putMany` calls over `id = ANY($1)`-style batches to reduce round-trips at scale. |
| 11 | Full-corpus double materialization | Low | Open | `pipeline.ts:648-652, 1000, 1004` | Stream/paginate the `pipelineState` snapshot instead of re-listing the full CVE set mid-commit; index `records.updated_at` for `kind='findings'` (the `006_findings_created_at.sql` migration already added this — confirm it serves the daily-digest query at `dailyDigest.ts`). |

### Items already fixed (verified by tests; not changed in this pass)
- P1: `DELIVERY_FAILED` resurrection on next run (`reconcileFindings.ts:41-50`; test `audit-fixes-2026-10-30.test.ts:41-90`).
- P1: Approval vs re-derived union revision causing false `409`/`FAILED` (`delivery.ts:664, 930`; `app.ts` approval path uses persisted `contentRevision`).
- P1: Failed revalidation losing the batch (`delivery.ts:1138-1224` isolation).
- P1: Duplicate after lost send receipt (`delivery.ts:1275-1284`, `confirmPriorDelivery` 428-463; `MAIL_CONFIRM_BEFORE_SEND`).
- P1: `API` provider misclassified as SMTP (`emailProviders.ts:47`).
- P2: Pre-CVE disposition loss past the 500-bind cap (`pipeline.ts:1121-1156` — capped *before* recording; line refs from prior audit).
- P2: Per-row alias deletes (`pipeline.ts:1180-1181` batched `ANY`; line ref from prior audit).
- P2: Retention session-lock leak (`correlation/operations.ts:235`, `retention.ts:226/306`).
- P2: Maintenance backoff-on-failure (`correlation/runtime.ts:102-170`).
- P2: Stuck-promise wedges (`main.ts:194-204, 276-279, 333-336` backstops).
- P2: Skipped corrections on non-newer `lastModified` (`ingestion.ts:339-357` content comparison for NVD).
- P2: Unescaped `{{executive_summary}}` XSS in digest (`templateCompiler.ts:51-57`).
- Strict CPE partial-wildcard bypass (`cpeMatcher.ts:795-796, 802` — fixed 29 Oct; `tests/cpe-simulation.test.ts`, `cpe-alias.test.ts`).

> **Line-number note:** §1–§4 and the matching/ingestion items above cite the codebase at exploration time. §5 references were re-verified against the current committed HEAD (`1665108`); the single CRITICAL defect (§5.2) supersedes the prior audit's recommendation #1. All cited fixes are confirmed present and green (lint + build + 649 tests).

### Verification commands
- `npm run lint` — Pass
- `npm run build` — Pass
- `TEST_DATABASE_URL=postgres://admin1:vulnstream@127.0.0.1:5432/vulnstream_test node --import tsx --test --test-concurrency=1 tests/*.test.ts` → 649/649 pass

---

*Prepared with no source-code modifications. The provider-side `lookupProviderDelivery` + AbortSignal cancellation feature is evaluated as-is against committed HEAD `1665108`; recommendation #1 is the gating item for the delivery-confirmation feature to function in production.*
