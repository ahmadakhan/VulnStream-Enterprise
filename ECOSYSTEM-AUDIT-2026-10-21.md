# Threat intelligence ecosystem audit and fixes

Reviewed on 21 October 2026. This follow-up audits the current source, Docker topology, ingestion and normalization, correlation, notification outbox, and de-duplication. It includes PostgreSQL-backed tests and small public-provider connectivity checks. It supersedes the outstanding code findings in `THREAT-INTELLIGENCE-AUDIT.md` where described below.

## Assessment

The application is a CVE-to-product-inventory correlation system. Its internal telemetry is an operator-managed CPE/PURL watchlist; it has no live EDR, CMDB, cloud, network-event, domain, IP, URL-indicator, or file-hash ingestion. It should not be represented as a complete IOC/SIEM correlation platform.

The core safety controls are useful: server-side accounts and permissions, pinned public-address HTTPS connections, encrypted integration secrets, review-only uncertain matches, transactional persistence, stable findings, and a durable outbox with provider acceptance tracked separately from inbox delivery. This audit fixed material correctness, source-lifecycle, scalability, and notification-filtering defects. Production readiness still depends on deployment-specific inventory quality, operating procedures, capacity tests, backups, and real delivery acceptance.

Existing staged UI work and earlier NVD timeout changes were preserved. No production records, operator accounts, deployment settings, or external notification targets were changed by this audit. Test mail transports were mocked.

## 1. Intelligence sources

The production seed configures **three implemented sources**, rather than the 16 vendor sources previously claimed by UI copy. That copy has been corrected. The local `vulnstream_pages` database contains disposable fixtures, including one disabled JSON source; it does not establish the production source inventory.

| Source | Quality and relevance | Coverage and reliability limits |
| --- | --- | --- |
| NVD CVE API 2.0 | Broad CVE descriptions, CVSS and CPE applicability; primary general vulnerability source. | Analysis can lag publication. Provisional CVEs now remain available for review; rejected revisions now invalidate cached entries. Modified-date windows and a 50,000-result bound limit retrieval. The earlier fix supplies 60-second total / 30-second idle budgets and a 16 MiB body cap for pages. |
| CISA KEV | High-value evidence of known exploitation, complementary to severity and prediction. | Enriches CVEs already in the cache; does not independently supply full product applicability for missing CVEs. Complete successful catalog responses reconcile removed flags. Failed retrieval preserves prior data rather than claiming freshness. |
| FIRST EPSS | Daily probability and percentile signal, useful for prioritization alongside KEV and CVSS. | Previously mirrored the entire public API every run. Now retrieves only CVEs potentially affecting current inventory, including review candidates, in validated batches of at most 100 identifiers and 1,900 query characters. Missing scores are cleared only within the successfully queried scope. |
| Normalized JSON integrations | Useful for vetted internal or vendor gateways that conform to the application's CVE schema. | Arbitrary vendor APIs cannot be treated as this schema. Malformed or incomplete source responses fail the source atomically. Source reliability and authority require integration-specific ownership and acceptance tests. |
| Legacy MSRC / Palo Alto seed entries | Potentially valuable vendor remediation and affected-product evidence. | Remain disabled because source-specific CVRF/PSIRT/CSAF adapters are absent. Adding a URL alone does not add a supported vendor integration. |

Source diversity spans vulnerability metadata, confirmed exploitation, and predictive risk. It remains weak in vendor-specific affected/fixed statements and organization-specific observed exposure. FIRST documents comma-separated CVE filtering with a 2,000-character maximum; the new implementation stays below that bound. FIRST recommends the daily file for large bulk mirrors. [EPSS API contract](https://api.first.org/epss/), [EPSS data guidance](https://www.first.org/epss/data.html).

One small live request to each provider through the application's allowlist, DNS screening, IP pinning, and TLS client returned:

| Provider | HTTP | Observed request latency | Payload |
| --- | --- | --- | --- |
| NVD | 200 | 798 ms | 2,517 bytes; requested one CVE, not the full corpus |
| CISA KEV | 200 | 177 ms | 1,803,455 bytes; 1,754 catalog entries |
| FIRST EPSS | 200 | 734 ms | 201 bytes; one requested CVE score |

These are connectivity samples from this host during the audit, not a reliability SLA, production schema acceptance for every record, or full-pipeline benchmark. No API key was used in these probes.

## 2. Pipeline and normalization

Ingestion uses up to six source workers. NVD pages are paced and bounded; EPSS runs after primary CVE ingestion so newly discovered, inventory-relevant CVEs receive scores in the same run. Network calls remain outside the state mutation transaction. Final correlation rechecks the current inventory under the mutation lock.

Implemented fixes:

- **P1 — PostgreSQL bulk-write limit:** CVE and finding batches could exceed 65,535 bind parameters. Writes now coalesce repeated row IDs and use 1,000-row statements inside the caller's transaction. Unchanged JSON is not rewritten, reducing write amplification and preserving meaningful update timestamps.
- **P1 — Rejected CVEs remained active:** NVD rejection revisions now persist withdrawal tombstones, remove older cached revisions, and reconcile associated findings to not applicable. An older JSON source cannot resurrect a rejected revision. A genuinely newer revision can supersede the tombstone.
- **P2 — Premature loss of new intelligence:** Awaiting/undergoing analysis records are retained as review-only rather than discarded. They cannot automatically dispatch solely on provisional applicability.
- **P2 — Excessive EPSS traffic:** Full-dataset polling is replaced by bounded, inventory-relevant requests. Responses validate totals, offsets, membership, duplicate rows, and completion. Failed/partial imports do not clear existing scores. Empty scopes perform no request and do not manufacture a successful remote-health observation.
- **P2 — Retry pacing:** NVD retries respect both provider delay and configured/public request pacing. A provider delay exceeding the bounded in-run budget defers the source instead of retrying too early. Unsolicited conditional responses are rejected for moving NVD queries.
- **P2 — Stale heartbeat:** Long ingestion runs now refresh the worker heartbeat every 15 seconds.
- **P2 — Worker ownership:** All started source workers settle before the owning pipeline releases its advisory lock after a failure.
- **P2 — Configuration race:** Responses from a source that was disabled, removed, moved, or had authentication changed during ingestion are excluded from cache and health updates.

Relevant implementation: `server/db.ts`, `server/ingestion.ts`, and `server/pipeline.ts`.

Remaining bottlenecks are whole-cache state loading, correlation inside a globally serialized mutation transaction, repeated applicability evaluation for EPSS candidate selection and final reconciliation, and growth of CVE/findings/outbox history without an approved retention policy. Broad NVD windows can still exceed the explicit result cap. Fixed lookback windows do not provide a complete persisted catch-up watermark after a long outage; initial/full-history and outage backfills need a dedicated bounded workflow.

## 3. Matching against internal inventory

CPE matching uses component tokens and individual version ranges; PURL matching uses package identity, versions, and qualifiers. Explicit structured exclusions remain authoritative over text heuristics. Text/alias fallback, unsupported version ordering, unsigned VEX, and complex AND/negated configurations cannot silently produce confirmed automatic notifications.

Implemented fixes:

- **P1 — Wildcards misrepresented as proof:** An unknown inventory field now requires review when the vulnerability constrains that field. This includes explicit version, product, target OS, edition, language, update, architecture, and other CPE components.
- **P2 — First-match ordering:** Matching now selects the strongest evidence across asset identifiers and vulnerability criteria. An earlier uncertain match no longer masks a later independently confirmed match.
- **P2 — Equal-revision disagreement:** The merge is independent of asynchronous source completion order. Equal-time conflicting applicability is explicitly review-only, rather than arbitrarily confirmed from whichever source finishes last.

Tests cover explicit versions, wildcard context, multiple criteria, range boundaries, PURL matching, CPE architecture, lifecycle promotion, patched inventory, and stable finding identities. This verifies specified behavior on fixtures; it does not measure production precision or recall. Those require a labeled inventory/vulnerability sample and operator false-positive feedback.

Remaining limits: no live endpoint inventory verification, no complete NVD Boolean applicability evaluator, conservative vendor-version handling, no candidate index, and no implemented source-specific per-field authority policy. The legacy `authorityPrecedence` setting does not implement such a policy.

Relevant implementation: `src/utils/cpeMatcher.ts`, `src/engine/pipelineEngine.ts`, and `src/engine/reconcileFindings.ts`.

## 4. Notification and email workflow

Advisories and outbox jobs commit together. Delivery claims are leased with lock tokens, targets are rechecked, webhook bodies are signed, retry attempts are bounded, and provider acceptance remains distinct from inbox delivery.

Implemented fixes:

- **P1 — Subscription cross-talk:** A high-severity or KEV item could cause unrelated lower-severity/non-KEV items in the same bundle to reach restricted subscribers. Automatic bundles now separate severity and KEV status. Every item must pass the recipient or webhook subscription filter, both at enqueue and again before delivery.
- **P1 — Stale rendered intelligence:** New jobs carry canonical CVE revision fingerprints. A changed CVE can no longer send previously rendered severity/remediation content. Never-accepted stale bundles can be rebuilt by the next pipeline; accepted or in-flight histories retain their safety guard.
- **P2 — Unbounded notices:** Bundles are limited to 200 findings and subjects summarize at most three CVE IDs plus a remainder count. Plain text includes the complete CVE list, severity, affected systems, remediation, and available vendor reference.
- **P2 — Unsafe reference schemes:** Normalized patch/advisory links accept only HTTP(S) without embedded credentials, or an empty value. Executable URL schemes are rejected before persistence.

Residual limitations: owner-group routing and tenant-specific disclosure policy are absent; severity/KEV filters are not an authorization boundary. `digestBatchingEnabled`/`digestWindowMinutes` remain reserved, unimplemented settings; the worker performs bounded grouping per run, not timed cross-run digests. SMTP acceptance cannot establish inbox receipt. SMTP is at-least-once across a crash between provider acceptance and local commit; stable message IDs help reconciliation but cannot guarantee exactly-once delivery. Legacy queued jobs lacking revision fingerprints are blocked before transport and rebuilt by a subsequent pipeline when wholly unaccepted. Partially accepted stale bundles require operator review before any resend.

Relevant implementation: `server/delivery.ts`, `server/pipeline.ts`, and `server/validation.ts`.

## 5. De-duplication and integrity

The same canonical CVE merger is used by ingestion persistence and the correlation engine. It prefers newer complete source revisions, uses a deterministic tie-break for equal revisions, unions provenance, and flags conflicting equal-time applicability for review. It does not flatten ranges from unrelated revisions. Canonical CVE keys are persisted and legacy whitespace/case aliases consolidate during a successful run.

Findings remain keyed conceptually by canonical CVE plus stable asset ID, with existing IDs, lifecycle decisions, and history preserved through reconciliation. Outbox uniqueness prevents repeat enqueue for the same dispatch/channel/target. Repeated bulk inventory imports now upsert identical asset/product/identifier combinations with stable IDs, preventing duplicate findings and alerts after re-import.

De-duplication does not extend to arbitrary IP/domain/hash/URL indicators, campaign aliases, or semantically equivalent but differently represented software inventories. Source authority and identity normalization across such datasets require explicit additional adapters and models.

## 6. Operational risks and next priorities

| Priority | Risk or bottleneck | Concrete next action |
| --- | --- | --- |
| P1 deployment acceptance | Production feed inventory, software versions, ownership and real mail/webhook behavior are not established by disposable fixtures. | Validate current enabled sources, freshness, installed-version evidence, recipients and provider receipts in the deployment. |
| P1 availability | Docker topology has one PostgreSQL service, one app service and one configured SMTP relay. | Exercise restore procedures; set recovery objectives; provision monitored DB/relay redundancy where required. Multiple app instances do not remove DB dependency. |
| P2 scale | Full-state polling and corpus × assets × identifiers correlation; a global mutation lock serializes long commits. | Add paginated server reads and indexed candidate generation; benchmark a representative corpus and inventory before choosing capacity limits. |
| P2 coverage | NVD lookback/backfill gaps and missing vendor PSIRT/CSAF adapters. | Add persisted catch-up watermarks and source-specific, contract-tested vendor adapters. |
| P2 alert quality | No owner routing, timed digest service, receipt reconciliation or per-source risk-age metadata. | Implement explicit routing and digest ownership semantics; track score freshness and transport receipts. |
| P2 operations | Source failures and integration health are recorded locally; one malformed source record rejects that source's run. | Export actionable freshness/error/backlog metrics; add auditable quarantine and replay before permitting partial imports. |
| P2 retention | Unbounded CVE, finding, execution and outbox history. | Define approved retention, archive and audit-export policies before automatic deletion. |

## Verification

- `npm run lint`: passed.
- `npm run build`: production client and server builds passed.
- `npm test` with `TEST_DATABASE_URL`: **72 passed, zero failures, zero skips**.
- `git diff --check`: passed.

Regression coverage includes a real 22,000-row bulk upsert beyond the old parameter boundary, idempotent inventory import, wildcard/strongest-evidence matching, deterministic conflicting revisions, targeted and partial EPSS responses, same-run enrichment, source edits during ingestion, subscription isolation, stale and legacy payload rejection/rebuild, rejected-CVE persistence, and preventing manual/older-source resurrection.

The full suite uses isolated schemas in the disposable `vulnstream_test` PostgreSQL database and mocks all notification transports. Live provider probes above use public, bounded read requests only. No real email or webhook notification was sent. Runtime application deployment was not changed.
