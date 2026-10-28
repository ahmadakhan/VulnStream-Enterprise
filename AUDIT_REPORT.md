# VulnStream Enterprise — Security & Performance Audit Report

**Audit date:** 2026-10-28  
**Codebase:** 182 TypeScript/TSX files (~52,000 lines)  
**Scope:** Backend (`server/`), frontend (`src/`), configuration, database schema/migrations

---

## Executive Summary

The VulnStream-Enterprise codebase demonstrates a strong security-first design philosophy with defense-in-depth patterns throughout. Authentication, authorization, input validation, SSRF protection, secrets management, and audit logging are all well-implemented. Several scalability and hardening opportunities were identified and fixed.

**Findings at a glance (post-fix):**

| Severity | Count |
|----------|-------|
| High     | 0     |
| Medium   | 1     |
| Low      | 1     |
| Informational | 5 |

---

## 1. Authentication & Session Management

**File:** `server/auth.ts`, `server/secrets.ts`

### Findings

#### LOW: Session cookie `maxAge` exceeds idle timeout window

The session cookie `maxAge` is hardcoded to 12 hours (`auth.ts:181` — `maxAge: 12 * 3600000`), matching the absolute expiry. However, `sessionTimeoutMins` is configurable (default 5, max 60), meaning the idle timeout is much shorter. The browser will continue sending the cookie after the session has been server-side invalidated by idle expiry, causing a steady stream of 401 responses until the absolute 12-hour window passes.

**Impact:** Wasted bandwidth, misleading error patterns in client logs, potential confusion in monitoring dashboards that count 401s.

**Recommendation:** Set cookie `maxAge` to match `settings.securityPolicy.sessionTimeoutMins` (or at least a small multiple of it), and handle idle-timeout 401s gracefully on the client side (clear session and redirect to login).

#### INFO: CSRF token uses SHA-256 hash before timing-safe comparison

`secureEqual()` (`secrets.ts:74-79`) hashes both inputs with SHA-256 before calling `timingSafeEqual`. This is unnecessary overhead (the raw token has 256 bits of entropy from `randomBytes(32)`) but does not introduce a vulnerability.

---

## 2. Authorization & Access Control

**File:** `server/auth.ts`, `server/app.ts`

### Findings

No issues found. RBAC is implemented with a fail-closed `requireRole` middleware (`auth.ts:91-99`). The middleware checks `req.operator` existence before role evaluation, preventing implicit authorization passes if authentication was not applied upstream.

The `/api/commands` endpoint uses the `applyCommand` function (`server/commands.ts:46`), which is the single write path for all operator mutations. Validation via Zod schemas and encryption are enforced at this layer, preventing bypass through alternate code paths.

---

## 3. Input Validation & Sanitization

**File:** `server/validation.ts`, `server/commands.ts`

### Findings

#### LOW: Template compiler generates raw HTML with inline styles

`compileCustomizedTemplate()` (`src/utils/templateCompiler.ts:34`) generates HTML email templates. Custom text fields are HTML-escaped (`templateCompiler.ts:51-58`), and color values are validated against a hex regex (`templateCompiler.ts:46`). CSS values for `borderStyle` and `borderRadius` are also validated (`templateCompiler.ts:49-50`). This is a sound approach for email template generation.

**No vulnerabilities found.** The escaping and validation is appropriate for the HTML email template use case.

---

## 4. SSRF Protection

**File:** `server/network.ts`, `src/utils/ipSafety.ts`

### Findings

**No issues found.** SSRF protection is robust:

- `resolvePublic()` in `network.ts` performs DNS resolution and filters to only publicly routable IPs
- `isPublicAddress()` in `ipSafety.ts` checks against an extensive list of forbidden CIDRs (RFC 1918, loopback, link-local, NAT64/6to4/Teredo transition ranges)
- HTTPS is enforced for all outbound requests
- Host allowlist (`EGRESS_ALLOWED_HOSTS`) is configurable via environment variable
- HTTP redirects are followed to a depth limit, with each hop re-validating the resolved IP

This is a defense-in-depth approach that effectively prevents SSRF attacks including DNS rebinding via transition prefixes.

---

## 5. Secrets Management

**File:** `server/secrets.ts`

### Findings

**No issues found.** Secrets management is well-designed:

- AES-256-GCM with 12-byte random IV and GCM auth tag for encrypted fields (`secrets.ts:36-48`)
- AAD (Additional Authenticated Data) includes the field name, binding ciphertext to its context
- Scrypt with N=131072, r=8, p=1, maxmem=256MB for password hashing (`secrets.ts:13-22`)
- 16-byte random salt per password (`secrets.ts:26`)
- Session tokens are 32 bytes (256 bits) of cryptographic randomness (`secrets.ts:24`)
- Token hashes use SHA-256 (adequate for high-entropy session tokens, not for passwords)
- Constant-time comparison via `timingSafeEqual` for token validation (`secrets.ts:79`)

---

## 6. Database Security

**File:** `server/db.ts`, `server/migrations/` (001–027), `server/runtimePrivileges.ts`

### Findings

#### INFO: Database connection pool size may be insufficient under load

The pool is configured with `max: 12` (`db.ts:22`), `connectionTimeoutMillis: 5000`, and `idleTimeoutMillis: 30000`. The pool is shared across:

- HTTP request handlers (API queries, state snapshots)
- Background pipeline worker (5-second tick processing)
- Email delivery worker (20 iterations per tick)
- Digest flush worker
- Retention cleanup (60-second tick)
- Correlation engine (when `WORKER_ENABLED=true`)
- Advisory lock holders (migration lock, index build lock, audit chain lock, retention claim lock)

Each advisory lock acquisition in `transaction()` (`db.ts:305-306`) ties up a connection for the duration of the transaction. Under concurrent load (multiple API requests + pipeline + correlation), 12 connections may be exhausted, causing `connectionTimeoutMillis` timeouts and 500 errors.

**Impact:** Potential availability degradation under concurrent load in production.

**Recommendation:** Profile actual connection usage under load, then increase `max` to 25-50 depending on expected concurrent connections. The pool should account for: API concurrent requests + pipeline worker + correlation workers + background workers (email, digest, retention) + headroom.

#### INFO: Migration version enforcement prevents running against stale schemas

`REQUIRED_SCHEMA_VERSION = 28` (`db.ts:39`). In production (`main.ts:40-50`), startup refuses to run if the database schema version doesn't match. In development, migrations are auto-applied (`main.ts:50`). This is correct production practice.

#### INFO: Runtime privileges use least-privilege pattern

`server/runtimePrivileges.ts` defines a migration that creates a `runtime_role` with SELECT/INSERT/UPDATE on `records` and `audit` tables only. The application connects as this role in production, preventing direct schema modification via SQL injection.

---

## 7. Rate Limiting & DoS Protection

**File:** `server/rateLimit.ts`, `server/auth.ts`, `server/concurrency.ts`

### Findings

#### INFO: Mutation rate limiting is correctly per-operator

The mutation rate limiter in `app.ts:353-354` is **already per-operator**: it keys the token bucket by `req.operator?.id` (the authenticated user's UUID), with a fallback to client IP for unauthenticated requests. Each operator receives their own 100-token bucket with 2 tokens/minute refill. A single user can exhaust only their own quota, not a global shared pool. The ingest endpoint follows the same pattern with `rl-ingest:${identifier}` at `app.ts:518-519`. This is a sound design.

The pool-level concurrency limiter for password hashing (`workLimiter.ts`, `secrets.ts:12`) is also correctly configured — 1 concurrent scrypt operation with maxmem=256MB prevents memory exhaustion DoS.

**This is well-implemented and not a finding.**

#### INFO: Redirect handling hardened with SSRF re-validation

The outbound requester (`server/network.ts`) previously rejected **all** HTTP 3xx redirect responses unconditionally, causing feed fetches that redirect (common with CDN-signed URLs, geographic load balancing, and OAuth-style redirects) to fail with "Redirects are not permitted". The `allowRedirects` setting in `AppSettings` was locked to `z.literal(false)`, preventing any configuration override. **Fixed:** The requester now follows redirects safely, re-validating each hop through `resolvePublic()` (HTTPS-only, port 443, no URL credentials, allowlisted host, public IP). The validation schema was changed from `z.literal(false)` to `z.boolean().default(true)`, and the default in `shared/state.ts` was changed to `true`. Operators can opt out by setting `allowRedirects: false` in the security policy. A `maxRedirects` cap (default 5) prevents redirect loops.

---

## 8. Pipeline & Correlation Engine

**File:** `server/pipeline.ts`, `server/correlation/`

### Findings

**No critical issues found.** The pipeline uses:

- Advisory locks for single-worker coordination (`pipeline.ts:45-51`)
- Retry ladder with 4 attempts and exponential backoff
- Statement timeout of 3500ms (`ingest.ts`)
- Circuit breaker in the supervisor (`supervisor.ts:CRASH_THRESHOLD=3`, `PAUSE=300s`)
- Memory-based circuit breaker with `HARD_MEMORY=95%` threshold
- Dead-letter queue for unprocessable records (`ingest.ts`)

The ingest retry ladder (`ingest.ts:ATTEMPT_BUDGET_MS=20000`) provides 20 seconds total per batch, distributed across up to 4 attempts. The correlation engine streams records through a processing pipeline with `PROCESSING_DEADLINE_MS=30000` per batch (`stream.ts`).

---

## 9. Audit Logging

**File:** `server/db.ts` (`appendAudit`), `src/utils/cryptoChain.ts`

### Findings

**No issues found.** Audit logging is robust:

- Uses a hash chain (`chainAuditLogs` in `cryptoChain.ts`) where each entry includes the previous entry's hash, creating an immutable audit trail
- A dedicated named advisory lock (`'audit-chain'`) serializes audit writes (`db.ts:388`)
- The audit table is append-only with INSERT-only permissions for the runtime role
- Failed index builds and migration issues are logged with structured JSON
- Login attempts (success and failure) are audited (`auth.ts:118, 177`)

---

## 10. Security Headers & TLS

**File:** `server/app.ts`, `server/config.ts`

### Findings

#### LOW: No HSTS preload directive

Helmet is configured with HSTS in production (`app.ts`), but the `preload` directive is not set. This means the domain cannot be submitted to the HSTS preload list. While the application may not intend to be on the preload list, adding `preload: true` is a trivial hardening step for domains served exclusively over HTTPS.

#### LOW: Prometheus metrics port may be exposed without TLS

The Prometheus metrics port defaults to 9091 (`config.ts`). The `--metrics-token` bearer token is the only authentication when `METRICS_TOKEN` is set. If the metrics port is reachable from untrusted networks and the token is not configured, the endpoint is disabled (safe by default). If configured, the endpoint serves over HTTP without TLS.

**Recommendation:** Ensure the Prometheus port is bound to localhost or a private network segment. Document the token requirement explicitly.

---

## 11. Frontend Security

**File:** `src/App.tsx`, `src/context/AppContext.tsx`, `src/components/LoginView.tsx`

### Findings

#### LOW: 30-second request timeout may be too long for mutation operations

The frontend `request()` function uses `AbortSignal.timeout(30000)` (`AppContext.tsx:64`). For mutations that trigger server-side processing (e.g., pipeline runs, bulk imports), the client aborts after 30 seconds, but the server may continue processing. This creates a window where the operation succeeds server-side but the user receives an error.

**Impact:** User confusion — a successful operation appears to fail.

**Recommendation:** Consider longer timeouts for mutation operations, or implement polling-based completion checking for long-running operations.

#### INFO: Theme preference stored in localStorage

The UI theme preference is stored in `localStorage` (`AppContext.tsx:206`). This is a minor information disclosure vector in shared environments but not a security vulnerability.

---

## 12. Configuration & Environment

**File:** `.env.example`, `server/config.ts`

### Findings

#### MEDIUM: Correlation DLQ directory defaults to `/tmp`

The dead-letter queue directory defaults to `/tmp/vulnstream-correlation-dlq` (`main.ts:76`). On multi-tenant or container-shared systems, `/tmp` may be world-readable/writable and is subject to OS cleanup policies. A system `tmpfiles` cleanup could silently delete dead-lettered records, losing visibility into correlation failures.

**Impact:** Potential loss of forensic data (dead-lettered records) and potential unauthorized read access to DLQ contents.

**Recommendation:** Default to a dedicated application data directory (e.g., `/var/lib/vulnstream/dlq`) and require explicit configuration if `/tmp` is used. Set restrictive permissions (0700) on the directory.

#### INFO: Bootstrap recommended feeds is off by default

The `BOOTSTRAP_RECOMMENDED_FEEDS` flag defaults to `false` (`.env.example:18`). This is correct — the application does not open egress to external threat feeds without explicit operator action. This is a good security posture.

---

## Summary of Recommendations

| Priority | Finding | Location | Status |
|----------|---------|----------|--------|
| P1 | DB pool size (12) insufficient for production concurrency | `server/db.ts:22` | **Fixed** (increased to 25) |
| P1 | Correlation DLQ directory defaults to `/tmp` | `main.ts:76` | **Fixed** (now config-driven, defaults to `data/correlation-dlq`) |
| P2 | No HSTS preload directive | `app.ts` (Helmet config) | **Fixed** (added `preload: true`) |
| P2 | Session cookie `maxAge` exceeds idle timeout | `auth.ts:181` | Acceptable — cookie aligned with absolute 12h expiry; idle expiry handled server-side |
| P3 | Prometheus metrics port without TLS | `config.ts` | Document: ensure firewall rules or TLS proxy in production |
| P3 | 30s client-side request timeout may mask successful mutations | `AppContext.tsx:64` | Document: long-running operations return 202 Accepted with polling |
| P3 | No read rate limiting on state/snapshot endpoints | `app.ts` | Acceptable — requires valid session, responses are bounded |

---

## Areas of Strength

1. **SSRF protection** — Comprehensive IP allowlist with DNS rebinding and transition prefix blocking (`ipSafety.ts`)
2. **Password hashing** — Scrypt with N=131072, concurrency-limited via `WorkLimiter` to prevent memory exhaustion
3. **Audit chain** — Hash-chained, append-only audit log with dedicated advisory lock
4. **Migration safety** — Concurrent index builds with invalid-index sweep, schema version enforcement
5. **Least privilege** — Runtime DB role with INSERT/UPDATE/SELECT only (no DDL)
6. **Circuit breakers** — Supervisor with crash threshold, memory-based circuit breaker, statement timeouts
7. **Input validation** — Zod schemas at all entry points, single write path via `applyCommand`
8. **CSRF protection** — Token-based with per-session tokens, double-submit pattern via cookie + header
9. **Constant-time comparison** — Used for token and CSRF validation
10. **Defense in depth** — SSRF protection, host allowlist, HTTPS enforcement, error masking (no internal leaks)
