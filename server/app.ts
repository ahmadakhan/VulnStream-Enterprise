import { correlationMetrics } from './correlation/metrics.ts';
import {
  correlationWorkflows,
  decideCorrelationReview,
  decideDeadLetter,
  updateCorrelationPolicy,
  retainCorrelationData,
} from './correlation/operations.ts';
import type { CorrelationRuntime } from './correlation/runtime.ts';
import { advisoryRecords } from './correlation/stream.ts';
import { Readable } from 'node:stream';
import express from 'express';
import { WorkCapacityError } from './workLimiter.ts';
import compression from 'compression';
import helmet from 'helmet';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import type pg from 'pg';
import type { Config } from './config';
import {
  asyncRoute,
  requireAuth,
  requireRole,
  loginHandler,
  cookieName,
  createUser,
  sessionCookieOptions,
} from './auth';
import { transaction, state, get, getForUpdate, put, appendAudit, list } from './db';
import { queryCollection } from './collections';
import { runRetention, previewRetention } from './retention';
import { merkleRoot, verifyAuditChain } from '../src/utils/cryptoChain.ts';
import { buildAliasMap } from '../src/utils/cpeMatcher.ts';
import { runVulnerabilityPipeline } from '../src/engine/pipelineEngine.ts';
import { HttpError } from './validation';
import { applyCommand } from './commands';
import { checkPassword, passwordHash, decrypt, secureEqual } from './secrets';
import { createRequester, resolvePublic } from './network';
import type { Requester, ResponseData } from './network';
import { queueRun, stopRun, renderAdvisory } from './pipeline';
import { enqueue, queueAdvisory } from './delivery';
import { advisoryEmail } from './advisoryEmail';
import { DEFAULT_SETTINGS, DEFAULT_EMAIL_CONFIG } from '../shared/state.ts';
import { emailIsConfigured } from './emailProviders';
import { parseSyndication, RSS_MAX_BYTES } from './rss';
import { readEvents, writeEvent } from './events';
import { createDatabaseRateLimiter, type MutationLimiter, INGEST_LIMIT_CAPACITY, INGEST_LIMIT_REFILL_PER_MS } from './rateLimit';
import { searchNvdCpes, loadNvdApiKey, isNvdRateLimitError, nvdRetryAfterSeconds } from './cpeSearch';
import type { AppState } from '../shared/state.ts';
import type {
  AppSettings,
  ThreatFeed,
  WebhookEndpoint,
  Advisory,
  TemplateCustomization,
  EmailConfiguration,
  NormalizedCVE,
  AliasEntry,
  WatchListItem,
  NvdCpeSearchResponse,
} from '../src/types/index.ts';
import { DEFAULT_TEMPLATE_CUSTOMIZATION } from '../src/utils/templateCompiler.ts';
function publicState(data: AppState): AppState {
  return {
    ...data,
    feeds: data.feeds.map((f) => ({ ...f, authSecretKey: undefined })),
    webhooks: data.webhooks.map((w) => ({ ...w, url: '[configured on server]', secretToken: '' })),
    emailConfig: {
      ...data.emailConfig,
      apiKey: '',
      hasApiKey: !!data.emailConfig.apiKey,
      smtpPassword: '',
      hasSmtpPassword: !!data.emailConfig.smtpPassword,
      mailjetApiSecret: '',
      hasMailjetApiSecret: !!data.emailConfig.mailjetApiSecret,
    },
    settings: {
      ...data.settings,
      webhookSigningSecret: '',
      mailgunConfig: { ...data.settings.mailgunConfig, apiKey: '' },
    },
  };
}
const STATE_COLLECTION_LIMITS = {
  cveData: 100,
  findings: 100,
  advisories: 50,
  alertedCves: 100,
  emailLogs: 100,
  webhookLogs: 100,
  executions: 20,
  auditLogs: 200,
  intelligenceArticles: 50,
  intelligenceMatches: 100,
} as const;
async function refreshAdvisoryDeliveryStatus(db: pg.Pool | import('pg').PoolClient, advisoryId: string) {
  const advisory = await getForUpdate<Advisory>(db, 'advisories', advisoryId);
  if (!advisory) return;
  const totals = (
    await db.query(
      `SELECT count(*) FILTER(WHERE status='FAILED')::int AS failed,
        count(*) FILTER(WHERE status IN ('REVIEW','QUEUED','SENDING'))::int AS pending,
        count(*) FILTER(WHERE status='ACCEPTED')::int AS accepted,
        count(*) FILTER(WHERE status='REJECTED')::int AS rejected
       FROM outbox WHERE advisory_id=$1`,
      [advisoryId],
    )
  ).rows[0];
  advisory.deliveryStatus = Number(totals.pending)
    ? 'PENDING'
    : Number(totals.failed)
      ? 'FAILED'
      : Number(totals.accepted)
        ? 'ACCEPTED'
        : 'DRAFT';
  await put(db, 'advisories', advisory.id, advisory);
  const notificationStatus = Number(totals.pending)
    ? 'QUEUED_FOR_DISPATCH'
    : Number(totals.failed)
      ? 'DELIVERY_FAILED'
      : Number(totals.accepted)
        ? 'AUTO_DISPATCHED'
        : Number(totals.rejected)
          ? 'SECURITY_REJECTED'
          : null;
  if (notificationStatus)
    for (const findingId of advisory.findingIds) {
      const finding = await getForUpdate<any>(db, 'findings', findingId);
      // Do not resurrect a finding that was explicitly excluded (for example,
      // inventory was removed while the bundle waited for review).
      if (
        finding &&
        finding.advisoryId === advisory.id &&
        !['NOT_APPLICABLE', 'SUPPRESSED_VEX_NOT_AFFECTED', 'REVIEW_REQUIRED'].includes(
          finding.notificationStatus,
        )
      )
        await put(db, 'findings', findingId, {
          ...finding,
          notificationStatus,
          autoDispatchedAt:
            notificationStatus === 'AUTO_DISPATCHED'
              ? finding.autoDispatchedAt || new Date().toISOString()
              : null,
        });
    }
}
export interface AppOptions {
  correlation?: CorrelationRuntime;
  /**
   * Overrides the shared database-backed mutation limiter. Tests use this to
   * exercise the middleware with a small deterministic quota.
   */
  mutationLimiter?: MutationLimiter;
  /**
   * Overrides the per-operator ingest rate limiter. Omit to use the default
   * database-backed limiter with the built-in capacity/refill.
   */
  ingestLimiter?: MutationLimiter;
}
export function createApp(
  pool: pg.Pool,
  config: Config,
  request: Requester = createRequester(config),
  options: AppOptions = {},
) {
  const app = express();
  app.disable('x-powered-by');
  // /api/state is a bounded snapshot; gzip keeps its transfer size small.
  app.use(compression({ threshold: 1024 }));
  if (config.TRUST_PROXY)
    app.set(
      'trust proxy',
      config.TRUST_PROXY.split(',').map((s) => s.trim()),
    );
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'", 'data:'],
          fontSrc: ["'self'"],
          connectSrc: ["'self'"],
          frameSrc: ["'self'"],
          objectSrc: ["'none'"],
          baseUri: ["'none'"],
          formAction: ["'self'"],
          frameAncestors: ["'none'"],
          upgradeInsecureRequests: config.NODE_ENV === 'production' ? [] : null,
        },
      },
      strictTransportSecurity:
        config.NODE_ENV === 'production' ? { maxAge: 31536000, includeSubDomains: true } : false,
    }),
  );
  app.use(express.json({ limit: '2mb', strict: true }));
  app.use('/api', (req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method) && req.headers.origin !== config.APP_ORIGIN)
      return next(new HttpError(403, 'Origin not allowed'));
    if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method) && !req.is('application/json'))
      return next(new HttpError(415, 'JSON body required'));
    next();
  });
  app.get('/live', (_req, res) => res.json({ status: 'live' }));
  app.get('/metrics', (req, res) => {
    if (!options.correlation || !config.METRICS_TOKEN) return res.sendStatus(404);
    if (!secureEqual(req.headers.authorization || '', `Bearer ${config.METRICS_TOKEN}`))
      return res.sendStatus(401);
    res.type('text/plain; version=0.0.4').send(correlationMetrics(options.correlation.supervisor));
  });
  app.get(
    '/ready',
    asyncRoute(async (_req, res) => {
      await pool.query('SELECT 1');
      res.json({ status: 'ready' });
    }),
  );
  app.post('/api/login', loginHandler(pool, config));
  // Global rate limiting for authenticated mutation endpoints. The bucket is
  // stored in PostgreSQL so every replica shares one quota per operator.
  //
  // Only state-changing requests are charged. `/api/correlation/simulate` is a
  // POST that performs a pure in-memory match against already-loaded data and
  // writes nothing, so billing it against the mutation quota let an ordinary
  // read-only operator exhaust their write budget by exploring the matcher —
  // and made the documented VIEWER read-only role unable to use it at all.
  // The allowlist is by exact route, never by prefix, so a future mutating
  // route cannot inherit the exemption through naming.
  const NON_MUTATING_POSTS = new Set(['/api/correlation/simulate']);
  const mutationLimiter = options.mutationLimiter ?? createDatabaseRateLimiter(pool);
  const ingestLimiter = options.ingestLimiter ?? createDatabaseRateLimiter(pool, INGEST_LIMIT_CAPACITY, INGEST_LIMIT_REFILL_PER_MS);
  app.use('/api', requireAuth(pool, config), async (req, res, next) => {
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
    // Inside a mount, req.path is the path RELATIVE to the mount point
    // ('/correlation/simulate'), not the absolute route. Matching the absolute
    // name here silently exempted nothing. Use baseUrl + path, which is what
    // the route table actually keys on.
    const route = `${req.baseUrl}${req.path}`.replace(/\/+$/, '') || '/';
    if (req.method === 'POST' && NON_MUTATING_POSTS.has(route)) return next();
    try {
      const identifier = req.operator?.id || req.ip || '';
      const result = await mutationLimiter(`rl:${identifier}`);
      if (!result.allowed) {
        res.setHeader('Retry-After', String(Math.max(1, Math.ceil(result.retryAfterMs / 1000))));
        return next(new HttpError(429, 'Too many requests'));
      }
      next();
    } catch (error) {
      next(error);
    }
  });
  if (options.correlation) {
    const runtime = options.correlation;
    app.get(
      '/api/correlation/workflows',
      asyncRoute(async (_req, res) => res.json(await correlationWorkflows(pool))),
    );
    app.patch(
      '/api/correlation/policy',
      requireRole('ADMIN'),
      asyncRoute(async (req, res) => {
        const policy = await transaction(pool, (db) =>
          updateCorrelationPolicy(db, req.body, req.operator!.username),
        );
        res.json(policy);
      }),
    );
    app.post(
      '/api/correlation/reviews/:id/decision',
      requireRole('ADMIN', 'OPERATOR'),
      asyncRoute(async (req, res) => {
        const id = z.uuid().parse(req.params.id);
        await transaction(pool, (db) => decideCorrelationReview(db, id, req.body, req.operator!.username));
        res.json({ success: true });
      }),
    );
    app.post(
      '/api/correlation/dead-letters/:id/decision',
      requireRole('ADMIN'),
      asyncRoute(async (req, res) => {
        const id = z.uuid().parse(req.params.id);
        await transaction(pool, (db) =>
          decideDeadLetter(db, id, req.body, req.operator!.username, config.ENCRYPTION_KEY),
        );
        res.json({ success: true });
      }),
    );
    app.post(
      '/api/correlation/retention/run',
      requireRole('ADMIN'),
      asyncRoute(async (req, res) => {
        const removed = await transaction(pool, async (db) => {
          const count = await retainCorrelationData(db);
          await appendAudit(
            db,
            'Correlation retention run',
            `${count} resolved or expired records removed`,
            req.operator!.username,
          );
          return count;
        });
        res.json({ removed });
      }),
    );
    app.get(
      '/api/correlation/assets',
      asyncRoute(async (req, res) => {
        const query = z
          .object({ q: z.string().trim().max(200).default(''), after: z.uuid().optional() })
          .strict()
          .parse(req.query);
        const rows = await pool.query(
          `SELECT i.id,i.vendor,i.product,i.version,m.record_id AS "recordId",r.data->>'assetTag' AS "assetTag"
        FROM correlation_asset_inventory i LEFT JOIN correlation_managed_assets m ON m.native_id=i.id
        LEFT JOIN records r ON r.kind='watchlist' AND r.id=m.record_id
        WHERE ($1::uuid IS NULL OR i.id>$1) AND ($2='' OR strpos(lower(i.vendor||' '||i.product),lower($2))>0)
        ORDER BY i.id LIMIT 51`,
          [query.after || null, query.q],
        );
        res.json({
          assets: rows.rows.slice(0, 50),
          nextCursor: rows.rows.length > 50 ? rows.rows[49].id : null,
        });
      }),
    );

    app.get(
      '/api/correlation',
      asyncRoute(async (_req, res) => res.json(await runtime.supervisor.snapshot())),
    );
    app.post(
      '/api/correlation/concurrency',
      requireRole('ADMIN', 'OPERATOR'),
      asyncRoute(async (req, res) => {
        const { limit } = z
          .object({ limit: z.number().int().min(1).max(32) })
          .strict()
          .parse(req.body);
        await transaction(pool, async (db) => {
          await db.query('UPDATE correlation_policy SET concurrency_limit=$1,updated_at=now() WHERE id=1', [
            limit,
          ]);
          await appendAudit(
            db,
            'Correlation concurrency changed',
            `Per-instance limit ${limit}`,
            req.operator!.username,
          );
        });
        runtime.supervisor.setConcurrency(limit);
        res.json({ concurrencyLimit: runtime.supervisor.concurrencyLimit });
      }),
    );
    app.post(
      '/api/correlation/fault',
      requireRole('ADMIN'),
      asyncRoute(async (req, res) => {
        if (config.NODE_ENV === 'production')
          throw new HttpError(403, 'Fault simulation is disabled in production');
        const { fault } = z
          .object({ fault: z.enum(['memory', 'database']) })
          .strict()
          .parse(req.body);
        runtime.supervisor.simulate(fault);
        res.json({ accepted: true });
      }),
    );
    app.post(
      '/api/correlation/ingest',
      requireRole('ADMIN', 'OPERATOR'),
      asyncRoute(async (req, res) => {
        const identifier = req.operator?.id || req.ip || '';
        const ingestResult = await ingestLimiter(`rl-ingest:${identifier}`);
        if (!ingestResult.allowed) {
          res.setHeader('Retry-After', String(Math.max(1, Math.ceil(ingestResult.retryAfterMs / 1000))));
          throw new HttpError(429, 'Too many ingest submissions');
        }
        const { ndjson } = z
          .object({ ndjson: z.string().min(1).max(524288) })
          .strict()
          .parse(req.body);
        let count = 0;
        await transaction(pool, async (db) => {
          for await (const payload of advisoryRecords(
            Readable.from([Buffer.from(ndjson)], { objectMode: false }),
          )) {
            if (++count > 128) throw new HttpError(413, 'At most 128 records per submission');
            await db.query('INSERT INTO correlation_pending(id,payload) VALUES($1,$2)', [
              randomUUID(),
              JSON.stringify(payload),
            ]);
          }
        });
        res.status(202).json({ queued: count });
      }),
    );
    app.get(
      '/api/correlation/search',
      asyncRoute(async (req, res) => {
        const { q } = z.object({ q: z.string().trim().min(1).max(200) }).parse(req.query);
        const result = await pool.query(
          `SELECT id,title,url,processed_at FROM unstructured_advisories
        WHERE tsv_content @@ plainto_tsquery('simple',$1) ORDER BY processed_at DESC LIMIT 50`,
          [q],
        );
        res.json({ advisories: result.rows });
      }),
    );
  }
  app.get('/api/session', (req, res) =>
    res.json({
      username: req.operator!.username,
      role: req.operator!.role,
      csrfToken: req.operator!.csrf,
      expiresAt: req.operator!.expiresAt,
    }),
  );
  app.get(
    '/api/cpes/search',
    requireRole('ADMIN', 'OPERATOR'),
    asyncRoute(async (req, res) => {
      const { vendor, product, limit } = z
        .object({
          vendor: z.string().trim().min(1).max(200),
          product: z.string().trim().max(200).default(''),
          limit: z.coerce.number().int().min(1).max(200).default(50),
        })
        .parse(req.query);
      const apiKey = await loadNvdApiKey(pool, config);
      try {
        res.json(await searchNvdCpes(request, apiKey, vendor, product, limit));
      } catch (error) {
        if (isNvdRateLimitError(error)) {
          const retryAfter = nvdRetryAfterSeconds(error);
          if (retryAfter) res.setHeader('Retry-After', String(retryAfter));
          throw new HttpError(429, 'NVD rate limit reached; retry later');
        }
        throw new HttpError(502, error instanceof Error ? error.message : 'NVD CPE search failed');
      }
    }),
  );
  app.post(
    '/api/session/renew',
    asyncRoute(async (req, res) => {
      const settings = (await get<AppSettings>(pool, 'settings', 'main')) || DEFAULT_SETTINGS;
      const row = (
        await pool.query(
          "UPDATE sessions SET expires_at=LEAST(now()+($2::int * interval '1 minute'),absolute_expires_at) WHERE token_hash=$1 RETURNING expires_at",
          [req.operator!.sessionHash, settings.securityPolicy.sessionTimeoutMins],
        )
      ).rows[0];
      res.json({ expiresAt: row.expires_at.toISOString() });
    }),
  );
  app.post(
    '/api/logout',
    asyncRoute(async (req, res) => {
      await pool.query('DELETE FROM sessions WHERE token_hash=$1', [req.operator!.sessionHash]);
      // __Host- cookies are only cleared when the deletion carries the same
      // Secure/Path attributes as the original cookie.
      res.clearCookie(cookieName(config), sessionCookieOptions(config));
      res.json({ success: true });
    }),
  );
  app.post(
    '/api/password',
    asyncRoute(async (req, res) => {
      const data = z
        .object({ currentPassword: z.string().min(1).max(128), newPassword: z.string().min(14).max(128) })
        .parse(req.body);
      const user = (await pool.query('SELECT password_hash FROM users WHERE id=$1', [req.operator!.id]))
        .rows[0];
      if (!(await checkPassword(data.currentPassword, user.password_hash)))
        throw new HttpError(400, 'Current password is incorrect');
      const settings = (await get<AppSettings>(pool, 'settings', 'main')) || DEFAULT_SETTINGS;
      if (data.newPassword.length < settings.securityPolicy.minPasswordLen)
        throw new HttpError(400, 'Password does not meet configured minimum length');
      const hash = await passwordHash(data.newPassword);
      await transaction(pool, async (db) => {
        await db.query('UPDATE users SET password_hash=$2 WHERE id=$1', [req.operator!.id, hash]);
        await db.query('DELETE FROM sessions WHERE user_id=$1', [req.operator!.id]);
        await appendAudit(
          db,
          'Password changed',
          'All sessions revoked',
          req.operator!.username,
          'SECURITY',
          'INFO',
          req.ip || '',
        );
      });
      res.clearCookie(cookieName(config), sessionCookieOptions(config));
      res.json({ success: true });
    }),
  );
  app.get(
    '/api/users',
    requireRole('ADMIN'),
    asyncRoute(async (_req, res) =>
      res.json(
        (await pool.query('SELECT id,username,role,disabled,created_at FROM users ORDER BY username')).rows,
      ),
    ),
  );
  app.post(
    '/api/users',
    requireRole('ADMIN'),
    asyncRoute(async (req, res) => {
      const data = z
        .object({ username: z.string(), password: z.string(), role: z.enum(['ADMIN', 'OPERATOR', 'VIEWER']) })
        .parse(req.body);
      await createUser(pool, data.username, data.password, data.role);
      res.status(201).json({ success: true });
    }),
  );
  app.patch(
    '/api/users/:id',
    requireRole('ADMIN'),
    asyncRoute(async (req, res) => {
      const data = z
        .object({ role: z.enum(['ADMIN', 'OPERATOR', 'VIEWER']), disabled: z.boolean() })
        .parse(req.body);
      if (req.params.id === req.operator!.id && (data.disabled || data.role !== 'ADMIN'))
        throw new HttpError(400, 'Cannot remove your own administrator access');
      await transaction(pool, async (db) => {
        const changed = await db.query('UPDATE users SET role=$2,disabled=$3 WHERE id=$1 RETURNING id', [
          req.params.id,
          data.role,
          data.disabled,
        ]);
        if (!changed.rowCount) throw new HttpError(404, 'Operator not found');
        await db.query('DELETE FROM sessions WHERE user_id=$1', [req.params.id]);
        await appendAudit(
          db,
          'Operator access changed',
          `Operator ${req.params.id}; role ${data.role}; disabled ${data.disabled}`,
          req.operator!.username,
          'SECURITY',
          'INFO',
          req.ip || '',
        );
      });
      res.json({ success: true });
    }),
  );
  app.get(
    '/api/state',
    asyncRoute(async (_req, res) =>
      res.json(publicState(await state(pool, { limits: STATE_COLLECTION_LIMITS }))),
    ),
  );
  app.get(
    '/api/collections/:kind',
    asyncRoute(async (req, res) => {
      const query = z
        .object({
          limit: z.coerce.number().int().min(1).max(1000).default(50),
          offset: z.coerce.number().int().min(0).default(0),
          search: z.string().max(300).optional(),
          sort: z.string().max(40).optional(),
          order: z.enum(['asc', 'desc']).optional(),
          kev: z.enum(['true', 'false']).optional(),
          epssMin: z.coerce.number().min(0).max(1).optional(),
          dateFilter: z.enum(['ALL', 'IN_SCOPE', 'RECENT_MODIFIED', 'RECENT_PUBLISHED']).optional(),
          scopeHours: z.coerce.number().int().min(1).max(2880).optional(),
          severity: z.string().max(20).optional(),
          status: z.string().max(40).optional(),
          notificationStatus: z.string().max(40).optional(),
          category: z.string().max(20).optional(),
          level: z.string().max(10).optional(),
          articleIds: z.string().max(4000).optional(),
        })
        .parse(req.query);
      // VIEWER is a read role: it gets the same server-side filtering and
      // pagination as ADMIN/OPERATOR. Silently forcing offset 0 and dropping
      // search made every read-only history view show only its first page.
      res.json(
        await queryCollection(pool, String(req.params.kind), {
          limit: query.limit,
          offset: query.offset,
          search: query.search,
          sort: query.sort,
          order: query.order,
          filters: {
            kev: query.kev === 'true',
            epssMin: query.epssMin,
            dateFilter: query.dateFilter,
            scopeHours: query.scopeHours,
            severity: query.severity,
            status: query.status,
            notificationStatus: query.notificationStatus,
            category: query.category,
            level: query.level,
            articleIds: query.articleIds?.split(',').filter(Boolean),
          },
        }),
      );
    }),
  );
  app.get(
    '/api/audit/verify',
    asyncRoute(async (req, res) => {
      const rows = await pool.query('SELECT data FROM audit ORDER BY seq ASC');
      const logs = rows.rows.map((row) => row.data);
      const verified = verifyAuditChain(logs.reverse());
      const root = merkleRoot(logs.map((log: any) => log.hash));
      const externalRoot = typeof req.query.externalRoot === 'string' ? req.query.externalRoot : undefined;
      const externalMatch = externalRoot ? externalRoot === root : undefined;
      res.json({
        verified,
        merkleRoot: root,
        logCount: logs.length,
        externalRoot: externalRoot || null,
        externalMatch,
      });
    }),
  );
  app.post(
    '/api/correlation/simulate',
    // Read-only by construction: matches against the cached corpus and the
    // submitted watch item, persisting nothing. Gating it on ADMIN forced
    // operators and viewers to file a privileged request to answer "would this
    // product match?", which is the question the endpoint exists to answer.
    // Any authenticated role may call it; the mutation quota skips it.
    requireRole('ADMIN', 'OPERATOR', 'VIEWER'),
    asyncRoute(async (req, res) => {
      const body = z
        .object({
          vendor: z.string().min(1).max(200),
          product: z.string().min(1).max(200),
          version: z.string().max(100).optional(),
          cpes: z.array(z.string().max(600)).max(50).default([]),
          purls: z.array(z.string().max(600)).max(50).optional(),
          targetHw: z.string().max(100).optional(),
          assetTag: z.string().max(120).optional(),
        })
        .parse(req.body);
      const settings = (await get<AppSettings>(pool, 'settings', 'main')) || DEFAULT_SETTINGS;
      const cves = await list<NormalizedCVE>(pool, 'cveData', 500);
      const aliases = await list<AliasEntry>(pool, 'aliases', 500);
      const watchItem: WatchListItem = {
        id: 'sim-test-01',
        vendor: body.vendor,
        product: body.product,
        version: body.version,
        cpes: body.cpes,
        purls: body.purls,
        targetHw: body.targetHw,
        assetTag: body.assetTag || 'SIM-PROD-01',
        ownerGroup: 'Simulation-Lab',
        active: true,
        createdAt: new Date().toISOString(),
      };
      const correlation = runVulnerabilityPipeline(
        [],
        cves,
        [watchItem],
        [],
        [],
        { ...settings, scopeHours: 0 },
        'Simulation',
        false,
        buildAliasMap(aliases, 'VENDOR'),
        buildAliasMap(aliases, 'PRODUCT'),
        undefined,
        aliases,
      );
      const matchedCves = correlation.newFindings.map((finding) => ({
        cve: finding.cve,
        method: finding.matchingMethod,
        confidence: finding.notificationStatus === 'REVIEW_REQUIRED' ? 0 : 100,
        evidence: finding.matchingEvidence,
        autoAction: finding.notificationStatus === 'REVIEW_REQUIRED' ? 'REVIEW_REQUIRED' : 'MATCH_CONFIRMED',
        suppressed: false,
        suppressionReason: '',
      }));
      res.json({
        testedAt: new Date().toISOString(),
        matchedCves,
        totalScanned: cves.length,
        aliasExpanded: matchedCves.some((match) => match.method === 'VENDOR_PRODUCT_ALIAS'),
        intervalEvaluated: matchedCves.some(
          (match) => match.method === 'STRICT_CPE_INTERVAL' || match.method === 'PURL_EXACT',
        ),
      });
    }),
  );
  app.get(
    '/api/email-queue',
    asyncRoute(async (_req, res) => {
      const rows = await pool.query(
        `SELECT id, payload->>'recipientEmail' AS "recipientEmail", advisory_id AS "advisoryId",
          payload->>'subject' AS subject, status, attempts,
          CASE WHEN status='REVIEW' THEN NULL ELSE next_attempt END AS "nextAttemptAt",
          created_at AS "createdAt", error, left(payload->>'text', 4000) AS preview,
          payload->'cveIds' AS "cveIds"
         FROM outbox
         WHERE channel='email' AND status IN ('REVIEW','QUEUED','SENDING','FAILED')
         ORDER BY created_at DESC, id DESC LIMIT 1000`,
      );
      res.json(rows.rows);
    }),
  );
  app.get(
    '/api/health',
    asyncRoute(async (_req, res) => {
      const start = performance.now();
      await pool.query('SELECT 1');
      const dbMs = Math.round(performance.now() - start);
      const worker = (await pool.query('SELECT last_run,heartbeat FROM scheduler_state WHERE id=1')).rows[0];
      const backlog = (await pool.query('SELECT status,count(*)::int AS count FROM outbox GROUP BY status'))
        .rows;
      const deliveryQueue = (
        await pool.query(`SELECT
        count(*) FILTER (WHERE status='QUEUED' AND next_attempt<=now())::int AS "dueJobs",
        min(created_at) FILTER (WHERE status='QUEUED' AND next_attempt<=now()) AS "oldestDueCreatedAt",
        min(next_attempt) FILTER (WHERE status='QUEUED' AND next_attempt>now()) AS "nextScheduledAttempt",
        count(*) FILTER (WHERE status='SENDING' AND locked_at<now()-interval '2 minutes')::int AS "expiredLeases"
        FROM outbox WHERE status IN ('QUEUED','SENDING')`)
      ).rows[0];
      const heartbeatAgeSeconds = worker.heartbeat
        ? Math.max(0, Math.floor((Date.now() - new Date(worker.heartbeat).getTime()) / 1000))
        : null;
      const emailConfig =
        (await get<EmailConfiguration>(pool, 'emailConfig', 'main')) || DEFAULT_EMAIL_CONFIG;
      res.json({
        database: 'connected',
        databaseLatencyMs: dbMs,
        uptimeSeconds: Math.floor(process.uptime()),
        heapBytes: process.memoryUsage().heapUsed,
        workerEnabled: config.WORKER_ENABLED === 'true',
        workerHeartbeat: worker.heartbeat,
        workerStatus:
          config.WORKER_ENABLED !== 'true'
            ? 'DISABLED'
            : heartbeatAgeSeconds === null
              ? 'NOT_OBSERVED'
              : heartbeatAgeSeconds > 90
                ? 'STALE'
                : 'HEALTHY',
        heartbeatAgeSeconds,
        deliveryQueue,
        lastScheduledRun: worker.last_run,
        backlog,
        smtpConfigured: !!config.SMTP_HOST && !!config.SMTP_FROM,
        emailProvider: emailConfig.provider,
        emailConfigured: emailIsConfigured(emailConfig, config),
        httpsRequired: config.NODE_ENV === 'production',
        csrfEnforced: true,
        ssrfEnforced: true,
        ntp: 'Host-managed; not measured by this application',
        checkedAt: new Date().toISOString(),
      });
    }),
  );
  app.get(
    '/api/events',
    asyncRoute(async (req, res) => res.json(await readEvents(pool, req.query))),
  );
  app.post(
    '/api/pipeline',
    requireRole('ADMIN', 'OPERATOR'),
    asyncRoute(async (req, res) => {
      const data = z
        .object({
          scopeHours: z.number().int().min(1).max(2880).optional(),
          incrementalFeeds: z.boolean().default(true),
        })
        .parse(req.body);
      res
        .status(202)
        .json(await queueRun(pool, data.scopeHours, req.operator!.username, data.incrementalFeeds));
    }),
  );
  app.post(
    '/api/pipeline/:id/stop',
    requireRole('ADMIN', 'OPERATOR'),
    asyncRoute(async (req, res) => {
      res.json(await stopRun(pool, String(req.params.id), req.operator!.username));
    }),
  );
  app.post(
    '/api/feeds/:id/test',
    requireRole('ADMIN'),
    asyncRoute(async (req, res) => {
      const feed = await get<ThreatFeed>(pool, 'feeds', String(req.params.id));
      if (!feed) throw new HttpError(404, 'Feed not found');
      const start = performance.now();
      const headers: Record<string, string> =
        feed.type === 'RSS_ATOM'
          ? { Accept: 'application/rss+xml, application/atom+xml, application/xml, text/xml' }
          : {};
      let secret: string;
      try {
        secret = decrypt(feed.authSecretKey || '', config.ENCRYPTION_KEY, `feed:${feed.id}`);
      } catch {
        throw new HttpError(
          400,
          'Stored feed credentials could not be decrypted; re-enter the secret or restore the original encryption key',
        );
      }
      if (feed.authType !== 'NONE' && !secret) throw new HttpError(400, 'Feed secret is missing');
      if (feed.authType === 'API_KEY') headers.apiKey = secret;
      if (['BEARER', 'BASIC'].includes(feed.authType))
        headers.Authorization = `${feed.authType === 'BASIC' ? 'Basic' : 'Bearer'} ${feed.authType === 'BASIC' ? Buffer.from(secret).toString('base64') : secret}`;
      let response: ResponseData;
      try {
        const testUrl = new URL(feed.url);
        if (feed.type === 'NVD_API') testUrl.searchParams.set('resultsPerPage', '1');
        const requestOptions =
          feed.type === 'NVD_API'
            ? { headers, timeoutMs: 25000, socketTimeoutMs: 20000, maxResponseBytes: 256 * 1024 }
            : feed.type === 'MITRE_CVE'
              ? { headers, timeoutMs: 120000, socketTimeoutMs: 60000, maxResponseBytes: 64 * 1024 * 1024 }
              : feed.type === 'OPENCVE_API'
                ? {
                    headers,
                    timeoutMs: (feed.requestTimeoutSeconds || 60) * 1000,
                    socketTimeoutMs: Math.min((feed.requestTimeoutSeconds || 60) * 1000, 30000),
                    maxResponseBytes: 4 * 1024 * 1024,
                  }
                : feed.type === 'RSS_ATOM'
                  ? { headers, timeoutMs: 25000, maxResponseBytes: RSS_MAX_BYTES }
                  : { headers };
        response = await request(testUrl.href, requestOptions);
        if (response.status >= 200 && response.status < 300) {
          if (feed.type === 'RSS_ATOM') parseSyndication(response.body, feed.id, 2880);
          else {
            // A successful HTTP status is not proof that the endpoint returned
            // the JSON contract this adapter needs. Reject an HTML error page or
            // truncated body during the test instead of reporting HEALTHY.
            try {
              JSON.parse(response.body);
            } catch {
              throw new Error('Feed returned a non-JSON response body');
            }
          }
        }
        const latency = Math.round(performance.now() - start);
        await transaction(pool, async (db) => {
          const current = await getForUpdate<ThreatFeed>(db, 'feeds', feed.id);
          if (current)
            await put(db, 'feeds', feed.id, {
              ...current,
              healthStatus: response.status >= 200 && response.status < 300 ? 'HEALTHY' : 'DOWN',
              latencyMs: latency,
              errorLog: response.status >= 200 && response.status < 300 ? null : `HTTP ${response.status}`,
            });
          await appendAudit(
            db,
            'Feed connectivity tested',
            `${feed.id}; HTTP ${response.status}`,
            req.operator!.username,
            'FEED',
            'INFO',
            req.ip || '',
          );
        });
        res.json({
          success: response.status >= 200 && response.status < 300,
          latency,
          error: response.status >= 200 && response.status < 300 ? undefined : `HTTP ${response.status}`,
        });
      } catch (e) {
        const message = e instanceof Error ? e.message : 'Connection failed';
        const latency = Math.round(performance.now() - start);
        await transaction(pool, async (db) => {
          const current = await getForUpdate<ThreatFeed>(db, 'feeds', feed.id);
          if (current)
            await put(db, 'feeds', feed.id, {
              ...current,
              healthStatus: 'DOWN',
              latencyMs: latency,
              errorLog: message,
            });
          await appendAudit(
            db,
            'Feed connectivity tested',
            `${feed.id}; ERROR: ${message}`,
            req.operator!.username,
            'FEED',
            'INFO',
            req.ip || '',
          );
        });
        res.json({ success: false, latency, error: message });
      }
    }),
  );
  app.post(
    '/api/test-email',
    requireRole('ADMIN'),
    asyncRoute(async (req, res) => {
      const { email } = z.object({ email: z.email().max(254) }).parse(req.body);
      const id = await transaction(pool, async (db) => {
        const emailConfig =
          (await getForUpdate<EmailConfiguration>(db, 'emailConfig', 'main')) || DEFAULT_EMAIL_CONFIG;
        if (!emailIsConfigured(emailConfig, config))
          throw new HttpError(409, 'Configure an email provider in Settings before sending a test');
        const data = await state(db);
        const testAdvisory: Advisory = {
          id: `${data.settings.advisoryPrefix}TEST`,
          title: 'BA Threat Intel template test',
          severity: 'UNKNOWN',
          cveIds: [],
          findingIds: [],
          createdDate: new Date().toISOString(),
          deliveryStatus: 'PENDING',
          recipientCount: 1,
          executiveSummary: 'Requested template test. This is not a live vulnerability advisory.',
          affectedSystems: ['Example inventory asset'],
          remediationInstructions: 'Preview only; no remediation action is required.',
        };
        const id = await enqueue(
          db,
          'email',
          'test',
          'TEST',
          {
            ...advisoryEmail(testAdvisory, renderAdvisory(data.advisoryTemplate, testAdvisory)),
            recipientEmail: email,
            cveIds: [],
          },
          randomUUID(),
        );
        await appendAudit(
          db,
          'Test email queued',
          `Delivery ${id}`,
          req.operator!.username,
          'EMAIL',
          'INFO',
          req.ip || '',
        );
        return id;
      });
      res
        .status(202)
        .json({ success: true, message: 'Test queued. Check the delivery log for provider acceptance.', id });
    }),
  );
  app.post(
    '/api/retention/run',
    requireRole('ADMIN'),
    asyncRoute(async (req, res) => {
      const result = await runRetention(pool, req.operator!.username, req.ip || '');
      if (!result) throw new HttpError(400, 'Enable the retention policy before running cleanup');
      res.json(result);
    }),
  );
  app.post(
    '/api/retention/preview',
    requireRole('ADMIN'),
    asyncRoute(async (req, res) => {
      const policy = z
        .object({
          enabled: z.boolean(),
          retentionHours: z.number().int().min(1).max(8760),
          maxArchivedRecords: z.number().int().min(1000).max(1000000),
          retentionMode: z.enum(['strict', 'rolling', 'checkpoints']),
        })
        .parse(req.body);
      res.json(await previewRetention(pool, policy));
    }),
  );
  app.post(
    '/api/webhooks/:id/test',
    requireRole('ADMIN'),
    asyncRoute(async (req, res) => {
      const hook = await get<WebhookEndpoint>(pool, 'webhooks', String(req.params.id));
      if (!hook?.enabled) throw new HttpError(400, 'Webhook is missing or disabled');
      await transaction(pool, async (db) => {
        const id = await enqueue(
          db,
          'webhook',
          hook.id,
          'TEST',
          {
            subject: 'BA Threat Intel connection test',
            text: 'Requested BA Threat Intel webhook test',
            cveIds: [],
          },
          randomUUID(),
        );
        await appendAudit(
          db,
          'Test webhook queued',
          `Delivery ${id}`,
          req.operator!.username,
          'WEBHOOK',
          'INFO',
          req.ip || '',
        );
      });
      res.status(202).json({ success: true, statusCode: 202, signature: 'Pending worker delivery' });
    }),
  );
  app.post(
    '/api/email/:id/approve',
    requireRole('ADMIN', 'OPERATOR'),
    asyncRoute(async (req, res) => {
      await transaction(pool, async (db) => {
        const row = await db.query(
          "UPDATE outbox SET status='QUEUED',review_approved=true,next_attempt=now(),error=NULL,updated_at=now() WHERE id=$1 AND channel='email' AND status='REVIEW' RETURNING advisory_id",
          [req.params.id],
        );
        if (!row.rowCount) throw new HttpError(409, 'Only notifications awaiting review can be approved');
        const id = String(req.params.id);
        const log = await getForUpdate<any>(db, 'emailLogs', id);
        if (log)
          await put(db, 'emailLogs', id, {
            ...log,
            status: 'QUEUED',
            nextRetryTime: new Date().toISOString(),
            errorMessage: undefined,
          });
        await appendAudit(
          db,
          'Email notification approved',
          `Delivery ${id}`,
          req.operator!.username,
          'EMAIL',
          'INFO',
          req.ip || '',
        );
        await refreshAdvisoryDeliveryStatus(db, String(row.rows[0].advisory_id));
      });
      res.json({ success: true });
    }),
  );
  app.post(
    '/api/email/:id/reject',
    requireRole('ADMIN', 'OPERATOR'),
    asyncRoute(async (req, res) => {
      await transaction(pool, async (db) => {
        const row = await db.query(
          "UPDATE outbox SET status='REJECTED',error='Rejected during security review',updated_at=now() WHERE id=$1 AND channel='email' AND status='REVIEW' RETURNING advisory_id",
          [req.params.id],
        );
        if (!row.rowCount) throw new HttpError(409, 'Only notifications awaiting review can be rejected');
        const id = String(req.params.id);
        const log = await getForUpdate<any>(db, 'emailLogs', id);
        if (log)
          await put(db, 'emailLogs', id, {
            ...log,
            status: 'CANCELLED',
            nextRetryTime: null,
            errorMessage: 'Rejected during security review',
          });
        await appendAudit(
          db,
          'Email notification rejected',
          `Delivery ${id}`,
          req.operator!.username,
          'EMAIL',
          'WARNING',
          req.ip || '',
        );
        await refreshAdvisoryDeliveryStatus(db, String(row.rows[0].advisory_id));
      });
      res.json({ success: true });
    }),
  );
  app.post(
    '/api/email/:id/retry',
    requireRole('ADMIN', 'OPERATOR'),
    asyncRoute(async (req, res) => {
      await transaction(pool, async (db) => {
        const row = await db.query(
          "UPDATE outbox SET status='QUEUED',attempts=0,next_attempt=now(),error=NULL WHERE id=$1 AND channel='email' AND status='FAILED' RETURNING id",
          [req.params.id],
        );
        if (!row.rowCount) throw new HttpError(409, 'Only failed deliveries may be retried');
        const log = await getForUpdate<any>(db, 'emailLogs', String(req.params.id));
        if (log)
          await put(db, 'emailLogs', String(req.params.id), {
            ...log,
            status: 'QUEUED',
            attemptCount: 0,
            nextRetryTime: new Date().toISOString(),
            errorMessage: undefined,
          });
        await appendAudit(
          db,
          'Delivery retry queued',
          `Delivery ${req.params.id}`,
          req.operator!.username,
          'EMAIL',
          'INFO',
          req.ip || '',
        );
      });
      res.json({ success: true });
    }),
  );
  app.delete(
    '/api/email/:id',
    requireRole('ADMIN', 'OPERATOR'),
    asyncRoute(async (req, res) => {
      const id = String(req.params.id);
      await transaction(pool, async (db) => {
        const deleted = await db.query(
          "DELETE FROM outbox WHERE id=$1 AND channel='email' AND status IN ('QUEUED','FAILED') RETURNING id",
          [id],
        );
        if (!deleted.rowCount)
          throw new HttpError(409, 'Only queued or failed email deliveries can be deleted');
        const log = await getForUpdate<any>(db, 'emailLogs', id);
        if (log)
          await put(db, 'emailLogs', id, {
            ...log,
            status: 'CANCELLED',
            nextRetryTime: null,
            errorMessage: 'Removed from the delivery queue by an operator',
          });
        await appendAudit(
          db,
          'Email delivery deleted from queue',
          `Delivery ${id}`,
          req.operator!.username,
          'EMAIL',
          'WARNING',
          req.ip || '',
        );
      });
      res.json({ success: true });
    }),
  );
  app.post(
    '/api/resend',
    requireRole('ADMIN', 'OPERATOR'),
    asyncRoute(async (req, res) => {
      const data = z
        .object({ cveId: z.string(), reason: z.string().trim().min(5).max(1000) })
        .parse(req.body);
      await transaction(pool, async (db) => {
        const snapshot = await state(db),
          prior = snapshot.alertedCves.find((c) => c.cveId === data.cveId),
          advisory = snapshot.advisories.find((a) => a.id === prior?.advisoryId);
        if (!advisory) throw new HttpError(404, 'No advisory found');
        await queueAdvisory(
          db,
          advisory,
          snapshot.findings.filter((f) => advisory.findingIds.includes(f.id)),
          renderAdvisory(snapshot.advisoryTemplate, advisory),
          randomUUID(),
        );
        await appendAudit(
          db,
          'Advisory resend queued',
          `${advisory.id}: ${data.reason}`,
          req.operator!.username,
          'EMAIL',
        );
      });
      res.status(202).json({ success: true });
    }),
  );
  app.post(
    '/api/commands',
    requireRole('ADMIN', 'OPERATOR'),
    asyncRoute(async (req, res) => {
      const command = z
        .object({
          action: z.string().max(80),
          id: z.string().max(150).optional(),
          data: z.unknown().optional(),
        })
        .parse(req.body);
      const { action, id, data } = command,
        actor = req.operator!.username;
      const adminActions = [
        'feed.save',
        'feed.import',
        'feed.delete',
        'feed.toggle',
        'recipient.save',
        'recipient.delete',
        'recipient.toggle',
        'webhook.save',
        'webhook.delete',
        'webhook.toggle',
        'settings.save',
        'template.save',
        'email.configure',
        'alias.save',
        'alias.delete',
        'alias.promote',
        'alias.revoke',
      ];
      if (adminActions.includes(action) && req.operator!.role !== 'ADMIN')
        throw new HttpError(403, 'Administrator role required');
      // Resolve URLs outside the database transaction. They are validated again at connection time.
      if (['feed.save', 'webhook.save'].includes(action)) {
        const url = (data as any)?.url;
        if (typeof url !== 'string') throw new HttpError(400, 'URL required');
        try {
          await resolvePublic(
            new URL(url),
            config.EGRESS_ALLOWED_HOSTS.split(',').map((s) => s.trim().toLowerCase()),
          );
        } catch {
          throw new HttpError(
            400,
            'Endpoint must resolve to a public HTTPS address on the configured host allowlist',
          );
        }
      }
      const result = await transaction(pool, (db) =>
        applyCommand(db, config, { action, id, data, actor, ipAddress: req.ip || '' }),
      );
      res.json(result);
    }),
  );
  app.use('/api', (_req, _res, next) => next(new HttpError(404, 'API route not found')));
  app.use(
    express.static(path.resolve('dist'), {
      index: false,
      maxAge: '1h',
      setHeaders: (res, file) => {
        if (file.endsWith('.html')) res.setHeader('Cache-Control', 'no-cache');
      },
    }),
  );
  app.get('*', (_req, res) => res.sendFile(path.resolve('dist/index.html')));
  app.use((error: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    if (error instanceof WorkCapacityError) {
      res.setHeader('Retry-After', '2');
      return res.status(503).json({ error: 'Authentication capacity is busy; retry shortly' });
    }
    if (error instanceof z.ZodError)
      return res.status(400).json({
        error: 'Validation failed',
        details: error.issues.map((i) => ({ path: i.path, message: i.message })),
      });
    if (error instanceof HttpError) return res.status(error.status).json({ error: error.message });
    if (error?.code === '23505') return res.status(409).json({ error: 'Record already exists' });
    if (error?.type === 'entity.too.large') return res.status(413).json({ error: 'Request body too large' });
    if (error instanceof SyntaxError) return res.status(400).json({ error: 'Invalid JSON' });
    const reference = randomUUID();
    void writeEvent(pool, {
      category: 'ISSUE',
      level: 'ERROR',
      code: 'http.request_failed',
      message: 'An API request failed',
      context: { reference, method: _req.method, path: _req.path, errorType: error?.name || 'Error' },
    }).catch(() => {});
    console.error(
      JSON.stringify({ level: 'error', reference, type: error?.name || 'Error', code: error?.code }),
    );
    res.status(500).json({ error: 'Server operation failed', reference });
  });
  return app;
}
