import express from 'express';
import helmet from 'helmet';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import type pg from 'pg';
import type { Config } from './config';
import { asyncRoute, requireAuth, requireRole, loginHandler, cookieName, createUser } from './auth';
import { transaction, state, get, list, put, remove, appendAudit } from './db';
import {
  feedSchema,
  assetSchema,
  recipientSchema,
  webhookSchema,
  cveSchema,
  settingsSchema,
  templateSchema,
  HttpError,
} from './validation';
import { encrypt, randomToken, checkPassword, passwordHash, decrypt } from './secrets';
import { createRequester, resolvePublic } from './network';
import type { Requester } from './network';
import { queueRun, renderAdvisory } from './pipeline';
import { enqueue, queueAdvisory } from './delivery';
import { DEFAULT_SETTINGS } from '../shared/state';
import type { AppState } from '../shared/state';
import type {
  AppSettings,
  ThreatFeed,
  WebhookEndpoint,
  Finding,
  Advisory,
  TemplateCustomization,
} from '../src/types';
import { compileCustomizedTemplate, DEFAULT_TEMPLATE_CUSTOMIZATION } from '../src/utils/templateCompiler';
function publicState(data: AppState): AppState {
  return {
    ...data,
    feeds: data.feeds.map((f) => ({ ...f, authSecretKey: undefined })),
    webhooks: data.webhooks.map((w) => ({ ...w, url: '[configured on server]', secretToken: '' })),
    settings: {
      ...data.settings,
      webhookSigningSecret: '',
      mailgunConfig: { ...data.settings.mailgunConfig, apiKey: '' },
    },
  };
}
export function createApp(pool: pg.Pool, config: Config, request: Requester = createRequester(config)) {
  const app = express();
  app.disable('x-powered-by');
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
  app.get(
    '/ready',
    asyncRoute(async (_req, res) => {
      await pool.query('SELECT 1');
      res.json({ status: 'ready' });
    }),
  );
  app.post('/api/login', loginHandler(pool, config));
  app.use('/api', requireAuth(pool, config));
  app.get('/api/session', (req, res) =>
    res.json({
      username: req.operator!.username,
      role: req.operator!.role,
      csrfToken: req.operator!.csrf,
      expiresAt: req.operator!.expiresAt,
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
      res.clearCookie(cookieName(config), { path: '/' });
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
        await appendAudit(db, 'Password changed', 'All sessions revoked', req.operator!.username);
      });
      res.clearCookie(cookieName(config), { path: '/' });
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
        );
      });
      res.json({ success: true });
    }),
  );
  app.get(
    '/api/state',
    asyncRoute(async (_req, res) => res.json(publicState(await state(pool)))),
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
      res.json({
        database: 'connected',
        databaseLatencyMs: dbMs,
        uptimeSeconds: Math.floor(process.uptime()),
        heapBytes: process.memoryUsage().heapUsed,
        workerEnabled: config.WORKER_ENABLED === 'true',
        workerHeartbeat: worker.heartbeat,
        lastScheduledRun: worker.last_run,
        backlog,
        smtpConfigured: !!config.SMTP_HOST && !!config.SMTP_FROM,
        httpsRequired: config.NODE_ENV === 'production',
        csrfEnforced: true,
        ssrfEnforced: true,
        ntp: 'Host-managed; not measured by this application',
        checkedAt: new Date().toISOString(),
      });
    }),
  );
  app.post(
    '/api/pipeline',
    requireRole('ADMIN', 'OPERATOR'),
    asyncRoute(async (req, res) => {
      const data = z.object({ scopeHours: z.number().int().min(1).max(2880).optional() }).parse(req.body);
      res.status(202).json(await queueRun(pool, data.scopeHours, req.operator!.username));
    }),
  );
  app.post(
    '/api/feeds/:id/test',
    requireRole('ADMIN'),
    asyncRoute(async (req, res) => {
      const feed = await get<ThreatFeed>(pool, 'feeds', String(req.params.id));
      if (!feed) throw new HttpError(404, 'Feed not found');
      const start = performance.now();
      const headers: Record<string, string> = {};
      const secret = decrypt(feed.authSecretKey || '', config.ENCRYPTION_KEY, `feed:${feed.id}`);
      if (feed.authType !== 'NONE' && !secret) throw new HttpError(400, 'Feed secret is missing');
      if (feed.authType === 'API_KEY') headers.apiKey = secret;
      if (['BEARER', 'BASIC'].includes(feed.authType))
        headers.Authorization = `${feed.authType === 'BASIC' ? 'Basic' : 'Bearer'} ${feed.authType === 'BASIC' ? Buffer.from(secret).toString('base64') : secret}`;
      const response = await request(feed.url, { headers });
      const success = response.status >= 200 && response.status < 300,
        latency = Math.round(performance.now() - start);
      await transaction(pool, async (db) => {
        const current = await get<ThreatFeed>(db, 'feeds', feed.id);
        if (current)
          await put(db, 'feeds', feed.id, {
            ...current,
            healthStatus: success ? 'HEALTHY' : 'DOWN',
            latencyMs: latency,
            errorLog: success ? null : `HTTP ${response.status}`,
          });
        await appendAudit(
          db,
          'Feed connectivity tested',
          `${feed.id}; HTTP ${response.status}`,
          req.operator!.username,
          'FEED',
        );
      });
      res.json({ success, latency, error: success ? undefined : `HTTP ${response.status}` });
    }),
  );
  app.post(
    '/api/test-email',
    requireRole('ADMIN'),
    asyncRoute(async (req, res) => {
      const { email } = z.object({ email: z.email().max(254) }).parse(req.body);
      if (!config.SMTP_HOST || !config.SMTP_FROM)
        throw new HttpError(409, 'Configure SMTP before sending a test');
      const id = await transaction(pool, async (db) => {
        const data = await state(db);
        const id = await enqueue(
          db,
          'email',
          'test',
          'TEST',
          {
            subject: 'VulnStream template test',
            text: 'Requested template test',
            html: data.advisoryTemplate,
            recipientEmail: email,
            cveIds: [],
          },
          randomUUID(),
        );
        await appendAudit(db, 'Test email queued', `Delivery ${id}`, req.operator!.username, 'EMAIL');
        return id;
      });
      res
        .status(202)
        .json({ success: true, message: 'Test queued. Check the delivery log for provider acceptance.', id });
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
          { subject: 'VulnStream connection test', text: 'Requested VulnStream webhook test', cveIds: [] },
          randomUUID(),
        );
        await appendAudit(db, 'Test webhook queued', `Delivery ${id}`, req.operator!.username, 'WEBHOOK');
      });
      res.status(202).json({ success: true, statusCode: 202, signature: 'Pending worker delivery' });
    }),
  );
  app.post(
    '/api/email/:id/retry',
    requireRole('ADMIN', 'OPERATOR'),
    asyncRoute(async (req, res) => {
      await transaction(pool, async (db) => {
        const row = await db.query(
          "UPDATE outbox SET status='QUEUED',attempts=0,next_attempt=now(),error=NULL WHERE id=$1 AND status='FAILED' RETURNING id",
          [req.params.id],
        );
        if (!row.rowCount) throw new HttpError(409, 'Only failed deliveries may be retried');
        await appendAudit(
          db,
          'Delivery retry queued',
          `Delivery ${req.params.id}`,
          req.operator!.username,
          'EMAIL',
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
      const adminActions = ['feed', 'recipient', 'webhook', 'settings', 'template'];
      if (adminActions.some((prefix) => action.startsWith(prefix)) && req.operator!.role !== 'ADMIN')
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
      const result = await transaction(pool, async (db) => {
        const now = new Date().toISOString(),
          newId = id || randomUUID();
        const checkExisting = async (kind: string) => {
          const previous = await get<any>(db, kind, newId);
          if (id && !previous) throw new HttpError(404, 'Record not found');
          return previous;
        };
        if (action === 'feed.save') {
          const input = feedSchema.parse(data),
            old = await checkExisting('feeds');
          await put(db, 'feeds', newId, {
            ...old,
            ...input,
            id: newId,
            authSecretKey: input.authSecretKey
              ? encrypt(input.authSecretKey, config.ENCRYPTION_KEY, `feed:${newId}`)
              : (old?.url === input.url && old?.authType === input.authType ? old?.authSecretKey : '') || '',
            healthStatus: 'UNTESTED',
            lastSync: old?.lastSync || null,
            latencyMs: 0,
            itemCountLastRun: old?.itemCountLastRun || 0,
            ssrfValidated: false,
          });
        } else if (action === 'asset.save') {
          const input = assetSchema.parse(data),
            old = await checkExisting('watchlist');
          await put(db, 'watchlist', newId, { ...input, id: newId, createdAt: old?.createdAt || now });
        } else if (action === 'asset.import') {
          const input = z.array(assetSchema).min(1).max(1000).parse(data);
          for (const item of input) {
            const assetId = randomUUID();
            await put(db, 'watchlist', assetId, { ...item, id: assetId, createdAt: now });
          }
          await appendAudit(db, 'Assets imported', `${input.length} assets`, actor, 'WATCHLIST');
          return { imported: input.length, errors: [] };
        } else if (action === 'recipient.save') {
          const input = recipientSchema.parse(data);
          await checkExisting('recipients');
          const exists = (await list<any>(db, 'recipients')).some(
            (r) => r.email === input.email && r.id !== id,
          );
          if (exists) throw new HttpError(409, 'Recipient already exists');
          await put(db, 'recipients', newId, { ...input, id: newId, deliverySuccessRate: 0 });
        } else if (action === 'webhook.save') {
          const input = webhookSchema.parse(data);
          await checkExisting('webhooks');
          await put(db, 'webhooks', newId, {
            ...input,
            id: newId,
            url: encrypt(input.url, config.ENCRYPTION_KEY, `webhook-url:${newId}`),
            secretToken: encrypt(
              input.secretToken || randomToken(),
              config.ENCRYPTION_KEY,
              `webhook:${newId}`,
            ),
            deliveryCount: 0,
          });
        } else if (action === 'cve.save') {
          const input = cveSchema.parse(data);
          await put(db, 'cveData', input.cveId, {
            ...input,
            vex: undefined,
            sourceFeeds: ['operator-import'],
          });
        } else if (action === 'settings.save') {
          const old = (await get<AppSettings>(db, 'settings', 'main')) || DEFAULT_SETTINGS;
          await put(
            db,
            'settings',
            'main',
            settingsSchema.parse({ ...old, ...z.record(z.string(), z.unknown()).parse(data) }),
          );
        } else if (action === 'template.save') {
          const input = z.object({ templateCustomization: templateSchema }).parse(data);
          await put(db, 'template', 'main', {
            templateCustomization: input.templateCustomization,
            advisoryTemplate: compileCustomizedTemplate(input.templateCustomization),
          });
        } else if (action === 'finding.status') {
          const input = z
            .object({
              status: z.enum([
                'MONITORED',
                'REMEDIATION_AVAILABLE',
                'PATCH_APPLIED',
                'RESOLVED',
                'FALSE_POSITIVE',
              ]),
              note: z.string().max(2000).optional(),
            })
            .parse(data);
          const f = await get<Finding>(db, 'findings', newId);
          if (!f) throw new HttpError(404, 'Finding not found');
          await put(db, 'findings', newId, {
            ...f,
            status: input.status,
            timeline: [
              ...f.timeline,
              { timestamp: now, action: input.status, system: actor, details: input.note || '' },
            ],
          });
        } else if (/^(feed|asset|recipient|webhook)\.(delete|toggle)$/.test(action)) {
          const [entity, operation] = action.split('.'),
            kind = (
              { feed: 'feeds', asset: 'watchlist', recipient: 'recipients', webhook: 'webhooks' } as Record<
                string,
                string
              >
            )[entity];
          if (!id) throw new HttpError(400, 'Record ID required');
          const old = await get<any>(db, kind, id);
          if (!old) throw new HttpError(404, 'Record not found');
          if (operation === 'delete') await remove(db, kind, id);
          else
            await put(db, kind, id, {
              ...old,
              [entity === 'asset' ? 'active' : 'enabled']: !old[entity === 'asset' ? 'active' : 'enabled'],
            });
        } else throw new HttpError(400, 'Unknown command');
        await appendAudit(
          db,
          action,
          `Record ${id || newId}`,
          actor,
          action.startsWith('asset') ? 'WATCHLIST' : 'SECURITY',
        );
        return { success: true };
      });
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
    console.error(
      JSON.stringify({ level: 'error', reference, type: error?.name || 'Error', code: error?.code }),
    );
    res.status(500).json({ error: 'Server operation failed', reference });
  });
  return app;
}
