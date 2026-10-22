import { writeEvent } from './events';
import { advisoryEmail } from './advisoryEmail';
import type pg from 'pg';
import { runVulnerabilityPipeline } from '../src/engine/pipelineEngine';
import { DEFAULT_SETTINGS, DEFAULT_EMAIL_CONFIG } from '../shared/state';
import type { WatchListItem, NormalizedCVE } from '../src/types';
import { randomUUID, createHmac, createHash } from 'node:crypto';
import { stableJson } from '../src/utils/deduplicator';
import nodemailer from 'nodemailer';
import type { Config } from './config';
import { transaction, get, list, put, appendAudit } from './db';
import type { Db } from './db';
import { createRequester, type Requester } from './network';
import { EMAIL_PROVIDER_LABELS, EmailProviderError, emailIsConfigured, sendProviderEmail } from './emailProviders';
import { decrypt } from './secrets';
import { isSmtpEmailProvider } from '../src/types';
import type {
  Advisory,
  Finding,
  EmailRecipient,
  WebhookEndpoint,
  EmailDeliveryLog,
  WebhookDeliveryLog,
  AlertedCVE,
  EmailConfiguration,
} from '../src/types';
export interface Job {
  id: string;
  dedupe_key: string;
  channel: 'email' | 'webhook';
  target_id: string;
  advisory_id: string;
  payload: {
    subject: string;
    text: string;
    html?: string;
    recipientEmail?: string;
    cveIds: string[];
    cveRevisions?: Record<string, string>;
    findingRevisions?: Record<string, string>;
  };
  attempts: number;
  lock_token: string;
  review_approved?: boolean;
}
export type MailSender = (job: Job) => Promise<string | { id: string; provider: EmailDeliveryLog['provider'] }>;
const revision = (cve: NormalizedCVE) => createHash('sha256').update(stableJson(cve)).digest('hex');
const findingRevision = (finding: Finding) =>
  createHash('sha256')
    .update(
      stableJson({
        cveId: finding.cveId,
        assetId: finding.matchedAssetId,
        assetName: finding.matchedAssetName,
      }),
    )
    .digest('hex');
export function recipientAllows(recipient: EmailRecipient, finding: Finding): boolean {
  return (
    recipient.subscriptionTier === 'ALL_SEVERITIES' ||
    (recipient.subscriptionTier === 'CRITICAL_HIGH_ONLY' &&
      ['CRITICAL', 'HIGH'].includes(finding.cve.cvss.severity)) ||
    (recipient.subscriptionTier === 'CISA_KEV_ONLY' && finding.cve.cisaKev.isKev)
  );
}
export function webhookAllows(hook: WebhookEndpoint, finding: Finding): boolean {
  return (
    hook.events.includes('ALL') ||
    (hook.events.includes('CRITICAL') && finding.cve.cvss.severity === 'CRITICAL') ||
    (hook.events.includes('CISA_KEV') && finding.cve.cisaKev.isKev)
  );
}
export function createMailSender(config: Config, db?: Db, request: Requester = createRequester(config)): MailSender {
  const transporter = config.SMTP_HOST
    ? nodemailer.createTransport({
        host: config.SMTP_HOST,
        port: config.SMTP_PORT,
        secure: config.SMTP_PORT === 465,
        requireTLS: true,
        auth: config.SMTP_USER ? { user: config.SMTP_USER, pass: config.SMTP_PASSWORD } : undefined,
        connectionTimeout: 10000,
        greetingTimeout: 10000,
        socketTimeout: 20000,
        disableFileAccess: true,
        disableUrlAccess: true,
      })
    : null;
  return async (job) => {
    const saved = (db && await get<EmailConfiguration>(db, 'emailConfig', 'main')) || DEFAULT_EMAIL_CONFIG;
    if (!emailIsConfigured(saved, config)) throw new Error('Email provider is not configured');
    if (!isSmtpEmailProvider(saved.provider)) {
      const token = decrypt(saved.apiKey, config.ENCRYPTION_KEY, `email-provider:${saved.provider}`);
      if (!token) throw new Error('Email provider token is missing');
      const provider = EMAIL_PROVIDER_LABELS[saved.provider];
      try {
        const id = await sendProviderEmail(saved, token, job, request);
        return { id, provider };
      } catch (error) {
        if (error instanceof EmailProviderError) { error.provider = provider; throw error; }
        throw new EmailProviderError(`${provider} connection failed`, 502, 0, provider);
      }
    }
    const fromEmail = saved.fromEmail || config.SMTP_FROM;
    const smtpPassword = saved.provider === 'SMTP'
      ? config.SMTP_PASSWORD
      : decrypt(saved.smtpPassword, config.ENCRYPTION_KEY, `email-smtp:${saved.provider}`);
    const smtpTransport = saved.provider === 'SMTP'
      ? transporter
      : nodemailer.createTransport({
          host: saved.smtpHost,
          port: saved.smtpPort,
          secure: saved.smtpSecurity === 'IMPLICIT_TLS',
          requireTLS: saved.smtpSecurity === 'STARTTLS',
          auth: saved.smtpUsername ? { user: saved.smtpUsername, pass: smtpPassword } : undefined,
          connectionTimeout: 10000,
          greetingTimeout: 10000,
          socketTimeout: 20000,
          dnsTimeout: 5000,
          disableFileAccess: true,
          disableUrlAccess: true,
        });
    if (!smtpTransport || !fromEmail) throw new Error('SMTP is not configured');
    const result = await smtpTransport.sendMail({
      from: { address: fromEmail, name: saved.fromName },
      to: job.payload.recipientEmail,
      subject: job.payload.subject,
      text: job.payload.text,
      html: job.payload.html,
      messageId: `<${job.id}@${fromEmail.split('@').pop()}>`,
      headers: { 'X-VulnStream-Delivery-ID': job.id },
    });
    if (
      !result.accepted?.some(
        (address) => String(address).toLowerCase() === job.payload.recipientEmail?.toLowerCase(),
      )
    )
      throw new Error('SMTP did not accept the recipient');
    return { id: result.messageId, provider: 'SMTP_Relay' };
  };
}
export async function enqueue(
  db: Db,
  channel: Job['channel'],
  targetId: string,
  advisoryId: string,
  payload: Job['payload'],
  dedupe: string,
  initialStatus: 'QUEUED' | 'REVIEW' = 'QUEUED',
) {
  const id = randomUUID();
  const inserted = await db.query(
    'INSERT INTO outbox(id,dedupe_key,channel,target_id,advisory_id,payload,status) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(dedupe_key) DO NOTHING RETURNING id',
    [id, dedupe, channel, targetId, advisoryId, JSON.stringify(payload), channel === 'email' ? initialStatus : 'QUEUED'],
  );
  if (!inserted.rowCount) return null;
  if (channel === 'email') {
    const configuration = (await get<EmailConfiguration>(db, 'emailConfig', 'main')) || DEFAULT_EMAIL_CONFIG;
    await put(db, 'emailLogs', id, {
      id,
      recipientEmail: payload.recipientEmail || '',
      advisoryId,
      subject: payload.subject,
      provider: EMAIL_PROVIDER_LABELS[configuration.provider],
      status: initialStatus === 'REVIEW' ? 'REVIEW_REQUIRED' : 'QUEUED',
      attemptCount: 0,
      retrySchedule: ['1m', '2m', '4m', '8m', '16m'],
      nextRetryTime: initialStatus === 'REVIEW' ? null : new Date().toISOString(),
      sentAt: '',
    } satisfies EmailDeliveryLog);
  } else {
    const hook = await get<WebhookEndpoint>(db, 'webhooks', targetId);
    await put(db, 'webhookLogs', id, {
      id,
      endpointId: targetId,
      endpointName: hook?.name || '',
      provider: hook?.provider || 'GENERIC_HMAC',
      advisoryId,
      cveId: payload.cveIds.join(', '),
      status: 'QUEUED',
      statusCode: 0,
      hmacSignature: '',
      sentAt: '',
    } satisfies WebhookDeliveryLog);
  }
  return id;
}
export async function queueAdvisory(
  db: Db,
  advisory: Advisory,
  findings: Finding[],
  html?: string,
  dispatchKey = advisory.id,
) {
  const recipients = await list<EmailRecipient>(db, 'recipients'),
    hooks = await list<WebhookEndpoint>(db, 'webhooks');
  const selected = recipients.filter(
    (r) => r.enabled && findings.length > 0 && findings.every((finding) => recipientAllows(r, finding)),
  );
  const payload = {
    ...advisoryEmail(advisory, html),
    cveIds: advisory.cveIds,
    findingRevisions: Object.fromEntries(findings.map((finding) => [finding.id, findingRevision(finding)])),
    cveRevisions: Object.fromEntries(findings.map((finding) => [finding.cveId, revision(finding.cve)])),
  };
  let count = 0;
  for (const recipient of selected)
    if (
      await enqueue(
        db,
        'email',
        recipient.id,
        advisory.id,
        { ...payload, recipientEmail: recipient.email },
        `${dispatchKey}:email:${recipient.id}`,
        recipient.deliveryGroup === 'EVERYONE' ? 'REVIEW' : 'QUEUED',
      )
    )
      count++;
  for (const hook of hooks.filter(
    (h) => h.enabled && findings.length > 0 && findings.every((finding) => webhookAllows(h, finding)),
  ))
    if (await enqueue(db, 'webhook', hook.id, advisory.id, payload, `${dispatchKey}:webhook:${hook.id}`))
      count++;
  if (!count) return 0;
  advisory.recipientCount = selected.length;
  advisory.deliveryStatus = count ? 'PENDING' : 'DRAFT';
  await put(db, 'advisories', advisory.id, advisory);
  return count;
}
export async function deliverNext(
  pool: pg.Pool,
  config: Config,
  request: Requester,
  sendMail: MailSender,
): Promise<boolean> {
  const job = await transaction(pool, async (db) => {
    const claimed = await db.query(
      `WITH candidate AS (SELECT id FROM outbox WHERE (status='QUEUED' AND next_attempt<=now()) OR (status='SENDING' AND locked_at<now()-interval '2 minutes') ORDER BY next_attempt FOR UPDATE SKIP LOCKED LIMIT 1) UPDATE outbox SET status='SENDING',locked_at=now(),lock_token=$1,attempts=attempts+1,updated_at=now() WHERE id IN (SELECT id FROM candidate) RETURNING *`,
      [randomUUID()],
    );
    return claimed.rows[0] as Job | undefined;
  });
  if (!job) return false;
  let providerId = '',
    statusCode = 0,
    signature = '',
    error = '',
    permanent = false,
    retryNotBefore = 0;
  let emailProvider: EmailDeliveryLog['provider'] | undefined,
    routeToReview = false;
  try {
    if (job.attempts > 6) {
      permanent = true;
      throw new Error('Delivery retry budget exhausted after worker recovery');
    }
    const advisory = await get<Advisory>(pool, 'advisories', job.advisory_id);
    const currentFindings: Finding[] = [];
    if (!advisory && job.advisory_id !== 'TEST') {
      permanent = true;
      throw new Error('Queued advisory no longer exists');
    }
    if (advisory && advisory.cveIds.some((id) => !job.payload.cveRevisions?.[id])) {
      permanent = true;
      throw new Error(
        'Advisory revision is no longer applicable; rebuild legacy queued payload from current intelligence',
      );
    }
    if (advisory) {
      const invalid: string[] = [];
      for (const id of advisory.findingIds) {
        const finding = await get<Finding>(pool, 'findings', id);
        const [asset, cve, withdrawal] = finding
          ? await Promise.all([
              get<WatchListItem>(pool, 'watchlist', finding.matchedAssetId),
              get<NormalizedCVE>(pool, 'cveData', finding.cveId),
              get<{ modifiedDate: string }>(pool, 'cveWithdrawals', finding.cveId),
            ])
          : [undefined, undefined, undefined];
        const match =
          asset && cve
            ? runVulnerabilityPipeline([], [cve], [asset], [], [], { ...DEFAULT_SETTINGS, scopeHours: 0 })
                .newFindings[0]
            : undefined;
        if (match) currentFindings.push(match);
        if (
          !finding ||
          (match && job.payload.findingRevisions?.[id] !== findingRevision(match)) ||
          (cve && withdrawal && Date.parse(cve.modifiedDate) <= Date.parse(withdrawal.modifiedDate)) ||
          (cve &&
            job.payload.cveRevisions?.[cve.cveId] &&
            job.payload.cveRevisions[cve.cveId] !== revision(cve)) ||
          ['RESOLVED', 'FALSE_POSITIVE', 'PATCH_APPLIED'].includes(finding.status) ||
          match?.notificationStatus !== 'QUEUED_FOR_DISPATCH'
        ) {
          invalid.push(id);
        }
      }
      // The queued payload contains the complete advisory. Sending it after any
      // finding becomes stale would disclose or act on invalidated inventory.
      // Fail the bundle so the next pipeline can rebuild it from current matches.
      if (invalid.length) {
        permanent = true;
        throw new Error('Some advisory findings are no longer applicable; rebuild from current inventory');
      }
    }
    if (job.channel === 'email') {
      if (job.target_id !== 'test') {
        const rec = await get<EmailRecipient>(pool, 'recipients', job.target_id);
        if (!rec?.enabled || rec.email !== job.payload.recipientEmail) {
          permanent = true;
          throw new Error('Recipient removed, changed, or disabled');
        }
        if (advisory && !currentFindings.every((finding) => recipientAllows(rec, finding))) {
          permanent = true;
          throw new Error('Recipient subscription no longer permits all advisory findings');
        }
        if (rec.deliveryGroup === 'EVERYONE' && !job.review_approved) {
          routeToReview = true;
          throw new Error('Recipient now requires security review');
        }
      }
      const result = await sendMail(job);
      providerId = typeof result === 'string' ? result : result.id;
      if (typeof result !== 'string') emailProvider = result.provider;
    } else {
      const hook = await get<WebhookEndpoint>(pool, 'webhooks', job.target_id);
      if (!hook?.enabled) {
        permanent = true;
        throw new Error('Webhook removed or disabled');
      }
      if (advisory && !currentFindings.every((finding) => webhookAllows(hook, finding))) {
        permanent = true;
        throw new Error('Webhook event subscription no longer permits all advisory findings');
      }
      const url = decrypt(hook.url, config.ENCRYPTION_KEY, `webhook-url:${hook.id}`),
        secret = decrypt(hook.secretToken, config.ENCRYPTION_KEY, `webhook:${hook.id}`);
      const body = JSON.stringify(
        hook.provider === 'GENERIC_HMAC'
          ? { id: job.id, advisoryId: job.advisory_id, ...job.payload }
          : { text: job.payload.text },
      );
      const timestamp = Math.floor(Date.now() / 1000).toString();
      signature = 'sha256=' + createHmac('sha256', secret).update(`${timestamp}.${body}`).digest('hex');
      const response = await request(url, {
        method: 'POST',
        body,
        headers: {
          'content-type': 'application/json',
          'x-vulnstream-signature': signature,
          'x-vulnstream-timestamp': timestamp,
          'idempotency-key': job.id,
        },
        timeoutMs: 25000,
        socketTimeoutMs: 15000,
      });
      statusCode = response.status;
      if (statusCode < 200 || statusCode >= 300) {
        const rawDelay = response.headers['retry-after'];
        const delay = (Array.isArray(rawDelay) ? rawDelay[0] : rawDelay)?.trim();
        if (delay) {
          const timestamp = /^\d+$/.test(delay)
            ? Date.now() + Number(delay) * 1000
            : /[a-z]/i.test(delay)
              ? Date.parse(delay)
              : NaN;
          if (timestamp > Date.now()) {
            if (!Number.isFinite(timestamp) || timestamp > 8640000000000000) {
              permanent = true;
              throw new Error(
                'Webhook Retry-After exceeds supported scheduling range; operator review required',
              );
            }
            retryNotBefore = timestamp;
          }
        }
        permanent = statusCode >= 400 && statusCode < 500 && ![408, 429].includes(statusCode);
        throw new Error(`Webhook HTTP ${statusCode}`);
      }
      providerId = String(statusCode);
    }
  } catch (e) {
    error = e instanceof Error ? e.message : 'Delivery failed';
    if (e instanceof EmailProviderError) {
      permanent = e.status >= 400 && e.status < 500 && ![408, 429].includes(e.status);
      retryNotBefore = e.retryAt;
      emailProvider = e.provider;
    }
  }
  await transaction(pool, async (db) => {
    const current = await db.query('SELECT status,lock_token FROM outbox WHERE id=$1 FOR UPDATE', [job.id]);
    if (current.rows[0]?.lock_token !== job.lock_token) return;
    const failed = !!error && !routeToReview && (permanent || job.attempts >= 6),
      next = new Date(
        Math.max(retryNotBefore, Date.now() + Math.min(3600000, 60000 * 2 ** (job.attempts - 1))),
      );
    await db.query(
      'UPDATE outbox SET status=$2,next_attempt=$3,error=$4,provider_id=$5,locked_at=NULL,lock_token=NULL,updated_at=now() WHERE id=$1',
      [job.id, routeToReview ? 'REVIEW' : error ? (failed ? 'FAILED' : 'QUEUED') : 'ACCEPTED', next, routeToReview ? null : error || null, providerId || null],
    );
    if (job.channel === 'email') {
      const log = await get<EmailDeliveryLog>(db, 'emailLogs', job.id);
      if (log)
        await put(db, 'emailLogs', job.id, {
          ...log,
          provider: emailProvider || log.provider,
          status: routeToReview ? 'REVIEW_REQUIRED' : error ? (failed ? 'FAILED' : 'RETRYING') : 'ACCEPTED',
          attemptCount: job.attempts,
          errorMessage: routeToReview ? undefined : error || undefined,
          nextRetryTime: routeToReview ? null : error && !failed ? next.toISOString() : null,
          sentAt: error ? '' : new Date().toISOString(),
        });
    } else {
      const log = await get<WebhookDeliveryLog>(db, 'webhookLogs', job.id);
      if (log)
        await put(db, 'webhookLogs', job.id, {
          ...log,
          status: error ? (failed ? 'FAILED' : 'QUEUED') : 'SUCCESS',
          statusCode,
          hmacSignature: signature,
          sentAt: error ? '' : new Date().toISOString(),
        });
      if (!error) {
        const hook = await get<WebhookEndpoint>(db, 'webhooks', job.target_id);
        if (hook) await put(db, 'webhooks', hook.id, { ...hook, deliveryCount: hook.deliveryCount + 1 });
      }
    }
    if (job.channel === 'email' && job.target_id !== 'test') {
      const recipient = await get<EmailRecipient>(db, 'recipients', job.target_id);
      if (recipient) {
        const counts = (
          await db.query(
            "SELECT count(*) FILTER (WHERE status='ACCEPTED')::int AS accepted, count(*) FILTER (WHERE status IN ('ACCEPTED','FAILED'))::int AS terminal FROM outbox WHERE channel='email' AND target_id=$1",
            [job.target_id],
          )
        ).rows[0];
        await put(db, 'recipients', recipient.id, {
          ...recipient,
          deliverySuccessRate: counts.terminal ? (counts.accepted / counts.terminal) * 100 : 0,
        });
      }
    }
    const advisory = await get<Advisory>(db, 'advisories', job.advisory_id);
    if (advisory) {
      const totals = (
        await db.query(
          "SELECT count(*) FILTER(WHERE status='FAILED')::int AS failed,count(*) FILTER(WHERE status IN ('REVIEW','QUEUED','SENDING'))::int AS pending FROM outbox WHERE advisory_id=$1",
          [advisory.id],
        )
      ).rows[0];
      // Acceptance by a transport is not proof of inbox delivery.
      advisory.deliveryStatus = totals.pending ? 'PENDING' : totals.failed ? 'FAILED' : 'ACCEPTED';
      await put(db, 'advisories', advisory.id, advisory);
      if (!error)
        for (const cveId of advisory.cveIds) {
          const prior = await get<AlertedCVE>(db, 'alertedCves', cveId),
            now = new Date().toISOString();
          const dispatchKey = job.dedupe_key.split(':email:')[0].split(':webhook:')[0];
          const dispatchId = `${cveId}:${dispatchKey}`;
          const same =
            prior?.lastDispatchKey === dispatchKey || !!(await get(db, 'alertDispatches', dispatchId));
          await put(db, 'alertDispatches', dispatchId, { cveId, dispatchKey, acceptedAt: now });
          await put(db, 'alertedCves', cveId, {
            cveId,
            firstAlertedAt: prior?.firstAlertedAt || now,
            lastAlertedAt: now,
            advisoryId: advisory.id,
            recipientEmails: Array.from(
              new Set([
                ...(prior?.recipientEmails || []),
                ...(job.channel === 'email' ? [job.payload.recipientEmail!] : []),
              ]),
            ),
            status: 'DISPATCHED',
            lastDispatchKey: dispatchKey,
            dispatchCount: (prior?.dispatchCount || 0) + (same ? 0 : 1),
          } satisfies AlertedCVE);
        }
      for (const findingId of advisory.findingIds) {
        const f = await get<Finding>(db, 'findings', findingId);
        if (f && f.advisoryId === advisory.id)
          await put(db, 'findings', findingId, {
            ...f,
            notificationStatus: ['NOT_APPLICABLE', 'REVIEW_REQUIRED'].includes(f.notificationStatus)
              ? f.notificationStatus
              : totals.pending
                ? 'QUEUED_FOR_DISPATCH'
                : totals.failed
                  ? 'DELIVERY_FAILED'
                  : 'AUTO_DISPATCHED',
            autoDispatchedAt: !totals.pending && !totals.failed ? new Date().toISOString() : null,
          });
      }
    }
    await writeEvent(db, {category:job.channel === 'email' ? 'EMAIL' : 'EVENT', level:error ? 'WARNING' : 'INFO', code:error ? 'delivery.attempt_failed' : 'delivery.accepted', message:error ? 'Delivery attempt failed; retry policy applied' : 'Transport accepted delivery', context:{jobId:job.id, channel:job.channel, attempt:job.attempts, advisoryId:job.advisory_id}});
    await appendAudit(
      db,
      error ? 'Delivery attempt failed' : 'Delivery accepted',
      `${job.channel} delivery ${job.id}; attempt ${job.attempts}`,
      'delivery-worker',
      job.channel === 'email' ? 'EMAIL' : 'WEBHOOK',
      error ? 'WARNING' : 'INFO',
    );
  });
  return true;
}
