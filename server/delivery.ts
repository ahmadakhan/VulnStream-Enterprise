import type pg from 'pg';
import { randomUUID, createHmac } from 'node:crypto';
import nodemailer from 'nodemailer';
import type { Config } from './config';
import { transaction, get, list, put, appendAudit } from './db';
import type { Db } from './db';
import type { Requester } from './network';
import { decrypt } from './secrets';
import type {
  Advisory,
  Finding,
  EmailRecipient,
  WebhookEndpoint,
  EmailDeliveryLog,
  WebhookDeliveryLog,
  AlertedCVE,
} from '../src/types';
export interface Job {
  id: string;
  dedupe_key: string;
  channel: 'email' | 'webhook';
  target_id: string;
  advisory_id: string;
  payload: { subject: string; text: string; html?: string; recipientEmail?: string; cveIds: string[] };
  attempts: number;
  lock_token: string;
}
export type MailSender = (job: Job) => Promise<string>;
export function createMailSender(config: Config): MailSender {
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
    if (!transporter || !config.SMTP_FROM) throw new Error('SMTP is not configured');
    const result = await transporter.sendMail({
      from: config.SMTP_FROM,
      to: job.payload.recipientEmail,
      subject: job.payload.subject,
      text: job.payload.text,
      html: job.payload.html,
      messageId: `<${job.id}@${config.SMTP_FROM.split('@').pop()}>`,
      headers: { 'X-VulnStream-Delivery-ID': job.id },
    });
    if (
      !result.accepted?.some(
        (address) => String(address).toLowerCase() === job.payload.recipientEmail?.toLowerCase(),
      )
    )
      throw new Error('SMTP did not accept the recipient');
    return result.messageId;
  };
}
export async function enqueue(
  db: Db,
  channel: Job['channel'],
  targetId: string,
  advisoryId: string,
  payload: Job['payload'],
  dedupe: string,
) {
  const id = randomUUID();
  const inserted = await db.query(
    'INSERT INTO outbox(id,dedupe_key,channel,target_id,advisory_id,payload) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(dedupe_key) DO NOTHING RETURNING id',
    [id, dedupe, channel, targetId, advisoryId, JSON.stringify(payload)],
  );
  if (!inserted.rowCount) return null;
  if (channel === 'email')
    await put(db, 'emailLogs', id, {
      id,
      recipientEmail: payload.recipientEmail || '',
      advisoryId,
      subject: payload.subject,
      provider: 'SMTP_Relay',
      status: 'QUEUED',
      attemptCount: 0,
      retrySchedule: ['1m', '2m', '4m', '8m', '16m'],
      nextRetryTime: new Date().toISOString(),
      sentAt: '',
    } satisfies EmailDeliveryLog);
  else {
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
  const isKev = findings.some((f) => f.cve.cisaKev.isKev),
    high = ['HIGH', 'CRITICAL'].includes(advisory.severity);
  const selected = recipients.filter(
    (r) =>
      r.enabled &&
      (r.subscriptionTier === 'ALL_SEVERITIES' ||
        (r.subscriptionTier === 'CRITICAL_HIGH_ONLY' && high) ||
        (r.subscriptionTier === 'CISA_KEV_ONLY' && isKev)),
  );
  const payload = {
    subject: `[${advisory.severity}] ${advisory.title}`,
    text: `${advisory.title}\n\n${advisory.executiveSummary}\n\nAffected systems:\n${advisory.affectedSystems.join('\n')}\n\n${advisory.remediationInstructions}`,
    html,
    cveIds: advisory.cveIds,
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
      )
    )
      count++;
  for (const hook of hooks.filter(
    (h) =>
      h.enabled &&
      (h.events.includes('ALL') ||
        (h.events.includes('CRITICAL') && advisory.severity === 'CRITICAL') ||
        (h.events.includes('CISA_KEV') && isKev)),
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
    permanent = false;
  try {
    if (job.attempts > 6) {
      permanent = true;
      throw new Error('Delivery retry budget exhausted after worker recovery');
    }
    if (job.channel === 'email') {
      if (job.target_id !== 'test') {
        const rec = await get<EmailRecipient>(pool, 'recipients', job.target_id);
        if (!rec?.enabled || rec.email !== job.payload.recipientEmail) {
          permanent = true;
          throw new Error('Recipient removed, changed, or disabled');
        }
      }
      providerId = await sendMail(job);
    } else {
      const hook = await get<WebhookEndpoint>(pool, 'webhooks', job.target_id);
      if (!hook?.enabled) {
        permanent = true;
        throw new Error('Webhook removed or disabled');
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
      });
      statusCode = response.status;
      if (statusCode < 200 || statusCode >= 300) {
        permanent = statusCode >= 400 && statusCode < 500 && ![408, 429].includes(statusCode);
        throw new Error(`Webhook HTTP ${statusCode}`);
      }
      providerId = String(statusCode);
    }
  } catch (e) {
    error = e instanceof Error ? e.message : 'Delivery failed';
  }
  await transaction(pool, async (db) => {
    const current = await db.query('SELECT status,lock_token FROM outbox WHERE id=$1 FOR UPDATE', [job.id]);
    if (current.rows[0]?.lock_token !== job.lock_token) return;
    const failed = !!error && (permanent || job.attempts >= 6),
      next = new Date(Date.now() + Math.min(3600000, 60000 * 2 ** (job.attempts - 1)));
    await db.query(
      'UPDATE outbox SET status=$2,next_attempt=$3,error=$4,provider_id=$5,locked_at=NULL,lock_token=NULL,updated_at=now() WHERE id=$1',
      [job.id, error ? (failed ? 'FAILED' : 'QUEUED') : 'ACCEPTED', next, error || null, providerId || null],
    );
    if (job.channel === 'email') {
      const log = await get<EmailDeliveryLog>(db, 'emailLogs', job.id);
      if (log)
        await put(db, 'emailLogs', job.id, {
          ...log,
          status: error ? (failed ? 'FAILED' : 'RETRYING') : 'ACCEPTED',
          attemptCount: job.attempts,
          errorMessage: error || undefined,
          nextRetryTime: error && !failed ? next.toISOString() : null,
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
          "SELECT count(*) FILTER(WHERE status='FAILED')::int AS failed,count(*) FILTER(WHERE status IN ('QUEUED','SENDING'))::int AS pending FROM outbox WHERE advisory_id=$1",
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
          const same = prior?.lastDispatchKey === dispatchKey;
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
        if (f)
          await put(db, 'findings', findingId, {
            ...f,
            notificationStatus: totals.pending
              ? 'QUEUED_FOR_DISPATCH'
              : totals.failed
                ? 'DELIVERY_FAILED'
                : 'AUTO_DISPATCHED',
            autoDispatchedAt: !totals.pending && !totals.failed ? new Date().toISOString() : null,
          });
      }
    }
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
