import { validateNativeDelivery, type NativeDelivery } from './correlation/notificationEvidence.ts';
import { describeError, writeEvent } from './events';
import { advisoryEmail } from './advisoryEmail';
import { advisoryFilename, renderAdvisoryPdf } from './pdf';
import type pg from 'pg';
import { runVulnerabilityPipeline } from '../src/engine/pipelineEngine';
import { DEFAULT_SETTINGS, DEFAULT_EMAIL_CONFIG } from '../shared/state.ts';
import type { WatchListItem, NormalizedCVE, AliasEntry } from '../src/types/index.ts';
import { buildAliasMap } from '../src/utils/cpeMatcher';
import { randomUUID, createHmac, createHash } from 'node:crypto';
import { stableJson } from '../src/utils/deduplicator';
import nodemailer from 'nodemailer';
import type { Config } from './config';
import { transaction, get, list, put, appendAudit } from './db';
import type { Db } from './db';
import { createRequester, type Requester } from './network';
import {
  EMAIL_PROVIDER_LABELS,
  EmailProviderError,
  emailIsConfigured,
  sendProviderEmail,
} from './emailProviders';
import { decrypt } from './secrets';
import { isSmtpEmailProvider } from '../src/types/index.ts';
import type {
  Advisory,
  Finding,
  EmailRecipient,
  WebhookEndpoint,
  EmailDeliveryLog,
  WebhookDeliveryLog,
  AlertedCVE,
  EmailConfiguration,
  AppSettings,
} from '../src/types/index.ts';
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
    nativeCorrelation?: NativeDelivery;
    cveRevisions?: Record<string, string>;
    findingRevisions?: Record<string, string>;
    /**
     * Digest jobs carry only the findings the target is subscribed to. Delivery
     * revalidation and receipt accounting must use this subset, not the union
     * advisory, or a KEV-only recipient would be blocked by unrelated findings.
     */
    includedFindingIds?: string[];
    /** Stable per-batch key used for CVE dispatch accounting across recipients. */
    digestKey?: string;
  };
  attempts: number;
  lock_token: string;
  review_approved?: boolean;
  priority?: number;
}
export type MailSender = (
  job: Job,
) => Promise<string | { id: string; provider: EmailDeliveryLog['provider'] }>;
export interface EmailAttachment {
  filename: string;
  content: Buffer;
  contentType: string;
};
export interface EmailRetryPolicy {
  /** When false, a transient failure becomes terminal after the first attempt. */
  enabled: boolean;
  /** Total attempts, including the first send. */
  maxAttempts: number;
  initialDelayMinutes: number;
  maxDelayMinutes: number;
}
const boundedInt = (value: unknown, fallback: number, min: number, max: number) => {
  const parsed = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, Math.floor(parsed)));
};
/**
 * Resolves the operator-configured retry policy. Persisted settings from older
 * deployments may not contain these fields yet, so missing values fall back to
 * the documented defaults instead of disabling retries silently.
 */
export function emailRetryPolicy(settings?: Partial<AppSettings> | null): EmailRetryPolicy {
  const initialDelayMinutes = boundedInt(
    settings?.emailRetryInitialDelayMinutes,
    DEFAULT_SETTINGS.emailRetryInitialDelayMinutes,
    1,
    1440,
  );
  return {
    enabled: settings?.emailRetryEnabled ?? DEFAULT_SETTINGS.emailRetryEnabled,
    maxAttempts: boundedInt(
      settings?.emailRetryMaxAttempts,
      DEFAULT_SETTINGS.emailRetryMaxAttempts,
      1,
      20,
    ),
    initialDelayMinutes,
    maxDelayMinutes: Math.max(
      initialDelayMinutes,
      boundedInt(
        settings?.emailRetryMaxDelayMinutes,
        DEFAULT_SETTINGS.emailRetryMaxDelayMinutes,
        1,
        10080,
      ),
    ),
  };
}
export const DEFAULT_EMAIL_RETRY_POLICY = emailRetryPolicy(DEFAULT_SETTINGS);
/**
 * Exponential backoff capped by the configured maximum, so a provider outage is
 * retried durably without hammering the relay and without retrying forever.
 */
export const emailRetryDelayMs = (attempt: number, policy: EmailRetryPolicy) =>
  Math.min(
    policy.maxDelayMinutes * 60_000,
    policy.initialDelayMinutes * 60_000 * 2 ** Math.max(0, attempt - 1),
  );
/** Human-readable schedule stored on the delivery log for operator visibility. */
export const emailRetrySchedule = (policy: EmailRetryPolicy) =>
  policy.enabled
    ? Array.from({ length: policy.maxAttempts }, (_, index) =>
        `${Math.round(emailRetryDelayMs(index + 1, policy) / 60_000)}m`,
      )
    : [];
const revision = (cve: NormalizedCVE) => createHash('sha256').update(stableJson(cve)).digest('hex');
const findingRevision = (finding: Finding) =>
  createHash('sha256')
    .update(
      stableJson({
        cveId: finding.cveId,
        assetId: finding.matchedAssetId,
        assetName: finding.matchedAssetName,
        matchingMethod: finding.matchingMethod,
        matchingEvidence: finding.matchingEvidence,
        exploitRisk: finding.exploitRisk,
      }),
    )
    .digest('hex');
/**
 * Content revision for one advisory. Queueing the same advisory revision twice
 * is idempotent; a materially changed advisory (new findings, revised severity,
 * summary, remediation, or changed CVE evidence) gets a new revision and can be
 * delivered again.
 */
const advisoryRevision = (advisory: Advisory, findings: Finding[]) =>
  createHash('sha256')
    .update(
      stableJson({
        advisory: {
          // The advisory ID is intentionally excluded: pipeline-created
          // advisories receive a new random ID on every run, so including it
          // would defeat idempotent delivery of unchanged content. An explicit
          // operator dispatch key still distinguishes intentional resends.
          title: advisory.title,
          severity: advisory.severity,
          // Delivery content is a set, not a sequence. Sorting here keeps the
          // dedupe key stable when the pipeline or a digest buffer returns the
          // same findings in a different database order.
          cveIds: [...advisory.cveIds].sort(),
          findingIds: [...advisory.findingIds].sort(),
          executiveSummary: advisory.executiveSummary,
          remediationInstructions: advisory.remediationInstructions,
          affectedSystems: [...advisory.affectedSystems].sort(),
          isDigestBatch: advisory.isDigestBatch ?? false,
          vendorLink: advisory.vendorLink ?? '',
        },
        findings: findings
          .map((finding) => [finding.id, findingRevision(finding)])
          .sort(([left], [right]) => left.localeCompare(right)),
      }),
    )
    .digest('hex')
    .slice(0, 20);
const SEVERITY_ORDER = ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const;
const uniqueSorted = (values: string[]) => Array.from(new Set(values)).sort();
/** Highest severity in a set of findings, used for combined digest subjects. */
const highestSeverity = (findings: Finding[]): Advisory['severity'] =>
  findings.reduce(
    (severity, finding) =>
      SEVERITY_ORDER.indexOf(finding.cve.cvss.severity) > SEVERITY_ORDER.indexOf(severity)
        ? finding.cve.cvss.severity
        : severity,
    'UNKNOWN' as Advisory['severity'],
  );
const findingDetail = (finding: Finding) =>
  `${finding.cveId} | ${finding.cve.cvss.severity}${finding.cve.cisaKev?.isKev ? ' | CISA KEV' : ''} | ${finding.matchedAssetName}`;
/** Deterministic vendor link so batch ordering cannot change the dedupe key. */
const vendorLinkFor = (findings: Finding[]) =>
  uniqueSorted(
    findings
      .map((finding) => finding.cve.remediation.vendorAdvisoryRef || finding.cve.remediation.patchUrl)
      .filter((link): link is string => !!link),
  )[0] || '';
/**
 * Builds the advisory view for a set of findings. Every recipient receives a
 * view containing exactly the findings its subscription permits, while the
 * persisted advisory is the union of all views for queue accounting.
 */
function digestView(advisory: Advisory, findings: Finding[]): Advisory {
  const cveIds = uniqueSorted(findings.map((finding) => finding.cveId));
  const systems = uniqueSorted(findings.map((finding) => finding.matchedAssetName));
  const severity = highestSeverity(findings);
  const summary =
    findings.length === 1
      ? '1 inventory correlation requires investigation. Confirm applicability and consult the vendor before remediation.'
      : `${findings.length} inventory correlations across ${systems.length} system${systems.length === 1 ? '' : 's'} require investigation. Confirm applicability and consult the vendor before remediation.`;
  return {
    ...advisory,
    title: `Vulnerability ${findings.length === 1 ? 'notice' : 'digest'}: ${cveIds.slice(0, 3).join(', ')}${cveIds.length > 3 ? ` (+${cveIds.length - 3} more)` : ''}`,
    severity,
    cveIds,
    findingIds: findings.map((finding) => finding.id),
    executiveSummary: summary,
    affectedSystems: systems,
    vendorLink: vendorLinkFor(findings),
    isDigestBatch: true,
  };
}
const advisoryPriority = (findings: Finding[]) =>
  Math.max(
    0,
    ...findings.map((finding) =>
      finding.cve.cisaKev?.isKev
        ? 100
        : finding.exploitRisk === 'REPORTED_IN_WILD_EXPLOIT' ||
            finding.exploitRisk === 'WEAPONIZED_EXPLOIT' ||
            finding.cve.exploitationSources?.length
          ? 50
          : finding.notificationStatus === 'REVIEW_REQUIRED'
            ? 50
            : 0,
    ),
  );
export function recipientAllows(recipient: EmailRecipient, finding: Finding): boolean {
  return (
    recipient.subscriptionTier === 'ALL_SEVERITIES' ||
    (recipient.subscriptionTier === 'CRITICAL_HIGH_ONLY' &&
      ['CRITICAL', 'HIGH'].includes(finding.cve.cvss.severity)) ||
    (recipient.subscriptionTier === 'CISA_KEV_ONLY' && finding.cve.cisaKev?.isKev)
  );
}
export function webhookAllows(hook: WebhookEndpoint, finding: Finding): boolean {
  return (
    hook.events.includes('ALL') ||
    (hook.events.includes('CRITICAL') && finding.cve.cvss.severity === 'CRITICAL') ||
    (hook.events.includes('CISA_KEV') && finding.cve.cisaKev?.isKev)
  );
}
/** Renders the advisory HTML to a PDF attachment for the job, or undefined when
 *  PDF delivery is disabled, the job carries no HTML body, or rendering fails.
 *  Failures degrade to HTML-only delivery instead of blocking the send. */
async function buildPdfAttachment(job: Job, config: Config, db?: Db): Promise<EmailAttachment | undefined> {
  if (config.ATTACH_ADVISORY_PDF !== 'true' || !job.payload.html) return undefined;
  try {
    const pdf = await renderAdvisoryPdf(job.payload.html, config);
    return {
      filename: advisoryFilename(job.advisory_id),
      content: Buffer.from(pdf),
      contentType: 'application/pdf',
    };
  } catch (error) {
    if (db)
      await writeEvent(db, {
        category: 'EMAIL',
        level: 'WARNING',
        code: 'delivery.pdf_attachment_failed',
        message: 'Advisory PDF attachment could not be generated; delivering HTML only',
        context: {
          jobId: job.id,
          channel: job.channel,
          advisoryId: job.advisory_id,
          error: String((error as Error)?.message || error),
        },
      }).catch(() => undefined);
    return undefined;
  }
}
export function createMailSender(
  config: Config,
  db?: Db,
  request: Requester = createRequester(config),
): MailSender {
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
    const saved = (db && (await get<EmailConfiguration>(db, 'emailConfig', 'main'))) || DEFAULT_EMAIL_CONFIG;
    if (!emailIsConfigured(saved, config)) throw new Error('Email provider is not configured');
    const attachment = await buildPdfAttachment(job, config, db);
    if (!isSmtpEmailProvider(saved.provider)) {
      const token = decrypt(saved.apiKey, config.ENCRYPTION_KEY, `email-provider:${saved.provider}`);
      if (!token) throw new Error('Email provider token is missing');
      const mailjetSecret =
        saved.provider === 'MAILJET_API'
          ? decrypt(saved.mailjetApiSecret, config.ENCRYPTION_KEY, `email-mailjet:${saved.provider}`)
          : saved.mailjetApiSecret;
      const provider = EMAIL_PROVIDER_LABELS[saved.provider];
      try {
        const id = await sendProviderEmail(
          { ...saved, mailjetApiSecret: mailjetSecret },
          token,
          job,
          request,
          config.MAILJET_SANDBOX_MODE === 'true',
          attachment,
        );
        return { id, provider };
      } catch (error) {
        if (error instanceof EmailProviderError) {
          error.provider = provider;
          throw error;
        }
        throw new EmailProviderError(`${provider} connection failed`, 502, 0, provider);
      }
    }
    const fromEmail = saved.fromEmail || config.SMTP_FROM;
    const configuredSmtpHost = saved.smtpHost;
    const usesDeploymentSmtp = saved.provider === 'SMTP' && !configuredSmtpHost;
    const smtpPassword = usesDeploymentSmtp
      ? config.SMTP_PASSWORD
      : decrypt(saved.smtpPassword, config.ENCRYPTION_KEY, `email-smtp:${saved.provider}`);
    const smtpTransport = usesDeploymentSmtp
      ? transporter
      : nodemailer.createTransport({
          host: configuredSmtpHost || config.SMTP_HOST,
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
       headers: { 'X-BA-Threat-Intel-Delivery-ID': job.id },
       ...(attachment ? { attachments: [attachment] } : {}),
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
  priority = 0,
) {
  const id = randomUUID();
  // A content revision that already exists is normally a duplicate. The one
  // safe exception is a bundle that was terminally failed because its findings
  // were temporarily inapplicable: the pipeline only calls queueAdvisory again
  // after revalidating the current inventory, so the same revision can be
  // re-opened without ever having been accepted by a transport. Transport,
  // recipient, and subscription failures are deliberately not resurrected.
  const inserted = await db.query(
    `INSERT INTO outbox(id,dedupe_key,channel,target_id,advisory_id,payload,status,priority)
     VALUES($1,$2,$3,$4,$5,$6,$7,$8)
     ON CONFLICT(dedupe_key) DO UPDATE SET
       advisory_id=EXCLUDED.advisory_id,
       payload=EXCLUDED.payload,
       status=EXCLUDED.status,
       priority=EXCLUDED.priority,
       attempts=0,
       next_attempt=now(),
       error=NULL,
       provider_id=NULL,
       locked_at=NULL,
       lock_token=NULL,
       updated_at=now()
     WHERE outbox.status='FAILED'
       AND COALESCE(outbox.error,'') LIKE '%no longer applicable%'
     RETURNING id`,
    [
      id,
      dedupe,
      channel,
      targetId,
      advisoryId,
      JSON.stringify(payload),
      channel === 'email' ? initialStatus : 'QUEUED',
      priority,
    ],
  );
  if (!inserted.rowCount) return null;
  const insertedId = inserted.rows[0].id as string;
  if (channel === 'email') {
    const configuration = (await get<EmailConfiguration>(db, 'emailConfig', 'main')) || DEFAULT_EMAIL_CONFIG;
    const settings = (await get<AppSettings>(db, 'settings', 'main')) || DEFAULT_SETTINGS;
    await put(db, 'emailLogs', insertedId, {
      id: insertedId,
      recipientEmail: payload.recipientEmail || '',
      advisoryId,
      subject: payload.subject,
      provider: EMAIL_PROVIDER_LABELS[configuration.provider],
      status: initialStatus === 'REVIEW' ? 'REVIEW_REQUIRED' : 'QUEUED',
      attemptCount: 0,
      retrySchedule: emailRetrySchedule(emailRetryPolicy(settings)),
      nextRetryTime: initialStatus === 'REVIEW' ? null : new Date().toISOString(),
      sentAt: '',
    } satisfies EmailDeliveryLog);
  } else {
    const hook = await get<WebhookEndpoint>(db, 'webhooks', targetId);
    await put(db, 'webhookLogs', insertedId, {
      id: insertedId,
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
  return insertedId;
}
export async function queueAdvisory(
  db: Db,
  advisory: Advisory,
  findings: Finding[],
  html?: string,
  dispatchKey?: string,
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
  // Deduplicate by content revision, not just advisory ID: a genuinely revised
  // advisory may be delivered again, while a repeated queue pass over the same
  // revision remains idempotent. Pipeline-created advisories get a new random
  // ID on every run, so the default dispatch key must be content-derived; an
  // explicit key (operator resend) still overrides it.
  const contentRevision = advisoryRevision(advisory, findings);
  const stableDispatchKey = dispatchKey ?? contentRevision;
  let count = 0;
  const priority = advisoryPriority(findings);
  for (const recipient of selected)
    if (
      await enqueue(
        db,
        'email',
        recipient.id,
        advisory.id,
        { ...payload, recipientEmail: recipient.email },
        `${stableDispatchKey}:${contentRevision}:email:${recipient.id}`,
        recipient.deliveryGroup === 'EVERYONE' ? 'REVIEW' : 'QUEUED',
        priority,
      )
    )
      count++;
  for (const hook of hooks.filter(
    (h) => h.enabled && findings.length > 0 && findings.every((finding) => webhookAllows(h, finding)),
  ))
    if (
      await enqueue(
        db,
        'webhook',
        hook.id,
        advisory.id,
        payload,
        `${stableDispatchKey}:${contentRevision}:webhook:${hook.id}`,
        'QUEUED',
        priority,
      )
    )
      count++;
  if (!count) return 0;
  advisory.recipientCount = selected.length;
  advisory.deliveryStatus = count ? 'PENDING' : 'DRAFT';
  await put(db, 'advisories', advisory.id, advisory);
  return count;
}
export interface DigestQueueResult {
  /** Persisted union advisory, or the supplied advisory when nothing was queued. */
  advisory: Advisory;
  /** Number of transport jobs created (email + webhook). */
  jobs: number;
  /** Findings that were included in at least one job. */
  findingIds: string[];
  /** Number of targets that could receive at least one finding. */
  eligible: number;
}

/**
 * Queues one combined email per recipient (and one webhook per endpoint) for a
 * batch of findings.
 *
 * The union advisory is persisted for queue accounting and UI visibility, while
 * each transport receives a recipient-specific view containing only the findings
 * its subscription tier permits. This is what makes a single digest safe for a
 * mixed set of ALL_SEVERITIES, CRITICAL_HIGH_ONLY and CISA_KEV_ONLY subscribers.
 *
 * Deduplication is content-derived and per target. Re-running the same batch is
 * idempotent, and the stable Message-ID in `createMailSender` lets the receiving
 * provider collapse a retry that raced a process crash.
 */
export async function queueDigestAdvisory(
  db: Db,
  advisory: Advisory,
  findings: Finding[],
  render?: (advisory: Advisory) => string | undefined,
  dispatchKey?: string,
): Promise<DigestQueueResult> {
  const recipients = (await list<EmailRecipient>(db, 'recipients')).filter(
    (recipient) => recipient.enabled,
  );
  const hooks = (await list<WebhookEndpoint>(db, 'webhooks')).filter((hook) => hook.enabled);

  const recipientBatches = new Map<string, Finding[]>();
  for (const recipient of recipients) {
    const permitted = findings.filter((finding) => recipientAllows(recipient, finding));
    if (permitted.length) recipientBatches.set(recipient.id, permitted);
  }
  const webhookBatches = new Map<string, Finding[]>();
  for (const hook of hooks) {
    const permitted = findings.filter((finding) => webhookAllows(hook, finding));
    if (permitted.length) webhookBatches.set(hook.id, permitted);
  }

  const includedIds = new Set<string>();
  for (const batch of [...recipientBatches.values(), ...webhookBatches.values()])
    for (const finding of batch) includedIds.add(finding.id);
  const included = findings.filter((finding) => includedIds.has(finding.id));
  if (!included.length)
    return { advisory, jobs: 0, findingIds: [], eligible: 0 };

  const union = digestView(advisory, included);
  const contentRevision = advisoryRevision(union, included);
  const stableDispatchKey = dispatchKey ?? contentRevision;
  const priority = advisoryPriority(included);
  let jobs = 0;
  let recipientCount = 0;

  for (const [recipientId, batch] of recipientBatches) {
    const recipient = recipients.find((candidate) => candidate.id === recipientId)!;
    const view = digestView(union, batch);
    const payload = {
      ...advisoryEmail(
        view,
        render?.(view),
        batch.map(findingDetail),
      ),
      cveIds: view.cveIds,
      includedFindingIds: batch.map((finding) => finding.id),
      findingRevisions: Object.fromEntries(
        batch.map((finding) => [finding.id, findingRevision(finding)]),
      ),
      cveRevisions: Object.fromEntries(
        batch.map((finding) => [finding.cveId, revision(finding.cve)]),
      ),
      digestKey: stableDispatchKey,
      recipientEmail: recipient.email,
    };
    if (
      await enqueue(
        db,
        'email',
        recipient.id,
        union.id,
        payload,
        `${stableDispatchKey}:${contentRevision}:email:${recipient.id}`,
        recipient.deliveryGroup === 'EVERYONE' ? 'REVIEW' : 'QUEUED',
        priority,
      )
    ) {
      jobs++;
      recipientCount++;
    }
  }

  for (const [hookId, batch] of webhookBatches) {
    const view = digestView(union, batch);
    const payload = {
      ...advisoryEmail(
        view,
        render?.(view),
        batch.map(findingDetail),
      ),
      cveIds: view.cveIds,
      includedFindingIds: batch.map((finding) => finding.id),
      findingRevisions: Object.fromEntries(
        batch.map((finding) => [finding.id, findingRevision(finding)]),
      ),
      cveRevisions: Object.fromEntries(
        batch.map((finding) => [finding.cveId, revision(finding.cve)]),
      ),
      digestKey: stableDispatchKey,
    };
    if (
      await enqueue(
        db,
        'webhook',
        hookId,
        union.id,
        payload,
        `${stableDispatchKey}:${contentRevision}:webhook:${hookId}`,
        'QUEUED',
        priority,
      )
    )
      jobs++;
  }

  if (!jobs)
    return {
      advisory: union,
      jobs: 0,
      // These findings were already accepted by an identical queued batch.
      // Callers use this to discard them from their local buffer.
      findingIds: included.map((finding) => finding.id),
      eligible: recipientBatches.size + webhookBatches.size,
    };

  union.recipientCount = recipientCount;
  union.deliveryStatus = 'PENDING';
  await put(db, 'advisories', union.id, union);
  return {
    advisory: union,
    jobs,
    findingIds: included.map((finding) => finding.id),
    eligible: recipientBatches.size + webhookBatches.size,
  };
}

export async function deliverNext(
  pool: pg.Pool,
  config: Config,
  request: Requester,
  sendMail: MailSender,
): Promise<boolean> {
  const job = await transaction(pool, async (db) => {
    const claimed = await db.query(
      `WITH candidate AS (SELECT id FROM outbox WHERE (status='QUEUED' AND next_attempt<=now()) OR (status='SENDING' AND locked_at<now()-interval '2 minutes') ORDER BY priority DESC, next_attempt FOR UPDATE SKIP LOCKED LIMIT 1) UPDATE outbox SET status='SENDING',locked_at=now(),lock_token=$1,attempts=attempts+1,updated_at=now() WHERE id IN (SELECT id FROM candidate) RETURNING *`,
      [randomUUID()],
    );
    return claimed.rows[0] as Job | undefined;
  });
  if (!job) return false;
  // Email retries follow the operator policy; webhooks retain the historical
  // six-attempt policy because their budget is not exposed as an email setting.
  const settings = (await get<AppSettings>(pool, 'settings', 'main')) || DEFAULT_SETTINGS;
  const retryPolicy = emailRetryPolicy(job.channel === 'email' ? settings : DEFAULT_SETTINGS);
  let providerId = '',
    statusCode = 0,
    signature = '',
    error = '',
    permanent = false,
    retryNotBefore = 0;
  // Structured transport failure for the event log; `error` stays the short
  // message used by retry policy and the outbox row.
  let errorInfo: Record<string, unknown> = {};
  let emailProvider: EmailDeliveryLog['provider'] | undefined,
    routeToReview = false;
  // Declared outside the try block: it is assigned inside and read again by the
  // post-delivery bookkeeping below. A block-scoped `const` made that read a
  // compile error and, under a non-strict loader, a ReferenceError *after* the
  // mail/webhook had already been sent — the outbox row would then never be
  // marked ACCEPTED and the alert would be re-sent on every retry.
  let declaredCveIds: string[] = [];
  let declaredFindingIds: string[] = [];
  try {
    if (!retryPolicy.enabled && job.attempts > 1 && job.channel === 'email' && !job.review_approved) {
      permanent = true;
      throw new Error('Automatic email retry is disabled by the current settings');
    }
    // A review-held job consumes its first attempt before an operator approves
    // it. Approval is an explicit send, so it must not be blocked by a retry
    // budget of one; subsequent attempts follow the configured policy.
    if (job.attempts > retryPolicy.maxAttempts && !job.review_approved) {
      permanent = true;
      throw new Error('Delivery retry budget exhausted after worker recovery');
    }
    let native: NativeDelivery | undefined;
    if (job.payload.nativeCorrelation) {
      try { native = await validateNativeDelivery(pool,job); }
      catch { permanent = true; throw new Error('Native evidence or notification policy is no longer applicable'); }
      if (native.confidence === 'MEDIUM' && !job.review_approved) {
        routeToReview = true; throw new Error('Native medium-confidence evidence requires security review');
      }
    }
    const advisory = await get<Advisory>(pool, 'advisories', job.advisory_id);
    const currentFindings: Finding[] = [];
    if (!advisory && !native && job.advisory_id !== 'TEST') {
      permanent = true;
      throw new Error('Queued advisory no longer exists');
    }
    // A digest job intentionally carries only the subset of the advisory that
    // this target may receive. Legacy and non-digest jobs omit these fields and
    // are validated against the whole advisory exactly as before.
    declaredCveIds = job.payload.cveIds?.length ? job.payload.cveIds : advisory?.cveIds ?? [];
    declaredFindingIds = job.payload.includedFindingIds?.length
      ? job.payload.includedFindingIds
      : advisory?.findingIds ?? [];
    if (advisory && declaredCveIds.some((id) => !job.payload.cveRevisions?.[id])) {
      permanent = true;
      throw new Error(
        'Advisory revision is no longer applicable; rebuild legacy queued payload from current intelligence',
      );
    }
    if (advisory && !declaredFindingIds.length) {
      permanent = true;
      throw new Error('Advisory has no findings; rebuild from current inventory before delivery');
    }
    if (advisory) {
      // Revalidation must use the same operator-managed aliases as the pipeline
      // that produced the finding; otherwise an alias-matched finding is
      // permanently rejected as "no longer applicable".
      const aliasEntries = await list<AliasEntry>(pool, 'aliases');
      const vendorAliases = buildAliasMap(aliasEntries, 'VENDOR');
      const productAliases = buildAliasMap(aliasEntries, 'PRODUCT');
      const invalid: string[] = [];
      for (const id of declaredFindingIds) {
        const finding = await get<Finding>(pool, 'findings', id);
        const [asset, cachedCve, withdrawal] = finding
          ? await Promise.all([
              get<WatchListItem>(pool, 'watchlist', finding.matchedAssetId),
              get<NormalizedCVE>(pool, 'cveData', finding.cveId),
              get<{ modifiedDate: string }>(pool, 'cveWithdrawals', finding.cveId),
            ])
          : [undefined, undefined, undefined];
        // Retention may delete the regenerable threat-cache record while a
        // manually reviewed advisory is still queued. The finding embeds the
        // validated CVE snapshot, so fall back to it instead of permanently
        // rejecting an otherwise deliverable bundle.
        const cve = cachedCve || finding?.cve;
        const match =
          asset && cve
            ? runVulnerabilityPipeline(
                [],
                [cve],
                [asset],
                [],
                [],
                { ...settings, scopeHours: 0 },
                'Server worker',
                false,
                vendorAliases,
                productAliases,
                undefined,
                aliasEntries,
              ).newFindings[0]
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
        if (native && rec.subscriptionTier !== 'ALL_SEVERITIES') {
          permanent = true; throw new Error('Recipient subscription no longer permits unscored intelligence');
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
      if (native && (native.confidence !== 'HIGH' || !hook.events.includes('ALL'))) {
        permanent = true; throw new Error('Webhook subscription does not permit native intelligence');
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
    errorInfo = describeError(e);
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
    const failed =
        !!error &&
        !routeToReview &&
        (permanent ||
          !retryPolicy.enabled ||
          job.attempts >= retryPolicy.maxAttempts),
      next = new Date(
        Math.max(retryNotBefore, Date.now() + emailRetryDelayMs(job.attempts, retryPolicy)),
      );
    await db.query(
      'UPDATE outbox SET status=$2,next_attempt=$3,error=$4,provider_id=$5,locked_at=NULL,lock_token=NULL,updated_at=now() WHERE id=$1',
      [
        job.id,
        routeToReview ? 'REVIEW' : error ? (failed ? 'FAILED' : 'QUEUED') : 'ACCEPTED',
        next,
        routeToReview ? null : error || null,
        providerId || null,
      ],
    );
    if (error && !routeToReview && !failed) {
      // A rate-limited or blackholed endpoint must not be hammered once per
      // queued job. Share this target's backoff with its remaining pending work;
      // bound the batch so the global state lock is not held across the queue.
      await db.query(
        `WITH pending AS (
           SELECT id FROM outbox
           WHERE channel=$1 AND target_id=$2 AND status='QUEUED' AND id<>$3 AND next_attempt < $4
           ORDER BY next_attempt
           LIMIT 1000
         )
         UPDATE outbox o SET next_attempt=$4, updated_at=now() FROM pending p WHERE o.id=p.id`,
        [job.channel, job.target_id, job.id, next],
      );
    }
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
        for (const cveId of declaredCveIds) {
          const prior = await get<AlertedCVE>(db, 'alertedCves', cveId),
            now = new Date().toISOString();
          // Digest jobs carry one batch key across every recipient, so the same
          // CVE is counted once even when several subscription cohorts receive
          // it. Non-digest jobs retain the original content-revision key.
          const dispatchKey =
            job.payload.digestKey ??
            job.dedupe_key.split(':email:')[0].split(':webhook:')[0];
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
    await writeEvent(db, {
      category: job.channel === 'email' ? 'EMAIL' : 'EVENT',
      level: error ? 'WARNING' : 'INFO',
      code: error ? 'delivery.attempt_failed' : 'delivery.accepted',
      message: error ? 'Delivery attempt failed; retry policy applied' : 'Transport accepted delivery',
      context: {
        jobId: job.id,
        channel: job.channel,
        attempt: job.attempts,
        advisoryId: job.advisory_id,
        ...(error ? errorInfo : {}),
      },
    });
    if (failed && error) {
      await writeEvent(db, {
        category: job.channel === 'email' ? 'EMAIL' : 'EVENT',
        level: 'ERROR',
        code: 'delivery.exhausted',
        message: `Delivery retries exhausted for advisory ${job.advisory_id}; permanent failure`,
        context: {
          jobId: job.id,
          channel: job.channel,
          attempts: job.attempts,
          advisoryId: job.advisory_id,
          error,
          ...errorInfo,
        },
      });
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
