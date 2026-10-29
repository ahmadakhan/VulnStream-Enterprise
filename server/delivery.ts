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
import { transaction, get, getMany, list, put, appendAudit } from './db';
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
  ReviewEdits,
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
    /**
     * When true, the job is a calendar daily-digest delivery: an overall summary
     * email. Such jobs never carry a PDF attachment — the body is the summary
     * itself — so the sender skips PDF rendering entirely.
     */
    dailyDigest?: boolean;
  };
  attempts: number;
  lock_token: string;
  review_approved?: boolean;
  edits?: ReviewEdits;
  priority?: number;
}
export type MailSender = (
  job: Job,
) => Promise<string | { id: string; provider: EmailDeliveryLog['provider'] }>;
export interface EmailAttachment {
  filename: string;
  content: Buffer;
  contentType: string;
}
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
    maxAttempts: boundedInt(settings?.emailRetryMaxAttempts, DEFAULT_SETTINGS.emailRetryMaxAttempts, 1, 20),
    initialDelayMinutes,
    maxDelayMinutes: Math.max(
      initialDelayMinutes,
      boundedInt(settings?.emailRetryMaxDelayMinutes, DEFAULT_SETTINGS.emailRetryMaxDelayMinutes, 1, 10080),
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
    ? Array.from(
        { length: policy.maxAttempts },
        (_, index) => `${Math.round(emailRetryDelayMs(index + 1, policy) / 60_000)}m`,
      )
    : [];
/**
 * Content-relevant CVE fingerprint used for delivery staleness checks.
 *
 * Only fields that affect advisory content (severity, remediation links,
 * CISA KEV status in the finding-detail line) or matching applicability are
 * included. Enrichment and metadata fields — EPSS scores, exploit status,
 * exploitation sources, source-feed attribution, publication/modification
 * timestamps, CPE weakness IDs — are excluded because feed refreshes update
 * them independently of the matching engine without altering the advisory a
 * recipient receives.
 *
 * This deliberately mirrors the field set of `matchingCveSignature` in
 * pipeline.ts (the signature the pipeline uses for its reusable-match
 * optimisation) plus `cvss`, `remediation` and `cisaKev.isKev`, all of which
 * surface in delivered content. Aligning these two signatures prevents a
 * benign enrichment refresh from triggering a false "CVE intelligence
 * changed" failure when the pipeline correctly treats the refresh as a
 * no-op.
 */
export const revision = (cve: NormalizedCVE) =>
  createHash('sha256')
    .update(
      stableJson({
        cveId: cve.cveId,
        title: cve.title,
        description: cve.description,
        cvss: cve.cvss,
        cpeMatches: cve.cpeMatches,
        cpeMatchDetails: cve.cpeMatchDetails,
        versionRange: cve.versionRange,
        purls: cve.purls,
        applicabilityRequiresReview: cve.applicabilityRequiresReview,
        remediation: cve.remediation,
        isKev: cve.cisaKev?.isKev ?? false,
      }),
    )
    .digest('hex');
/**
 * Finding fingerprint for delivery staleness checks and advisory content
 * revision (dedupe key).
 *
 * `exploitRisk` is intentionally excluded: it is derived from enrichment
 * data (EPSS, KEV, exploit status) that the pipeline refreshes independently
 * of matching. Including it would make the content-revision change whenever
 * a feed refresh updated a score, which in turn prevents the ON-CONFLICT
 * resurrection of a failed job from matching (different dedupe key) and
 * forces a new advisory even though the delivered email content — severity,
 * remediation links, affected systems — is unchanged. The revalidation
 * already catches genuine applicability changes via the `!match` and
 * `notificationStatus` checks below.
 *
 * `matchedCpe` and the free-text `matchingEvidence` are excluded as well: the
 * CPE recorded is the NVD criterion in one context and the inventory CPE in
 * another, while the evidence string embeds the confidence the policy happened
 * to require. Both describe *how* the match was spelled, not *whether* the
 * asset is affected, so including them made revalidation report "inventory or
 * matching evidence changed" — and the bundle fail — after a benign policy or
 * spelling difference. Affected-system content is covered by `assetName`.
 */
export const findingRevision = (finding: Finding) =>
  createHash('sha256')
    .update(
      stableJson({
        cveId: finding.cveId,
        assetId: finding.matchedAssetId,
        assetName: finding.matchedAssetName,
      }),
    )
    .digest('hex');
/**
 * Content revision for one advisory. Queueing the same advisory revision twice
 * is idempotent; a materially changed advisory (new findings, revised severity,
 * summary, remediation, or changed CVE evidence) gets a new revision and can be
 * delivered again.
 */
export const advisoryRevision = (advisory: Advisory, findings: Finding[]) =>
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
          .map((finding) => [
            finding.id,
            findingRevision(finding),
            // A CVE evidence change (affected CPEs, version range, remediation,
            // severity) alters the delivered advisory even when the finding row
            // itself is unchanged. `revision` excludes enrichment noise, so this
            // honours the documented dedupe contract without churn on feed
            // refreshes.
            revision(finding.cve),
          ])
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
  if (job.payload.dailyDigest) return undefined;
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
    if (!fromEmail) throw new Error('SMTP from address is not configured');
    const fromDomain = fromEmail.split('@').pop() || 'localhost';
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
    if (!smtpTransport) throw new Error('SMTP is not configured');
    const result = await smtpTransport.sendMail({
      from: { address: fromEmail, name: saved.fromName },
      ...(saved.replyTo ? { replyTo: saved.replyTo } : {}),
      to: job.payload.recipientEmail,
      subject: job.payload.subject,
      text: job.payload.text,
      html: job.payload.html,
      messageId: `<${job.id}@${fromDomain}>`,
      headers: {
        'X-BA-Threat-Intel-Delivery-ID': job.id,
        'Auto-Submitted': 'auto-generated',
        'List-Unsubscribe': saved.unsubscribeUrl || `<mailto:${fromEmail}?subject=unsubscribe>`,
        // RFC 8058 one-click is only valid for an HTTP(S) unsubscribe URL. A
        // mailto fallback is handled by the mail client, not an HTTP POST.
        ...(saved.unsubscribeUrl && /^https?:\/\//i.test(saved.unsubscribeUrl)
          ? { 'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click' }
          : {}),
      },
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
  const recipients = (await list<EmailRecipient>(db, 'recipients')).filter((recipient) => recipient.enabled);
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
  if (!included.length) return { advisory, jobs: 0, findingIds: [], eligible: 0 };

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
      ...advisoryEmail(view, render?.(view), batch.map(findingDetail)),
      cveIds: view.cveIds,
      includedFindingIds: batch.map((finding) => finding.id),
      findingRevisions: Object.fromEntries(batch.map((finding) => [finding.id, findingRevision(finding)])),
      cveRevisions: Object.fromEntries(batch.map((finding) => [finding.cveId, revision(finding.cve)])),
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
      ...advisoryEmail(view, render?.(view), batch.map(findingDetail)),
      cveIds: view.cveIds,
      includedFindingIds: batch.map((finding) => finding.id),
      findingRevisions: Object.fromEntries(batch.map((finding) => [finding.id, findingRevision(finding)])),
      cveRevisions: Object.fromEntries(batch.map((finding) => [finding.cveId, revision(finding.cve)])),
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
  // Set when the revalidation detects a stale advisory bundle so the catch
  // block can trigger an immediate rebuild instead of a hard permanent failure.
  let staleAdvisory = false;
  // Set when a legacy payload was rebuilt from current intelligence during this
  // attempt, so the recovery path does not rebuild the same payload twice.
  let legacyRebuilt = false;
  // Set when the bundle is blocked by a finding that is deliberately held for
  // review (confidence policy or unverifiable applicability) rather than one
  // whose applicability changed. A rebuild cannot change a held verdict, so the
  // job is routed to operator review instead of a permanent FAILED + rebuild.
  let holdGated = false;
  try {
    if (!retryPolicy.enabled && job.attempts > 1 && job.channel === 'email') {
      permanent = true;
      throw new Error('Automatic email retry is disabled by the current settings');
    }
    // Approval resets the attempt count. The transport budget still applies
    // after approval, including recovery of an abandoned sending lease.
    if (job.attempts > retryPolicy.maxAttempts) {
      permanent = true;
      throw new Error('Delivery retry budget exhausted after worker recovery');
    }
    let native: NativeDelivery | undefined;
    if (job.payload.nativeCorrelation) {
      try {
        native = await validateNativeDelivery(pool, job);
      } catch {
        // FIX: Added space after comma
        permanent = true;
        throw new Error('Native evidence or notification policy is no longer applicable');
      }
      if (native.confidence === 'MEDIUM' && !job.review_approved) {
        routeToReview = true;
        throw new Error('Native medium-confidence evidence requires security review');
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
    declaredCveIds = job.payload.cveIds ?? advisory?.cveIds ?? [];
    declaredFindingIds = job.payload.includedFindingIds ?? advisory?.findingIds ?? [];
    if (advisory && declaredCveIds.some((id) => !job.payload.cveRevisions?.[id])) {
      // Jobs queued before content-revision evidence existed cannot be validated
      // against the advisory they describe. Rebuild the payload from the
      // current CVE cache first; revalidation below then decides whether it is
      // still deliverable. If the rebuild cannot produce evidence for every
      // declared CVE (e.g. the CVE was removed from the cache), the bundle is
      // stale and recovery rebuilds it from the current inventory instead.
      const { rebuildLegacyDeliveryPayload } = await import('./pipeline');
      if (await rebuildLegacyDeliveryPayload(pool, job)) {
        legacyRebuilt = true;
        declaredCveIds = job.payload.cveIds ?? advisory.cveIds;
      }
      if (declaredCveIds.some((id) => !job.payload.cveRevisions?.[id])) {
        permanent = true;
        staleAdvisory = true;
        throw new Error(
          'Advisory revision is no longer applicable; rebuild legacy queued payload from current intelligence',
        );
      }
    }
    if (advisory && !declaredFindingIds.length && !job.payload.digestKey) {
      // Nothing in this bundle can still be delivered; recover through the same
      // current-inventory rebuild path instead of a bare operator-facing error.
      // A bundle keyed as a digest carries its own content revision per CVE, so
      // it is validated below like any other payload even when it references no
      // findings (a consolidated digest view can legitimately be a summary).
      permanent = true;
      staleAdvisory = true;
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
      const findingMap = await getMany<Finding>(pool, 'findings', declaredFindingIds);
      const findings = [...findingMap.values()];
      const assetIds = [...new Set(findings.map((f) => f.matchedAssetId))];
      const cveIds = [...new Set(findings.map((f) => f.cveId))];
      // Only inventory that is still active can confirm a finding. A paused,
      // disabled or deleted asset must not let a queued advisory pass the
      // applicability recheck and reach the transport, so inactive rows are
      // dropped here and the finding is reported as no longer matching below.
      const [storedAssets, cveMap, withdrawalMap] = await Promise.all([
        getMany<WatchListItem>(pool, 'watchlist', assetIds),
        getMany<NormalizedCVE>(pool, 'cveData', cveIds),
        getMany<{ modifiedDate: string }>(pool, 'cveWithdrawals', cveIds),
      ]);
      const assetMap = new Map([...storedAssets].filter(([, asset]) => asset.active !== false));
      for (const id of declaredFindingIds) {
        const finding = findingMap.get(id);
        const asset = finding ? assetMap.get(finding.matchedAssetId) : undefined;
        const cachedCve = finding ? cveMap.get(finding.cveId) : undefined;
        const withdrawal = finding ? withdrawalMap.get(finding.cveId) : undefined;
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
                // Fall back to the documented defaults for any setting the stored
                // object does not carry, so revalidation applies the same policy
                // the pipeline used instead of an implicit 90% threshold.
                { ...DEFAULT_SETTINGS, ...settings, scopeHours: 0 },
                'Server worker',
                false,
                vendorAliases,
                productAliases,
                undefined,
                aliasEntries,
              ).newFindings[0]
            : undefined;
        if (match) currentFindings.push(match);
        const reason = !finding
          ? 'a finding was removed'
          : ['RESOLVED', 'FALSE_POSITIVE', 'PATCH_APPLIED'].includes(finding.status)
            ? 'a finding was resolved or dismissed'
            : cve && withdrawal && Date.parse(cve.modifiedDate) <= Date.parse(withdrawal.modifiedDate)
              ? 'a CVE was withdrawn'
              : cve &&
                  job.payload.cveRevisions?.[cve.cveId] &&
                  job.payload.cveRevisions[cve.cveId] !== revision(cve)
                ? 'CVE intelligence changed'
                : !match
                  ? 'current inventory no longer matches'
                  : match.notificationStatus !== 'QUEUED_FOR_DISPATCH'
                    ? (holdGated = true) && 'current applicability or confidence policy requires review'
                    : job.payload.findingRevisions?.[id] !== findingRevision(match)
                      ? 'inventory or matching evidence changed'
                      : undefined;
        if (reason) invalid.push(reason);
      }
      // The queued payload contains the complete advisory. Sending it after any
      // finding becomes stale would disclose or act on invalidated inventory.
      // Mark the bundle as stale and trigger an immediate rebuild instead of
      // surfacing this as a hard error that requires operator intervention.
      if (invalid.length) {
        // A first-pass send nobody approved yet is held for review; an approved
        // send that is still held keeps the stale-bundle recovery so the finding
        // returns to the review queue rather than being re-sent silently.
        if (
          holdGated &&
          !currentFindings.some((finding) => finding.notificationStatus === 'QUEUED_FOR_DISPATCH') &&
          !job.review_approved &&
          job.channel === 'email'
        ) {
          routeToReview = true;
          throw new Error(`Some advisory findings require review: ${[...new Set(invalid)].join('; ')}.`);
        }
        permanent = true;
        staleAdvisory = true;
        throw new Error(
          `Some advisory findings are no longer applicable; rebuild from current inventory. Reason: ${[...new Set(invalid)].join('; ')}.`,
        );
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
          permanent = true;
          throw new Error('Recipient subscription no longer permits unscored intelligence');
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
        permanent = true;
        throw new Error('Webhook subscription does not permit native intelligence');
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
          const retryAt = /^\d+$/.test(delay)
            ? Date.now() + Number(delay) * 1000
            : /[a-z]/i.test(delay)
              ? Date.parse(delay)
              : NaN;
          if (retryAt > Date.now()) {
            if (!Number.isFinite(retryAt) || retryAt > 8640000000000000) {
              permanent = true;
              throw new Error(
                'Webhook Retry-After exceeds supported scheduling range; operator review required',
              );
            }
            retryNotBefore = retryAt;
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
  let finalized = false;
  await transaction(pool, async (db) => {
    const current = await db.query('SELECT status,lock_token FROM outbox WHERE id=$1 FOR UPDATE', [job.id]);
    if (current.rows[0]?.lock_token !== job.lock_token) return;
    const failed =
        !!error &&
        !routeToReview &&
        (permanent || !retryPolicy.enabled || job.attempts >= retryPolicy.maxAttempts),
      next = new Date(Math.max(retryNotBefore, Date.now() + emailRetryDelayMs(job.attempts, retryPolicy)));
    await db.query(
      'UPDATE outbox SET status=$2,next_attempt=$3,error=$4,provider_id=$5,locked_at=NULL,lock_token=NULL,updated_at=now() WHERE id=$1',
      [
        job.id,
        routeToReview ? 'REVIEW' : error ? (failed ? 'FAILED' : 'QUEUED') : 'ACCEPTED',
        next,
        // Keep the reason on a review-routed job: the operator needs it in the
        // review queue, and the reviewer must not have to re-derive why.
        !routeToReview && !error ? null : error || null,
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
      if (log) {
        // FIX: Correct sentAt logic to preserve sent timestamp on retries.
        // Only stamp sentAt when the email is accepted; preserve the existing
        // value on RETRYING so a provider-accepted-but-temporarily-deferred
        // timestamp survives the retry cycle.
        const status = routeToReview
          ? 'REVIEW_REQUIRED'
          : error
            ? failed
              ? 'FAILED'
              : 'RETRYING'
            : 'ACCEPTED';
        const sentAt =
          status === 'ACCEPTED' ? new Date().toISOString() : status === 'RETRYING' ? log.sentAt : undefined;
        await put(db, 'emailLogs', job.id, {
          ...log,
          provider: emailProvider || log.provider,
          status,
          attemptCount: job.attempts,
          errorMessage: routeToReview ? undefined : error || undefined,
          nextRetryTime: routeToReview ? null : error && !failed ? next.toISOString() : null,
          sentAt,
        });
      }
    } else {
      const log = await get<WebhookDeliveryLog>(db, 'webhookLogs', job.id);
      if (log)
        await put(db, 'webhookLogs', job.id, {
          ...log,
          status: error ? (failed ? 'FAILED' : 'QUEUED') : 'SUCCESS',
          statusCode,
          hmacSignature: signature,
          // FIX: Preserve sentAt on retry (QUEUED) and null on permanent
          // failure (FAILED), mirroring the email-log sentAt fix. The old
          // `error ? '' : ...` cleared the timestamp on every error including
          // retries, losing the original dispatch time.
          sentAt: !error ? new Date().toISOString() : failed ? null : log.sentAt,
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
          "SELECT count(*) FILTER(WHERE status='FAILED')::int AS failed,count(*) FILTER(WHERE status IN ('REVIEW','QUEUED','SENDING'))::int AS pending,count(*) FILTER(WHERE status='ACCEPTED')::int AS accepted FROM outbox WHERE advisory_id=$1",
          [advisory.id],
        )
      ).rows[0];
      // Acceptance by a transport is not proof of inbox delivery. A bundle whose
      // only outcome so far is a transport failure stays FAILED; an advisory can
      // have several batches over its lifetime (daily digests, re-queued
      // findings), so an earlier acceptance must not be overwritten by a later
      // partial failure, and a failure must not erase an accepted bundle.
      advisory.deliveryStatus = Number(totals.pending)
        ? 'PENDING'
        : Number(totals.accepted)
          ? 'ACCEPTED'
          : Number(totals.failed)
            ? 'FAILED'
            : advisory.deliveryStatus;
      await put(db, 'advisories', advisory.id, advisory);
      if (!error) {
        const dispatchKey = job.payload.digestKey ?? job.dedupe_key.split(':email:')[0].split(':webhook:')[0];
        const dispatchIds = declaredCveIds.map((cveId) => `${cveId}:${dispatchKey}`);
        const priorAlerts = await getMany<AlertedCVE>(db, 'alertedCves', declaredCveIds);
        const priorDispatches = await getMany(db, 'alertDispatches', dispatchIds);
        for (const cveId of declaredCveIds) {
          const prior = priorAlerts.get(cveId);
          const now = new Date().toISOString();
          // Digest jobs carry one batch key across every recipient, so the same
          // CVE is counted once even when several subscription cohorts receive
          // it. Non-digest jobs retain the original content-revision key.
          const same =
            prior?.lastDispatchKey === dispatchKey || !!priorDispatches.get(`${cveId}:${dispatchKey}`);
          await put(db, 'alertDispatches', `${cveId}:${dispatchKey}`, {
            cveId,
            dispatchKey,
            acceptedAt: now,
          });
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
      }
      // Batch-fetch all finding rows in a single query instead of per-finding.
      const findingMap = await getMany<Finding>(db, 'findings', advisory.findingIds);
      // Only the findings this target actually delivered describe this
      // recipient's bundle. Assessment or digest bundles that are already
      // accepted must not be flipped back to FAILED because the digest window
      // rolled over and a later partial bundle for the same advisory is still
      // pending.
      const deliveredIds =
        job.payload.includedFindingIds !== undefined ? new Set(job.payload.includedFindingIds) : undefined;
      for (const findingId of deliveredIds ?? advisory.findingIds) {
        const f = findingMap.get(findingId);
        if (!f) continue;
        // A finding held for review was queued in this bundle deliberately
        // (assessment and digest payloads may include them). Once the transport
        // for that bundle accepts it, its notification lifecycle is dispatched;
        // otherwise it would remain REVIEW_REQUIRED — perpetually re-selected by
        // the daily digest — while its advisory reports ACCEPTED. A rejected or
        // still-pending bundle keeps the hold in place.
        const reviewHeld = f?.notificationStatus === 'REVIEW_REQUIRED';
        const releasedByReview = reviewHeld && !error && !totals.pending && !totals.failed;
        // Generated advisories (pipeline, digest, daily) are never bound to the
        // findings they describe — only manually reviewed advisories set
        // `advisoryId`. Gating this bookkeeping on that binding left every
        // auto-queued finding marked QUEUED_FOR_DISPATCH after an accepted send,
        // so it was re-queued and re-sent on the next pipeline run. A
        // REVIEW_REQUIRED finding released by this acceptance has neither
        // field set yet, so it must be admitted explicitly.
        if (f.advisoryId === advisory.id || (!f.advisoryId && f.autoDispatchedAt) || releasedByReview)
          await put(db, 'findings', findingId, {
            ...f,
            advisoryId: f.advisoryId ?? advisory.id,
            notificationStatus: releasedByReview
              ? 'AUTO_DISPATCHED'
              : ['NOT_APPLICABLE', 'REVIEW_REQUIRED'].includes(f.notificationStatus)
                ? f.notificationStatus
                : totals.pending
                  ? 'QUEUED_FOR_DISPATCH'
                  : totals.failed
                    ? 'DELIVERY_FAILED'
                    : 'AUTO_DISPATCHED',
            autoDispatchedAt:
              (releasedByReview || !reviewHeld) && !totals.pending && !totals.failed
                ? new Date().toISOString()
                : null,
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
    finalized = true;
  });
  if (finalized && staleAdvisory) {
    try {
      const { rebuildFromCurrentInventory } = await import('./pipeline');
      await rebuildFromCurrentInventory(pool, job.advisory_id, error, { payloadRebuilt: legacyRebuilt });
    } catch (rebuildError) {
      await writeEvent(pool, {
        category: 'EMAIL',
        level: 'ERROR',
        code: 'delivery.rebuild_failed',
        message: 'Stale delivery was retained as failed; rebuilding could not complete',
        context: { jobId: job.id, advisoryId: job.advisory_id, ...describeError(rebuildError) },
      });
    }
  }

  return true;
}
