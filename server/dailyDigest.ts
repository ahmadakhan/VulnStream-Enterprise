import type pg from 'pg';
import { get, getMany, list, put, transaction, schemaLockKey, type Db } from './db';
import { writeEvent } from './events';
import { enqueue, findingRevision, revision, recipientAllows } from './delivery';
import { advisoryEmail } from './advisoryEmail';
import { runVulnerabilityPipeline } from '../src/engine/pipelineEngine';
import { buildAliasMap } from '../src/utils/cpeMatcher';
import { resolveTimezone as resolveSettingsTimezone } from '../src/utils/dateTime';
import { DEFAULT_SETTINGS } from '../shared/state';
import {
  DEFAULT_DAILY_DIGEST_CUSTOMIZATION,
  renderDailyDigest,
  renderDailyFindingSummary,
  renderDailyHealthReport,
  type DailyDigestParts,
} from '../src/utils/templateCompiler';
import type {
  Advisory,
  AliasEntry,
  NormalizedCVE,
  WatchListItem,
  AppSettings,
  EmailRecipient,
  Finding,
  TemplateCustomization,
} from '../src/types/index';

/** Advisory-lock class dedicated to the daily digest, distinct from the burst-digest lock (800003). */
const DAILY_LOCK_CLASS = 800004;
const DAILY_SCHEDULE_ID = 'dailyDigest-schedule';
const SEVERITY_RANK: Advisory['severity'][] = ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

/**
 * Daily digest subscription.
 *
 * Unlike the burst digest (which coalesces a live ingestion burst into one email
 * per recipient), the daily digest is a calendar job: once per day, in the
 * operator-configured timezone, it sends each opted-in recipient a single email
 * containing a rolled-up summary of that day's findings plus an operational
 * health-check report.
 *
 * The job is serialized with a session-level advisory lock (mirroring the burst
 * digest and retention workers) and de-duplicated per calendar day via a
 * `systemState` claim row, so a multi-tick window or a multi-replica deployment
 * cannot produce a second 9 AM mail.
 */

// The daily digest runs on the same clock as the UI: the operator-configured
// Settings timezone, or the documented system default when none is stored or
// the stored value is not a zone this runtime knows.
const resolveTimezone = (value: string | undefined): string => resolveSettingsTimezone(value);

const calendarDateKey = (timezone: string, now: number): string =>
  new Intl.DateTimeFormat('en-CA', {
    timeZone: timezone,
    year: 'numeric',
    month: '2-digit',
    day: 'numeric',
  }).format(now);

const wallClock = (timezone: string, now: number): { hour: number; minute: number } => {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone: timezone,
    hourCycle: 'h23',
    hour: 'numeric',
    minute: '2-digit',
  }).formatToParts(now);
  let hour = 0;
  let minute = 0;
  for (const part of parts) {
    if (part.type === 'hour') hour = Number(part.value);
    else if (part.type === 'minute') minute = Number(part.value);
  }
  return { hour, minute };
};

const parseTime = (value: string | undefined): { hour: number; minute: number } => {
  const [h, m] = String(value ?? '09:00').split(':').map(Number);
  return { hour: Number.isFinite(h) ? h : 9, minute: Number.isFinite(m) ? m : 0 };
};

async function readDailyDigestConfig(db: Db): Promise<TemplateCustomization> {
  const row = await get<{ dailyDigestCustomization?: TemplateCustomization }>(db, 'template', 'main');
  return row?.dailyDigestCustomization || DEFAULT_DAILY_DIGEST_CUSTOMIZATION;
}

const severityRank = (s: Advisory['severity']) => SEVERITY_RANK.indexOf(s);

const buildDailyDigestAdvisory = (
  findings: Finding[],
  settings: AppSettings,
  dateKey: string,
): Advisory => {
  const cveIds = Array.from(new Set(findings.map((finding) => finding.cveId))).sort();
  const severity = findings.reduce<Advisory['severity']>(
    (severity, finding) =>
      severityRank(finding.cve.cvss.severity) > severityRank(severity)
        ? finding.cve.cvss.severity
        : severity,
    'UNKNOWN',
  );
  const severityCounts = countSeverities(findings);
  return {
    id: `${settings.advisoryPrefix}DAILY_${dateKey.replace(/-/g, '')}`,
    title: `Daily Vulnerability Digest — ${dateKey}`,
    severity,
    cveIds,
    findingIds: findings.map((finding) => finding.id),
    createdDate: new Date().toISOString(),
    deliveryStatus: 'PENDING',
    recipientCount: 0,
    executiveSummary: `${findings.length} finding(s) in the last 24 hours. ${formatSeverityCounts(severityCounts)}.`,
    remediationInstructions:
      'Review the findings below, confirm applicability against inventory, and deploy tested remediation through your change process.',
    vendorLink:
      Array.from(
        new Set(
          findings
            .map((finding) => finding.cve.remediation?.vendorAdvisoryRef || finding.cve.remediation?.patchUrl)
            .filter(Boolean),
        ),
      ).sort()[0] || '',
    affectedSystems: Array.from(new Set(findings.map((finding) => finding.matchedAssetName))).sort(),
    isDigestBatch: true,
  };
};

const formatSeverityCounts = (counts: Record<string, number>) =>
  Object.entries(counts)
    .filter(([, n]) => n > 0)
    .map(([s, n]) => `${n} ${s.toLowerCase()}`)
    .join(', ');

const countSeverities = (findings: Finding[]): Record<string, number> => {
  const counts: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
  for (const finding of findings) counts[finding.cve.cvss.severity] = (counts[finding.cve.cvss.severity] ?? 0) + 1;
  return counts;
};

interface HealthSnapshot {
  database: 'connected' | 'degraded';
  databaseLatencyMs: number;
  workerStatus: 'DISABLED' | 'NOT_OBSERVED' | 'STALE' | 'HEALTHY';
  workerHeartbeatAgeSeconds: number | null;
  nextScheduledAttempt: string | null;
  backlog: { status: string; count: number }[];
  checkedAt: string;
}

async function computeHealth(db: Db, workerEnabled: boolean, workerHeartbeat: string | null): Promise<HealthSnapshot> {
  const start = performance.now();
  let database: HealthSnapshot['database'] = 'connected';
  try {
    await db.query('SELECT 1');
  } catch {
    database = 'degraded';
  }
  const databaseLatencyMs = Math.round(performance.now() - start);
  const workerHeartbeatAgeSeconds = workerHeartbeat
    ? Math.max(0, Math.floor((Date.now() - new Date(workerHeartbeat).getTime()) / 1000))
    : null;
  const workerStatus: HealthSnapshot['workerStatus'] = !workerEnabled
    ? 'DISABLED'
    : workerHeartbeatAgeSeconds === null
      ? 'NOT_OBSERVED'
      : workerHeartbeatAgeSeconds > 90
        ? 'STALE'
        : 'HEALTHY';
  const deliveryQueue = (
    await db.query<{
      nextScheduledAttempt: string | null;
      expiredLeases: number;
    }>(
      `SELECT
         min(next_attempt) FILTER (WHERE status='QUEUED' AND next_attempt>now()) AS "nextScheduledAttempt",
         count(*) FILTER (WHERE status='SENDING' AND locked_at<now()-interval '2 minutes')::int AS "expiredLeases"
       FROM outbox WHERE status IN ('QUEUED','SENDING')`,
    )
  ).rows[0];
  const backlog = (
    await db.query<{ status: string; count: number }>(
      `SELECT status,count(*)::int AS count FROM outbox WHERE status IN ('QUEUED','SENDING','FAILED','REVIEW') GROUP BY status`,
    )
  ).rows;
  return {
    database,
    databaseLatencyMs,
    workerStatus,
    workerHeartbeatAgeSeconds,
    nextScheduledAttempt: deliveryQueue?.nextScheduledAttempt ?? null,
    backlog,
    checkedAt: new Date().toISOString(),
  };
}


/**
 * Runs the daily digest job. Returns the number of transport jobs queued (0 when
 * the job is not scheduled/claimed, disabled, already sent today, or no recipient
 * has opted in). Intended to be polled on a short interval by the worker; the
 * claim logic guarantees at-most-once execution per calendar day per timezone.
 */
export async function runDailyDigest(pool: pg.Pool): Promise<number> {
  const settings = (await get<AppSettings>(pool, 'settings', 'main')) || DEFAULT_SETTINGS;
  const daily = settings.dailyDigest || DEFAULT_SETTINGS.dailyDigest;
  if (!daily?.enabled) return 0;

  const timezone = resolveTimezone(settings.timezone);
  const now = Date.now();
  const todayKey = calendarDateKey(timezone, now);
  const nowClock = wallClock(timezone, now);
  const targetClock = parseTime(daily.time);
  const pastTarget = nowClock.hour * 60 + nowClock.minute >= targetClock.hour * 60 + targetClock.minute;

  if (!pastTarget) return 0;

  const client = await pool.connect();
  let locked = false;
  try {
    locked =
      (
        await client.query<{ locked: boolean }>(
          `SELECT pg_try_advisory_lock(${DAILY_LOCK_CLASS}, ${schemaLockKey}) AS locked`,
        )
      ).rows[0]?.locked === true;
    if (!locked) return 0;

    return await transaction(
      pool,
      async (db) => {
        const row = await db.query<{ data: Record<string, unknown> }>(
          `SELECT data FROM records WHERE kind='systemState' AND id=$1 FOR UPDATE`,
          [DAILY_SCHEDULE_ID],
        );
        const data = row.rows[0]?.data ?? {};

        const recipients = (await list<EmailRecipient>(db, 'recipients')).filter(
          (r) => r.enabled && r.dailyDigest,
        );
        // The day is claimed only when there is somebody to send to. Claiming it
        // first meant that a tick running before any recipient opted in (or with
        // every recipient temporarily disabled) burned the whole day: the claim
        // request repeated every minute, reported "queued for 0 recipient(s)",
        // and never delivered the findings that were right there in the window.
        // A recipient added later that same day now still receives the digest.
        if (!recipients.length) {
          await put(db, 'systemState', DAILY_SCHEDULE_ID, {
            ...data,
            lastCheckedAt: new Date(now).toISOString(),
          });
          await writeEvent(db, {
            category: 'EMAIL',
            level: 'INFO',
            code: 'digest.daily.no_recipients',
            message: 'Daily digest is enabled but no recipients have opted in',
            context: { date: todayKey, time: daily.time, timezone },
          });
          return 0;
        }
        if (data.lastKey === todayKey) {
          await put(db, 'systemState', DAILY_SCHEDULE_ID, {
            ...data,
            lastCheckedAt: new Date(now).toISOString(),
          });
          return 0;
        }
        // Commit the claim before queueing so a crash mid-send cannot re-fire
        // today's digest.
        await put(db, 'systemState', DAILY_SCHEDULE_ID, {
          ...data,
          lastKey: todayKey,
          lastRun: new Date(now).toISOString(),
          lastRecipients: recipients.length,
        });

        const findingRows = await db.query<{ id: string; created_at: string; data: Finding }>(
          `SELECT data FROM records WHERE kind='findings' AND created_at > now() - interval '24 hours'`,
        );
        // A daily digest is a summary of the last 24 hours of *deliverable*
        // findings. A `REVIEW_REQUIRED` finding is deliberately withheld by the
        // confidence policy or by unverifiable applicability evidence, and the
        // delivery worker refuses to carry it in an email bundle. Including it
        // made the whole digest fail as stale every day (and, because the
        // findings stay held, repeat on the next day too). Held findings remain
        // available for operator review; they are not summarised in the email.
        const candidates: Finding[] = findingRows.rows
          .map((r) => r.data)
          .filter(
            (f) =>
              f &&
              f.cveId &&
              !['RESOLVED', 'FALSE_POSITIVE', 'PATCH_APPLIED'].includes(f.status) &&
              ![
                'NOT_APPLICABLE',
                'SUPPRESSED_VEX_NOT_AFFECTED',
                'DELIVERY_FAILED',
              ].includes(f.notificationStatus),
          );

        // Reassess against today's inventory and policy, including findings
        // held under an older threshold. Never treat a stored hold as approval.
        const ids = [...new Set(candidates.map(f => f.cveId))];
        const [cached, assets, withdrawals, aliases] = await Promise.all([
          getMany<NormalizedCVE>(db, 'cveData', ids),
          getMany<WatchListItem>(db, 'watchlist', [...new Set(candidates.map(f => f.matchedAssetId))]),
          getMany<{ modifiedDate: string }>(db, 'cveWithdrawals', ids),
          list<AliasEntry>(db, 'aliases'),
        ]);
        const cves = new Map(candidates.map(f => [f.cveId, cached.get(f.cveId) || f.cve]));
        const current = runVulnerabilityPipeline([], [...cves.values()], [...assets.values()], [], [],
          { ...DEFAULT_SETTINGS, ...settings, scopeHours: 0 }, 'Daily digest', false,
          buildAliasMap(aliases, 'VENDOR'), buildAliasMap(aliases, 'PRODUCT'), undefined, aliases).newFindings;
        const matches = new Map(current.map(f => [`${f.cveId}:${f.matchedAssetId}`, f]));
        const findings = candidates.flatMap(f => {
          const match = matches.get(`${f.cveId}:${f.matchedAssetId}`);
          const withdrawal = withdrawals.get(f.cveId);
          if (match?.notificationStatus !== 'QUEUED_FOR_DISPATCH' ||
              (withdrawal && Date.parse(match.cve.modifiedDate) <= Date.parse(withdrawal.modifiedDate))) return [];
          return [{ ...f, ...match, id: f.id }];
        });

        const dailyConfig = await readDailyDigestConfig(db);
        const advisory = buildDailyDigestAdvisory(findings, settings, todayKey);
        const heldForReview = findingRows.rows.filter(
          (r) => r.data?.cveId && r.data.notificationStatus === 'REVIEW_REQUIRED',
        ).length;
        const worker = (await db.query('SELECT heartbeat FROM scheduler_state WHERE id=1')).rows[0];
        const health = daily.includeHealthReport
          ? await computeHealth(db, settings.schedulerEnabled, worker?.heartbeat ?? null)
          : null;
        const healthReportHtml = health ? renderDailyHealthReport(health, dailyConfig) : '';
        // No findings and no health report means there is nothing to email. Skip
        // enqueueing to avoid deliverNext rejecting an empty advisory as stale
        // and triggering a futile pipeline rebuild every day.
        if (!findings.length && !health) {
          await writeEvent(db, {
            category: 'EMAIL',
            level: 'INFO',
            code: 'digest.daily.no_findings',
            message: 'Daily digest skipped: no findings in the last 24 hours and health report disabled',
            context: { date: todayKey },
          });
          return 0;
        }
        let jobs = 0;
        for (const recipient of recipients) {
          const included = findings.filter(finding => recipientAllows(recipient, finding));
          if (!included.length && !health) continue;
          const view = buildDailyDigestAdvisory(included, settings, todayKey);
          const severityCounts = countSeverities(included);
          const parts: DailyDigestParts = {
            advisory_id: view.id,
            advisory_title: view.title,
            dispatch_date: new Date().toISOString(),
            severity: view.severity,
            finding_count: included.length,
            severity_counts: formatSeverityCounts(severityCounts),
            findings_summary: renderDailyFindingSummary(
              included.map((finding) => ({
                cveId: finding.cveId,
                severity: finding.cve.cvss.severity,
                assetName: finding.matchedAssetName,
                vendor: finding.matchedAssetVendor,
              })),
              dailyConfig,
            ),
            health_report: healthReportHtml,
            recipient_name: recipient.name || recipient.email,
          };
          const html = renderDailyDigest(dailyConfig, parts);
          const payload = {
            ...advisoryEmail(view, html),
            cveIds: view.cveIds,
            recipientEmail: recipient.email,
            includedFindingIds: included.map((finding) => finding.id),
            // Content-revision evidence, so the delivery worker can prove the
            // queued body still describes the current CVE cache instead of
            // rejecting it as a revision-less legacy payload.
            findingRevisions: Object.fromEntries(
              included.map((finding) => [finding.id, findingRevision(finding)]),
            ),
            cveRevisions: Object.fromEntries(
              included.map((finding) => [finding.cveId, revision(finding.cve)]),
            ),
            digestKey: `daily:${todayKey}`,
            dailyDigest: true,
          };
          if (
            await enqueue(
              db,
              'email',
              recipient.id,
              advisory.id,
              payload,
              `daily:${todayKey}:email:${recipient.id}`,
              recipient.deliveryGroup === 'EVERYONE' ? 'REVIEW' : 'QUEUED',
            )
          )
            jobs++;
        }

        advisory.recipientCount = jobs;
        advisory.deliveryStatus = 'PENDING';
        await put(db, 'advisories', advisory.id, advisory);
        await writeEvent(db, {
          category: 'EMAIL',
          level: 'INFO',
          code: 'digest.daily.sent',
          message: `Daily digest queued for ${jobs} recipient(s) with ${findings.length} finding(s)`,
          context: {
            advisoryId: advisory.id,
            recipients: jobs,
            findings: findings.length,
            heldForReview,
            date: todayKey,
            time: daily.time,
            timezone,
          },
        });
        return jobs;
      },
      client,
    );
  } finally {
    if (locked)
      await client
        .query(`SELECT pg_advisory_unlock(${DAILY_LOCK_CLASS}, ${schemaLockKey}) AS locked`)
        .catch(() => {});
    client.release();
  }
}
