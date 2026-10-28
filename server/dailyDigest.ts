import type pg from 'pg';
import { get, list, put, transaction, schemaLockKey, type Db } from './db';
import { writeEvent } from './events';
import { enqueue } from './delivery';
import { advisoryEmail } from './advisoryEmail';
import { renderAdvisory } from './advisoryRender';
import { DEFAULT_SETTINGS } from '../shared/state';
import {
  DEFAULT_TEMPLATE_CUSTOMIZATION,
  compileCustomizedTemplate,
} from '../src/utils/templateCompiler';
import type {
  Advisory,
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

const resolveTimezone = (value: string | undefined): string => {
  if (!value) return 'UTC';
  try {
    new Intl.DateTimeFormat('en', { timeZone: value });
    return value;
  } catch {
    return 'UTC';
  }
};

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

async function readTemplate(db: Db): Promise<string> {
  const row = await get<{ templateCustomization?: TemplateCustomization }>(db, 'template', 'main');
  return (row?.templateCustomization && compileCustomizedTemplate(row.templateCustomization)) ||
    compileCustomizedTemplate(DEFAULT_TEMPLATE_CUSTOMIZATION);
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
  const severityCounts: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
  for (const finding of findings) severityCounts[finding.cve.cvss.severity] = (severityCounts[finding.cve.cvss.severity] ?? 0) + 1;
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

const renderHealthReport = (health: HealthSnapshot): string => `
  <h2 style="margin:24px 0 8px;font-family:Arial,sans-serif;font-size:16px;font-weight:600;color:#e4e4e7">Operational health check</h2>
  <table style="font-family:Arial,sans-serif;font-size:12px;border-collapse:collapse;width:100%;margin-bottom:16px">
    <tr><td style="padding:4px 8px;border:1px solid #27272a">Database</td><td style="padding:4px 8px;border:1px solid #27272a">${health.database} (${health.databaseLatencyMs} ms)</td></tr>
    <tr><td style="padding:4px 8px;border:1px solid #27272a">Delivery worker</td><td style="padding:4px 8px;border:1px solid #27272a">${health.workerStatus}${health.workerHeartbeatAgeSeconds !== null ? ` · ${health.workerHeartbeatAgeSeconds}s since heartbeat` : ''}</td></tr>
    <tr><td style="padding:4px 8px;border:1px solid #27272a">Next scheduled delivery</td><td style="padding:4px 8px;border:1px solid #27272a">${health.nextScheduledAttempt ? new Date(health.nextScheduledAttempt).toISOString() : 'none pending'}</td></tr>
    <tr><td style="padding:4px 8px;border:1px solid #27272a">Outbox backlog</td><td style="padding:4px 8px;border:1px solid #27272a">${health.backlog.map((b) => `${b.count} ${b.status}`).join(', ') || 'idle'}</td></tr>
    <tr><td style="padding:4px 8px;border:1px solid #27272a">Checked at</td><td style="padding:4px 8px;border:1px solid #27272a">${new Date(health.checkedAt).toISOString()}</td></tr>
  </table>`;

const renderFindingsSummary = (findings: Finding[]): string => {
  if (!findings.length)
    return '<p style="font-family:Arial,sans-serif;font-size:12px;color:#a1a1aa">No findings in the last 24 hours.</p>';
  const bySeverity: Record<string, Finding[]> = {};
  for (const finding of findings)
    (bySeverity[finding.cve.cvss.severity] ||= []).push(finding);
  const sections = (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'] as const)
    .filter((s) => bySeverity[s]?.length)
    .map(
      (s) =>
        `<h3 style="margin:16px 0 4px;font-family:Arial,sans-serif;font-size:13px;font-weight:600;color:#e4e4e7">${s} (${bySeverity[s].length})</h3><ul style="font-family:Arial,sans-serif;font-size:11px;color:#d4d4d8;margin:0 0 8px;padding-left:18px;list-style:disc">
          ${bySeverity[s]
            .slice(0, 25)
            .map(
              (f) =>
                `<li style="margin-bottom:2px"><strong>${f.cveId}</strong> — ${f.matchedAssetName}${f.matchedAssetVendor ? ` (${f.matchedAssetVendor})` : ''}</li>`,
            )
            .join('')}
          ${bySeverity[s].length > 25 ? `<li style="color:#71717a">…and ${bySeverity[s].length - 25} more</li>` : ''}
        </ul>`,
    )
    .join('');
  return `<h2 style="margin:24px 0 8px;font-family:Arial,sans-serif;font-size:16px;font-weight:600;color:#e4e4e7">Findings summary</h2>${sections}`;
};

const appendDailySections = (html: string, findings: Finding[], health: HealthSnapshot | null): string => {
  const extra = `${renderFindingsSummary(findings)}${health ? renderHealthReport(health) : ''}`;
  return html.includes('</body>') ? html.replace(/<\/body>/i, `${extra}</body>`) : `${html}${extra}`;
};

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
        if (data.lastKey === todayKey) {
          await put(db, 'systemState', DAILY_SCHEDULE_ID, {
            ...data,
            lastCheckedAt: new Date(now).toISOString(),
          });
          return 0;
        }

        const recipients = (await list<EmailRecipient>(db, 'recipients')).filter(
          (r) => r.enabled && r.dailyDigest,
        );
        // Commit the claim first so a crash mid-send cannot re-fire today's digest.
        await put(db, 'systemState', DAILY_SCHEDULE_ID, {
          ...data,
          lastKey: todayKey,
          lastRun: new Date(now).toISOString(),
          lastRecipients: recipients.length,
        });
        if (!recipients.length) {
          await writeEvent(db, {
            category: 'EMAIL',
            level: 'INFO',
            code: 'digest.daily.no_recipients',
            message: 'Daily digest is enabled but no recipients have opted in',
            context: { date: todayKey, time: daily.time, timezone },
          });
          return 0;
        }

        const findingRows = await db.query<{ data: Finding }>(
          `SELECT data FROM records WHERE kind='findings' AND created_at > now() - interval '24 hours'`,
        );
        const findings: Finding[] = findingRows.rows
          .map((r) => r.data)
          .filter((f) => f && f.cveId && f.notificationStatus !== 'NOT_APPLICABLE');

        const template = await readTemplate(db);
        const advisory = buildDailyDigestAdvisory(findings, settings, todayKey);
        const worker = (await db.query('SELECT heartbeat FROM scheduler_state WHERE id=1')).rows[0];
        const health = daily.includeHealthReport
          ? await computeHealth(db, settings.schedulerEnabled, worker?.heartbeat ?? null)
          : null;
        const html = appendDailySections(renderAdvisory(template, advisory), findings, health);

        let jobs = 0;
        for (const recipient of recipients) {
          const payload = {
            ...advisoryEmail(advisory, html),
            cveIds: advisory.cveIds,
            recipientEmail: recipient.email,
            includedFindingIds: findings.map((finding) => finding.id),
            digestKey: `daily:${todayKey}`,
          };
          if (
            await enqueue(
              db,
              'email',
              recipient.id,
              advisory.id,
              payload,
              `daily:${todayKey}:email:${recipient.id}`,
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
