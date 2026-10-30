import { describeError, writeEvent } from './events';
import { mergeArticles, matchIntelligence } from '../src/utils/intelligenceMatcher';
import { formatExecutionName, formatAdvisoryId } from '../src/utils/executionName';
import type pg from 'pg';
import { randomUUID, createHash } from 'node:crypto';
import {
  get,
  getForUpdate,
  getMany,
  list,
  put,
  putMany,
  remove,
  transaction,
  appendAudit,
  pipelineState,
  schemaLockKey,
} from './db';
import { DEFAULT_SETTINGS } from '../shared/state.ts';
import type {
  AppSettings,
  PipelineExecution,
  ThreatFeed,
  Advisory,
  Finding,
  NormalizedCVE,
  WatchListItem,
  AliasEntry,
  EmailDeliveryLog,
  WebhookDeliveryLog,
  EmailRecipient,
  IntelligenceMatch,
  IntelligenceArticle,
} from '../src/types/index.ts';
import { buildAliasMap, parseCPE23 } from '../src/utils/cpeMatcher';
import {
  deriveCorrelationAliases,
  deriveInventoryAliases,
  reconcileAutoAliases,
} from '../src/utils/aliasLifecycle';
import { mergeCveRecords, normalizeCveId, stableJson } from '../src/utils/deduplicator';
import { reconcileFindings } from '../src/engine/reconcileFindings';
import {
  applyVexSuppression,
  determineExploitRisk,
  rankAndRateLimitZeroDays,
  runVulnerabilityPipeline,
} from '../src/engine/pipelineEngine';
import { ingestFeed, type IngestContext } from './ingestion';
import { bindClusterToCve, clusterSuppressedAssets } from './correlation/clusters.ts';
import { refreshCandidatePairs } from './versionIndex';
import { recoveryDue, recoveryAt, shouldStartAutomaticRun } from './feedRecovery';
import { ingestionWindow, type FeedCursor, OPENCVE_MAX_WINDOW_HOURS } from './ingestionState';
import type { Requester } from './network';
import type { Config } from './config';
import {
  enqueue,
  findingRevision,
  queueAdvisory,
  queueNewsEvidenceNotifications,
  queueUnverifiableMatchNotification,
  revision,
  type Job,
} from './delivery';
import { bufferFindingsForDigest } from './digest';
import { renderAdvisory } from './advisoryRender';
import { HttpError } from './validation';
import { advisoryEmail } from './advisoryEmail';
import { currentAdvisoryView, currentAdvisoryBody } from './advisoryRebuild';
export { renderAdvisory } from './advisoryRender';
/**
 * Rebuilds a queued job's stored payload from current intelligence.
 *
 * Jobs queued before content-revision evidence existed (or whose payload was
 * queued under an older revision scheme) carry no `cveRevisions`, so the
 * delivery worker cannot prove the advisory text still describes the current
 * CVE corpus. Rather than failing such a job permanently, the payload is
 * regenerated from the advisory and the findings it currently references, with
 * fresh `cveRevisions` / `findingRevisions` computed from the current cache. A
 * job whose findings no longer match the stored CVE revisions keeps its stale
 * evidence, so the worker's normal applicability check still rejects it and
 * rebuilds the bundle instead of delivering outdated content.
 *
 * Returns true when the payload was rewritten; false when the job no longer
 * exists, belongs to a native correlation (which has its own evidence hash), or
 * already carries revision evidence.
 */
export async function rebuildLegacyDeliveryPayload(db: pg.Pool | pg.PoolClient, job: Job): Promise<boolean> {
  if (job.payload.nativeCorrelation) return false;
  const advisory = await get<Advisory>(db, 'advisories', job.advisory_id);
  if (!advisory) return false;
  const declaredCves = job.payload.cveIds ?? advisory.cveIds;
  const evidence = job.payload.cveRevisions ?? {};
  if (declaredCves.every(cveId => evidence[cveId])) return false;
  const findingIds = job.payload.includedFindingIds ?? advisory.findingIds;
  const findingMap = await getMany<Finding>(db, 'findings', findingIds);
  if (!findingIds.length || findingMap.size !== new Set(findingIds).size) return false;
  const settings = (await get<AppSettings>(db, 'settings', 'main')) || DEFAULT_SETTINGS;
  const aliases = await list<AliasEntry>(db, 'aliases');
  const current: Finding[] = [];
  for (const finding of findingMap.values()) {
    // Serial: `db` is a single client inside this transaction, and issuing
    // queries concurrently on one pg connection races the protocol queue.
    const asset = await get<WatchListItem>(db, 'watchlist', finding.matchedAssetId);
    const cve = await get<NormalizedCVE>(db, 'cveData', finding.cveId);
    const withdrawal = await get<{ modifiedDate: string }>(db, 'cveWithdrawals', finding.cveId);
    if (!asset?.active || !cve || ['RESOLVED', 'FALSE_POSITIVE', 'PATCH_APPLIED'].includes(finding.status) ||
        (withdrawal && Date.parse(cve.modifiedDate) <= Date.parse(withdrawal.modifiedDate))) return false;
    const match = runVulnerabilityPipeline([], [cve], [asset], [], [], { ...DEFAULT_SETTINGS, ...settings, scopeHours: 0 },
      'Server worker', false, buildAliasMap(aliases, 'VENDOR'), buildAliasMap(aliases, 'PRODUCT'), undefined, aliases).newFindings[0];
    if (match?.notificationStatus !== 'QUEUED_FOR_DISPATCH') return false;
    current.push({ ...finding, ...match, id: finding.id });
  }
  const view = currentAdvisoryView(advisory, current);
  if (view.cveIds.length !== new Set(declaredCves).size || declaredCves.some(id => !view.cveIds.includes(id))) return false;
  const payload = {
    ...job.payload,
    ...await currentAdvisoryBody(db, view, current),
    cveIds: view.cveIds,
    includedFindingIds: view.findingIds,
    cveRevisions: Object.fromEntries(current.map(f => [f.cveId, revision(f.cve)])),
    findingRevisions: Object.fromEntries(current.map(f => [f.id, findingRevision(f)])),
  };
  const updated = await db.query(
    "UPDATE outbox SET payload=$2::jsonb, review_approved=false, updated_at=now() WHERE id=$1 AND (status='QUEUED' OR (status='SENDING' AND lock_token=$3))",
    [job.id, JSON.stringify(payload), job.lock_token],
  );
  if (!updated.rowCount) return false;
  job.payload = payload;
  job.review_approved = false;
  return true;
}

type KevSnapshot = {
  fingerprint: string;
  etag?: string;
  kev: NonNullable<Awaited<ReturnType<typeof ingestFeed>>['kev']>;
};
const sourceFingerprint = (feed: ThreatFeed) =>
  createHash('sha256')
    .update(JSON.stringify([feed.type, feed.url, feed.authType, feed.authSecretKey || '']))
    .digest('hex');
const matchingCveSignature = (cves: NormalizedCVE[]) => {
  const digest = createHash('sha256');
  for (const cve of [...cves].sort((a, b) => a.cveId.localeCompare(b.cveId)))
    digest.update(
      stableJson({
        cveId: cve.cveId,
        title: cve.title,
        description: cve.description,
        cpeMatches: cve.cpeMatches,
        cpeMatchDetails: cve.cpeMatchDetails,
        versionRange: cve.versionRange,
        purls: cve.purls,
        applicabilityRequiresReview: cve.applicabilityRequiresReview,
      }),
    );
  return digest.digest('hex');
};
const inventorySignature = (assets: WatchListItem[]) => {
  const digest = createHash('sha256');
  for (const asset of [...assets].sort((a, b) => a.id.localeCompare(b.id))) digest.update(stableJson(asset));
  return digest.digest('hex');
};
const aliasSignature = (entries: readonly AliasEntry[]) => {
  const digest = createHash('sha256');
  for (const entry of [...entries].sort((a, b) => a.id.localeCompare(b.id)))
    digest.update(
      stableJson({
        id: entry.id,
        scope: entry.scope,
        canonical: entry.canonical,
        aliases: entry.aliases,
        source: entry.source,
        provenance: entry.provenance,
        expiresAt: entry.expiresAt,
      }),
    );
  return digest.digest('hex');
};
/** (vendor, product) identities a CVE asserts, used to join pre-CVE clusters.
 * Derived only from non-wildcard CPE criteria; a CVE with no parseable
 * structured identity cannot bind a cluster (binding on prose would let a
 * poisoned CVE claim another vulnerability's rulings). */
/** Bounded retries for a pre-CVE disposition bind that lost its lock race. */
const DEFERRED_BIND_MAX_ATTEMPTS = 5;
function cveClusterIdentities(cve: NormalizedCVE): { vendor: string; product: string }[] {
  const criteria = cve.cpeMatchDetails?.length
    ? cve.cpeMatchDetails.map((detail) => detail.criteria)
    : cve.cpeMatches;
  const identities = new Map<string, { vendor: string; product: string }>();
  for (const criterion of criteria) {
    const parsed = parseCPE23(criterion);
    if (!parsed.isValid || /[?*]/.test(parsed.vendor) || /[?*]/.test(parsed.product)) continue;
    const vendor = parsed.vendor.toLowerCase();
    const product = parsed.product.toLowerCase();
    identities.set(`${vendor}\u0000${product}`, { vendor, product });
  }
  return [...identities.values()];
}
export async function queueRun(
  pool: pg.Pool,
  scope: number | undefined,
  actor: string,
  incrementalFeeds = true,
): Promise<PipelineExecution> {
  return transaction(
    pool,
    async (db) => {
      const existing = (await list<PipelineExecution>(db, 'executions')).find((e) =>
        ['QUEUED', 'RUNNING'].includes(e.status),
      );
      if (existing) return existing;
      const settings = (await get<AppSettings>(db, 'settings', 'main')) || DEFAULT_SETTINGS;
      const id = randomUUID();
      const execution: PipelineExecution = {
        id,
        name: formatExecutionName(id),
        startTime: new Date().toISOString(),
        endTime: null,
        status: 'QUEUED',
        scopeHours: scope ?? settings.scopeHours,
        incrementalFeeds,
        phases: [],
        stats: {
          rawIngested: 0,
          normalized: 0,
          deduplicated: 0,
          inRunDuplicatesDropped: 0,
          matchedWatchlist: 0,
          autoDispatchedNotifications: 0,
          advisoriesDispatched: 0,
          webhooksFired: 0,
          vexSuppressedCount: 0,
        },
        logs: [],
      };
      await put(db, 'executions', id, execution);
      await writeEvent(db, {
        category: 'PIPELINE',
        code: 'pipeline.queued',
        message: 'Pipeline queued',
        runId: id,
      });
      await appendAudit(db, 'Pipeline queued', `Execution ${id}`, actor, 'PIPELINE');
      return execution;
    },
    undefined,
    { locks: ['pipeline-queue'] },
  );
}
/** Recover an unsent stale advisory after its failed attempt is committed.
 * Rebuild applicable subsets, invalidate remaining queued siblings, and leave
 * every in-flight delivery lease untouched. Policy holds do not start ingestion
 * loops; a wholly inapplicable bundle schedules one reconciliation run.
 */
export async function rebuildFromCurrentInventory(
  pool: pg.Pool,
  advisoryId: string,
  reason: string,
  options: { payloadRebuilt?: boolean } = {},
): Promise<void> {
  if (!options.payloadRebuilt) {
    const legacy = await pool.query<Job>(
      "SELECT * FROM outbox WHERE advisory_id=$1 AND status='QUEUED' AND payload->'cveRevisions' IS NULL",
      [advisoryId],
    );
    for (const job of legacy.rows) await rebuildLegacyDeliveryPayload(pool, job).catch(() => false);
  }
  // Regroup the still-deliverable jobs of this bundle before failing the rest,
  // so a single held finding cannot silently drop the deliverable findings.
  const { regrouped, holdGated } = await regroupStaleAdvisory(pool, advisoryId).catch(() => ({
    regrouped: false,
    holdGated: false,
  }));
  await transaction(pool, async db => {
    const invalidated = await db.query<{ id: string; channel: string; attempts: number }>(
      `UPDATE outbox
         SET status='FAILED', error=$1, next_attempt=now(),
             locked_at=NULL, lock_token=NULL, updated_at=now()
       WHERE advisory_id=$2 AND status='QUEUED' RETURNING id,channel,attempts`,
      [reason, advisoryId],
    );
    for (const row of invalidated.rows) {
      if (row.channel === 'email') {
        const log = await getForUpdate<EmailDeliveryLog>(db, 'emailLogs', row.id);
        if (log) await put(db, 'emailLogs', row.id, { ...log, status: 'FAILED', attemptCount: row.attempts, nextRetryTime: null, errorMessage: reason });
      } else {
        const log = await getForUpdate<WebhookDeliveryLog>(db, 'webhookLogs', row.id);
        if (log) await put(db, 'webhookLogs', row.id, { ...log, status: 'FAILED', errorMessage: reason });
      }
    }
  });
  // Fresh replacement jobs are already queued. Only a wholly inapplicable
  // bundle needs correlation to reconcile inventory; policy holds await review.
  if (!regrouped && !holdGated) await queueRun(pool, 24, 'delivery-rebuild');
}
/** Regenerate unsent delivery subsets from current inventory and policy.
 * Queued jobs move to a fresh advisory; failed pre-transport attempts retain
 * their history and receive an idempotent replacement. Accepted and sending
 * jobs are excluded. Only the retained findings bind to the new advisory.
 */
export async function regroupStaleAdvisory(
  pool: pg.Pool,
  advisoryId: string,
): Promise<{ regrouped: boolean; holdGated: boolean }> {
  return transaction(pool, async (db) => {
    const advisory = await get<Advisory>(db, 'advisories', advisoryId);
    if (!advisory) return { regrouped: false, holdGated: false };
    const settings = (await get<AppSettings>(db, 'settings', 'main')) || DEFAULT_SETTINGS;
    const jobs = (
      await db.query<Job>(
        "SELECT * FROM outbox WHERE advisory_id=$1 AND (status='QUEUED' OR (status='FAILED' AND COALESCE(error,'') LIKE '%no longer applicable%')) AND payload->'nativeCorrelation' IS NULL FOR UPDATE",
        [advisoryId],
      )
    ).rows;
    if (!jobs.length) return { regrouped: false, holdGated: false };
    const aliasEntries = await list<AliasEntry>(db, 'aliases');
    const vendorAliases = buildAliasMap(aliasEntries, 'VENDOR');
    const productAliases = buildAliasMap(aliasEntries, 'PRODUCT');
    const deliverability = new Map<string, boolean>();
    const evidence = new Map<
      string,
      { cveRevisions: Record<string, string>; findingRevisions: Record<string, string>; findings: Finding[] }
    >();
    let holdGated = false;
    for (const job of jobs) {
      const findingIds = job.payload.includedFindingIds ?? advisory.findingIds;
      const findings = [...(await getMany<Finding>(db, 'findings', findingIds)).values()];
      const cves = await getMany<NormalizedCVE>(db, 'cveData', [...new Set(findings.map((f) => f.cveId))]);
      const assets = await getMany<WatchListItem>(db, 'watchlist', [...new Set(findings.map((f) => f.matchedAssetId))]);
      const cveRevisions: Record<string, string> = {};
      const findingRevisions: Record<string, string> = {};
      const current: Finding[] = [];
      let held = false;
      for (const finding of findings) {
        const cve = cves.get(finding.cveId) || finding.cve;
        const asset = assets.get(finding.matchedAssetId);
        if (cve) cveRevisions[cve.cveId] = revision(cve);
        // Only findings the current policy and inventory still admit may move to
        // the new bundle; a review-held or unverifiable finding stays in place and
        // is finalized by the caller's FAILED update.
        const withdrawal = await get<{ modifiedDate: string }>(db, 'cveWithdrawals', finding.cveId);
        if (!asset?.active || !cve || ['RESOLVED', 'FALSE_POSITIVE', 'PATCH_APPLIED'].includes(finding.status) ||
            (withdrawal && Date.parse(cve.modifiedDate) <= Date.parse(withdrawal.modifiedDate))) {
          continue;
        }
        const match = runVulnerabilityPipeline(
          [],
          [cve],
          [asset],
          [],
          [],
          { ...DEFAULT_SETTINGS, ...settings, scopeHours: 0 },
          'Server worker',
          false,
          vendorAliases,
          productAliases,
          undefined,
          aliasEntries,
        ).newFindings[0];
        if (match?.notificationStatus === 'REVIEW_REQUIRED') held = true;
        if (match?.notificationStatus !== 'QUEUED_FOR_DISPATCH') {
          continue;
        }
        const fresh = { ...finding, ...match, id: finding.id };
        findingRevisions[finding.id] = findingRevision(fresh);
        current.push(fresh);
      }
      deliverability.set(job.id, current.length > 0);
      evidence.set(job.id, { cveRevisions, findingRevisions, findings: current });
      holdGated ||= held;
    }
    const regroup = jobs.filter((job) => deliverability.get(job.id));
    if (!regroup.length) return { regrouped: false, holdGated };
    const isDigest = Boolean(jobs[0].payload.digestKey) && jobs.every((job) => job.payload.digestKey === jobs[0].payload.digestKey);
    const replacement: Advisory = {
      ...currentAdvisoryView(advisory, [...new Map(regroup.flatMap(job => evidence.get(job.id)!.findings.map(f => [f.id, f] as const))).values()]),
      id: formatAdvisoryId(settings.advisoryPrefix),
      createdDate: new Date().toISOString(),
      deliveryStatus: 'PENDING',
    };
    let regroupedJobs = 0;
    let emailJobs = 0;
    for (const job of regroup) {
      const { cveRevisions, findingRevisions, findings: groupedFindings } = evidence.get(job.id)!;
      const included = groupedFindings.map(f => f.id);
      const body = await currentAdvisoryBody(db, currentAdvisoryView(replacement, groupedFindings), groupedFindings);
      const payload = {
        ...job.payload,
        ...body,
        cveIds: Array.from(new Set(groupedFindings.map(f => f.cveId))).sort(),
        includedFindingIds: included,
        cveRevisions: Object.fromEntries(groupedFindings.map(f => [f.cveId, revision(f.cve)])),
        findingRevisions,
        digestKey: isDigest ? `${job.payload.digestKey}:regrouped` : undefined,
      };
      // Preserve the failed attempt and its log. A deterministic rebuild key
      // prevents the same failed job from creating multiple replacement sends.
      if ((job as Job & { status?: string }).status === 'FAILED') {
        const fingerprint = createHash('sha256').update(stableJson({
          cveRevisions: payload.cveRevisions, findingRevisions, included,
        })).digest('hex');
        const inserted = await enqueue(db, job.channel, job.target_id, replacement.id, payload,
          `rebuild:${job.id}:${fingerprint}`, 'QUEUED', job.priority || 0);
        if (!inserted) continue;
      } else {
      await db.query(
        `UPDATE outbox
            SET advisory_id=$2, payload=$3::jsonb, review_approved=false, status='QUEUED', attempts=0,
                locked_at=NULL, lock_token=NULL, next_attempt=now(), error=NULL, updated_at=now()
          WHERE id=$1 AND (status='QUEUED' OR (status='FAILED' AND COALESCE(error,'') LIKE '%no longer applicable%'))`,
        [
          job.id,
          replacement.id,
          JSON.stringify(payload),
        ],
      );
      }
      regroupedJobs++;
      if (job.channel === 'email') emailJobs++;
      for (const finding of groupedFindings) {
        await put(db, 'findings', finding.id, { ...finding, advisoryId: replacement.id, notificationStatus: 'QUEUED_FOR_DISPATCH' });
      }
    }
    if (!regroupedJobs) return { regrouped: true, holdGated };
    await put(db, 'advisories', replacement.id, { ...replacement, recipientCount: emailJobs });
    await writeEvent(db, {
      category: 'EMAIL',
      code: 'delivery.bundle_regrouped',
      message: `Regrouped ${regroupedJobs} deliverable job(s) from a stale advisory bundle`,
      context: { staleAdvisoryId: advisoryId, advisoryId: replacement.id, jobs: regroupedJobs },
    });
    return { regrouped: true, holdGated };
  });
}
class PipelineStopped extends Error {
  constructor() {
    super('Pipeline stopped by operator; uncommitted results discarded');
  }
}
/** Atomically reject a stale worker write after an operator has stopped a run.
 * A checkpoint read alone leaves a race before the following JSON upsert. */
async function saveActiveExecution(db: pg.PoolClient, execution: PipelineExecution) {
  const saved = await db.query(
    `UPDATE records SET data=$2::jsonb,updated_at=now()
     WHERE kind='executions' AND id=$1 AND data->>'status' IN ('QUEUED','RUNNING')
       AND COALESCE(data->>'stopRequestedAt','')='' RETURNING id`,
    [execution.id, JSON.stringify(execution)],
  );
  if (saved.rowCount) return;
  if (!(await get(db, 'executions', execution.id))) throw new Error('Pipeline execution no longer exists');
  throw new PipelineStopped();
}
export async function stopRun(pool: pg.Pool, id: string, actor: string): Promise<PipelineExecution> {
  return transaction(
    pool,
    async (db) => {
      const run = await getForUpdate<PipelineExecution>(db, 'executions', id);
      if (!run) throw new HttpError(404, 'Execution not found');
      if (!['QUEUED', 'RUNNING'].includes(run.status) || run.stopRequestedAt) return run;
      run.stopRequestedAt = new Date().toISOString();
      if (run.status === 'QUEUED') {
        run.status = 'CANCELLED';
        run.endTime = run.stopRequestedAt;
      }
      run.logs.push('Operator requested stop');
      await put(db, 'executions', id, run);
      await writeEvent(db, {
        category: 'PIPELINE',
        code: 'pipeline.stop_requested',
        message: 'Operator requested pipeline stop',
        runId: id,
      });
      await appendAudit(db, 'Pipeline stop requested', `Execution ${id}`, actor, 'PIPELINE');
      return run;
    },
    undefined,
    { locks: ['pipeline-queue'] },
  );
}
export async function processPipeline(pool: pg.Pool, config: Config, request: Requester): Promise<boolean> {
  const lock = await pool.connect();
  let connectionLost = false;
  const onError = () => {
    connectionLost = true;
  };
  lock.on('error', onError);
  const lockedTransaction = <T>(fn: (db: pg.PoolClient) => Promise<T>) => transaction(pool, fn, lock);
  let locked = false,
    execution: PipelineExecution | undefined;
  let heartbeat: ReturnType<typeof setInterval> | undefined;
  try {
    locked = (await lock.query(`SELECT pg_try_advisory_lock(800003, ${schemaLockKey}) AS locked`)).rows[0]
      .locked;
    if (!locked) return false;
    const runs = await list<PipelineExecution>(pool, 'executions');
    // Owning the advisory lock proves no other live worker owns a run. Recovery
    // is safe because records, advisories and outbox are committed atomically.
    await lockedTransaction(async (db) => {
      for (const scanned of runs.filter((e) => e.status === 'RUNNING')) {
        const stale = await getForUpdate<PipelineExecution>(db, 'executions', scanned.id);
        if (!stale || stale.status !== 'RUNNING') continue;
        if (stale.stopRequestedAt) {
          await put(db, 'executions', stale.id, {
            ...stale,
            status: 'CANCELLED',
            endTime: new Date().toISOString(),
            phases: stale.phases.map((phase) =>
              ['RUNNING', 'PENDING'].includes(phase.status) ? { ...phase, status: 'CANCELLED' } : phase,
            ),
            logs: [...stale.logs, 'Recovered interrupted worker with an outstanding stop request; cancelled'],
          });
          await writeEvent(db, {
            category: 'PIPELINE',
            code: 'pipeline.cancelled',
            message: 'Recovered pipeline stop request',
            runId: stale.id,
          });
          continue;
        }
        const recoveryCount = stale.logs.filter((l) => l.includes('Recovered interrupted worker')).length + 1;
        if (recoveryCount > 3) {
          await put(db, 'executions', stale.id, {
            ...stale,
            status: 'FAILED',
            endTime: new Date().toISOString(),
            logs: [
              ...stale.logs,
              `Worker exceeded maximum recovery attempts (${recoveryCount - 1}); marked FAILED to prevent poison-pill crash loop`,
            ],
          });
          await writeEvent(db, {
            category: 'ISSUE',
            level: 'ERROR',
            code: 'pipeline.recovery_limit_exceeded',
            message: 'Pipeline execution repeatedly failed; marked FAILED',
            runId: stale.id,
          });
          await appendAudit(
            db,
            'Pipeline recovery limit exceeded',
            `Execution ${stale.id} marked FAILED after ${recoveryCount - 1} crashes`,
            'worker',
            'PIPELINE',
            'ERROR',
          );
        } else {
          await put(db, 'executions', stale.id, {
            ...stale,
            status: 'QUEUED',
            logs: [
              ...stale.logs,
              `Recovered interrupted worker (attempt ${recoveryCount}/3); restarting idempotently`,
            ],
          });
        }
      }
    });
    execution = (await list<PipelineExecution>(pool, 'executions'))
      .reverse()
      .find((e) => e.status === 'QUEUED');
    if (!execution) {
      const settings = (await get<AppSettings>(pool, 'settings', 'main')) || DEFAULT_SETTINGS;
      const last = (await pool.query('SELECT last_run, next_catchup_run FROM scheduler_state WHERE id=1'))
        .rows[0];
      const configuredFeeds = await list<ThreatFeed>(pool, 'feeds');
      const cursors = new Map(
        (await pool.query("SELECT id,data FROM records WHERE kind='feedCursors'")).rows.map((row) => [
          row.id,
          row.data as FeedCursor,
        ]),
      );
      const now = Date.now();
      const catchupDue = configuredFeeds.some((feed) => {
        const cursor = cursors.get(feed.id);
        if (!feed.enabled || cursor?.fingerprint !== sourceFingerprint(feed)) return false;
        if (Date.parse(feed.circuitOpenUntil || '') > now) return false;
        // A catch-up in progress respects its next_catchup_at cooldown: hasMore
        // alone must not bypass the cooldown, or multi-run catch-up storms the
        // provider immediately after a partial run.
        if (cursor?.catch_up) {
          if (!cursor.next_catchup_at) return false;
          return Date.parse(cursor.next_catchup_at) <= now;
        }
        return Boolean(cursor?.hasMore);
      });
      // Prioritize catch-up run if scheduled.
      const catchupScheduled = last?.next_catchup_run && Date.parse(last.next_catchup_run) <= now;
      const recoveryProbeDue = configuredFeeds.some((feed) => recoveryDue(feed));
      if (
        shouldStartAutomaticRun({
          schedulerEnabled: settings.schedulerEnabled,
          recoveryProbeDue,
          catchupDue: catchupDue || catchupScheduled,
          lastRun: last?.last_run ? new Date(last.last_run).toISOString() : null,
          intervalMinutes: settings.schedulerIntervalMinutes,
        })
      )
        execution = await queueRun(pool, undefined, 'scheduler');
    }
    await pool.query('UPDATE scheduler_state SET heartbeat=now() WHERE id=1');
    if (!execution) return false;
    const checkpoint = async (db: pg.Pool | pg.PoolClient = pool) => {
      if (connectionLost) throw new Error('Pipeline worker lost its database lock connection');
      const current = await get<PipelineExecution>(db, 'executions', execution!.id);
      if (!current) throw new Error('Pipeline execution no longer exists');
      if (current?.stopRequestedAt || current?.status === 'CANCELLED') throw new PipelineStopped();
    };
    await checkpoint();
    execution.status = 'RUNNING';
    execution.phases = [
      'Feed ingestion',
      'Normalize & deduplicate',
      'Product matching',
      'Delivery queue',
    ].map((name, index) => ({
      name,
      status: index === 0 ? 'RUNNING' : 'PENDING',
      durationMs: 0,
      details: index === 0 ? 'Retrieving and enriching enabled sources' : 'Waiting for dependencies',
    }));
    execution.startTime = new Date().toISOString();
    let heartbeatPending = false;
    heartbeat = setInterval(() => {
      if (heartbeatPending) return;
      heartbeatPending = true;
      void pool
        .query('UPDATE scheduler_state SET heartbeat=now() WHERE id=1')
        .catch(() => console.error(JSON.stringify({ level: 'error', event: 'pipeline-heartbeat' })))
        .finally(() => {
          heartbeatPending = false;
        });
    }, 15000);
    heartbeat.unref();
    await lockedTransaction(async (db) => {
      await checkpoint(db);
      await saveActiveExecution(db, execution!);
      await db.query('UPDATE scheduler_state SET last_run=now() WHERE id=1');
      await writeEvent(db, {
        category: 'PIPELINE',
        code: 'pipeline.started',
        message: 'Pipeline started',
        runId: execution!.id,
      });
    });
    const feeds = (await list<ThreatFeed>(pool, 'feeds')).filter((f) => f.enabled);
    const [cachedCves, cachedWithdrawals, inventory, aliasEntries] = await Promise.all([
      list<NormalizedCVE>(pool, 'cveData'),
      list<{ cveId: string; modifiedDate: string }>(pool, 'cveWithdrawals'),
      list<WatchListItem>(pool, 'watchlist'),
      list<AliasEntry>(pool, 'aliases'),
    ]);
    // Operator-managed additions to the built-in alias thesaurus (see cpeMatcher.ts
    // DEFAULT_VENDOR_ALIASES/DEFAULT_PRODUCT_ALIASES) plus the automatic rows
    // that were derived on previous runs. Inventory-derived aliases are merged
    // immediately so a newly added/renamed asset benefits from the current run;
    // the full add/remove reconciliation happens once correlation evidence for
    // this run is known.
    const inventoryAliases = deriveInventoryAliases(inventory, aliasEntries);
    const startedAliasEntries: AliasEntry[] = [...aliasEntries, ...inventoryAliases];
    const vendorAliases = buildAliasMap(startedAliasEntries, 'VENDOR');
    const productAliases = buildAliasMap(startedAliasEntries, 'PRODUCT');
    const canonicalCache = mergeCveRecords(cachedCves);
    const knownCveModifiedAt = new Map([...canonicalCache].map(([id, cve]) => [id, cve.modifiedDate]));
    const knownWithdrawalAt = new Map(cachedWithdrawals.map((entry) => [entry.cveId, entry.modifiedDate]));
    let succeeded = 0,
      rawCount = 0;
    const results: Awaited<ReturnType<typeof ingestFeed>>[] = [];
    const feedUpdates: ThreatFeed[] = [];
    let preliminaryCorrelation: ReturnType<typeof runVulnerabilityPipeline> | undefined;
    let preliminaryCveSignature = '';
    let preliminaryInventorySignature = '';
    let preliminaryAliasSignature = '';
    let preliminarySourceIds: string[] = [];
    // Bound cross-feed concurrency; each adapter also paces its own pages.
    const ingestSources = async (sources: ThreatFeed[], targets: string[] = []) => {
      const concurrency = Math.min(sources.length, 6);
      let nextIndex = 0;
      const worker = async () => {
        while (nextIndex < sources.length) {
          const i = nextIndex++;
          const feed = sources[i];
          await checkpoint();
          if (feed.circuitOpenUntil && Date.parse(feed.circuitOpenUntil) > Date.now()) {
            execution!.logs.push(
              `Feed ${feed.id}: skipped (circuit open, ${feed.consecutiveFailures} consecutive failures)`,
            );
            continue;
          }
          const start = Date.now();
          // MITRE can return up to 5,000 delta records; at its documented feed
          // pacing that bootstrap needs over 40 minutes for detail retrieval.
          // Give that source enough time to finish atomically while preserving
          // the configured limit for all other feeds.
          const maxDurationSeconds =
            feed.type === 'MITRE_CVE'
              ? Math.max(config.FEED_MAX_DURATION_SECONDS, 3600)
              : config.FEED_MAX_DURATION_SECONDS;
          const deadline = start + maxDurationSeconds * 1000;
          const sourceCheckpoint = async () => {
            await checkpoint();
            if (Date.now() >= deadline)
              throw new Error('Feed ingestion exceeded its configured duration limit');
          };
          try {
            const checkedRequest: Requester = async (url, options) => {
              await sourceCheckpoint();
              const remaining = Math.max(1, deadline - Date.now());
              const response = await request(url, {
                ...options,
                timeoutMs: Math.min(options?.timeoutMs ?? 20000, remaining),
                socketTimeoutMs: Math.min(options?.socketTimeoutMs ?? 15000, remaining),
              });
              await sourceCheckpoint();
              return response;
            };
            const checkedSleep = async (ms: number) => {
              const until = Date.now() + ms;
              while (Date.now() < until) {
                // `sourceCheckpoint` awaits a database read and a clock check, so
                // the remaining time can cross zero between the loop test and the
                // timer. A negative delay is clamped by Node only after warning,
                // which flooded the worker log with TimeoutNegativeWarning.
                const delay = until - Date.now();
                await sourceCheckpoint();
                if (delay <= 0) return;
                await new Promise((resolve) => setTimeout(resolve, Math.min(500, delay)));
              }
            };
            const savedCursor = await get<FeedCursor>(pool, 'feedCursors', feed.id);
            const cursor = savedCursor?.fingerprint === sourceFingerprint(feed) ? savedCursor : undefined;
            if (['NVD_API', 'OPENCVE_API', 'MITRE_CVE', 'VULNCHECK_KEV'].includes(feed.type)) {
              const maxWindow = feed.type === 'OPENCVE_API' ? OPENCVE_MAX_WINDOW_HOURS : 24;
              const window = ingestionWindow(execution!.scopeHours, cursor, undefined, maxWindow);
              execution!.logs.push(
                `Feed ${feed.id}: ${window.incremental ? 'incremental' : 'initial bounded'} sync ${window.start.toISOString()} to ${window.end.toISOString()}`,
              );
            }
            const savedKev =
              feed.type === 'CISA_KEV' ? await get<KevSnapshot>(pool, 'feedSnapshots', feed.id) : undefined;
            const cachedKev = savedKev?.fingerprint === sourceFingerprint(feed) ? savedKev : undefined;
            const context: IngestContext = {
              ...(execution!.incrementalFeeds !== false && cursor ? cursor : {}),
              knownCveModifiedAt,
              knownWithdrawalAt,
              knownCveContent: canonicalCache,
            };
            // A validator is usable only together with its complete source snapshot.
            let result = await ingestFeed(
              feed.type === 'CISA_KEV' ? { ...feed, etag: cachedKev?.etag } : feed,
              execution!.scopeHours,
              checkedRequest,
              config,
              checkedSleep,
              targets,
              feed.type === 'NVD_API'
                ? async ({ offset, total, records }) => {
                    await transaction(pool, async (db) => {
                      await checkpoint(db);
                      execution!.phases[0].durationMs = Date.now() - Date.parse(execution!.startTime);
                      execution!.phases[0].details = `NVD: ${offset.toLocaleString()} of ${total.toLocaleString()} records in incremental sync; ${records.toLocaleString()} retrieved`;
                      execution!.stats.rawIngested = rawCount + records;
                      await saveActiveExecution(db, execution!);
                    });
                  }
                : undefined,
              context,
            );
            if (feed.type === 'CISA_KEV' && result.notModified) {
              if (!cachedKev) throw new Error('KEV conditional response has no source snapshot');
              result = { ...result, kev: cachedKev.kev };
            }
            results.push({ ...result, sourceId: feed.id });
            rawCount += result.notModified ? 0 : result.count;
            succeeded++;
            if (feed.type === 'EPSS_API' && targets.length === 0) {
              execution!.logs.push(`Feed ${feed.id}: no applicable CVEs; EPSS network retrieval skipped`);
              // No request was needed: clear expired recovery state without claiming
              // a successful connectivity check or changing lastSync.
              feedUpdates.push({
                ...feed,
                healthStatus: 'UNTESTED',
                errorLog: null,
                consecutiveFailures: 0,
                circuitOpenUntil: null,
              });
              continue;
            }
            feedUpdates.push({
              ...feed,
              healthStatus: result.warnings?.length ? 'DEGRADED' : 'HEALTHY',
              lastSync: new Date().toISOString(),
              latencyMs: Date.now() - start,
              itemCountLastRun: result.notModified ? feed.itemCountLastRun : result.count,
              errorLog: result.warnings?.join('; ') || null,
              ssrfValidated: true,
              etag: result.etag,
              consecutiveFailures: 0,
              circuitOpenUntil: null,
            });
          } catch (e) {
            if (e instanceof PipelineStopped || connectionLost) throw e;
            const message = e instanceof Error ? e.message : 'Ingestion failed';
            const consecutiveFailures = (feed.consecutiveFailures || 0) + 1;
            feedUpdates.push({
              ...feed,
              healthStatus: 'DOWN',
              latencyMs: Date.now() - start,
              errorLog: message,
              consecutiveFailures,
              circuitOpenUntil: recoveryAt(feed, consecutiveFailures),
            });
            execution!.logs.push(`Feed ${feed.id}: ${message}`);
          }
          await transaction(pool, async (db) => {
            await checkpoint(db);
            execution!.phases[0].durationMs = Date.now() - Date.parse(execution!.startTime);
            execution!.phases[0].details = `${results.length + feedUpdates.filter((f) => f.healthStatus === 'DOWN').length}/${feeds.length} sources processed; ${rawCount} records read`;
            execution!.stats.rawIngested = rawCount;
            await saveActiveExecution(db, execution!);
          });
        }
      };
      const workers = await Promise.allSettled(Array.from({ length: concurrency }, worker));
      const failure = workers.find((result) => result.status === 'rejected');
      if (failure?.status === 'rejected') throw failure.reason;
    };
    const primaryIngestionStartedAt = Date.now();
    await ingestSources(feeds.filter((feed) => feed.type !== 'EPSS_API'));
    const primaryIngestionDuration = Date.now() - primaryIngestionStartedAt;
    const matchingSettings = (await get<AppSettings>(pool, 'settings', 'main')) || DEFAULT_SETTINGS;
    const preliminaryCorpus = mergeCveRecords([...cachedCves, ...results.flatMap((result) => result.cves)]);
    const preliminaryCves = [...preliminaryCorpus.values()];
    // Push structured identity + typed version-range filtering into PostgreSQL.
    // The JS matcher still decides every candidate; this only avoids the full
    // corpus x inventory cross product.
    const preliminaryPairs = await transaction(
      pool,
      (db) =>
        refreshCandidatePairs(db, preliminaryCves, inventory, {
          vendorAliases,
          productAliases,
        }),
      undefined,
      { locks: ['match-index'] },
    );
    preliminaryCorrelation = runVulnerabilityPipeline(
      [],
      preliminaryCves,
      inventory,
      [],
      [],
      // A partial persisted settings object would fall back to the 90% default
      // threshold. Use the loaded defaults so the preliminary pass honours the
      // same confidence policy as the final pass.
      { ...DEFAULT_SETTINGS, ...matchingSettings, scopeHours: 0 },
      'Server worker',
      false,
      vendorAliases,
      productAliases,
      preliminaryPairs.size ? preliminaryPairs : undefined,
      aliasEntries,
    );
    preliminaryCveSignature = matchingCveSignature(preliminaryCves);
    preliminaryInventorySignature = inventorySignature(inventory);
    preliminaryAliasSignature = aliasSignature(aliasEntries);
    preliminarySourceIds = results
      .filter((result) => result.cves.length > 0 || (result.withdrawals?.length || 0) > 0)
      .map((result) => result.sourceId || '')
      .sort();
    const epssFeeds = feeds.filter((feed) => feed.type === 'EPSS_API');
    const epssIngestionStartedAt = Date.now();
    if (epssFeeds.length) {
      // EPSS changes risk, not product applicability. Query only CVEs that can
      // currently affect inventory, including uncertain matches awaiting review.
      await ingestSources(epssFeeds, [
        ...new Set(preliminaryCorrelation.newFindings.map((finding) => finding.cveId)),
      ]);
    }
    const epssIngestionDuration = Date.now() - epssIngestionStartedAt;
    results.sort((a, b) => (a.sourceId || '').localeCompare(b.sourceId || ''));
    const ingestionDuration = primaryIngestionDuration + epssIngestionDuration;
    execution.phases[0] = {
      name: 'Feed ingestion',
      status:
        succeeded < feeds.length || results.some((result) => result.warnings?.length) ? 'WARNING' : 'SUCCESS',
      durationMs: ingestionDuration,
      details: `${succeeded}/${feeds.length} feeds succeeded; ${rawCount} records read`,
    };
    execution.phases[1].status = 'RUNNING';
    execution.phases[1].details = 'Canonicalizing records and resolving source revisions';
    execution.phases[2].details = 'Waiting for normalized CVEs';
    await lockedTransaction(async (db) => {
      await checkpoint(db);
      await saveActiveExecution(db, execution!);
    });
    await lockedTransaction(async (db) => {
      await checkpoint(db);
      const currentFeeds = new Map((await list<ThreatFeed>(db, 'feeds')).map((feed) => [feed.id, feed]));
      const validSources = new Set(
        feeds
          .filter((feed) => {
            const current = currentFeeds.get(feed.id);
            return (
              current?.enabled &&
              current.url === feed.url &&
              current.type === feed.type &&
              current.authType === feed.authType &&
              (current.authSecretKey || '') === (feed.authSecretKey || '')
            );
          })
          .map((feed) => feed.id),
      );
      const acceptedResults = results.filter((result) => validSources.has(result.sourceId!));
      succeeded = acceptedResults.length;
      rawCount = acceptedResults.reduce((sum, result) => sum + (result.notModified ? 0 : result.count), 0);
      for (const feed of feeds)
        if (!validSources.has(feed.id))
          execution!.logs.push(
            `Feed ${feed.id}: configuration changed during ingestion; obsolete response ignored`,
          );
      for (const feed of feedUpdates) {
        const current = currentFeeds.get(feed.id);
        if (current && validSources.has(feed.id))
          await put(db, 'feeds', feed.id, {
            ...current,
            healthStatus: feed.healthStatus,
            lastSync: feed.lastSync,
            latencyMs: feed.latencyMs,
            itemCountLastRun: feed.itemCountLastRun,
            errorLog: feed.errorLog,
            ssrfValidated: feed.ssrfValidated,
            etag: feed.etag,
            consecutiveFailures: feed.consecutiveFailures,
            circuitOpenUntil: feed.circuitOpenUntil,
          });
      }
      if (feeds.length && !succeeded) {
        await appendAudit(
          db,
          'Pipeline warning',
          'All enabled feeds failed; running correlation against cache',
          'worker',
          'PIPELINE',
          'WARNING',
        );
        execution!.logs.push('All feeds failed; proceeding with cached CVE correlation');
      }
      for (const result of acceptedResults) {
        if (result.syncState) {
          const source = currentFeeds.get(result.sourceId!)!;
          // Clear catch_up flag when hasMore is false (catch-up complete).
          const cursorState = result.syncState.hasMore
            ? result.syncState
            : { ...result.syncState, catch_up: false, next_catchup_at: undefined };
          await put(db, 'feedCursors', source.id, {
            ...cursorState,
            fingerprint: sourceFingerprint(source),
          } satisfies FeedCursor);
        }
        if (result.kev && !result.notModified) {
          const source = currentFeeds.get(result.sourceId!)!;
          await put(db, 'feedSnapshots', source.id, {
            fingerprint: sourceFingerprint(source),
            etag: result.etag,
            kev: result.kev,
          } satisfies KevSnapshot);
        }
      }
      for (const update of feedUpdates.filter((feed) => validSources.has(feed.id)))
        await writeEvent(db, {
          category: 'FEED',
          level:
            update.healthStatus === 'DOWN'
              ? 'ERROR'
              : update.healthStatus === 'DEGRADED'
                ? 'WARNING'
                : 'INFO',
          code: 'feed.ingestion',
          message: `${update.name}: ${update.healthStatus}`,
          runId: execution!.id,
          context: { feedId: update.id, count: update.itemCountLastRun, latencyMs: update.latencyMs },
        });
      // Commit a durable native-correlation handoff with the source checkpoint.
      // Existing inventory remains authoritative; no record-store assets are copied.
      for (const result of acceptedResults)
        for (const article of result.articles || [])
          await db.query(
            `INSERT INTO correlation_pending(id,payload) VALUES($1,$2)
          ON CONFLICT(id) DO NOTHING`,
            [
              article.id,
              JSON.stringify({
                title: article.title,
                content: article.summary,
                url: article.url,
              }),
            ],
          );
      const snapshot = await pipelineState(db);
      // Re-read alias entries inside the commit transaction: operator alias
      // changes during ingestion (save/promote/revoke) must not be silently
      // overwritten by a stale snapshot loaded before network I/O.
      const aliasEntries = await list<AliasEntry>(db, 'aliases');
      const articles = mergeArticles([
        ...snapshot.intelligenceArticles,
        ...acceptedResults.flatMap((result) => result.articles || []),
      ]);
      await putMany(
        db,
        'intelligenceArticles',
        articles.map((data) => ({ id: data.id, data })),
      );
      const byId = mergeCveRecords([
        ...snapshot.cveData,
        ...acceptedResults.filter((result) => !result.notModified).flatMap((result) => result.cves),
      ]);
      type Withdrawal = { cveId: string; modifiedDate: string };
      const oldWithdrawals = new Map(
        (await list<Withdrawal>(db, 'cveWithdrawals')).map((entry) => [entry.cveId, entry]),
      );
      const withdrawals = new Map(oldWithdrawals);
      for (const entry of acceptedResults.flatMap((result) => result.withdrawals || [])) {
        const old = withdrawals.get(entry.cveId);
        if (!old || Date.parse(entry.modifiedDate) > Date.parse(old.modifiedDate))
          withdrawals.set(entry.cveId, entry);
      }
      const changedWithdrawals = [...withdrawals.values()].filter((entry) => {
        const old = oldWithdrawals.get(entry.cveId);
        return !old || old.modifiedDate !== entry.modifiedDate;
      });
      await putMany(
        db,
        'cveWithdrawals',
        changedWithdrawals.map((entry) => ({ id: entry.cveId, data: entry })),
      );
      for (const entry of withdrawals.values()) {
        const cve = byId.get(entry.cveId);
        if (cve && Date.parse(cve.modifiedDate) <= Date.parse(entry.modifiedDate)) byId.delete(entry.cveId);
      }
      const oldCveMap = mergeCveRecords(snapshot.cveData);
      for (const old of oldCveMap.values()) {
        const current = byId.get(normalizeCveId(old.cveId) || '');
        if (current) {
          current.epss = old.epss;
          current.cisaKev = old.cisaKev;
        }
      }
      const kevReports = acceptedResults.filter((result) => result.kev);
      const cisaKevEnabled = [...currentFeeds.values()].some(
        (feed) => feed.type === 'CISA_KEV' && feed.enabled,
      );
      if (
        cisaKevEnabled &&
        !acceptedResults.some((result) => currentFeeds.get(result.sourceId || '')?.type === 'CISA_KEV')
      )
        execution!.logs.push('CISA KEV was not refreshed; cached KEV flags are retained and may be stale');
      const exploitedReports = acceptedResults.filter((result) => result.exploited && !result.notModified);
      const epssReports = acceptedResults.filter((result) => result.epss && !result.notModified);
      const epssScopes = new Map(epssReports.map((result) => [result, new Set(result.epssScope)]));
      for (const cve of byId.values()) {
        const exploitationSources = exploitedReports
          .filter((result) => result.exploited?.[cve.cveId])
          .map((result) => result.sourceId!)
          .sort();
        if (exploitationSources.length) {
          cve.exploitationSources = [
            ...new Set([...(cve.exploitationSources || []), ...exploitationSources]),
          ];
          if (cve.exploitStatus === 'None') cve.exploitStatus = 'Reported In Wild';
        }
        if (kevReports.length) {
          const hasFullCisaKev = kevReports.some((r) => {
            const feed = currentFeeds.get(r.sourceId || '');
            return feed?.type === 'CISA_KEV';
          });
          const kevMatch = kevReports.map((result) => result.kev![cve.cveId]).find((entry) => entry?.isKev);
          if (kevMatch) {
            cve.cisaKev = kevMatch;
          } else if (hasFullCisaKev) {
            cve.cisaKev = { isKev: false };
          }
        }
        const scopedReports = epssReports.filter((result) => epssScopes.get(result)!.has(cve.cveId));
        if (scopedReports.length) {
          cve.epss = scopedReports.map((result) => result.epss![cve.cveId]).find(Boolean) || {
            score: 0,
            percentile: 0,
          };
        }
      }
      const changedCves = [...byId.values()].filter((cve) => {
        const old = oldCveMap.get(cve.cveId);
        return !old || stableJson(old) !== stableJson(cve);
      });
      // Bind published CVEs to their pre-CVE clusters so early-intelligence
      // evidence and operator rulings travel with the canonical identifier.
      // Only CVEs that are new to the corpus (not merely re-versioned) can
      // establish the publication event; a re-publication never re-binds.
      //
      // A bind that loses its bounded lock race throws BIND_LOCK_CONTENDED. That
      // is not "no cluster to bind": swallowing it would record the CVE as
      // already-published, so no later run would retry and the operator's
      // FALSE_POSITIVE/NOT_AFFECTED ruling would never reach the canonical
      // finding. Deferred identities are merged into the pending pin, which the
      // next citation run retries before re-deriving new publications.
      type DeferredBind = { cveId: string; vendor: string; product: string; attempts?: number };
      const deferredBinds: DeferredBind[] = [];
      const previous = await get<{ pending: DeferredBind[] }>(
        db,
        'systemState',
        'correlation-deferred-binds',
      ).catch(() => undefined);
      // At most 500 entries fit in the durable pin, and CVEs beyond the cap are
      // never revisited (a CVE that is already in the corpus is skipped by
      // `oldCveMap.has` on every later run). Defer only what the pin can hold:
      // the rest still inherits its cluster, because bindClusterToCve's own
      // bounded retries already ran and a cluster that genuinely exists is
      // bindable. Losing a bound identity silently is the outcome this list
      // exists to prevent.
      const DEFERRED_BIND_LIMIT = 500;
      const defer = (bind: DeferredBind, attempts = 1) => {
        if (deferredBinds.length >= DEFERRED_BIND_LIMIT) return;
        deferredBinds.push({ ...bind, attempts });
      };
      for (const identity of previous?.pending ?? []) {
        try {
          await bindClusterToCve(db, identity.cveId, identity.vendor, identity.product);
        } catch (error) {
          if ((error as { code?: string }).code !== 'BIND_LOCK_CONTENDED') throw error;
          const attempts = (identity.attempts ?? 0) + 1;
          if (attempts < DEFERRED_BIND_MAX_ATTEMPTS) defer(identity, attempts);
          else
            execution!.logs.push(
              `Pre-CVE disposition inheritance for ${identity.cveId} was deferred ${attempts} times and is now abandoned`,
            );
        }
      }
      for (const cve of changedCves) {
        if (oldCveMap.has(cve.cveId)) continue;
        for (const identity of cveClusterIdentities(cve)) {
          try {
            await bindClusterToCve(db, cve.cveId, identity.vendor, identity.product);
          } catch (error) {
            if ((error as { code?: string }).code !== 'BIND_LOCK_CONTENDED') throw error;
            defer({ cveId: cve.cveId, ...identity }, 1);
          }
        }
      }
      // Retried binds whose CVE has left the changed set are carried forward
      // too; dropping them here is the same loss as never recording them.
      if (deferredBinds.length)
        await put(db, 'systemState', 'correlation-deferred-binds', {
          pending: deferredBinds.slice(0, DEFERRED_BIND_LIMIT),
          updatedAt: new Date().toISOString(),
        });
      else if (previous)
        await put(db, 'systemState', 'correlation-deferred-binds', {
          pending: [],
          updatedAt: new Date().toISOString(),
        });
      await putMany(
        db,
        'cveData',
        changedCves.map((cve) => ({ id: cve.cveId, data: cve })),
      );
      const keys = await db.query("SELECT id FROM records WHERE kind='cveData'");
      // Batch deletion of superseded/withdrawn CVE aliases into a single query
      // instead of one DELETE per row, reducing O(N) round-trips to O(1).
      const staleIds = keys.rows
        .map((row) => {
          const canonical = normalizeCveId(row.id);
          return canonical &&
            ((canonical !== row.id && byId.has(canonical)) ||
              (withdrawals.has(canonical) && !byId.has(canonical)))
            ? row.id
            : null;
        })
        .filter((id): id is string => id !== null);
      if (staleIds.length)
        await db.query("DELETE FROM records WHERE kind='cveData' AND id = ANY($1::text[])", [staleIds]);
      // The run window limits network ingestion, not applicability of already cached CVEs.
      const settings = { ...snapshot.settings, scopeHours: 0 };
      const finalCves = [...byId.values()];
      const finalSourceIds = acceptedResults
        .filter((result) => result.cves.length > 0 || (result.withdrawals?.length || 0) > 0)
        .map((result) => result.sourceId || '')
        .sort();
      const reusableMatches =
        preliminaryCorrelation !== undefined &&
        stableJson(preliminarySourceIds) === stableJson(finalSourceIds) &&
        preliminaryCveSignature === matchingCveSignature(finalCves) &&
        preliminaryInventorySignature === inventorySignature(snapshot.watchlist) &&
        preliminaryAliasSignature === aliasSignature(aliasEntries) &&
        (matchingSettings.autoDispatchConfidenceThreshold ?? 90) ===
          (settings.autoDispatchConfidenceThreshold ?? 90);
      // Inventory may have changed while this run was ingesting. Re-derive its
      // automatic aliases for the final snapshot so both the PostgreSQL
      // candidate index and the JavaScript matcher use the same expanded keys.
      const finalInventoryAliases = deriveInventoryAliases(snapshot.watchlist, aliasEntries);
      const finalAliasEntries: AliasEntry[] = [...aliasEntries, ...finalInventoryAliases];
      const finalVendorAliases = buildAliasMap(finalAliasEntries, 'VENDOR');
      const finalProductAliases = buildAliasMap(finalAliasEntries, 'PRODUCT');
      const finalPairs = reusableMatches
        ? undefined
        : await refreshCandidatePairs(db, finalCves, snapshot.watchlist, {
            vendorAliases: finalVendorAliases,
            productAliases: finalProductAliases,
          });
      const correlated = reusableMatches
        ? {
            ...preliminaryCorrelation!,
            newFindings: preliminaryCorrelation!.newFindings
              .filter((finding) => byId.has(finding.cveId))
              .map((finding) => {
                const cve = byId.get(finding.cveId)!;
                return { ...finding, cve, exploitRisk: determineExploitRisk(cve) };
              }),
          }
        : runVulnerabilityPipeline(
            feeds,
            finalCves,
            snapshot.watchlist,
            snapshot.alertedCves,
            snapshot.findings,
            settings,
            'Server worker',
            true,
            finalVendorAliases,
            finalProductAliases,
            finalPairs?.size ? finalPairs : undefined,
            aliasEntries,
          );
      // A wholly rejected stale bundle may be rebuilt from current matches. Never
      // automatically resend a bundle with any acceptance or an in-flight delivery.
      const staleBundles = new Set<string>(
        (
          await db.query(
            `SELECT advisory_id FROM outbox GROUP BY advisory_id HAVING bool_and(status='FAILED' AND COALESCE(error,'') LIKE '%no longer applicable%')`,
          )
        ).rows.map((row) => row.advisory_id),
      );
      // Pre-CVE operator rulings suppress their canonical CVE's new findings
      // before reconciliation or any delivery queue sees them. A finding whose
      // asset an operator ruled FALSE_POSITIVE/NOT_AFFECTED during the pre-CVE
      // window is created MONITORED with the ruling recorded, never queued.
      const suppressedNewFindings: Finding[] = [];
      const survivingNewFindings: Finding[] = [];
      {
        const suppressionCache = new Map<string, Set<string>>();
        for (const finding of correlated.newFindings) {
          let suppressed = suppressionCache.get(finding.cveId);
          if (!suppressed) {
            suppressed = await clusterSuppressedAssets(db, finding.cveId);
            suppressionCache.set(finding.cveId, suppressed);
          }
          if (suppressed.has(finding.matchedAssetId))
            suppressedNewFindings.push({
              ...finding,
              status: 'FALSE_POSITIVE',
              notificationStatus: 'NOT_APPLICABLE',
              matchingEvidence:
                'Suppressed by operator ruling on the pre-CVE cluster; canonical CVE inherits the earlier decision',
            });
          else survivingNewFindings.push(finding);
        }
      }
      const reconciled = reconcileFindings(
        snapshot.findings.map((f) =>
          f.advisoryId && staleBundles.has(f.advisoryId) && !f.autoDispatchedAt
            ? { ...f, advisoryId: null }
            : f,
        ),
        survivingNewFindings,
      );
      const vexEnforced = applyVexSuppression(reconciled);
      // Suppressed findings are persisted alongside the surviving set: dropping
      // them would let the next run re-create and queue the same finding.
      const persistedFindings = [...vexEnforced, ...suppressedNewFindings];
      await putMany(
        db,
        'findings',
        persistedFindings.map((f) => ({ id: f.id, data: f })),
      );
      // Rebuild the automatic alias layer from current inventory and from the
      // correlations that survived this run. Rows that are no longer supported
      // by either source are removed, while operator-managed rows are never
      // touched. The effective maps include this run's changes so news evidence
      // matching also sees the freshly learned names.
      // A stop requested during the commit window must surface before the
      // alias reconciliation writes back: once upserts/removals hit the table,
      // a cancellation can no longer prevent a lossy overwrite of concurrent
      // operator alias edits.
      await checkpoint(db);
      const desiredAutoAliases = [
        ...deriveInventoryAliases(snapshot.watchlist, aliasEntries),
        ...deriveCorrelationAliases(persistedFindings, snapshot.watchlist, byId, aliasEntries),
      ];
      const autoAliases = reconcileAutoAliases(aliasEntries, desiredAutoAliases);
      for (const entry of autoAliases.upserts) await put(db, 'aliases', entry.id, entry);
      for (const id of autoAliases.removals) await remove(db, 'aliases', id);
      const effectiveAliasEntries = autoAliases.aliases;
      const effectiveVendorAliases = buildAliasMap(effectiveAliasEntries, 'VENDOR');
      const effectiveProductAliases = buildAliasMap(effectiveAliasEntries, 'PRODUCT');
      const intelligenceMatches = matchIntelligence(
        articles,
        snapshot.watchlist,
        vexEnforced,
        [...byId.values()],
        effectiveVendorAliases,
        effectiveProductAliases,
        // Cached CVEs stay applicable regardless of age, but news vendor +
        // product evidence is limited to the run's published/modified window.
        execution!.scopeHours,
      );
      await putMany(
        db,
        'intelligenceMatches',
        intelligenceMatches.map((data) => ({ id: data.id, data })),
      );
      await db.query("DELETE FROM records WHERE kind='intelligenceMatches' AND NOT (id=ANY($1::text[]))", [
        intelligenceMatches.map((item) => item.id),
      ]);
      // Apply zero-day rate limiting and digest consolidation.
      const { matches: rateLimitedMatches, digests: zeroDayDigests } = rankAndRateLimitZeroDays(
        vexEnforced,
        intelligenceMatches,
      );
      await writeEvent(db, {
        category: 'MATCHING',
        code: 'matching.completed',
        message: 'Structured applicability and news evidence correlation completed',
        runId: execution!.id,
        context: {
          findings: correlated.newFindings.length,
          articles: articles.length,
          evidenceMatches: rateLimitedMatches.length,
          reviewRequired: rateLimitedMatches.filter((item) => item.status === 'REVIEW_REQUIRED').length,
          zeroDayDigests: zeroDayDigests.length,
          zeroDaysRateLimited: intelligenceMatches.length - rateLimitedMatches.length,
        },
      });
      const queueStarted = Date.now();
      let notificationsQueued = 0,
        advisoriesQueued = 0,
        digestBuffered = 0,
        newsNotificationsQueued = 0,
        unverifiableNotificationsQueued = 0;
      if (settings.autoDispatchNewsToSecurityTeam && rateLimitedMatches.length) {
        const articleMap = new Map(
          articles.map((article) => [article.id, article] as [string, IntelligenceArticle]),
        );
        const assetMap = new Map(
          snapshot.watchlist.map((item) => [item.id, item] as [string, WatchListItem]),
        );
        const securityRecipients = (await list<EmailRecipient>(db, 'recipients')).filter(
          (r) => r.enabled && (r.deliveryGroup === 'SECURITY_TEAM' || r.deliveryGroup === undefined),
        );
        if (securityRecipients.length) {
          for (const match of rateLimitedMatches) {
            const article = articleMap.get(match.articleIds[0]);
            if (!article) continue;
            const assetItem = assetMap.get(match.assetId);
            newsNotificationsQueued += await queueNewsEvidenceNotifications(
              db,
              match,
              article,
              {
                name: match.assetName,
                vendor: assetItem?.vendor || undefined,
                product: assetItem?.product || undefined,
              },
              securityRecipients,
            );
          }
          await writeEvent(db, {
            category: 'MATCHING',
            code: 'matching.news_dispatched',
            message: 'Matching news evidence auto-dispatched to the security team',
            runId: execution!.id,
            context: { matches: rateLimitedMatches.length, recipientsNotified: newsNotificationsQueued },
          });
        }
      }
      if (settings.reviewUnverifiableMatches) {
        const securityRecipients = (await list<EmailRecipient>(db, 'recipients')).filter(
          (r) => r.enabled && (r.deliveryGroup === 'SECURITY_TEAM' || r.deliveryGroup === undefined),
        );
        if (securityRecipients.length) {
          const unverifiableFindings = survivingNewFindings.filter(
            (f) => f.notificationStatus === 'REVIEW_REQUIRED' && f.confidence === 0,
          );
          if (unverifiableFindings.length) {
            unverifiableNotificationsQueued += await queueUnverifiableMatchNotification(
              db,
              unverifiableFindings,
              securityRecipients,
            );
          }
          if (unverifiableFindings.length) {
            await writeEvent(db, {
              category: 'MATCHING',
              code: 'matching.unverifiable_dispatched',
              message: 'Unverifiable matches notified to the Security team for review',
              runId: execution!.id,
              context: {
                unverifiableFindings: unverifiableFindings.length,
                recipientsNotified: unverifiableNotificationsQueued,
              },
            });
          }
        }
      }
      // Previously queued findings also become deliverable after enabling dispatch.
      const pending = vexEnforced.filter(
        (f) =>
          (f.notificationStatus === 'QUEUED_FOR_DISPATCH' || f.notificationStatus === 'AUTO_DISPATCHED') &&
          !f.advisoryId &&
          !['RESOLVED', 'FALSE_POSITIVE', 'PATCH_APPLIED'].includes(f.status),
      );
      const buildAdvisory = (batch: Finding[], isDigestBatch: boolean): Advisory => {
        const cveIds = Array.from(new Set(batch.map((finding) => finding.cveId))).sort();
        const rank = ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
        return {
          id: formatAdvisoryId(settings.advisoryPrefix),
          title: `Vulnerability ${isDigestBatch ? 'digest' : 'notice'}: ${cveIds.slice(0, 3).join(', ')}${cveIds.length > 3 ? ` (+${cveIds.length - 3} more)` : ''}`,
          severity: batch.reduce(
            (s, f) => (rank.indexOf(f.cve.cvss.severity) > rank.indexOf(s) ? f.cve.cvss.severity : s),
            'UNKNOWN' as Advisory['severity'],
          ),
          cveIds,
          findingIds: batch.map((f) => f.id),
          createdDate: new Date().toISOString(),
          deliveryStatus: 'PENDING',
          recipientCount: 0,
          executiveSummary: `${batch.length} inventory correlations require investigation. Confirm applicability and consult the vendor before remediation.`,
          remediationInstructions:
            'Review vendor advisories and deploy tested remediation through your change process.',
          vendorLink:
            Array.from(
              new Set(
                batch
                  .map((f) => f.cve.remediation.vendorAdvisoryRef || f.cve.remediation.patchUrl)
                  .filter(Boolean),
              ),
            ).sort()[0] || '',
          affectedSystems: Array.from(new Set(batch.map((f) => f.matchedAssetName))).sort(),
          isDigestBatch,
        };
      };
      // The confidence policy gates *automatic* dispatch. With automatic dispatch
      // disabled the finding is still recorded and remains eligible for delivery
      // through an explicit operator action (review approval or a manually
      // assembled advisory), so it must not be replaced by an advisory-bound
      // delivery here — that would consume the finding and block the release.
      if (!settings.autoDispatchEnabled && pending.length) {
        await writeEvent(db, {
          category: 'MATCHING',
          code: 'matching.dispatch_held_by_policy',
          message: 'Findings held for review by the workspace confidence policy',
          runId: execution!.id,
          context: { findings: pending.length },
        });
      }
      if (settings.autoDispatchEnabled && pending.length) {
        if (settings.digestBatchingEnabled) {
          // flushes the window into one recipient-specific combined email, so a
          // burst of detections (including detections from several pipeline
          // runs) produces a single message per recipient instead of a storm.
          digestBuffered = await bufferFindingsForDigest(
            db,
            pending.map((finding) => finding.id),
            settings.digestWindowMinutes,
          );
        } else {
          // A KEV-only or high-severity subscriber must never receive unrelated
          // findings merely because one other item in a bundle passes its filter.
          const groups = new Map<string, Finding[]>();
          for (const finding of pending) {
            const key = `${finding.cve.cvss.severity}:${finding.cve.cisaKev?.isKev ?? false}`;
            const group = groups.get(key) || [];
            group.push(finding);
            groups.set(key, group);
          }
          for (const group of groups.values()) {
            for (let offset = 0; offset < group.length; offset += 200) {
              const batch = group.slice(offset, offset + 200);
              const advisory = buildAdvisory(batch, false);
              const count = await queueAdvisory(
                db,
                advisory,
                batch,
                renderAdvisory(snapshot.advisoryTemplate, advisory, batch),
              );
              notificationsQueued += count;
              advisoriesQueued += count ? 1 : 0;
              if (count)
                for (const f of batch) await put(db, 'findings', f.id, { ...f, advisoryId: advisory.id });
            }
          }
        }
      } else if (pending.length && !settings.autoDispatchEnabled) {
        await writeEvent(db, {
          category: 'EMAIL',
          level: 'WARNING',
          code: 'pipeline.auto_dispatch_disabled',
          message: `Auto-dispatch is disabled. ${pending.length} findings are eligible for notification but will not be queued until autoDispatchEnabled is enabled in settings.`,
          context: { pendingFindings: pending.length },
        });
      }
      let deliveryLog = `${notificationsQueued} jobs queued${digestBuffered ? `; ${digestBuffered} findings buffered for the digest window` : ''}${newsNotificationsQueued ? `; ${newsNotificationsQueued} news notifications queued` : ''}`;
      if (pending.length && !settings.autoDispatchEnabled) {
        deliveryLog += `; ${pending.length} findings pending but autoDispatchEnabled is false`;
      }
      execution = {
        ...correlated.execution,
        id: execution!.id,
        startTime: execution!.startTime,
        endTime: new Date().toISOString(),
        status: feeds.length > 0 && succeeded === 0 ? 'FAILED' : correlated.execution.status,
        scopeHours: execution!.scopeHours,
        logs: [
          ...execution!.logs,
          `Product matching: ${correlated.newFindings.length} current matches; ${reconciled.length} retained findings`,
          `Delivery queue: ${deliveryLog}`,
        ],
        phases: [
          {
            name: 'Feed ingestion',
            status:
              succeeded < feeds.length || acceptedResults.some((result) => result.warnings?.length)
                ? 'WARNING'
                : 'SUCCESS',
            durationMs: ingestionDuration,
            details: `${succeeded}/${feeds.length} feeds succeeded; ${rawCount} records read; cached intelligence retained`,
          },
          {
            ...correlated.execution.phases[0],
            details: `${byId.size} canonical CVEs; ${correlated.execution.stats.inRunDuplicatesDropped} duplicate records removed`,
          },
          {
            ...correlated.execution.phases[1],
            details: `${byId.size} CVEs evaluated against ${snapshot.watchlist.filter((asset) => asset.active).length} active products; ${correlated.newFindings.length} matches`,
          },
          {
            name: 'Delivery queue',
            status: 'SUCCESS',
            durationMs: Date.now() - queueStarted,
            details: `${notificationsQueued} jobs queued${digestBuffered ? `; ${digestBuffered} findings buffered for the digest window` : ''}${pending.length && !settings.autoDispatchEnabled ? `; ${pending.length} findings pending but autoDispatchEnabled is false` : ''}${newsNotificationsQueued ? `; ${newsNotificationsQueued} news notifications queued` : ''}${unverifiableNotificationsQueued ? `; ${unverifiableNotificationsQueued} unverifiable-match notifications queued` : ''}; transport acceptance is tracked separately`,
          },
        ],
      };
      execution.stats.rawIngested = rawCount;
      execution.stats.matchedWatchlist = correlated.newFindings.length;
      execution.stats.notificationsQueued = notificationsQueued;
      execution.stats.advisoriesQueued = advisoriesQueued;
      execution.stats.digestBuffered = digestBuffered;
      execution.stats.newsNotificationsQueued = newsNotificationsQueued;
      execution.stats.unverifiableNotificationsQueued = unverifiableNotificationsQueued;
      await saveActiveExecution(db, execution);
      // Clear next_catchup_run if all feeds have completed their catch-up.
      const pendingCatchup = acceptedResults.some((r) => r.syncState?.catch_up && r.syncState.hasMore);
      if (pendingCatchup) {
        // Back off to the latest per-feed next_catchup_at so the scheduler does
        // not retrigger catch-up before the per-feed cooldown has elapsed.
        const allCatchup = acceptedResults.flatMap((r) =>
          r.syncState?.catch_up && r.syncState?.next_catchup_at
            ? [Date.parse(r.syncState.next_catchup_at)]
            : [],
        );
        const nextCatchupRun = allCatchup.length ? Math.max(...allCatchup) : Date.now() + 60000;
        await db.query('UPDATE scheduler_state SET last_run=now(), next_catchup_run=$1 WHERE id=1', [
          new Date(Math.max(nextCatchupRun, Date.now())).toISOString(),
        ]);
      } else {
        await db.query('UPDATE scheduler_state SET last_run=now(), next_catchup_run=NULL WHERE id=1');
      }
      await writeEvent(db, {
        category: 'PIPELINE',
        level: execution!.status === 'FAILED' ? 'ERROR' : 'INFO',
        code: 'pipeline.finished',
        message: `Pipeline ${execution!.status.toLowerCase()}`,
        runId: execution!.id,
        context: { stats: execution!.stats },
      });
      await appendAudit(
        db,
        execution.status === 'FAILED' ? 'Pipeline failed' : 'Pipeline completed',
        `${execution.id}; ${correlated.newFindings.length} findings; ${succeeded}/${feeds.length} feeds succeeded`,
        'worker',
        'PIPELINE',
        execution.status === 'FAILED' ? 'ERROR' : undefined,
      );
    });
    return true;
  } catch (e) {
    if (connectionLost) throw e;
    if (execution) {
      // Cancellation is an intentional operator action; only a real failure
      // carries an error payload into the event and the audit trail.
      const failure: Record<string, unknown> = e instanceof PipelineStopped ? {} : describeError(e);
      await lockedTransaction(async (db) => {
        const current = await getForUpdate<PipelineExecution>(db, 'executions', execution!.id);
        await put(db, 'executions', execution!.id, {
          ...execution,
          status: e instanceof PipelineStopped ? 'CANCELLED' : 'FAILED',
          stopRequestedAt: current?.stopRequestedAt,
          phases: execution!.phases.map((phase) =>
            phase.status === 'RUNNING' || phase.status === 'PENDING'
              ? { ...phase, status: e instanceof PipelineStopped ? 'CANCELLED' : 'FAILED' }
              : phase,
          ),
          endTime: new Date().toISOString(),
          logs: [
            ...new Set([...(current?.logs || []), ...execution!.logs]),
            e instanceof Error ? e.message : 'Worker failed',
          ],
        });
        await writeEvent(db, {
          category: e instanceof PipelineStopped ? 'PIPELINE' : 'ISSUE',
          level: e instanceof PipelineStopped ? 'INFO' : 'ERROR',
          code: e instanceof PipelineStopped ? 'pipeline.cancelled' : 'pipeline.failed',
          message:
            e instanceof PipelineStopped
              ? 'Pipeline stopped by operator'
              : 'Pipeline failed; inspect execution details',
          runId: execution!.id,
          context: failure,
        });
        await appendAudit(
          db,
          e instanceof PipelineStopped ? 'Pipeline stopped' : 'Pipeline failed',
          `Execution ${execution!.id}${
            typeof failure.error === 'string' ? `; ${failure.error.slice(0, 500)}` : ''
          }`,
          'worker',
          'PIPELINE',
          e instanceof PipelineStopped ? undefined : 'ERROR',
        );
      });
    } else throw e;
    return true;
  } finally {
    if (heartbeat) clearInterval(heartbeat);
    if (locked)
      await lock.query(`SELECT pg_advisory_unlock(800003, ${schemaLockKey})`).catch(() => {
        connectionLost = true;
      });
    lock.removeListener('error', onError);
    lock.release(connectionLost);
  }
}
