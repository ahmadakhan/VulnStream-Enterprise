import type pg from 'pg';
import { randomUUID } from 'node:crypto';
import { get, list, put, putMany, transaction, appendAudit, state } from './db';
import { DEFAULT_SETTINGS } from '../shared/state';
import type {
  AppSettings,
  PipelineExecution,
  ThreatFeed,
  Advisory,
  Finding,
  NormalizedCVE,
  WatchListItem,
} from '../src/types';
import { mergeCveRecords, normalizeCveId } from '../src/utils/deduplicator';
import { reconcileFindings } from '../src/engine/reconcileFindings';
import { runVulnerabilityPipeline } from '../src/engine/pipelineEngine';
import { ingestFeed } from './ingestion';
import type { Requester } from './network';
import type { Config } from './config';
import { queueAdvisory } from './delivery';
import { HttpError } from './validation';
export async function queueRun(
  pool: pg.Pool,
  scope: number | undefined,
  actor: string,
): Promise<PipelineExecution> {
  return transaction(pool, async (db) => {
    const existing = (await list<PipelineExecution>(db, 'executions')).find((e) =>
      ['QUEUED', 'RUNNING'].includes(e.status),
    );
    if (existing) return existing;
    const settings = (await get<AppSettings>(db, 'settings', 'main')) || DEFAULT_SETTINGS;
    const execution: PipelineExecution = {
      id: randomUUID(),
      startTime: new Date().toISOString(),
      endTime: null,
      status: 'QUEUED',
      scopeHours: scope ?? settings.scopeHours,
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
    await put(db, 'executions', execution.id, execution);
    await appendAudit(db, 'Pipeline queued', `Execution ${execution.id}`, actor, 'PIPELINE');
    return execution;
  });
}
class PipelineStopped extends Error {
  constructor() {
    super('Pipeline stopped by operator; uncommitted results discarded');
  }
}
export async function stopRun(pool: pg.Pool, id: string, actor: string): Promise<PipelineExecution> {
  return transaction(pool, async (db) => {
    const run = await get<PipelineExecution>(db, 'executions', id);
    if (!run) throw new HttpError(404, 'Execution not found');
    if (!['QUEUED', 'RUNNING'].includes(run.status) || run.stopRequestedAt) return run;
    run.stopRequestedAt = new Date().toISOString();
    if (run.status === 'QUEUED') {
      run.status = 'CANCELLED';
      run.endTime = run.stopRequestedAt;
    }
    run.logs.push('Operator requested stop');
    await put(db, 'executions', id, run);
    await appendAudit(db, 'Pipeline stop requested', `Execution ${id}`, actor, 'PIPELINE');
    return run;
  });
}
export function renderAdvisory(template: string, advisory: Advisory): string {
  const escape = (v: string) =>
    v.replace(
      /[&<>"']/g,
      (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]!,
    );
  const values: Record<string, string> = {
    severity: advisory.severity,
    advisory_id: advisory.id,
    advisory_title: advisory.title,
    dispatch_date: new Date().toISOString(),
    executive_summary: advisory.executiveSummary,
    cve_ids: advisory.cveIds.join(', '),
    affected_systems: advisory.affectedSystems.join('\n'),
    remediation_steps: advisory.remediationInstructions,
    vendor_link: advisory.vendorLink || '',
  };
  return template.replace(/{{([a-z_]+)}}/g, (_, key) => escape(values[key] || ''));
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
    locked = (await lock.query('SELECT pg_try_advisory_lock(800003) AS locked')).rows[0].locked;
    if (!locked) return false;
    const runs = await list<PipelineExecution>(pool, 'executions');
    // Owning the advisory lock proves no other live worker owns a run. Recovery
    // is safe because records, advisories and outbox are committed atomically.
    await lockedTransaction(async (db) => {
      for (const stale of runs.filter((e) => e.status === 'RUNNING'))
        await put(db, 'executions', stale.id, {
          ...stale,
          status: 'QUEUED',
          logs: [...stale.logs, 'Recovered interrupted worker; restarting idempotently'],
        });
    });
    execution = (await list<PipelineExecution>(pool, 'executions'))
      .reverse()
      .find((e) => e.status === 'QUEUED');
    if (!execution) {
      const settings = (await get<AppSettings>(pool, 'settings', 'main')) || DEFAULT_SETTINGS;
      const last = (await pool.query('SELECT last_run FROM scheduler_state WHERE id=1')).rows[0]?.last_run;
      if (
        settings.schedulerEnabled &&
        (!last || Date.now() - new Date(last).getTime() >= settings.schedulerIntervalMinutes * 60000)
      )
        execution = await queueRun(pool, undefined, 'scheduler');
    }
    await pool.query('UPDATE scheduler_state SET heartbeat=now() WHERE id=1');
    if (!execution) return false;
    const checkpoint = async (db: pg.Pool | pg.PoolClient = pool) => {
      const current = await get<PipelineExecution>(db, 'executions', execution!.id);
      if (current?.stopRequestedAt || current?.status === 'CANCELLED') throw new PipelineStopped();
    };
    await checkpoint();
    execution.status = 'RUNNING';
    execution.phases = ['Feed ingestion', 'Structured correlation', 'Delivery queue'].map((name, index) => ({
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
      await put(db, 'executions', execution!.id, execution);
      await db.query('UPDATE scheduler_state SET last_run=now() WHERE id=1');
    });
    const feeds = (await list<ThreatFeed>(pool, 'feeds')).filter((f) => f.enabled);
    let succeeded = 0,
      rawCount = 0;
    const results: Awaited<ReturnType<typeof ingestFeed>>[] = [];
    const feedUpdates: ThreatFeed[] = [];
    // Bound cross-feed concurrency; each adapter also paces its own pages.
    const ingestSources = async (sources: ThreatFeed[], targets: string[] = []) => {
      const concurrency = Math.min(sources.length, 6);
      let nextIndex = 0;
      const worker = async () => {
        while (nextIndex < sources.length) {
          const i = nextIndex++;
          const feed = sources[i];
          await checkpoint();
          if (
            (feed.consecutiveFailures || 0) >= 5 &&
            feed.circuitOpenUntil &&
            Date.parse(feed.circuitOpenUntil) > Date.now()
          ) {
            execution!.logs.push(
              `Feed ${feed.id}: skipped (circuit open, ${feed.consecutiveFailures} consecutive failures)`,
            );
            continue;
          }
          const start = Date.now();
          try {
            const checkedRequest: Requester = async (url, options) => {
              await checkpoint();
              const response = await request(url, options);
              await checkpoint();
              return response;
            };
            const checkedSleep = async (ms: number) => {
              const until = Date.now() + ms;
              while (Date.now() < until) {
                await checkpoint();
                await new Promise((resolve) => setTimeout(resolve, Math.min(500, until - Date.now())));
              }
            };
            const result = await ingestFeed(
              feed,
              execution!.scopeHours,
              checkedRequest,
              config,
              checkedSleep,
              targets,
            );
            results.push({ ...result, sourceId: feed.id });
            rawCount += result.notModified ? 0 : result.count;
            succeeded++;
            if (feed.type === 'EPSS_API' && targets.length === 0) {
              execution!.logs.push(`Feed ${feed.id}: no applicable CVEs; EPSS network retrieval skipped`);
              continue;
            }
            feedUpdates.push({
              ...feed,
              healthStatus: 'HEALTHY',
              lastSync: new Date().toISOString(),
              latencyMs: Date.now() - start,
              itemCountLastRun: result.notModified ? feed.itemCountLastRun : result.count,
              errorLog: null,
              ssrfValidated: true,
              etag: result.etag || feed.etag,
              consecutiveFailures: 0,
              circuitOpenUntil: null,
            });
          } catch (e) {
            if (e instanceof PipelineStopped) throw e;
            const message = e instanceof Error ? e.message : 'Ingestion failed';
            const consecutiveFailures = (feed.consecutiveFailures || 0) + 1;
            feedUpdates.push({
              ...feed,
              healthStatus: 'DOWN',
              latencyMs: Date.now() - start,
              errorLog: message,
              consecutiveFailures,
              circuitOpenUntil:
                consecutiveFailures >= 5
                  ? new Date(
                      Date.now() + Math.min(3600000, 60000 * 2 ** Math.min(6, consecutiveFailures - 5)),
                    ).toISOString()
                  : null,
            });
            execution!.logs.push(`Feed ${feed.id}: ${message}`);
          }
          await transaction(pool, async (db) => {
            await checkpoint(db);
            execution!.phases[0].durationMs = Date.now() - Date.parse(execution!.startTime);
            execution!.phases[0].details = `${results.length + feedUpdates.filter((f) => f.healthStatus === 'DOWN').length}/${feeds.length} sources processed; ${rawCount} records read`;
            execution!.stats.rawIngested = rawCount;
            await put(db, 'executions', execution!.id, execution);
          });
          await lock.query('SELECT 1');
        }
      };
      const workers = await Promise.allSettled(Array.from({ length: concurrency }, worker));
      const failure = workers.find((result) => result.status === 'rejected');
      if (failure?.status === 'rejected') throw failure.reason;
    };
    await ingestSources(feeds.filter((feed) => feed.type !== 'EPSS_API'));
    const epssFeeds = feeds.filter((feed) => feed.type === 'EPSS_API');
    if (epssFeeds.length) {
      const [cached, inventory] = await Promise.all([
        list<NormalizedCVE>(pool, 'cveData'),
        list<WatchListItem>(pool, 'watchlist'),
      ]);
      // EPSS changes risk, not product applicability. Query only CVEs that can
      // currently affect inventory, including uncertain matches awaiting review.
      const candidates = runVulnerabilityPipeline(
        [],
        [...mergeCveRecords([...cached, ...results.flatMap((result) => result.cves)]).values()],
        inventory,
        [],
        [],
        { ...DEFAULT_SETTINGS, scopeHours: 0 },
      ).newFindings;
      await ingestSources(epssFeeds, [...new Set(candidates.map((finding) => finding.cveId))]);
    }
    results.sort((a, b) => (a.sourceId || '').localeCompare(b.sourceId || ''));
    const ingestionDuration = Date.now() - new Date(execution.startTime).getTime();
    execution.phases[0] = {
      name: 'Feed ingestion',
      status: succeeded < feeds.length ? 'WARNING' : 'SUCCESS',
      durationMs: ingestionDuration,
      details: `${succeeded}/${feeds.length} feeds succeeded; ${rawCount} records read`,
    };
    execution.phases[1].status = 'RUNNING';
    execution.phases[1].details = 'Normalizing, merging and correlating cached indicators';
    await lockedTransaction(async (db) => {
      await checkpoint(db);
      await put(db, 'executions', execution!.id, execution);
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
      const snapshot = await state(db);
      const byId = mergeCveRecords([
        ...snapshot.cveData,
        ...acceptedResults.filter((result) => !result.notModified).flatMap((result) => result.cves),
      ]);
      type Withdrawal = { cveId: string; modifiedDate: string };
      const withdrawals = new Map(
        (await list<Withdrawal>(db, 'cveWithdrawals')).map((entry) => [entry.cveId, entry]),
      );
      for (const entry of acceptedResults.flatMap((result) => result.withdrawals || [])) {
        const old = withdrawals.get(entry.cveId);
        if (!old || Date.parse(entry.modifiedDate) > Date.parse(old.modifiedDate))
          withdrawals.set(entry.cveId, entry);
      }
      await putMany(
        db,
        'cveWithdrawals',
        [...withdrawals.values()].map((entry) => ({ id: entry.cveId, data: entry })),
      );
      for (const entry of withdrawals.values()) {
        const cve = byId.get(entry.cveId);
        if (cve && Date.parse(cve.modifiedDate) <= Date.parse(entry.modifiedDate)) byId.delete(entry.cveId);
      }
      for (const old of mergeCveRecords(snapshot.cveData).values()) {
        const current = byId.get(normalizeCveId(old.cveId) || '');
        if (current) {
          current.epss = old.epss;
          current.cisaKev = old.cisaKev;
        }
      }
      const kevReports = acceptedResults.filter((result) => result.kev && !result.notModified);
      const epssReports = acceptedResults.filter((result) => result.epss && !result.notModified);
      const epssScopes = new Map(epssReports.map((result) => [result, new Set(result.epssScope)]));
      for (const cve of byId.values()) {
        if (kevReports.length) {
          cve.cisaKev = kevReports.map((result) => result.kev![cve.cveId]).find((entry) => entry?.isKev) || {
            isKev: false,
          };
        }
        const scopedReports = epssReports.filter((result) => epssScopes.get(result)!.has(cve.cveId));
        if (scopedReports.length) {
          cve.epss = scopedReports.map((result) => result.epss![cve.cveId]).find(Boolean) || {
            score: 0,
            percentile: 0,
          };
        }
      }
      await putMany(
        db,
        'cveData',
        [...byId.values()].map((cve) => ({ id: cve.cveId, data: cve })),
      );
      const keys = await db.query("SELECT id FROM records WHERE kind='cveData'");
      for (const { id } of keys.rows) {
        const canonical = normalizeCveId(id);
        if (
          canonical &&
          ((canonical !== id && byId.has(canonical)) || (withdrawals.has(canonical) && !byId.has(canonical)))
        )
          await db.query("DELETE FROM records WHERE kind='cveData' AND id=$1", [id]);
      }
      // The run window limits network ingestion, not applicability of already cached CVEs.
      const settings = { ...snapshot.settings, scopeHours: 0 };
      const correlated = runVulnerabilityPipeline(
        feeds,
        [...byId.values()],
        snapshot.watchlist,
        snapshot.alertedCves,
        snapshot.findings,
        settings,
        'Server worker',
        true,
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
      const reconciled = reconcileFindings(
        snapshot.findings.map((f) =>
          f.advisoryId && staleBundles.has(f.advisoryId) && !f.autoDispatchedAt
            ? { ...f, advisoryId: null }
            : f,
        ),
        correlated.newFindings,
      );
      await putMany(
        db,
        'findings',
        reconciled.map((f) => ({ id: f.id, data: f })),
      );
      const queueStarted = Date.now();
      let notificationsQueued = 0,
        advisoriesQueued = 0;
      // Previously queued findings also become deliverable after enabling dispatch.
      const pending = reconciled.filter(
        (f) =>
          f.notificationStatus === 'QUEUED_FOR_DISPATCH' &&
          !f.advisoryId &&
          !['RESOLVED', 'FALSE_POSITIVE', 'PATCH_APPLIED'].includes(f.status),
      );
      if (settings.autoDispatchEnabled && pending.length) {
        // A KEV-only or high-severity subscriber must never receive unrelated
        // findings merely because one other item in a bundle passes its filter.
        const groups = new Map<string, Finding[]>();
        for (const finding of pending) {
          const key = `${finding.cve.cvss.severity}:${finding.cve.cisaKev.isKev}`;
          const group = groups.get(key) || [];
          group.push(finding);
          groups.set(key, group);
        }
        for (const group of groups.values()) {
          for (let offset = 0; offset < group.length; offset += 200) {
            const pending = group.slice(offset, offset + 200);
            const cveIds = Array.from(new Set(pending.map((finding) => finding.cveId))).sort();
            const rank = ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
            const advisory: Advisory = {
              id: settings.advisoryPrefix + randomUUID(),
              title: `Vulnerability notice: ${cveIds.slice(0, 3).join(', ')}${cveIds.length > 3 ? ` (+${cveIds.length - 3} more)` : ''}`,
              severity: pending.reduce(
                (s, f) => (rank.indexOf(f.cve.cvss.severity) > rank.indexOf(s) ? f.cve.cvss.severity : s),
                'UNKNOWN' as Advisory['severity'],
              ),
              cveIds,
              findingIds: pending.map((f) => f.id),
              createdDate: new Date().toISOString(),
              deliveryStatus: 'PENDING',
              recipientCount: 0,
              executiveSummary: `${pending.length} inventory correlations require investigation. Confirm applicability and consult the vendor before remediation.`,
              remediationInstructions:
                'Review vendor advisories and deploy tested remediation through your change process.',
              vendorLink: pending[0].cve.remediation.vendorAdvisoryRef || pending[0].cve.remediation.patchUrl,
              affectedSystems: Array.from(new Set(pending.map((f) => f.matchedAssetName))),
            };
            const count = await queueAdvisory(
              db,
              advisory,
              pending,
              renderAdvisory(snapshot.advisoryTemplate, advisory),
            );
            notificationsQueued += count;
            advisoriesQueued += count ? 1 : 0;
            if (count)
              for (const f of pending) await put(db, 'findings', f.id, { ...f, advisoryId: advisory.id });
          }
        }
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
          `Structured correlation: ${correlated.newFindings.length} current matches; ${reconciled.length} retained findings`,
          `Delivery queue: ${notificationsQueued} jobs queued`,
        ],
        phases: [
          {
            name: 'Feed ingestion',
            status: succeeded < feeds.length ? 'WARNING' : 'SUCCESS',
            durationMs: ingestionDuration,
            details: `${succeeded}/${feeds.length} feeds succeeded; ${rawCount} records read`,
          },
          ...correlated.execution.phases.map((phase) => ({
            ...phase,
            details: `${byId.size} cached CVEs evaluated; ${correlated.newFindings.length} current matches`,
          })),
          {
            name: 'Delivery queue',
            status: 'SUCCESS',
            durationMs: Date.now() - queueStarted,
            details: `${notificationsQueued} jobs queued; transport acceptance is tracked separately`,
          },
        ],
      };
      execution.stats.rawIngested = rawCount;
      execution.stats.notificationsQueued = notificationsQueued;
      execution.stats.advisoriesQueued = advisoriesQueued;
      await put(db, 'executions', execution.id, execution);
      await db.query('UPDATE scheduler_state SET last_run=now() WHERE id=1');
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
    if (execution)
      await lockedTransaction(async (db) => {
        await put(db, 'executions', execution!.id, {
          ...execution,
          status: e instanceof PipelineStopped ? 'CANCELLED' : 'FAILED',
          stopRequestedAt: (await get<PipelineExecution>(db, 'executions', execution!.id))?.stopRequestedAt,
          phases: execution!.phases.map((phase) =>
            phase.status === 'RUNNING' || phase.status === 'PENDING'
              ? { ...phase, status: e instanceof PipelineStopped ? 'CANCELLED' : 'FAILED' }
              : phase,
          ),
          endTime: new Date().toISOString(),
          logs: [...execution!.logs, e instanceof Error ? e.message : 'Worker failed'],
        });
        await appendAudit(
          db,
          e instanceof PipelineStopped ? 'Pipeline stopped' : 'Pipeline failed',
          `Execution ${execution!.id}`,
          'worker',
          'PIPELINE',
          e instanceof PipelineStopped ? undefined : 'ERROR',
        );
      });
    else throw e;
    return true;
  } finally {
    if (heartbeat) clearInterval(heartbeat);
    if (locked) await lock.query('SELECT pg_advisory_unlock(800003)').catch(() => {});
    lock.removeListener('error', onError);
    lock.release(connectionLost);
  }
}
