import type pg from 'pg';
import { randomUUID } from 'node:crypto';
import { get, list, put, transaction, appendAudit, state } from './db';
import { DEFAULT_SETTINGS } from '../shared/state';
import type { AppSettings, PipelineExecution, ThreatFeed, Advisory, Finding } from '../src/types';
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
    vendor_link: '',
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
    execution.status = 'RUNNING';
    execution.startTime = new Date().toISOString();
    await lockedTransaction(async (db) => {
      await put(db, 'executions', execution!.id, execution);
      await db.query('UPDATE scheduler_state SET last_run=now() WHERE id=1');
    });
    const feeds = (await list<ThreatFeed>(pool, 'feeds')).filter((f) => f.enabled);
    let succeeded = 0,
      rawCount = 0;
    const results: Awaited<ReturnType<typeof ingestFeed>>[] = [];
    const feedUpdates: ThreatFeed[] = [];
    for (const feed of feeds) {
      const start = Date.now();
      try {
        const result = await ingestFeed(feed, execution.scopeHours, request, config);
        results.push(result);
        rawCount += result.count;
        succeeded++;
        feedUpdates.push({
          ...feed,
          healthStatus: 'HEALTHY',
          lastSync: new Date().toISOString(),
          latencyMs: Date.now() - start,
          itemCountLastRun: result.count,
          errorLog: null,
          ssrfValidated: true,
        });
      } catch (e) {
        const message = e instanceof Error ? e.message : 'Ingestion failed';
        feedUpdates.push({ ...feed, healthStatus: 'DOWN', latencyMs: Date.now() - start, errorLog: message });
        execution.logs.push(`Feed ${feed.id}: ${message}`);
      }
      await lock.query('SELECT 1'); // Fail if the lock-owning connection has been lost.
    }
    const ingestionDuration = Date.now() - new Date(execution.startTime).getTime();
    await lockedTransaction(async (db) => {
      for (const feed of feedUpdates) {
        const current = await get<ThreatFeed>(db, 'feeds', feed.id);
        if (current)
          await put(db, 'feeds', feed.id, {
            ...current,
            healthStatus: feed.healthStatus,
            lastSync: feed.lastSync,
            latencyMs: feed.latencyMs,
            itemCountLastRun: feed.itemCountLastRun,
            errorLog: feed.errorLog,
            ssrfValidated: feed.ssrfValidated,
          });
      }
      if (feeds.length && !succeeded) {
        execution!.status = 'FAILED';
        execution!.endTime = new Date().toISOString();
        await put(db, 'executions', execution!.id, execution);
        await appendAudit(db, 'Pipeline failed', 'All enabled feeds failed', 'worker', 'PIPELINE', 'ERROR');
        return;
      }
      const snapshot = await state(db);
      const byId = new Map(snapshot.cveData.map((c) => [c.cveId, c]));
      for (const result of results)
        for (const cve of result.cves) {
          const old = byId.get(cve.cveId);
          if (!old || new Date(cve.modifiedDate) >= new Date(old.modifiedDate))
            byId.set(cve.cveId, {
              ...cve,
              epss: old?.epss || cve.epss,
              cisaKev: old?.cisaKev || cve.cisaKev,
              sourceFeeds: Array.from(new Set([...(old?.sourceFeeds || []), ...cve.sourceFeeds])),
            });
        }
      for (const cve of byId.values()) {
        for (const result of results) {
          if (result.kev) cve.cisaKev = result.kev[cve.cveId] || { isKev: false };
          if (result.epss?.[cve.cveId]) cve.epss = result.epss[cve.cveId];
        }
        await put(db, 'cveData', cve.cveId, cve);
      }
      // The run window limits network ingestion, not applicability of already cached CVEs.
      const settings = { ...snapshot.settings, scopeHours: 0 };
      const correlated = runVulnerabilityPipeline(
        feeds,
        [...byId.values()],
        snapshot.watchlist,
        snapshot.alertedCves,
        [],
        settings,
      );
      // A wholly rejected stale bundle may be rebuilt from current matches. Never
      // automatically resend a bundle with any acceptance or an in-flight delivery.
      const staleBundles = new Set<string>(
        (
          await db.query(
            `SELECT advisory_id FROM outbox GROUP BY advisory_id HAVING bool_and(status='FAILED' AND COALESCE(error,'') LIKE 'Advisory applicability changed;%')`,
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
      for (const f of reconciled) await put(db, 'findings', f.id, f);
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
        const rank = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
        const advisory: Advisory = {
          id: settings.advisoryPrefix + randomUUID(),
          title: `Vulnerability notice: ${Array.from(new Set(pending.map((f) => f.cveId))).join(', ')}`,
          severity: pending.reduce(
            (s, f) => (rank.indexOf(f.cve.cvss.severity) > rank.indexOf(s) ? f.cve.cvss.severity : s),
            'LOW' as Advisory['severity'],
          ),
          cveIds: Array.from(new Set(pending.map((f) => f.cveId))),
          findingIds: pending.map((f) => f.id),
          createdDate: new Date().toISOString(),
          deliveryStatus: 'PENDING',
          recipientCount: 0,
          executiveSummary: `${pending.length} inventory correlations require investigation. Confirm applicability and consult the vendor before remediation.`,
          remediationInstructions:
            'Review vendor advisories and deploy tested remediation through your change process.',
          affectedSystems: Array.from(new Set(pending.map((f) => f.matchedAssetName))),
        };
        const count = await queueAdvisory(
          db,
          advisory,
          pending,
          renderAdvisory(snapshot.advisoryTemplate, advisory),
        );
        notificationsQueued = count;
        advisoriesQueued = count ? 1 : 0;
        if (count)
          for (const f of pending) await put(db, 'findings', f.id, { ...f, advisoryId: advisory.id });
      }
      execution = {
        ...correlated.execution,
        id: execution!.id,
        startTime: execution!.startTime,
        endTime: new Date().toISOString(),
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
        'Pipeline completed',
        `${execution.id}; ${correlated.newFindings.length} findings`,
        'worker',
        'PIPELINE',
      );
    });
    return true;
  } catch (e) {
    if (connectionLost) throw e;
    if (execution)
      await lockedTransaction(async (db) => {
        await put(db, 'executions', execution!.id, {
          ...execution,
          status: 'FAILED',
          endTime: new Date().toISOString(),
          logs: [...execution!.logs, e instanceof Error ? e.message : 'Worker failed'],
        });
        await appendAudit(db, 'Pipeline failed', `Execution ${execution!.id}`, 'worker', 'PIPELINE', 'ERROR');
      });
    else throw e;
    return true;
  } finally {
    if (locked) await lock.query('SELECT pg_advisory_unlock(800003)').catch(() => {});
    lock.removeListener('error', onError);
    lock.release(connectionLost);
  }
}
