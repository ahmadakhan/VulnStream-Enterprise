/**
 * Scheduled retraining cron for the ML subsystem.
 *
 * Designed to run as a standalone process (e.g., via a cron job or a
 * background worker). Connects to the database, collects training data,
 * runs the TrainingOrchestrator, and logs the results.
 *
 * Usage:
 *   node --import tsx server/ml/train/cron.ts
 *
 * Or programmatically:
 *   import { runScheduledTraining } from './cron.ts';
 *   await runScheduledTraining(pgPool, { directory: '/var/lib/vulnstream/ml' });
 */
import pg from 'pg';
import type { Db } from '../../db.ts';
import type { ModelStorageOptions } from '../types.ts';
import { TrainingOrchestrator, type TrainingDataSources, type TrainingSummary } from './orchestrator.ts';
import type { MetricFeatures } from '../models/metricAnomalyDetector.ts';
import type { ThresholdSample } from '../models/autoDispatchThreshold.ts';
import type { DeliveryOutcome } from '../models/deliveryOptimizer.ts';
import type { RemediationFeatures } from '../models/advisoryRemediationHelper.ts';
import type { FindingFeatures } from '../models/reviewRanker.ts';

const { Pool } = pg;

/**
 * Collects training data from the database for all ML models.
 *
 * Each method queries a different table/view. The queries are designed
 * to be efficient (single query per model) and to only fetch data from
 * the last N days (configurable via `lookbackDays`).
 */
export interface CronTrainingData {
  cpeStrings: string[];
  telemetryHistory: MetricFeatures[];
  dispatchOutcomes: ThresholdSample[];
  reviewOutcomeHistory: Array<{
    features: FindingFeatures;
    statusAfterReview: 'FALSE_POSITIVE' | 'PATCHED' | 'RESOLVED' | 'DELIVERED' | 'EXPIRED';
    daysToAction: number;
  }>;
  calibrationPairs: Array<{ credibilityScore: number; isActionable: boolean }>;
  deliveryOutcomes: DeliveryOutcome[];
  remediationFindings: Array<{
    features: RemediationFeatures;
    playbook: Record<string, unknown>;
  }>;
}

const DEFAULT_LOOKBACK_DAYS = 30;

/**
 * Default data provider — queries the VulnStream database directly.
 *
 * Each query fetches data from the last `lookbackDays` days.
 * Results are mapped to the TrainingSample format expected by the orchestrator.
 */
export class CronDataProvider {
  readonly lookbackDays: number;

  constructor(lookbackDays: number = DEFAULT_LOOKBACK_DAYS) {
    this.lookbackDays = lookbackDays;
  }

  async collectCpeStrings(db: Db): Promise<string[]> {
    const cutoff = new Date(Date.now() - this.lookbackDays * 86_400_000).toISOString();
    const result = await db.query<{ matched_cpe: string }>(
      `SELECT DISTINCT matched_cpe FROM correlation_matches WHERE matched_cpe IS NOT NULL AND created_at >= $1`,
      [cutoff],
    );
    return result.rows.map((row) => row.matched_cpe);
  }

  async collectTelemetry(db: Db): Promise<MetricFeatures[]> {
    const cutoff = new Date(Date.now() - this.lookbackDays * 86_400_000).toISOString();
    const result = await db.query<{
      memory_percent: number;
      active_workers: number;
      concurrency_limit: number;
      latency_ms: number;
      dead_letters: number;
      pending_claims: number;
      items_per_second: number;
      pool_waiting: number;
    }>(
      `SELECT memory_percent, active_workers, concurrency_limit, latency_ms, dead_letters, pending_claims, items_per_second, pool_waiting FROM correlation_telemetry WHERE timestamp >= $1 ORDER BY timestamp ASC`,
      [cutoff],
    );
    return result.rows.map((row) => ({
      memoryPercent: Number(row.memory_percent),
      activeWorkers: Number(row.active_workers),
      concurrencyLimit: Number(row.concurrency_limit),
      latencyMs: Number(row.latency_ms),
      deadLetters: Number(row.dead_letters),
      pendingClaims: Number(row.pending_claims),
      itemsPerSecond: Number(row.items_per_second),
      poolWaiting: Number(row.pool_waiting),
    }));
  }

  async collectDispatchOutcomes(db: Db): Promise<ThresholdSample[]> {
    const cutoff = new Date(Date.now() - this.lookbackDays * 86_400_000).toISOString();
    const result = await db.query<{
      confidence: number;
      notification_status: string;
      status: string;
      cve_id: string;
    }>(
      `SELECT confidence, notification_status, status, cve_id FROM correlation_matches WHERE created_at >= $1 AND confidence IS NOT NULL`,
      [cutoff],
    );
    return result.rows.map((row) => {
      const confidence = Number(row.confidence);
      const dispatched = row.notification_status === 'QUEUED_FOR_DISPATCH';
      const foundTruePositive = row.status === 'PATCHED' || row.status === 'RESOLVED' || row.status === 'DELIVERED';
      const wasFalsePositive = row.status === 'FALSE_POSITIVE';
      return { confidence, dispatched, wasFalsePositive, foundTruePositive } as ThresholdSample;
    });
  }

  async collectReviewOutcomeHistory(db: Db): Promise<Array<{ features: FindingFeatures; statusAfterReview: 'FALSE_POSITIVE' | 'PATCHED' | 'RESOLVED' | 'DELIVERED' | 'EXPIRED'; daysToAction: number }>> {
    const cutoff = new Date(Date.now() - this.lookbackDays * 86_400_000).toISOString();
    const result = await db.query<{
      confidence: number;
      cvss_score: number;
      epss_score: number;
      cisa_kev: boolean;
      exploit_status: number;
      cwe_risk_level: number;
      signal_density: number;
      source_feed_weight: number;
      has_version_evidence: boolean;
      days_since_published: number;
      status: string;
      created_at: string;
      resolved_at: string | null;
    }>(
      `SELECT m.confidence, m.cvss_score, m.epss_score, m.cisa_kev, m.exploit_status, m.cwe_risk_level, m.signal_density, m.source_feed_weight, m.has_version_evidence, m.days_since_published, m.status, m.created_at, m.resolved_at FROM correlation_matches m JOIN correlation_review_decisions r ON m.id = r.match_id WHERE m.status IN ('FALSE_POSITIVE','PATCHED','RESOLVED','DELIVERED','EXPIRED') AND m.created_at >= $1`,
      [cutoff],
    );

    const statusMap: Record<string, 'FALSE_POSITIVE' | 'PATCHED' | 'RESOLVED' | 'DELIVERED' | 'EXPIRED'> = {
      FALSE_POSITIVE: 'FALSE_POSITIVE',
      PATCHED: 'PATCHED',
      RESOLVED: 'RESOLVED',
      DELIVERED: 'DELIVERED',
      EXPIRED: 'EXPIRED',
    };

    return result.rows.map((row) => {
      const createdAt = new Date(row.created_at);
      const resolvedAt = row.resolved_at ? new Date(row.resolved_at) : new Date();
      const daysToAction = (resolvedAt.getTime() - createdAt.getTime()) / 86_400_000;
      return {
        features: {
          matchConfidence: Number(row.confidence),
          cvssScore: Number(row.cvss_score),
          epssScore: Number(row.epss_score),
          cisaKev: row.cisa_kev,
          exploitStatus: Number(row.exploit_status),
          cweRiskLevel: Number(row.cwe_risk_level),
          signalDensity: Number(row.signal_density),
          matchMethod: 'STRICT_CPE',
          sourceFeedWeight: Number(row.source_feed_weight),
          assetCriticality: 0,
          hasVersionEvidence: row.has_version_evidence,
          daysSincePublished: Number(row.days_since_published),
          negated: false,
        } as FindingFeatures,
        statusAfterReview: statusMap[row.status] ?? 'EXPIRED',
        daysToAction: Math.max(0, daysToAction),
      };
    });
  }

  async collectCalibrationPairs(db: Db): Promise<Array<{ credibilityScore: number; isActionable: boolean }>> {
    const cutoff = new Date(Date.now() - this.lookbackDays * 86_400_000).toISOString();
    const result = await db.query<{
      credibility_score: number;
      status: string;
    }>(
      `SELECT credibility_score, status FROM correlation_matches WHERE created_at >= $1 AND credibility_score IS NOT NULL`,
      [cutoff],
    );
    return result.rows.map((row) => ({
      credibilityScore: Number(row.credibility_score),
      isActionable: row.status === 'PATCHED' || row.status === 'RESOLVED' || row.status === 'DELIVERED',
    }));
  }

  async collectDeliveryOutcomes(db: Db): Promise<DeliveryOutcome[]> {
    const cutoff = new Date(Date.now() - this.lookbackDays * 86_400_000).toISOString();

    // Email delivery outcomes
    const emailResult = await db.query<{
      provider: string;
      attempt: number;
      delay_ms: number;
      succeeded: boolean;
      is_rate_limited: boolean;
      is_permanent_failure: boolean;
    }>(
      `SELECT COALESCE(o.provider_id, 'unknown') AS provider, o.attempts AS attempt, EXTRACT(EPOCH FROM (o.next_attempt - o.created_at)) * 1000 AS delay_ms, o.status = 'ACCEPTED' AS succeeded, o.error ILIKE '%rate%limit%' AS is_rate_limited, o.status = 'FAILED' AS is_permanent_failure FROM outbox o WHERE o.channel = 'email' AND o.created_at >= $1 AND o.status IN ('ACCEPTED', 'FAILED')`,
      [cutoff],
    );

    // Webhook delivery outcomes (infer provider type)
    const webhookResult = await db.query<{
      provider: string;
      attempt: number;
      delay_ms: number;
      succeeded: boolean;
      is_rate_limited: boolean;
      is_permanent_failure: boolean;
    }>(
      `SELECT 'webhook' AS provider, o.attempts AS attempt, EXTRACT(EPOCH FROM (o.next_attempt - o.created_at)) * 1000 AS delay_ms, o.status = 'ACCEPTED' AS succeeded, false AS is_rate_limited, o.status = 'FAILED' AS is_permanent_failure FROM outbox o WHERE o.channel = 'webhook' AND o.created_at >= $1 AND o.status IN ('ACCEPTED', 'FAILED')`,
      [cutoff],
    );

    const combined = [...emailResult.rows, ...webhookResult.rows];
    return combined.map((row) => ({
      provider: row.provider,
      attempt: Number(row.attempt),
      delayMs: Number(row.delay_ms),
      succeeded: row.succeeded,
      isRateLimited: row.is_rate_limited,
      isPermanentFailure: row.is_permanent_failure,
    }));
  }

  async collectRemediationFindings(db: Db): Promise<Array<{ features: RemediationFeatures; playbook: Record<string, unknown> }>> {
    const cutoff = new Date(Date.now() - this.lookbackDays * 86_400_000).toISOString();
    const result = await db.query<{
      cvss_score: number;
      epss_score: number;
      cisa_kev: boolean;
      days_since_published: number;
      source_feed_weight: number;
      has_version_evidence: boolean;
      cwe_risk_level: number;
      exploit_status: number;
      patch_url: string | null;
      vendor_advisory_ref: string | null;
      has_workarounds: boolean;
      has_immediate_actions: boolean;
      has_rollback_plan: boolean;
      has_step_by_step: boolean;
    }>(
      `SELECT m.cvss_score, m.epss_score, m.cisa_kev, m.days_since_published, m.source_feed_weight, m.has_version_evidence, m.cwe_risk_level, m.exploit_status, r.patch_url, r.vendor_advisory_ref, r.workarounds IS NOT NULL AS has_workarounds, r.immediate_actions IS NOT NULL AS has_immediate_actions, r.rollback_plan IS NOT NULL AS has_rollback_plan, r.step_by_step IS NOT NULL AS has_step_by_step FROM correlation_matches m LEFT JOIN remediation_playbooks r ON m.id = r.match_id WHERE m.created_at >= $1`,
      [cutoff],
    );

    return result.rows.map((row) => ({
      features: {
        cvssScore: Number(row.cvss_score),
        epssScore: Number(row.epss_score),
        cisaKev: row.cisa_kev,
        daysSincePublished: Number(row.days_since_published),
        sourceFeedWeight: Number(row.source_feed_weight),
        hasVersionEvidence: row.has_version_evidence,
        cweRiskLevel: Number(row.cwe_risk_level),
        exploitStatus: Number(row.exploit_status),
      },
      playbook: {
        patch_url: row.patch_url,
        vendor_advisory_ref: row.vendor_advisory_ref,
        workarounds: row.has_workarounds ? ['workaround'] : undefined,
        immediate_actions: row.has_immediate_actions ? ['action'] : undefined,
        rollback_plan: row.has_rollback_plan ? 'rollback' : undefined,
        step_by_step: row.has_step_by_step ? ['step'] : undefined,
      },
    }));
  }

  async collectAll(db: Db): Promise<TrainingDataSources> {
    const [
      cpeStrings,
      telemetryHistory,
      dispatchOutcomes,
      reviewOutcomeHistory,
      calibrationPairs,
      deliveryOutcomes,
      remediationFindings,
    ] = await Promise.all([
      this.collectCpeStrings(db),
      this.collectTelemetry(db),
      this.collectDispatchOutcomes(db),
      this.collectReviewOutcomeHistory(db),
      this.collectCalibrationPairs(db),
      this.collectDeliveryOutcomes(db),
      this.collectRemediationFindings(db),
    ]);

    return {
      cpeStrings,
      telemetryHistory,
      dispatchOutcomes,
      reviewOutcomeHistory,
      calibrationPairs,
      deliveryOutcomes,
      remediationFindings,
    };
  }
}

/**
 * Custom data provider function type — allows callers to provide
 * their own data collection logic instead of querying the database.
 */
export type DataCollector = (db: Db) => Promise<TrainingDataSources>;

/**
 * Runs a full scheduled training cycle.
 *
 * 1. Collects training data from the database via the provided data collector
 * 2. Trains all models via TrainingOrchestrator
 * 3. Returns a summary with per-model results
 *
 * Throws only if the database query fails — model training failures are
 * captured in the summary (status: 'failed'), not thrown.
 */
export async function runScheduledTraining(
  pool: pg.Pool,
  options: ModelStorageOptions & {
    lookbackDays?: number;
    dataCollector?: DataCollector;
  },
): Promise<TrainingSummary> {
  const lookbackDays = options.lookbackDays ?? DEFAULT_LOOKBACK_DAYS;
  const dataCollector = options.dataCollector ?? ((db) => new CronDataProvider(lookbackDays).collectAll(db));

  const client = await pool.connect();
  try {
    const data = await dataCollector(client);
    const orchestrator = new TrainingOrchestrator({ directory: options.directory });
    const summary = await orchestrator.trainAll(data);

    // Log summary
    console.log(`[ML Training] ${summary.timestamp} — ${summary.summary.trained}/${summary.summary.total} models trained, ${summary.summary.saved} saved, ${summary.summary.failed} failed`);

    for (const result of summary.results) {
      const status = result.status === 'trained' ? '✔' : result.status === 'skipped' ? '⊘' : '✗';
      const saved = result.saved ? ' saved' : '';
      console.log(`  ${status} ${result.modelId}: ${result.samplesCollected} samples → ${result.validation.passed ? 'passed gate' : `failed: ${result.validation.failureReason ?? 'unknown'}`}${saved}`);
    }

    return summary;
  } finally {
    client.release();
  }
}

/**
 * CLI entry point — runs scheduled training with a database pool.
 * Exits with code 1 if any model fails to train or fails its quality gate.
 */
export async function main(): Promise<void> {
  const connectionString = process.env.DATABASE_URL ?? process.env.PG_CONNECTION_STRING;
  const mlDir = process.env.ML_DIRECTORY ?? '/var/lib/vulnstream/ml';
  const lookbackDays = process.env.ML_LOOKBACK_DAYS ? parseInt(process.env.ML_LOOKBACK_DAYS, 10) : DEFAULT_LOOKBACK_DAYS;

  if (!connectionString) {
    console.error('ERROR: DATABASE_URL or PG_CONNECTION_STRING environment variable is required');
    process.exit(1);
  }

  const pool = new Pool({ connectionString });

  try {
    const summary = await runScheduledTraining(pool, {
      directory: mlDir,
      lookbackDays,
    });

    const failed = summary.results.filter((r) => r.status === 'failed');
    if (failed.length > 0) {
      console.error(`ERROR: ${failed.length} model(s) failed training:`);
      for (const f of failed) {
        console.error(`  - ${f.modelId}: ${f.error ?? f.validation.failureReason ?? 'unknown'}`);
      }
      process.exit(1);
    }

    console.log('Training complete.');
  } finally {
    await pool.end();
  }
}

// Run as CLI when executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  void main();
}
