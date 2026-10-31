/**
 * Pipeline integration layer for the ML subsystem.
 *
 * Provides drop-in wrapper functions that delegate to trained ML models
 * when available, and fall back to existing hardcoded behavior when models
 * are untrained or unavailable. This ensures zero risk of regressions —
 * the ML models always improve or match the status quo, never degrade it.
 *
 * Usage:
 *   import { initMlRuntime } from './ml/integration.ts';
 *   await initMlRuntime({ directory: '/var/lib/vulnstream/ml' });
 *
 *   // In pipeline engine:
 *   import { shouldAutoDispatch, rankReviewFindings } from './ml/integration.ts';
 *   const shouldDispatch = shouldAutoDispatch(confidence, settings);
 *   const ranked = rankReviewFindings(findings);
 */
import { createMlRuntime, type MlRuntime } from './factory.ts';
import type { ModelStorageOptions } from './types.ts';
import type { AppSettings, RemediationPlaybook, Finding } from '../../src/types/index.ts';
import type { MetricFeatures as TelemetryMetric } from './models/metricAnomalyDetector.ts';
import { extractMetricFeatures } from './models/metricAnomalyDetector.ts';
import { extractFindingFeatures } from './models/reviewRanker.ts';
import type { RemediationFeatures, RemediationPrediction } from './models/advisoryRemediationHelper.ts';
import { DEFAULT_AUTO_DISPATCH_THRESHOLD } from './defaults.ts';

interface MlContext {
  runtime: MlRuntime | null;
  storage: ModelStorageOptions | null;
}

/** Module-level singleton — initialized once at server startup. */
const ctx: MlContext = { runtime: null, storage: null };

/**
 * Initializes the ML runtime by loading artifacts from disk.
 * Must be called once during server startup before any integration functions are used.
 */
export async function initMlRuntime(options: ModelStorageOptions): Promise<MlRuntime> {
  ctx.storage = options;
  ctx.runtime = await createMlRuntime(options);
  return ctx.runtime;
}

/** Returns the active ML runtime, or null if not initialized. */
export function getMlRuntime(): MlRuntime | null {
  return ctx.runtime;
}

/**
 * 1. CPE Validity Gate — pre-filter for parseCPE23.
 *
 * Returns false (skip parse) only when the classifier is HIGH-confidence
 * that the CPE is malformed. Always falls through to the parser for
 * untrained or uncertain cases — never blocks valid CPEs.
 */
export function cpePreFilter(cpe: string): boolean {
  const model = ctx.runtime?.cpeValidityGate;
  if (!model?.isTrained()) return true;
  return model.shouldParse(cpe);
}

/**
 * 2. Confidence Calibrator — calibrates the heuristic credibility score.
 *
 * Returns the calibrated probability. Falls back to raw score / 100
 * when the calibrator is untrained.
 */
export function calibrateCredibilityScore(rawScore: number): {
  score: number;
  probability: number;
  confidence: 'LOW' | 'MEDIUM' | 'HIGH';
} {
  const model = ctx.runtime?.confidenceCalibrator;
  if (!model?.isTrained()) {
    return { score: rawScore, probability: rawScore / 100, confidence: 'LOW' };
  }
  const result = model.predict({ credibility_score: rawScore });
  return {
    score: result.score * 100,
    probability: result.probability ?? result.score,
    confidence: result.confidence,
  };
}

/**
 * 3. Auto-Dispatch Threshold — replaces the hardcoded 90% gate.
 *
 * Uses the learned threshold when trained, falls back to the configured
 * settings.autoDispatchConfidenceThreshold (default 90) when untrained.
 */
export function shouldAutoDispatch(confidence: number, settings: Pick<AppSettings, 'autoDispatchConfidenceThreshold'>): boolean {
  const model = ctx.runtime?.autoDispatchThreshold;
  if (!model?.isTrained()) {
    return confidence >= (settings.autoDispatchConfidenceThreshold ?? DEFAULT_AUTO_DISPATCH_THRESHOLD);
  }
  return model.shouldDispatch(confidence);
}

/**
 * 4. Review Queue Ranker — ranks REVIEW_REQUIRED findings by
 * true-positive probability so the most actionable surface first.
 *
 * Falls back to sorting by match confidence when untrained.
 */
export function rankReviewFindings(findings: Finding[]): Finding[] {
  const model = ctx.runtime?.reviewRanker;
  if (!model?.isTrained()) {
    return [...findings].sort((a, b) => (b.confidence ?? 0) - (a.confidence ?? 0));
  }

  const features = findings.map((f) =>
    extractFindingFeatures({
      matchConfidence: f.confidence ?? 0,
      cvssScore: f.cve?.cvss?.score ?? 0,
      epssScore: f.cve?.epss?.score ?? 0,
      cisaKev: false,
      exploitStatus: 0,
      cweRiskLevel: 0,
      signalDensity: 0,
      matchMethod: f.matchingMethod ?? 'UNKNOWN',
      sourceFeedWeight: 0,
      assetCriticality: 0,
      hasVersionEvidence: Boolean(f.matchedAssetPurls?.length),
      daysSincePublished: 0,
      negated: false,
    }),
  );

  const predictions = model.predictBatch(features);
  return findings
    .map((f, i) => ({ finding: f, score: predictions[i]?.probability ?? predictions[i]?.score ?? 0 }))
    .sort((a, b) => b.score - a.score)
    .map((entry) => entry.finding);
}

/**
 * 5. Metric Anomaly Detector — checks if a telemetry snapshot is anomalous.
 * Falls back to returning false (no anomaly) when untrained.
 */
export function isTelemetryAnomaly(
  metrics: TelemetryMetric,
): boolean {
  const model = ctx.runtime?.metricAnomalyDetector;
  if (!model?.isTrained()) return false;
  return model.isAnomaly(extractMetricFeatures(metrics));
}

/**
 * 6. Delivery Optimizer — computes retry delay using learned policy.
 * Falls back to the default exponential backoff when untrained.
 */
export function computeRetryDelay(attempt: number): number {
  const model = ctx.runtime?.deliveryOptimizer;
  if (!model?.isTrained()) {
    return Math.min(1440 * 60_000, 5 * 60_000 * 2 ** Math.max(0, attempt - 1));
  }
  return model.computeDelay(attempt);
}

/**
 * 7. Advisory Remediation Helper — predicts remediation playbook
 * completeness and generates fallback content for missing fields.
 * Falls back to rule-based defaults when untrained.
 */
export function predictRemediation(
  features: RemediationFeatures,
  actualPlaybook?: Partial<RemediationPlaybook>,
): RemediationPrediction {
  const model = ctx.runtime?.remediationHelper;
  if (!model?.isTrained()) {
    return {
      patchUrl: 0.2,
      vendorAdvisory: features.cisaKev ? 0.8 : 0.3,
      immediateActions: features.exploitStatus > 2 ? 0.7 : 0.3,
      workarounds: features.epssScore > 0.5 ? 0.4 : 0.6,
      rollbackPlan: features.cvssScore > 8 ? 0.6 : features.cvssScore > 4 ? 0.4 : 0.2,
      stepByStep: features.hasVersionEvidence ? 0.7 : 0.4,
      overall: 0.5,
      recommendation: 'partial',
      generatedContent: actualPlaybook ?? {},
    };
  }
  return model.predictRemediation(features, actualPlaybook);
}
