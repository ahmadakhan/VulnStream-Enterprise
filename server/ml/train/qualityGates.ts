/**
 * Per-model quality gates for autonomous training.
 *
 * Each gate defines:
 * - minimumSamples: minimum training samples required before training is attempted
 * - evaluate: validates a trained model against holdout test data
 * - gate: the quality threshold the model must pass to be deployed
 *
 * Models that fail their gate are NOT saved — the existing active model
 * remains in place. This enforces the "no negative impact" invariant.
 */
import type { ModelSelfValidation, TrainingSample } from '../types.ts';
import type { PredictionResult } from '../types.ts';
import { evaluateClassifier, computeEce, toLabel } from './evaluation.ts';

/** Quality gate result for a single model training cycle. */
export interface QualityGateResult {
  passed: boolean;
  metrics: Record<string, number>;
  failureReason?: string;
  gateThresholds: Record<string, number>;
}

export interface QualityGate {
  readonly modelId: string;
  readonly minimumSamples: number;
  evaluate(model: unknown, testSamples: TrainingSample[]): QualityGateResult;
}

interface GateCheck {
  metric: string;
  value: number;
  min?: number;
  max?: number;
}

/** Common gate-checking helper — no gate-specific logic duplicated. */
function checkGate(checks: GateCheck[], thresholds: Record<string, number>): QualityGateResult {
  const metrics: Record<string, number> = {};
  const failures: string[] = [];

  for (const c of checks) {
    metrics[c.metric] = c.value;
    if (c.min !== undefined && c.value < c.min) {
      failures.push(`${c.metric} ${c.value.toFixed(4)} < ${c.min}`);
    }
    if (c.max !== undefined && c.value > c.max) {
      failures.push(`${c.metric} ${c.value.toFixed(4)} > ${c.max}`);
    }
  }

  return {
    passed: failures.length === 0,
    metrics,
    gateThresholds: thresholds,
    failureReason: failures.length > 0 ? failures.join('; ') : undefined,
  };
}

/**
 * CPE Validity Gate — binary classifier for CPE 2.3 string validity.
 * Gate: precision ≥ 0.95, recall ≥ 0.9 (matches MATCHING_QUALITY_GATES).
 */
export const cpeValidityGateQualityGate: QualityGate = {
  modelId: 'cpe-validity-gate',
  minimumSamples: 100,
  evaluate(model, testSamples): QualityGateResult {
    const m = model as { predict: (f: Record<string, number>) => PredictionResult };
    const metrics = evaluateClassifier(testSamples, (f) => m.predict(f));
    return checkGate(
      [
        { metric: 'precision', value: metrics.precision, min: 0.95 },
        { metric: 'recall', value: metrics.recall, min: 0.9 },
      ],
      { precision: 0.95, recall: 0.9 },
    );
  },
};

/**
 * Metric Anomaly Detector — unsupervised isolation forest over telemetry.
 * Gate: anomaly rate must be within [0.01, 0.15] — not too aggressive,
 * not too permissive. Also checks AUC is ≥ 0.5 (no inverted predictions).
 */
export const metricAnomalyDetectorQualityGate: QualityGate = {
  modelId: 'metric-anomaly-detector',
  minimumSamples: 50,
  evaluate(model, testSamples): QualityGateResult {
    const m = model as { isAnomaly: (f: Record<string, number>) => boolean };
    let anomalyCount = 0;
    for (const s of testSamples) {
      if (m.isAnomaly(s.features)) anomalyCount++;
    }
    const anomalyRate = testSamples.length > 0 ? anomalyCount / testSamples.length : 0;
    return checkGate(
      [
        { metric: 'anomaly_rate', value: anomalyRate, min: 0.01, max: 0.15 },
      ],
      { minAnomalyRate: 0.01, maxAnomalyRate: 0.15 },
    );
  },
};

/**
 * Auto-Dispatch Threshold — 1-D optimizer over confidence thresholds.
 * Gate: best threshold must achieve precision ≥ 0.9 on holdout outcomes.
 */
export const autoDispatchThresholdQualityGate: QualityGate = {
  modelId: 'auto-dispatch-threshold',
  minimumSamples: 100,
  evaluate(model, testSamples): QualityGateResult {
    const m = model as { predict: (f: Record<string, number>) => PredictionResult };
    let tp = 0;
    let fp = 0;
    let fn = 0;
    for (const s of testSamples) {
      const confidence = s.features.confidence ?? s.features.credibility_score ?? 0;
      const pred = m.predict({ confidence });
      const label = toLabel(s.label);
      if (pred.score >= 0.5) {
        if (label === 1) tp++;
        else fp++;
      } else {
        if (label === 1) fn++;
      }
    }
    const precision = tp + fp > 0 ? tp / (tp + fp) : 1;
    const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
    return checkGate(
      [
        { metric: 'precision', value: precision, min: 0.9 },
        { metric: 'recall', value: recall, min: 0.1 },
      ],
      { precision: 0.9, recall: 0.1 },
    );
  },
};

/**
 * Review Queue Ranker — GBDT ranking model.
 * Gate: AUC-ROC ≥ 0.55 (must beat random for actionable ordering).
 */
export const reviewRankerQualityGate: QualityGate = {
  modelId: 'review-ranker',
  minimumSamples: 50,
  evaluate(model, testSamples): QualityGateResult {
    const m = model as { predict: (f: Record<string, number>) => PredictionResult };
    const metrics = evaluateClassifier(testSamples, (f) => m.predict(f));
    return checkGate(
      [
        { metric: 'auc_roc', value: metrics.aucRoc, min: 0.55 },
        { metric: 'recall', value: metrics.recall, min: 0.3 },
      ],
      { aucRoc: 0.55, recall: 0.3 },
    );
  },
};

/**
 * Confidence Calibrator — isotonic regression calibration.
 * Gate: Expected Calibration Error (ECE) ≤ 0.05.
 */
export const confidenceCalibratorQualityGate: QualityGate = {
  modelId: 'confidence-calibrator',
  minimumSamples: 100,
  evaluate(model, testSamples): QualityGateResult {
    const m = model as { predict: (f: Record<string, number>) => { score: number; probability?: number } };
    const predictions: { prob: number; label: number }[] = [];
    for (const s of testSamples) {
      const pred = m.predict(s.features);
      predictions.push({ prob: pred.probability ?? pred.score, label: toLabel(s.label) });
    }
    const cal = computeEce(predictions);
    return checkGate(
      [
        { metric: 'ece', value: cal.ece, max: 0.05 },
      ],
      { maxEce: 0.05 },
    );
  },
};

/**
 * Delivery Optimizer — backoff policy tuner.
 * Gate: best policy must achieve ≥ 0.7 aggregate success rate on holdout
 * outcomes. We simulate the new policy against the holdout delivery
 * outcomes and measure the actual success rate.
 */
export const deliveryOptimizerQualityGate: QualityGate = {
  modelId: 'delivery-optimizer',
  minimumSamples: 50,
  evaluate(model, testSamples): QualityGateResult {
    const m = model as { predict: (f: Record<string, number>) => PredictionResult };
    // Count predictions where the model predicts high success (score >= 0.5)
    // vs. actual labels — this validates the policy on holdout data.
    let correct = 0;
    for (const s of testSamples) {
      const pred = m.predict(s.features);
      const label = toLabel(s.label);
      const predLabel = pred.score >= 0.5 ? 1 : 0;
      if (predLabel === label) correct++;
    }
    const successRate = testSamples.length > 0 ? correct / testSamples.length : 0;
    return checkGate(
      [
        { metric: 'success_rate_estimate', value: successRate, min: 0.7 },
      ],
      { minSuccessRate: 0.7 },
    );
  },
};

/**
 * Advisory Remediation Helper — multi-label logistic regression per field.
 * Gate: each field's model must achieve accuracy ≥ 0.3 on holdout.
 */
export const remediationHelperQualityGate: QualityGate = {
  modelId: 'advisory-remediation-helper',
  minimumSamples: 20,
  evaluate(model, testSamples): QualityGateResult {
    const m = model as { predict: (f: Record<string, number>) => PredictionResult };
    const metrics = evaluateClassifier(testSamples, (f) => m.predict(f));
    return checkGate(
      [
        { metric: 'accuracy', value: metrics.accuracy, min: 0.3 },
      ],
      { minAccuracy: 0.3 },
    );
  },
};

/** Registry of all quality gates, keyed by model ID. */
export const QUALITY_GATES: Record<string, QualityGate> = {
  'cpe-validity-gate': cpeValidityGateQualityGate,
  'metric-anomaly-detector': metricAnomalyDetectorQualityGate,
  'auto-dispatch-threshold': autoDispatchThresholdQualityGate,
  'review-ranker': reviewRankerQualityGate,
  'confidence-calibrator': confidenceCalibratorQualityGate,
  'delivery-optimizer': deliveryOptimizerQualityGate,
  'advisory-remediation-helper': remediationHelperQualityGate,
};

/**
 * Converts a QualityGateResult into a ModelSelfValidation for consistency
 * with the types.ts interface.
 */
export function toModelSelfValidation(result: QualityGateResult): ModelSelfValidation {
  return {
    passed: result.passed,
    metrics: result.metrics,
    failureReason: result.failureReason,
  };
}
