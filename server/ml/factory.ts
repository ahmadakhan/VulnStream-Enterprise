/**
 * ML subsystem factory — creates, registers, and wires all autonomous ML
 * models into the VulnStream-Enterprise pipeline.
 *
 * Usage:
 *   import { createMlRuntime } from './ml/factory.ts';
 *   const runtime = createMlRuntime(config.mlDirectory);
 *
 * The factory instantiates every model, loads persisted artifacts from disk
 * (with automatic rollback on failure), and exposes typed access to each
 * model for integration into existing pipeline code.
 *
 * Integration points:
 *   - CPE Validity Gate     → cpeMatcher.ts:55 (parseCPE23 pre-filter)
 *   - Metric Anomaly Detector → supervisor.ts + metrics.ts (telemetry)
 *   - Auto-Dispatch Threshold → pipelineEngine.ts:497 (90% auto-dispatch gate)
 *   - Review Queue Ranker  → pipelineEngine.ts:397 (REVIEW_REQUIRED sorting)
 *   - Confidence Calibrator → intelligenceMatcher.ts:49 (credibility scoring)
 *   - Delivery Optimizer   → delivery.ts:183 (emailRetryDelayMs/backoff)
 *   - Remediation Helper   → templateCompiler.ts:249 (remediation template fields)
 */
import { ModelRegistry } from './runtime.ts';
import { CpeValidityGateModel } from './models/cpeValidityGate.ts';
import { MetricAnomalyDetectorModel } from './models/metricAnomalyDetector.ts';
import { AutoDispatchThresholdModel } from './models/autoDispatchThreshold.ts';
import { ReviewRankerModel } from './models/reviewRanker.ts';
import { ConfidenceCalibrator } from './models/confidenceCalibrator.ts';
import { DeliveryOptimizerModel } from './models/deliveryOptimizer.ts';
import { AdvisoryRemediationHelper } from './models/advisoryRemediationHelper.ts';
import type { ModelStorageOptions } from './types.ts';

export interface MlRuntime {
  registry: ModelRegistry;
  cpeValidityGate: CpeValidityGateModel;
  metricAnomalyDetector: MetricAnomalyDetectorModel;
  autoDispatchThreshold: AutoDispatchThresholdModel;
  reviewRanker: ReviewRankerModel;
  confidenceCalibrator: ConfidenceCalibrator;
  deliveryOptimizer: DeliveryOptimizerModel;
  remediationHelper: AdvisoryRemediationHelper;
}

export async function createMlRuntime(options: ModelStorageOptions): Promise<MlRuntime> {
  const registry = new ModelRegistry(options);

  const cpeValidityGate = new CpeValidityGateModel();
  const metricAnomalyDetector = new MetricAnomalyDetectorModel();
  const autoDispatchThreshold = new AutoDispatchThresholdModel();
  const reviewRanker = new ReviewRankerModel();
  const confidenceCalibrator = new ConfidenceCalibrator();
  const deliveryOptimizer = new DeliveryOptimizerModel();
  const remediationHelper = new AdvisoryRemediationHelper();

   // autoDispatchThreshold uses a 1-D optimizer (not a TrainableModel), so it is
   // loaded via saveArtifact/loadArtifact rather than the standard TrainableModel path.
   await registry.loadArtifact(autoDispatchThreshold, 'auto-dispatch-threshold');

  await registry.load(cpeValidityGate, 'cpe-validity-gate');
  await registry.load(metricAnomalyDetector, 'metric-anomaly-detector');
  await registry.load(reviewRanker, 'review-ranker');
  await registry.load(confidenceCalibrator, 'confidence-calibrator');
  await registry.load(deliveryOptimizer, 'delivery-optimizer');
  await registry.load(remediationHelper, 'advisory-remediation-helper');
  return {
    registry,
    cpeValidityGate,
    metricAnomalyDetector,
    autoDispatchThreshold,
    reviewRanker,
    confidenceCalibrator,
    deliveryOptimizer,
    remediationHelper,
  };
}
