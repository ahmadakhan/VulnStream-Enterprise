export { BaseModel } from './baseModel.ts';
export {
  CpeValidityGateModel,
  extractCpeValidityFeatures,
  type CpeValidityFeatures,
} from './models/cpeValidityGate.ts';
export {
  MetricAnomalyDetectorModel,
  extractMetricFeatures,
  type MetricFeatures,
  METRIC_FEATURE_NAMES,
} from './models/metricAnomalyDetector.ts';
export { AutoDispatchThresholdModel, type ThresholdSample } from './models/autoDispatchThreshold.ts';
export {
  ReviewRankerModel,
  extractFindingFeatures,
  type FindingFeatures,
  REVIEW_RANKER_FEATURES,
} from './models/reviewRanker.ts';
export { ConfidenceCalibrator } from './models/confidenceCalibrator.ts';
export { DeliveryOptimizerModel, type DeliveryOutcome } from './models/deliveryOptimizer.ts';
export {
  AdvisoryRemediationHelper,
  extractRemediationFeatures,
  type RemediationFeatures,
  type RemediationPrediction,
  REMEDIATION_FIELD_NAMES,
} from './models/advisoryRemediationHelper.ts';
export { ModelRegistry } from './runtime.ts';
export { createMlRuntime, type MlRuntime } from './factory.ts';

export {
  initMlRuntime,
  getMlRuntime,
  cpePreFilter,
  calibrateCredibilityScore,
  shouldAutoDispatch,
  rankReviewFindings,
  isTelemetryAnomaly,
  computeRetryDelay,
  predictRemediation,
} from './integration.ts';
export {
  DEFAULT_AUTO_DISPATCH_THRESHOLD,
  DEFAULT_EMAIL_RETRY_INITIAL_DELAY_MINUTES,
  DEFAULT_EMAIL_RETRY_MULTIPLIER,
  DEFAULT_EMAIL_RETRY_MAX_DELAY_MINUTES,
  DEFAULT_EMAIL_RETRY_MAX_ATTEMPTS,
} from './defaults.ts';
export { TrainingOrchestrator, type TrainingDataSources, type TrainingResult, type TrainingSummary } from './train/orchestrator.ts';
export { QUALITY_GATES, type QualityGate, type QualityGateResult } from './train/qualityGates.ts';
export {
  computePsi,
  detectFeatureDrift,
  detectConceptDrift,
  shouldRetrain,
  type DriftReport,
  type FeatureDriftReport,
  type ConceptDriftReport,
  PSI_THRESHOLDS,
  CONCEPT_DRIFT_THRESHOLDS,
} from './train/driftDetection.ts';
export { evaluateClassifier, computeEce, splitData, toLabel } from './train/evaluation.ts';
export { createRng, DEFAULT_TRAINING_SEED } from './algorithms/rng.ts';
export { LogisticRegression } from './algorithms/logisticRegression.ts';
export { IsolationForest } from './algorithms/isolationForest.ts';
export { GBDTRanker } from './algorithms/gbdtRanker.ts';
export { StandardScaler } from './algorithms/standardScaler.ts';
export type {
  ModelMetadata,
  ModelArtifact,
  ModelRegistryEntry,
  PredictionResult,
  TrainableModel,
  TrainingSample,
  Scaler,
  ModelStorageOptions,
  ModelSelfValidation,
  ModelType,
  FeedbackSignal,
} from './types.ts';
