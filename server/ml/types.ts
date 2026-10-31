/**
 * Core type definitions for the autonomous ML subsystem.
 *
 * Design constraints:
 * - Pure TypeScript, zero external ML dependencies.
 * - All models serialize to/from JSON for on-disk storage.
 * - Training is offline; inference runs in-process during pipeline ticks.
 * - Every model carries a version + trainedAt timestamp for rollback safety.
 */

export type ModelType =
  | 'logistic'
  | 'isolation_forest'
  | 'decision_tree'
  | 'gradient_boosting'
  | 'threshold_optimizer'
  | 'gbdt_ranker'
  | 'calibrator';

export interface ModelMetadata {
  id: string;
  type: ModelType;
  version: string;
  trainedAt: string;
  featureSchema: string[];
  description: string;
  performance?: {
    accuracy?: number;
    precision?: number;
    recall?: number;
    aucRoc?: number;
    bce?: number;
    meanAverageError?: number;
  };
  rollbackTrigger?: string;
}

export interface PredictionResult {
  score: number;
  probability?: number;
  confidence: 'LOW' | 'MEDIUM' | 'HIGH';
  reason: string;
}

export interface ModelArtifact {
  metadata: ModelMetadata;
  weights: unknown;
}

export interface TrainableModel {
  train(samples: TrainingSample[]): void;
  predict(features: Record<string, number>): PredictionResult;
  predictBatch(features: Record<string, number>[]): PredictionResult[];
  serialize(): ModelArtifact;
  load(artifact: ModelArtifact): void;
  getFeatureNames(): string[];
}

export interface TrainingSample {
  id: string;
  features: Record<string, number>;
  label: number | boolean;
  weight?: number;
  timestamp: string;
}

export interface FeedbackSignal {
  modelId: string;
  sampleId: string;
  predicted: number;
  actual: number | boolean;
  timestamp: string;
  weight?: number;
}

export interface ModelRegistryEntry {
  model: TrainableModel;
  metadata: ModelMetadata;
  loadedAt: string;
  status: 'ACTIVE' | 'STANDBY_ROLLBACK' | 'DEGRADED';
}

/** Numerical feature scaler — standardization (z-score) or min-max. */
export interface Scaler {
  transform(features: number[]): number[];
  inverseTransform(scaled: number[]): number[];
  serialize(): unknown;
  load(data: unknown): void;
  getFeatureNames(): string[];
}

/** Options for the local persistence layer. */
export interface ModelStorageOptions {
  directory: string;
}

/**
 * Result of self-validation — used by the autonomous gate that decides whether
 * a freshly trained model can replace the active one or rolls back.
 */
export interface ModelSelfValidation {
  passed: boolean;
  metrics: Record<string, number>;
  failureReason?: string;
}
