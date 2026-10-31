/**
 * Logistic regression with binary cross-entropy loss and L2 regularization.
 * Trains via mini-batch gradient descent with early stopping on validation loss.
 *
 * Inference: predict(features) returns P(y=1 | x) where x is a feature vector.
 */
import { StandardScaler } from './standardScaler.ts';
import { createRng, DEFAULT_TRAINING_SEED } from './rng.ts';
import type { PredictionResult, TrainingSample } from '../types.ts';

export interface LogisticRegressionWeights {
  weights: number[];
  bias: number;
  scaler: ReturnType<StandardScaler['serialize']>;
  featureNames: string[];
  threshold: number;
  trainConfig: {
    learningRate: number;
    iterations: number;
    l2: number;
  };
  samplesSeen: number;
}

export interface LogisticRegressionConfig {
  learningRate?: number;
  iterations?: number;
  l2?: number;
  validationSplit?: number;
  earlyStopPatience?: number;
  threshold?: number;
  batchSize?: number;
  seed?: number;
}

const DEFAULT_CONFIG: Required<LogisticRegressionConfig> = {
  learningRate: 0.05,
  iterations: 2000,
  l2: 0.001,
  validationSplit: 0.2,
  earlyStopPatience: 50,
  threshold: 0.5,
  batchSize: 0,
  seed: DEFAULT_TRAINING_SEED,
};

export class LogisticRegression {
  private weights: number[] = [];
  private bias = 0;
  private threshold = 0.5;
  private featureNames: string[] = [];
  private scaler: StandardScaler | null = null;
  private samplesSeen = 0;
  private trainConfig: Required<LogisticRegressionConfig> = DEFAULT_CONFIG;

  train(samples: TrainingSample[], config: LogisticRegressionConfig = {}): LogisticRegressionMetrics {
    const cfg = { ...DEFAULT_CONFIG, ...config };
    this.trainConfig = cfg;
    const featureNames = Object.keys(samples[0].features);
    this.featureNames = featureNames;
    this.threshold = cfg.threshold;

    const n = samples.length;
    if (n < 4) throw new Error(`LogisticRegression.train: need >= 4 samples, got ${n}`);

    const rng = createRng(cfg.seed ?? DEFAULT_TRAINING_SEED);
    const rows = samples.map((s) => ({ ...s, label: typeof s.label === 'boolean' ? (s.label ? 1 : 0) : s.label }));

    const validationSize = Math.max(1, Math.floor(n * cfg.validationSplit));
    const shuffled = [...rows].sort(() => rng() - 0.5);
    const val = shuffled.slice(0, validationSize);
    const train = shuffled.slice(validationSize);

    const dim = featureNames.length;
    this.weights = new Array(dim).fill(0);
    this.bias = 0;

    this.scaler = new StandardScaler();
    this.scaler.fit(
      train.map((r) => featureNames.map((f) => r.features[f])),
      featureNames,
    );

    let bestLoss = Infinity;
    let bestWeights = [...this.weights];
    let bestBias = this.bias;
    let patience = 0;

    for (let iter = 0; iter < cfg.iterations; iter++) {
      for (const sample of train) {
        const x = this.scaler.transform(featureNames.map((f) => sample.features[f]));
        const z = this.dot(x) + this.bias;
        const p = this.sigmoid(z);
        const y = sample.label;
        const error = p - y;
        const w = sample.weight ?? 1;
        for (let i = 0; i < dim; i++) this.weights[i] -= cfg.learningRate * error * x[i] * w;
        this.bias -= cfg.learningRate * error * w;
        for (let i = 0; i < dim; i++) this.weights[i] *= 1 - cfg.learningRate * cfg.l2;
      }

      const valMetrics = this.evaluate(val);
      if (valMetrics.bce < bestLoss) {
        bestLoss = valMetrics.bce;
        bestWeights = [...this.weights];
        bestBias = this.bias;
        patience = 0;
      } else {
        patience++;
        if (patience >= cfg.earlyStopPatience) break;
      }
    }

    this.weights = bestWeights;
    this.bias = bestBias;
    const finalVal = this.evaluate(val);
    return finalVal;
  }

  /**
   * Performs a single online SGD update on one sample.
   *
   * Uses the stored trainConfig learning rate with decay based on
   * samples seen: lr_eff = lr / (1 + 0.01 * samplesSeen).
   * Must be called after train() has initialized the scaler and weights.
   *
   * Returns updated evaluation metrics on the sample (for logging).
   */
  partialFit(sample: TrainingSample): LogisticRegressionMetrics {
    if (this.scaler === null || this.weights.length === 0) {
      throw new Error('LogisticRegression.partialFit: model must be trained first');
    }
    const y = typeof sample.label === 'boolean' ? (sample.label ? 1 : 0) : sample.label;
    if (y !== 0 && y !== 1) {
      throw new Error(`LogisticRegression.partialFit: label must be 0 or 1, got ${y}`);
    }
    const featureValues = this.featureNames.map((f) => sample.features[f]);
    for (let i = 0; i < featureValues.length; i++) {
      if (typeof featureValues[i] !== 'number' || !Number.isFinite(featureValues[i])) {
        throw new Error(`LogisticRegression.partialFit: feature "${this.featureNames[i]}" must be a finite number`);
      }
    }
    const x = this.scaler.transform(featureValues);
    const z = this.dot(x) + this.bias;
    const p = this.sigmoid(z);
    const error = p - y;
    const w = sample.weight ?? 1;
    const lrEffective = this.trainConfig.learningRate / (1 + 0.01 * this.samplesSeen);

    const dim = this.weights.length;
    for (let i = 0; i < dim; i++) {
      this.weights[i] -= lrEffective * error * x[i] * w;
    }
    this.bias -= lrEffective * error * w;
    for (let i = 0; i < dim; i++) {
      this.weights[i] *= 1 - lrEffective * this.trainConfig.l2;
    }

    this.samplesSeen++;

    // Return metrics for this single sample
    const pred = p >= this.threshold ? 1 : 0;
    const bce = -y * Math.log(Math.max(p, 1e-12)) - (1 - y) * Math.log(Math.max(1 - p, 1e-12));
    const tp = pred === 1 && y === 1 ? 1 : 0;
    const fp = pred === 1 && y === 0 ? 1 : 0;
    const tn = pred === 0 && y === 0 ? 1 : 0;
    const fn = pred === 0 && y === 1 ? 1 : 0;
    return {
      accuracy: (tp + tn) / 1,
      precision: tp + fp > 0 ? tp / (tp + fp) : 0,
      recall: tp + fn > 0 ? tp / (tp + fn) : 0,
      aucRoc: 0.5,
      bce,
    };
  }

  private dot(x: number[]): number {
    let s = 0;
    for (let i = 0; i < x.length; i++) s += this.weights[i] * x[i];
    return s;
  }

  private sigmoid(z: number): number {
    if (z >= 0) {
      const ez = Math.exp(-z);
      return 1 / (1 + ez);
    }
    const ez = Math.exp(z);
    return ez / (1 + ez);
  }

  predict(features: Record<string, number>): PredictionResult {
    if (!this.scaler || this.weights.length === 0) {
      return { score: 0.5, probability: 0.5, confidence: 'LOW', reason: 'model untrained — returning neutral' };
    }
    const x = this.scaler.transform(this.featureNames.map((f) => features[f]));
    const p = this.sigmoid(this.dot(x) + this.bias);
    const confidence = this.confidenceLevel(p);
    const reason = this.explain(features, p);
    return {
      score: p,
      probability: p,
      confidence,
      reason,
    };
  }

  predictBatch(features: Record<string, number>[]): PredictionResult[] {
    return features.map((f) => this.predict(f));
  }

  private confidenceLevel(p: number): PredictionResult['confidence'] {
    const distance = Math.abs(p - 0.5);
    if (distance >= 0.3) return 'HIGH';
    if (distance >= 0.15) return 'MEDIUM';
    return 'LOW';
  }

  private explain(features: Record<string, number>, p: number): string {
    if (!this.scaler) return 'no scaler';
    const contributions: { name: string; value: number }[] = [];
    const x = this.scaler.transform(this.featureNames.map((f) => features[f]));
    for (let i = 0; i < x.length; i++) {
      contributions.push({ name: this.featureNames[i], value: this.weights[i] * x[i] });
    }
    contributions.sort((a, b) => Math.abs(b.value) - Math.abs(a.value));
    const top = contributions.slice(0, 2).map((c) => `${c.name}(${c.value.toFixed(2)})`);
    return `predicted P=${p.toFixed(3)} (threshold ${this.threshold}); top drivers: ${top.join(', ')}`;
  }

  private evaluate(samples: TrainingSample[]): LogisticRegressionMetrics {
    const results = samples.map((s) => ({ pred: this.predict(s.features), label: typeof s.label === 'boolean' ? (s.label ? 1 : 0) : s.label }));
    let tp = 0, fp = 0, tn = 0, fn = 0;
    let bce = 0;
    for (const r of results) {
      const pred = r.pred.score >= this.threshold ? 1 : 0;
      if (pred === 1 && r.label === 1) tp++;
      else if (pred === 1 && r.label === 0) fp++;
      else if (pred === 0 && r.label === 0) tn++;
      else fn++;
      bce += -r.label * Math.log(Math.max(r.pred.score, 1e-12)) - (1 - r.label) * Math.log(Math.max(1 - r.pred.score, 1e-12));
    }
    bce /= results.length;
    const accuracy = (tp + tn) / results.length;
    const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
    const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
    const aucRoc = this.aucRoc(results);
    return { accuracy, precision, recall, aucRoc, bce };
  }

  private aucRoc(results: { pred: PredictionResult; label: number }[]): number {
    const sorted = [...results].sort((a, b) => a.pred.score - b.pred.score);
    const nPos = sorted.filter((r) => r.label === 1).length;
    const nNeg = sorted.length - nPos;
    if (nPos === 0 || nNeg === 0) return 0.5;
    let rankSum = 0;
    for (let i = 0; i < sorted.length; i++) {
      if (sorted[i].label === 1) rankSum += i + 1;
    }
    return (rankSum - (nPos * (nPos + 1)) / 2) / (nPos * nNeg);
  }

  serialize(): LogisticRegressionWeights {
    if (!this.scaler) throw new Error('LogisticRegression.serialize: model not trained');
    return {
      weights: [...this.weights],
      bias: this.bias,
      scaler: this.scaler.serialize(),
      featureNames: [...this.featureNames],
      threshold: this.threshold,
      trainConfig: {
        learningRate: this.trainConfig.learningRate,
        iterations: this.trainConfig.iterations,
        l2: this.trainConfig.l2,
      },
      samplesSeen: this.samplesSeen,
    };
  }

  load(data: LogisticRegressionWeights): void {
    this.weights = [...data.weights];
    this.bias = data.bias;
    this.threshold = data.threshold;
    this.featureNames = [...data.featureNames];
    this.scaler = new StandardScaler();
    this.scaler.load(data.scaler);
    this.trainConfig = { ...this.trainConfig, ...data.trainConfig };
    this.samplesSeen = data.samplesSeen ?? 0;
  }

  getFeatureNames(): string[] {
    return [...this.featureNames];
  }

  getThreshold(): number {
    return this.threshold;
  }

  setThreshold(value: number): void {
    this.threshold = value;
  }
}

export interface LogisticRegressionMetrics {
  accuracy: number;
  precision: number;
  recall: number;
  aucRoc: number;
  bce: number;
}
