/**
 * News Credibility Weight Model — learns the optimal blend of feed-weight
 * and keyword-confidence scores for intelligence credibility, replacing the
 * hardcoded `feedScore * 0.6 + keywordScore * 0.4` in
 * intelligenceMatcher.ts:46.
 *
 * File target: src/utils/intelligenceMatcher.ts:46 (computeCredibilityScore)
 *
 * Uses a grid-search optimizer over (feedWeight, keywordWeight) pairs that
 * must sum to 1.0, evaluating each pair by how well the resulting blended
 * score separates actionable from non-actionable findings. This follows the
 * same threshold_optimizer pattern as AutoDispatchThresholdModel.
 *
 * Training data: correlation_matches with feed_weight, credibility_score,
 * and outcome (PATCHED/RESOLVED/DELIVERED = actionable).
 */
import type { ModelArtifact, ModelMetadata, PredictionResult } from '../types.ts';

export interface CredibilitySample {
  feedWeight: number;
  keywordScore: number;
  isActionable: boolean;
}

export interface CredibilityWeights {
  feedWeight: number;
  keywordWeight: number;
  featureNames: string[];
}

export const CREDIBILITY_FEATURE_NAMES = ['feed_weight', 'keyword_score'] as const;

export class NewsCredibilityWeightModel {
  private weights: CredibilityWeights | null = null;
  private metadata: ModelMetadata;
  private history: CredibilitySample[] = [];
  private readonly maxHistory = 5000;

  constructor() {
    this.metadata = {
      id: 'news-credibility-weight-model',
      type: 'threshold_optimizer',
      version: '1.0.0',
      trainedAt: new Date().toISOString(),
      featureSchema: [...CREDIBILITY_FEATURE_NAMES],
      description: 'Learned weights for blending feed credibility and keyword confidence',
    };
  }

  record(sample: CredibilitySample): void {
    this.history.push(sample);
    if (this.history.length > this.maxHistory) {
      this.history = this.history.slice(this.history.length - this.maxHistory);
    }
  }

  train(samples: CredibilitySample[] = this.history): void {
    if (samples.length < 100) return;

    const grid = [
      { feed: 0.9, keyword: 0.1 },
      { feed: 0.8, keyword: 0.2 },
      { feed: 0.7, keyword: 0.3 },
      { feed: 0.6, keyword: 0.4 },
      { feed: 0.5, keyword: 0.5 },
      { feed: 0.4, keyword: 0.6 },
      { feed: 0.3, keyword: 0.7 },
      { feed: 0.2, keyword: 0.8 },
      { feed: 0.1, keyword: 0.9 },
    ];

    let bestWeights = { feedWeight: 0.6, keywordWeight: 0.4 };
    let bestAccuracy = 0;

    for (const combo of grid) {
      let correct = 0;
      for (const s of samples) {
        const blended = s.feedWeight * combo.feed + s.keywordScore * combo.keyword;
        const predicted = blended >= 50;
        if (predicted === s.isActionable) correct++;
      }
      const accuracy = correct / samples.length;
      if (accuracy > bestAccuracy) {
        bestAccuracy = accuracy;
        bestWeights = { feedWeight: combo.feed, keywordWeight: combo.keyword };
      }
    }

    this.weights = { ...bestWeights, featureNames: [...CREDIBILITY_FEATURE_NAMES] };
    this.metadata = { ...this.metadata, version: '1.0.1', trainedAt: new Date().toISOString() };
  }

  predict(feedWeight: number, keywordScore: number): PredictionResult {
    if (!this.weights) {
      return {
        score: 0.6,
        probability: 0.6,
        confidence: 'LOW',
        reason: 'weight model untrained — using default 0.6/0.4 split',
      };
    }

    const blended = feedWeight * this.weights.feedWeight + keywordScore * this.weights.keywordWeight;
    const distance = Math.abs(this.weights.feedWeight - 0.6);
    const confidence: PredictionResult['confidence'] = distance > 0.2 ? 'HIGH' : distance > 0.05 ? 'MEDIUM' : 'LOW';

    return {
      score: blended,
      probability: blended / 100,
      confidence,
      reason: `blended=${blended.toFixed(1)} (feedWeight=${this.weights.feedWeight}, keywordWeight=${this.weights.keywordWeight})`,
    };
  }

  computeCredibility(feedWeight: number, keywordScore: number): number {
    if (!this.weights) {
      return Math.round(feedWeight * 0.6 + keywordScore * 0.4);
    }
    return Math.round(feedWeight * this.weights.feedWeight + keywordScore * this.weights.keywordWeight);
  }

  getWeights(): { feedWeight: number; keywordWeight: number } {
    if (!this.weights) return { feedWeight: 0.6, keywordWeight: 0.4 };
    return { feedWeight: this.weights.feedWeight, keywordWeight: this.weights.keywordWeight };
  }

  serialize(): ModelArtifact {
    return {
      metadata: this.metadata,
      weights: this.weights ?? {
        feedWeight: 0.6,
        keywordWeight: 0.4,
        featureNames: [...CREDIBILITY_FEATURE_NAMES],
      },
    };
  }

  load(artifact: ModelArtifact): void {
    this.weights = artifact.weights as CredibilityWeights;
    this.metadata = artifact.metadata;
  }

  getFeatureNames(): string[] {
    return [...CREDIBILITY_FEATURE_NAMES];
  }

  getMetadata(): ModelMetadata {
    return this.metadata;
  }

  isTrained(): boolean {
    return this.weights !== null;
  }
}
