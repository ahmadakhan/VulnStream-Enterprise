import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { LogisticRegression } from '../server/ml/algorithms/logisticRegression';
import { StandardScaler } from '../server/ml/algorithms/standardScaler';
import { IsolationForest } from '../server/ml/algorithms/isolationForest';
import { GBDTRanker } from '../server/ml/algorithms/gbdtRanker';
import type { TrainingSample } from '../server/ml/types';

describe('StandardScaler', () => {
  it('fits and transforms to zero mean / unit variance', () => {
    const scaler = new StandardScaler();
    const samples = [
      [1, 10],
      [2, 20],
      [3, 30],
      [4, 40],
      [5, 50],
    ];
    scaler.fit(samples, ['a', 'b']);
    const transformed = scaler.transform([3, 30]);
    assert.ok(Math.abs(transformed[0]) < 1e-9, 'mean of feature a should be ~0');
    assert.ok(Math.abs(transformed[1]) < 1e-9, 'mean of feature b should be ~0');
  });

  it('serializes and loads round-trip', () => {
    const scaler = new StandardScaler();
    scaler.fit([[1, 2], [3, 4], [5, 6]], ['x', 'y']);
    const data = scaler.serialize();
    const restored = new StandardScaler();
    restored.load(data as unknown as Record<string, unknown>);
    const original = scaler.transform([3, 4]);
    const reloaded = restored.transform([3, 4]);
    assert.deepEqual(original, reloaded);
  });

  it('rejects dimension mismatch on transform', () => {
    const scaler = new StandardScaler();
    scaler.fit([[1, 2]], ['x', 'y']);
    assert.throws(() => scaler.transform([1, 2, 3]), /expected 2 features/);
  });

  it('handles single sample (zero variance → epsilon)', () => {
    const scaler = new StandardScaler();
    scaler.fit([[5, 5]], ['x', 'y']);
    const t = scaler.transform([5, 5]);
    assert.ok(Number.isFinite(t[0]));
  });
});

describe('LogisticRegression', () => {
  const makeSamples = (n: number, label: boolean): TrainingSample[] =>
    Array.from({ length: n }, (_, i) => ({
      id: `s-${i}`,
      features: { x: label ? 3 + i * 0.1 : -3 + i * 0.1, y: label ? 2 : -2 },
      label,
      weight: 1,
      timestamp: new Date().toISOString(),
    }));

  it('separates linearly separable data', () => {
    const lr = new LogisticRegression();
    const samples = [...makeSamples(50, false), ...makeSamples(50, true)];
    lr.train(samples, { threshold: 0.5, iterations: 500 });

    const neg = lr.predict({ x: -3, y: -2 });
    const pos = lr.predict({ x: 3, y: 2 });
    assert.ok(neg.score < 0.5, `negative sample score should be < 0.5, got ${neg.score}`);
    assert.ok(pos.score > 0.5, `positive sample score should be > 0.5, got ${pos.score}`);
  });

  it('outputs AUC > 0.9 on separable data', () => {
    const lr = new LogisticRegression();
    const samples = [...makeSamples(100, false), ...makeSamples(100, true)];
    const perf = lr.train(samples, { threshold: 0.5, iterations: 1000 });
    assert.ok(perf.accuracy !== undefined);
    assert.ok(perf.aucRoc !== undefined && perf.aucRoc > 0.9, `AUC should be > 0.9, got ${perf.aucRoc}`);
  });

  it('serializes and loads without drift', () => {
    const lr = new LogisticRegression();
    const samples = [...makeSamples(60, false), ...makeSamples(60, true)];
    lr.train(samples, { threshold: 0.5, iterations: 500 });

    const artifact = { metadata: { id: 'test', type: 'logistic', version: '1', trainedAt: '', featureSchema: [], description: '' }, weights: lr.serialize() };
    const restored = new LogisticRegression();
    restored.load(artifact.weights as ReturnType<LogisticRegression['serialize']>);

    const orig = lr.predict({ x: 3, y: 2 });
    const loaded = restored.predict({ x: 3, y: 2 });
    assert.ok(Math.abs(orig.score - loaded.score) < 1e-9, 'loaded model should match original');
  });

  it('rejects training with fewer than 4 samples', () => {
    const lr = new LogisticRegression();
    assert.throws(() => lr.train(makeSamples(2, true), {}), /need >= 4 samples/);
  });

  it('returns numerical-stable sigmoid for large inputs', () => {
    const lr = new LogisticRegression();
    const features = { x: -1000, y: 1000 };
    const result = lr.predict(features);
    assert.ok(result.score >= 0 && result.score <= 1);
  });
});

describe('IsolationForest', () => {
  const generate = (n: number, offset = 0): number[][] =>
    Array.from({ length: n }, (_, _i) => [offset + Math.random() * 0.1, offset + Math.random() * 0.1]);

  it('flags injected anomalies', () => {
    const normal = generate(100, 0);
    const anomal = generate(5, 50); // clear outlier cluster
    const samples = [...normal, ...anomal];
    const forest = new IsolationForest();
    forest.train(samples, ['x', 'y'], 50, 8, 0.1);

    const anomalyScore = forest.anomalyScore([50.05, 49.98]);
    const normalScore = forest.anomalyScore([0.05, 0.03]);
    assert.ok(anomalyScore > normalScore, 'anomaly should score higher');
  });

  it('serializes and loads with matching predictions', () => {
    const forest = new IsolationForest();
    forest.train(generate(100), ['x', 'y'], 50, 8, 0.1);
    const orig = forest.anomalyScore([0.5, 0.5]);
    const data = forest.serialize();

    const restored = new IsolationForest();
    restored.load(data);
    const loaded = restored.anomalyScore([0.5, 0.5]);
    assert.ok(Math.abs(orig - loaded) < 1e-9, 'restored model should match');
  });

  it('rejects training with fewer than 10 samples', () => {
    const forest = new IsolationForest();
    assert.throws(() => forest.train([[1, 2]], ['x', 'y'], 10, 8, 0.1), /need >= 10 samples/);
  });
});

describe('GBDTRanker', () => {
  it('ranks high-label samples above low-label', () => {
    const gbdt = new GBDTRanker();
    const samples: TrainingSample[] = [];
    for (let i = 0; i < 100; i++) {
      samples.push({
        id: `pos-${i}`,
        features: { important: 1, noise: Math.random() },
        label: 1,
        weight: 1,
        timestamp: new Date().toISOString(),
      });
      samples.push({
        id: `neg-${i}`,
        features: { important: -1, noise: Math.random() },
        label: 0,
        weight: 1,
        timestamp: new Date().toISOString(),
      });
    }
    gbdt.train(samples, ['important', 'noise'], { nTrees: 20, learningRate: 0.3, maxDepth: 3 });

    const pos = gbdt.predict({ important: 1, noise: 0.5 });
    const neg = gbdt.predict({ important: -1, noise: 0.5 });
    assert.ok(pos.score > neg.score, 'positive sample should rank higher');
  });

  it('serializes and loads without drift', () => {
    const gbdt = new GBDTRanker();
    const samples: TrainingSample[] = [];
    for (let i = 0; i < 50; i++) {
      samples.push({
        id: `p-${i}`,
        features: { feature: 1 },
        label: 1,
        weight: 1,
        timestamp: new Date().toISOString(),
      });
      samples.push({
        id: `n-${i}`,
        features: { feature: -1 },
        label: 0,
        weight: 1,
        timestamp: new Date().toISOString(),
      });
    }
    gbdt.train(samples, ['feature'], { nTrees: 10, learningRate: 0.3, maxDepth: 3 });
    const orig = gbdt.predict({ feature: 1 });

    const artifact = { metadata: { id: 'test', type: 'gbdt_ranker', version: '1', trainedAt: '', featureSchema: [], description: '' }, weights: gbdt.serialize() };
    const restored = new GBDTRanker();
    restored.load(artifact.weights as ReturnType<GBDTRanker['serialize']>);
    const loaded = restored.predict({ feature: 1 });
    assert.ok(Math.abs(orig.score - loaded.score) < 1e-9, 'loaded model should match');
  });

  it('rejects training with fewer than 10 samples', () => {
    const gbdt = new GBDTRanker();
    assert.throws(() => gbdt.train([{ id: 'a', features: { x: 1 }, label: 1, timestamp: '' }], ['x'], {}), /need >= 10 samples/);
  });
});
