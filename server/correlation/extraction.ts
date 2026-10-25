import { Worker } from 'node:worker_threads';
import { performance } from 'node:perf_hooks';
import type { ExtractedText } from './validation.ts';
import type { CorrelationTelemetry } from './telemetry.ts';
// Regex executes ONLY inside a disposable worker. A timer around synchronous
// RegExp.exec on the parent event loop cannot interrupt catastrophic backtracking.
const source = String.raw`
const { parentPort } = require('node:worker_threads');
const { performance } = require('node:perf_hooks');
parentPort.on('message', ({ text }) => {
  const start = performance.now();
  const check = () => { if (performance.now() - start > 200) throw new Error('budget'); };
  try {
    // Bounded, non-nested expressions; no feed-provided regular expressions.
    const plain = text.replace(/<script\b[^>]*>[\s\S]*?<\/script\s*>/gi, ' ')
      .replace(/<style\b[^>]*>[\s\S]*?<\/style\s*>/gi, ' ')
      .replace(/<[^>]*>/g, ' ').toLowerCase();
    check();
    const cves = new Set();
    const pattern = /\bcve-[0-9]{4}-[0-9]{4,19}\b/g;
    let match;
    while ((match = pattern.exec(plain)) !== null) {
      check(); cves.add(match[0].toUpperCase());
      if (cves.size > 100) throw new Error('limit');
    }
    const indicators = ['zero-day', 'zero day', 'actively exploited', 'in the wild', 'unpatched', 'remote code execution', 'vulnerability', 'exploit'];
    let signals = 0;
    for (const word of indicators) { check(); if (plain.includes(word)) signals++; }
    const tokens = plain.split(/[^a-z0-9_.+-]+/).filter(Boolean);
    check();
    const normalized = ' ' + tokens.join(' ') + ' ';
    const ranges = [];
    const rangePattern = /(?:^| )([a-z0-9_.+-]+(?: [a-z0-9_.+-]+){0,3}) (?:versions? )?(before|prior to|through|up to|below) (v?[0-9]{1,9}(?:\.[0-9]{1,9}){1,2}(?:-(?:rc|alpha|beta)[.-][0-9]{1,6})?)(?= |$)/g;
    while ((match = rangePattern.exec(normalized)) !== null) {
      check();
      if (ranges.length >= 100) throw new Error('limit');
      ranges.push({ productPhrase: match[1].replace(/ versions?$/, ''), range: (['before','prior to','below'].includes(match[2]) ? '<' : '<=') + match[3] });
    }
    // Inclusive bands phrased in prose: "vulnerable between 2.1.0 and 2.3.4".
    // The strict single-bound rangePattern cannot express these; without this
    // second pass the comparator falls back to identity matching.
    const bandPattern = /(?:^| )(?:between|from) (v?[0-9]{1,9}(?:\.[0-9]{1,9}){1,2}) (?:and|to|through) (v?[0-9]{1,9}(?:\.[0-9]{1,9}){1,2})(?= |$)/g;
    while ((match = bandPattern.exec(normalized)) !== null) {
      check();
      if (ranges.length >= 100) throw new Error('limit');
      ranges.push({ productPhrase: '', range: '>=' + match[1] + ' <=' + match[2] });
    }
    const density = signals / Math.max(1,tokens.length);
    parentPort.postMessage({ text: normalized, cleanContent: plain.trim(), ranges, cveIds: [...cves],
      zeroDay: cves.size === 0 && signals >= 2 && density >= 0.002,
      securitySignal: signals > 0, negated: /\b(not affected|not vulnerable|unaffected|false positive)\b/.test(plain), zeroDayDensity: density });
  } catch { parentPort.postMessage({ failed: true }); }
});
parentPort.postMessage({ ready: true });
`;
export async function extractText(
  text: string,
  telemetry: CorrelationTelemetry,
  trackingId: string,
  signal?: AbortSignal,
): Promise<ExtractedText> {
  if (text.length > 50_201) throw new Error('EXTRACTION_INPUT_LIMIT');
  signal?.throwIfAborted();
  const start = performance.now();
  return new Promise((resolve, reject) => {
    const worker = new Worker(source, {
      eval: true,
      resourceLimits: { maxOldGenerationSizeMb: 24, stackSizeMb: 2 },
    });
    let done = false;
    let timer: ReturnType<typeof setTimeout>;
    const finish = (error?: Error, value?: ExtractedText) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
      void worker.terminate();
      telemetry.log(error ? 'CRITICAL' : 'INFO', error ? 'extraction.isolated' : 'extraction.completed', {
        trackingId,
        extractionLatencyMs: performance.now() - start,
      });
      if (error) reject(error);
      else resolve(value!);
    };
    const abort = () => finish(new Error('WORKER_ABORTED'));
    signal?.addEventListener('abort', abort, { once: true });
    timer = setTimeout(() => finish(new Error('WORKER_START_TIMEOUT')), 2000);
    worker.on('message', (value: ExtractedText & { ready?: boolean; failed?: boolean }) => {
      if (value.ready) {
        clearTimeout(timer);
        timer = setTimeout(() => finish(new Error('EXTRACTION_TIMEOUT')), 200);
        worker.postMessage({ text });
      } else if (value.failed) finish(new Error('EXTRACTION_BUDGET'));
      else finish(undefined, value);
    });
    worker.on('error', () => finish(new Error('EXTRACTION_WORKER_FAILED')));
    worker.on('exit', () => {
      if (!done) finish(new Error('EXTRACTION_WORKER_EXIT'));
    });
  });
}
