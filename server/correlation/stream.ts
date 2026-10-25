import { Readable } from 'node:stream';
import { randomUUID } from 'node:crypto';
import type { Pool } from 'pg';
import type { PipelineSupervisor } from './supervisor.ts';
const MAX_RECORD_BYTES = 262144;
/** Object-mode records or UTF-8 NDJSON. A record is bounded even across chunks. */
export async function* advisoryRecords(input: Readable): AsyncGenerator<unknown> {
  if (input.readableObjectMode) {
    for await (const item of input) yield item;
    return;
  }
  // One allocation per stream: one-byte chunks must not create 262,144 Buffer objects.
  const record = Buffer.allocUnsafe(MAX_RECORD_BYTES);
  let bytes = 0;
  let oversized = false;
  const decode = (): unknown => {
    if (oversized) return { invalidFrame: 'OVERSIZED_NDJSON' };
    let raw: string;
    try { raw = new TextDecoder('utf-8', { fatal: true }).decode(record.subarray(0, bytes)); }
    catch { return { invalidFrame: 'INVALID_UTF8_NDJSON' }; }
    try { return JSON.parse(raw); }
    catch { return { invalidFrame: 'MALFORMED_NDJSON', raw }; }
  };
  for await (const chunk of input) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as string);
    let offset = 0;
    while (offset < buffer.length) {
      const newline = buffer.indexOf(10, offset);
      const end = newline < 0 ? buffer.length : newline;
      const length = end - offset;
      if (!oversized) {
        if (length > MAX_RECORD_BYTES - bytes) oversized = true;
        else { buffer.copy(record, bytes, offset, end); bytes += length; }
      }
      if (newline >= 0) {
        if (oversized || bytes) yield decode();
        bytes = 0;
        oversized = false;
      }
      offset = newline < 0 ? buffer.length : newline + 1;
    }
  }
  if (oversized || bytes) yield decode();
}
export class AdvisoryStreamProcessor {
  constructor(readonly supervisor: PipelineSupervisor) {}
  async processAdvisoryStream(inputStream: Readable, concurrencyLimit: number, dbPool: Pool): Promise<void> {
    if (!Number.isInteger(concurrencyLimit) || concurrencyLimit < 1 || concurrencyLimit > 32)
      throw new Error('INVALID_CONCURRENCY');
    const running = new Set<Promise<void>>();
    let failure: unknown;
    try {
      for await (const raw of advisoryRecords(inputStream)) {
        while (running.size >= concurrencyLimit) await Promise.race(running);
        if (failure) throw failure;
        const trackingId = randomUUID();
        const controller = new AbortController();
        await this.supervisor.acquire(trackingId, controller);
        // A separate timer enforces the deadline even when a health probe is slow.
        const timer = setTimeout(() => controller.abort(), 15_000);
        const promise = this.supervisor.ingestor
          .processIncomingAdvisory(raw, dbPool, trackingId, controller.signal)
          .then(() => {})
          .catch((error) => {
            failure = error;
            this.supervisor.ingestor.telemetry.log('CRITICAL', 'stream.durable_capture_failed', {
              trackingId,
            });
          })
          .finally(() => {
            clearTimeout(timer);
            running.delete(promise);
            this.supervisor.active.delete(trackingId);
          });
        running.add(promise);
      }
    } finally {
      await Promise.all(running);
    }
    if (failure) throw failure;
  }
}
