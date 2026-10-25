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
  let chunks: Buffer[] = [];
  let bytes = 0;
  let oversized = false;
  for await (const chunk of input) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as string);
    let offset = 0;
    while (offset < buffer.length) {
      const newline = buffer.indexOf(10, offset);
      const end = newline < 0 ? buffer.length : newline;
      const piece = buffer.subarray(offset, end);
      bytes += piece.length;
      if (bytes > MAX_RECORD_BYTES) {
        oversized = true;
        chunks = [];
      } else if (!oversized) chunks.push(Buffer.from(piece));
      if (newline >= 0) {
        if (oversized) yield { invalidFrame: 'OVERSIZED_NDJSON' };
        else if (bytes) {
          try {
            yield JSON.parse(Buffer.concat(chunks).toString('utf8'));
          } catch {
            yield { invalidFrame: 'MALFORMED_NDJSON', raw: Buffer.concat(chunks).toString('utf8') };
          }
        }
        chunks = [];
        bytes = 0;
        oversized = false;
      }
      offset = newline < 0 ? buffer.length : newline + 1;
    }
  }
  if (oversized) yield { invalidFrame: 'OVERSIZED_NDJSON' };
  else if (bytes) {
    try {
      yield JSON.parse(Buffer.concat(chunks).toString('utf8'));
    } catch {
      yield { invalidFrame: 'MALFORMED_NDJSON', raw: Buffer.concat(chunks).toString('utf8') };
    }
  }
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
