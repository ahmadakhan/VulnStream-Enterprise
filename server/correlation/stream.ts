import { Readable } from 'node:stream';
import { randomUUID } from 'node:crypto';
import type { Pool } from 'pg';
import type { PipelineSupervisor, IngestPriority } from './supervisor.ts';
import type { AdvisoryInput } from './validation.ts';
const MAX_RECORD_BYTES = 262144;
type AdvisoryRecord = AdvisoryInput | { invalidFrame: string; raw?: string };
/** Object-mode records or UTF-8 NDJSON. A record is bounded even across chunks. */
export async function* advisoryRecords(input: Readable): AsyncGenerator<AdvisoryRecord> {
  if (input.readableObjectMode) {
    for await (const item of input) yield item;
    return;
  }
  // One allocation per stream: one-byte chunks must not create 262,144 Buffer objects.
  const record = Buffer.allocUnsafe(MAX_RECORD_BYTES);
  let bytes = 0;
  let oversized = false;
  const decode = (): AdvisoryRecord => {
    if (oversized) return { invalidFrame: 'OVERSIZED_NDJSON' };
    let raw: string;
    try {
      raw = new TextDecoder('utf-8', { fatal: true }).decode(record.subarray(0, bytes));
    } catch {
      return { invalidFrame: 'INVALID_UTF8_NDJSON' };
    }
    try {
      return JSON.parse(raw);
    } catch {
      return { invalidFrame: 'MALFORMED_NDJSON', raw: '' };
    }
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
        else {
          buffer.copy(record, bytes, offset, end);
          bytes += length;
        }
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
        // Skip invalid frames but log them
        if (typeof raw === 'object' && raw !== null && 'invalidFrame' in raw) {
          this.supervisor.ingestor.telemetry.log('WARN', 'stream.invalid_frame', {
            trackingId: 'stream',
            count: 1,
          });
          continue;
        }
        while (running.size >= concurrencyLimit) await Promise.race(running);
        // A durability failure on one record is recorded and reported after the
        // stream drains (see the final `if (failure) throw failure` below), but
        // must not stop this loop from reading and dispatching the records that
        // follow it — that would silently drop every remaining item in the
        // batch for one bad record. Only an explicit stop (abort/shutdown)
        // short-circuits here, not an ingest-level failure.
        const trackingId = randomUUID();
        const controller = new AbortController();
        // Determine priority from advisory content
        const priority = this.inferPriority(raw);
        await this.supervisor.acquire(trackingId, controller, priority);
        // A separate timer enforces the deadline even when a health probe is slow.
        const timer = setTimeout(() => controller.abort(), 15_000);
        const promise = this.supervisor.ingestor
          .processIncomingAdvisory(raw, dbPool, trackingId, controller.signal)
          .then(() => {})
          .catch((error) => {
            // A single record whose durability could not be established must not
            // abort the whole stream: the remaining records in the batch are
            // still processable, and killing the stream loses all of them. The
            // record itself is already reported through the dead-letter chain.
            this.supervisor.ingestor.telemetry.log('CRITICAL', 'stream.durable_capture_failed', {
              trackingId,
            });
            failure ??= error;
          })
          .finally(() => {
            clearTimeout(timer);
            running.delete(promise);
            this.supervisor.release(trackingId);
          });
        running.add(promise);
      }
    } finally {
      await Promise.all(running);
    }
    if (failure) throw failure;
  }
  /** Infer priority from advisory content. HIGH = CVE present or critical keywords.
   * The record is untrusted stream input and may not match the advisory shape
   * at all, so every field is validated before it is dereferenced. */
  private inferPriority(raw: AdvisoryRecord): 'HIGH' | 'MEDIUM' | 'LOW' {
    if (!raw || typeof raw !== 'object' || 'invalidFrame' in raw) return 'LOW';
    const advisory = raw as Partial<AdvisoryInput>;
    // HIGH: structured identity or explicit critical keywords
    if ((advisory.cpes?.length ?? 0) > 0 || (advisory.purls?.length ?? 0) > 0) return 'HIGH';
    // Check for critical keywords in title/content
    const text = `${advisory.title ?? ''} ${advisory.content ?? ''}`.toLowerCase();
    if (
      /\b(remote code execution|rce|zero.day|zero-day|actively exploited|in.the.wild|unpatched|critical|severity)\b/.test(
        text,
      )
    )
      return 'HIGH';
    // MEDIUM: Has security signals but no CVE
    if (/\b(vulnerability|exploit|patch|update|security|advisory)\b/.test(text)) return 'MEDIUM';
    return 'LOW';
  }
}
