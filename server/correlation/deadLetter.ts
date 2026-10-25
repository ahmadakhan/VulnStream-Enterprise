import { timedQuery } from './query.ts';
import { mkdir, open, readdir, readFile, rename, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import type { Pool } from 'pg';
import { encrypt } from '../secrets.ts';
import type { CorrelationTelemetry } from './telemetry.ts';
interface Letter {
  id: string;
  trackingId: string;
  errorCode: string;
  encryptedPayload: string;
}
/** Durable encrypted fallback, with a strict disk ceiling. A full spool fails closed. */
export class DeadLetterQueue {
  private tail: Promise<unknown> = Promise.resolve();
  constructor(
    private readonly directory: string,
    private readonly key: string,
    private readonly telemetry: CorrelationTelemetry,
  ) {
    if (Buffer.from(key, 'base64').length !== 32) throw new Error('DLQ_KEY_REQUIRED');
  }
  async capture(raw: unknown, errorCode: string, trackingId: string, pool: Pool): Promise<void> {
    // JSON inputs from HTTP/NDJSON are bounded upstream. Never serialize arbitrary
    // class instances, cycles, or unlimited object-mode inputs into the fallback.
    let serialized: string;
    try {
      let remaining = 262144;
      let nodes = 0;
      serialized = JSON.stringify(raw, (_field: string, value: unknown) => {
        if (++nodes > 4096) throw new Error('SERIALIZATION_BUDGET');
        if (typeof value === 'string') remaining -= Buffer.byteLength(value);
        if (remaining < 0 || (Array.isArray(value) && value.length > 4096))
          throw new Error('SERIALIZATION_BUDGET');
        return value;
      });
    } catch {
      serialized = '"[unserializable input]"';
    }
    if (!serialized || Buffer.byteLength(serialized) > 262144) serialized = '"[oversized input omitted]"';
    const letter: Letter = {
      id: randomUUID(),
      trackingId,
      errorCode,
      encryptedPayload: encrypt(serialized, this.key, 'correlation-dlq'),
    };
    const persist = async () => {
      await mkdir(this.directory, { recursive: true, mode: 0o700 });
      const files = await readdir(this.directory);
      // Each serialized letter is <= 351 KiB. 256 files cap disk at ~90 MiB.
      if (files.length >= 256) throw new Error('DLQ_CAPACITY_EXHAUSTED');
      const temporary = join(this.directory, letter.id + '.tmp');
      const file = await open(temporary, 'wx', 0o600);
      try {
        await file.writeFile(JSON.stringify(letter));
        await file.sync();
      } finally {
        await file.close();
      }
      await rename(temporary, join(this.directory, letter.id + '.json'));
      const dir = await open(this.directory, 'r');
      try {
        await dir.sync();
      } finally {
        await dir.close();
      }
      this.telemetry.deadLetters++;
    };
    const pending = this.tail.then(persist);
    this.tail = pending.catch(() => {});
    await pending;
    this.telemetry.log('WARN', 'dead_letter.persisted', { trackingId });
    // Flush is handled by the supervisor; never wait for an unavailable DB here.
    void pool;
  }
  async flush(pool: Pool): Promise<void> {
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
    const files = (await readdir(this.directory))
      .filter((file) => /^[a-f0-9-]{36}\.json$/.test(file))
      .slice(0, 10);
    for (const name of files) {
      const letter = JSON.parse(await readFile(join(this.directory, name), 'utf8')) as Letter;
      await pool.query(
        timedQuery(
          `INSERT INTO correlation_dead_letters(id,tracking_id,error_code,encrypted_payload)
        VALUES($1,$2,$3,$4) ON CONFLICT(id) DO NOTHING`,
          [letter.id, letter.trackingId, letter.errorCode, letter.encryptedPayload],
          2000,
        ),
      );
      await unlink(join(this.directory, name));
    }
  }
}
