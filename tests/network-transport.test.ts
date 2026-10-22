import { test } from 'node:test';
import assert from 'node:assert/strict';
import { gzipSync } from 'node:zlib';
import { Readable } from 'node:stream';
import { readResponseBody } from '../server/network';

test('HTTP response reader decompresses gzip while enforcing the decoded response limit', async () => {
  const body = JSON.stringify({ data: 'CVE metadata '.repeat(1000) });
  const compressed = gzipSync(Buffer.from(body));
  assert.ok(compressed.length < Buffer.byteLength(body));
  assert.equal(await readResponseBody(Readable.from([compressed]), 'gzip', Buffer.byteLength(body)), body);
  await assert.rejects(
    readResponseBody(Readable.from([compressed]), 'gzip', Buffer.byteLength(body) - 1),
    /Decoded response exceeds configured/,
  );
});

test('HTTP response reader limits wire bytes and rejects unsupported encodings', async () => {
  const compressed = gzipSync(Buffer.from('small body'));
  await assert.rejects(
    readResponseBody(Readable.from([compressed]), 'gzip', compressed.length - 1),
    /Response transfer exceeds configured/,
  );
  await assert.rejects(
    readResponseBody(Readable.from(['body']), 'br', 100),
    /Unsupported response content encoding/,
  );
});
