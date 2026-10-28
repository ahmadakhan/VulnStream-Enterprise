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

// Redirect policy, exercised end to end against a local HTTPS server. The
// fixture certificate is trusted only by this test and the socket hook dials
// loopback after the real allowlist/port/public-IP checks have passed.
import { createServer, type Server } from 'node:https';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { connect } from 'node:tls';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { createRequester } from '../server/network.ts';
import { loadConfig } from '../server/config.ts';

const fixtures = join(import.meta.dirname, 'fixtures/tls');
const TLS = { key: readFileSync(join(fixtures, 'key.pem')), cert: readFileSync(join(fixtures, 'cert.pem')) };
const config = loadConfig({
  NODE_ENV: 'test',
  DATABASE_URL: 'postgres://unused',
  APP_ORIGIN: 'http://localhost',
  ENCRYPTION_KEY: Buffer.alloc(32, 1).toString('base64'),
  EGRESS_ALLOWED_HOSTS: 'feed.example.test,cdn.example.test',
});
const publicDns = async () => [{ address: '93.184.216.34', family: 4 }];
let localPort = 0;
const hooks = {
  resolver: publicDns,
  tls: { ca: TLS.cert },
  connect: (options: any) =>
    connect({ ...options, host: '127.0.0.1', port: localPort, ca: TLS.cert, servername: options.host }).setTimeout(2000),
};

type Handler = (req: IncomingMessage, res: ServerResponse) => void;

async function serve(handler: Handler) {
  const requests: { method?: string; headers: Record<string, unknown>; path: string }[] = [];
  const server: Server = createServer(TLS, (req, res) => {
    requests.push({ method: req.method, headers: req.headers, path: req.url ?? '' });
    handler(req, res);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  localPort = (server.address() as { port: number }).port;
  return {
    requests,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

test('redirects are followed for allowlisted hosts and keep the ETag/304 contract', async () => {
  const { requests, close } = await serve((req, res) => {
    if (req.url === '/feed.xml') {
      res.writeHead(301, { location: '/moved.xml' });
      res.end('redirect body that must not be read');
      return;
    }
    res.writeHead(304, { etag: '"v2"' });
    res.end();
  });
  try {
    const request = createRequester(config, hooks);
    const response = await request('https://feed.example.test/feed.xml', {
      headers: { 'If-None-Match': '"v1"', 'content-type': 'application/json' },
      allowRedirects: true,
    });
    assert.equal(response.status, 304);
    assert.equal(response.headers.etag, '"v2"');
    assert.equal(requests.length, 2);
    assert.equal(requests[1].path, '/moved.xml');
    // The validator belonged to the original URL and must not be replayed.
    assert.equal(requests[1].headers['if-none-match'], undefined);
    assert.equal(requests[1].headers['content-type'], undefined);
  } finally {
    await close();
  }
});

test('redirects are refused when disabled, when the chain loops, or when the host changes', async () => {
  const { close } = await serve((req, res) => {
    res.writeHead(302, { location: req.url === '/loop' ? 'https://feed.example.test/loop' : 'https://elsewhere.test/' });
    res.end();
  });
  try {
    const request = createRequester(config, hooks);
    await assert.rejects(
      request('https://feed.example.test/feed.xml', { allowRedirects: false }),
      /Redirects are not permitted/,
    );
    await assert.rejects(request('https://feed.example.test/loop', { maxRedirects: 2 }), /Too many redirects/);
    // An off-allowlist redirect target is refused by the SSRF check.
    await assert.rejects(
      request('https://feed.example.test/feed.xml', { sameHostRedirects: false }),
      /not in EGRESS_ALLOWED_HOSTS/,
    );
  } finally {
    await close();
  }
});

test('a cross-host redirect is followed only to another allowlisted host', async () => {
  const { close } = await serve((req, res) => {
    if (req.url === '/final') {
      res.writeHead(304, { etag: '"v3"' });
      res.end();
      return;
    }
    res.writeHead(302, { location: 'https://cdn.example.test/final' });
    res.end();
  });
  // cdn.example.test serves the same content; the test certificate only covers
  // the primary host, so trust it for every test host without disabling checks.
  const crossHostHooks = { ...hooks, tls: { ca: TLS.cert, checkServerIdentity: () => undefined } };
  try {
    const request = createRequester(config, crossHostHooks);
    await assert.rejects(
      request('https://feed.example.test/feed.xml', { sameHostRedirects: true }),
      /different hostname/,
    );
    const response = await request('https://feed.example.test/feed.xml', { sameHostRedirects: false });
    assert.equal(response.status, 304);
  } finally {
    await close();
  }
});
