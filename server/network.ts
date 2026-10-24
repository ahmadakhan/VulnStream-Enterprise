import https from 'node:https';
import { lookup } from 'node:dns/promises';
import { pipeline } from 'node:stream/promises';
import { Transform, Writable, type Readable } from 'node:stream';
import { createGunzip } from 'node:zlib';
import ipaddr from 'ipaddr.js';
import type { Config } from './config';
export function publicAddress(address: string): boolean {
  try {
    const ip = ipaddr.process(address);
    return ip.range() === 'unicast';
  } catch {
    return false;
  }
}
export async function resolvePublic(url: URL, allowedHosts: string[], resolver = lookup) {
  const host = url.hostname
    .replace(/^\[|\]$/g, '')
    .toLowerCase()
    .replace(/\.$/, '');
  if (url.protocol !== 'https:' || url.username || url.password || (url.port && url.port !== '443'))
    throw new Error('Only HTTPS port 443 without URL credentials is permitted');
  if (!allowedHosts.includes(host)) throw new Error('Destination hostname is not in EGRESS_ALLOWED_HOSTS');
  let timer: ReturnType<typeof setTimeout> | undefined;
  const resolveAddresses = () =>
    Promise.race([
      resolver(host, { all: true, verbatim: true }),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error('DNS lookup timed out')), 5000);
      }),
    ]).finally(() => clearTimeout(timer));
  const addresses = ipaddr.isValid(host)
    ? [{ address: host, family: ipaddr.parse(host).kind() === 'ipv4' ? 4 : 6 }]
    : await resolveAddresses();
  if (!addresses.length || addresses.some((record) => !publicAddress(record.address)))
    throw new Error('Destination resolves to a non-public address');
  return addresses[0];
}
export interface ResponseData {
  status: number;
  body: string;
  headers: Record<string, string | string[] | undefined>;
}
export interface RequestOptions {
  method?: 'GET' | 'POST';
  headers?: Record<string, string>;
  body?: string;
  /** Maximum duration for the request, including response-body transfer. */
  timeoutMs?: number;
  /** Maximum period without socket activity. */
  socketTimeoutMs?: number;
  /** Maximum accepted response body size. */
  maxResponseBytes?: number;
}
/** Read a response stream with independent wire and decompressed size limits. */
export async function readResponseBody(
  response: Readable,
  contentEncoding: string | undefined,
  maxResponseBytes: number,
): Promise<string> {
  const encoding = (contentEncoding || 'identity').trim().toLowerCase();
  if (!['identity', 'gzip', 'x-gzip'].includes(encoding)) {
    response.destroy();
    throw new Error(`Unsupported response content encoding: ${encoding}`);
  }
  const limiter = (label: string) => {
    let size = 0;
    return new Transform({
      transform(chunk: Buffer, _encoding, callback) {
        size += chunk.length;
        if (size > maxResponseBytes) callback(new Error(`${label} exceeds configured ${maxResponseBytes}-byte limit`));
        else callback(null, chunk);
      },
    });
  };
  const chunks: Buffer[] = [];
  const sink = new Writable({
    write(chunk: Buffer, _encoding, callback) {
      chunks.push(Buffer.from(chunk));
      callback();
    },
  });
  await pipeline(
    response,
    limiter('Response transfer'),
    ...(encoding === 'identity' ? [] : [createGunzip()]),
    limiter('Decoded response'),
    sink,
  );
  return Buffer.concat(chunks).toString('utf8');
}
export type Requester = (
  url: string,
  options?: RequestOptions,
) => Promise<ResponseData>;
export function createRequester(config: Config): Requester {
  const allowlist = config.EGRESS_ALLOWED_HOSTS.split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  return async (value, options = {}) => {
    const url = new URL(value),
      selected = await resolvePublic(url, allowlist);
    return new Promise((resolve, reject) => {
      let deadline: ReturnType<typeof setTimeout>;
      const clearDeadline = () => clearTimeout(deadline);
      // Connect to the validated IP while preserving TLS hostname verification and SNI.
      const request = https.request(
        url,
        {
          method: options.method || 'GET',
          headers: { 'user-agent': 'BA-Threat-Intel/1.0', accept: 'application/json', 'accept-encoding': 'gzip', ...options.headers },
          lookup: ((_host: string, opts: any, cb: any) =>
            opts?.all ? cb(null, [selected]) : cb(null, selected.address, selected.family)) as any,
          agent: false,
          timeout: options.socketTimeoutMs ?? 15000,
          maxHeaderSize: 16384,
        },
        (response) => {
          const maxResponseBytes = options.maxResponseBytes ?? 8 * 1024 * 1024;
          void readResponseBody(response, response.headers['content-encoding'], maxResponseBytes).then((body) => {
            const status = response.statusCode || 0;
            if (status >= 300 && status < 400 && status !== 304) {
              reject(new Error('Redirects are not permitted'));
              return;
            }
            resolve({ status, body, headers: response.headers });
          }, reject).finally(clearDeadline);
        },
      );
      deadline = setTimeout(
        () => request.destroy(new Error('Outbound request timed out')),
        options.timeoutMs ?? 20000,
      );
      request.on('timeout', () => request.destroy(new Error('Outbound request timed out')));
      request.on('error', (error) => {
        clearDeadline();
        reject(error);
      });
      if (options.body) request.write(options.body);
      request.end();
    });
  };
}
