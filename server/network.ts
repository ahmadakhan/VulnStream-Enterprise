import https, { Agent } from 'node:https';
import { lookup } from 'node:dns/promises';
import type { LookupFunction } from 'node:net';
import { pipeline } from 'node:stream/promises';
import { Transform, Writable, type Readable } from 'node:stream';
import { createGunzip } from 'node:zlib';
import ipaddr from 'ipaddr.js';
import { isPublicAddress } from '../src/utils/ipSafety.ts';
import type { Config } from './config';
export function publicAddress(address: string): boolean {
  return isPublicAddress(address);
}
/** Resolver shape used by the SSRF check: every address the host maps to. */
export type Resolver = (
  host: string,
  options: { all: true; verbatim: true },
) => Promise<unknown>;
export async function resolvePublic(
  url: URL,
  allowedHosts: string[],
  resolver: Resolver = lookup as Resolver,
  allowedPorts: readonly string[] = ['443'],
) {
  const host = url.hostname
    .replace(/^\[|\]$/g, '')
    .toLowerCase()
    .replace(/\.$/, '');
  if (url.protocol !== 'https:' || url.username || url.password || (url.port && !allowedPorts.includes(url.port)))
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
  // DNS answers arrive as { address, family } objects when `all` is set, but
  // resolvers are pluggable, so accept a bare address string as well and never
  // let an unexpected shape reach the connect path as `undefined`.
  const asRecord = (record: unknown) => {
    if (typeof record === 'string') return { address: record, family: record.includes(':') ? 6 : 4 };
    const candidate = record as { address?: unknown; family?: unknown } | null;
    if (typeof candidate?.address !== 'string' || !candidate.address) return undefined;
    return {
      address: candidate.address,
      family: candidate.family === 6 ? 6 : candidate.family === 4 ? 4 : candidate.address.includes(':') ? 6 : 4,
    };
  };
  const addresses = ipaddr.isValid(host)
    ? [{ address: host, family: ipaddr.parse(host).kind() === 'ipv4' ? 4 : 6 }]
    : (await resolveAddresses() as unknown[] | undefined)?.map(asRecord);
  if (!addresses?.length || addresses.some((record) => !record))
    throw new Error(`Destination hostname ${host} did not resolve`);
  const records = addresses as { address: string; family: number }[];
  if (records.some((record) => !publicAddress(record.address)))
    throw new Error('Destination resolves to a non-public address');
  return records[0];
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
  /**
   * When true (default), redirects to allowlisted HTTPS hosts are followed
   * with full SSRF re-validation on each hop (public IP, port 443, no URL
   * credentials). Set to false to reject redirects like the previous behavior.
   */
  allowRedirects?: boolean;
  /** Maximum number of redirect hops to follow. Defaults to 5. */
  maxRedirects?: number;
  /**
   * Applied when a redirect answers with a status that does not preserve the
   * method (301/302/303, or any 3xx to a POST). The https module sends no
   * body on such a hop, so the default drops body-dependent headers; callers
   * sending a payload must opt in with 'GET' to follow it as a plain fetch.
   */
  redirectMethod?: 'GET' | 'DROP';
  /** Reject redirects whose target is a different hostname. Defaults to false; each hop is still re-validated through the SSRF gauntlet. */
  sameHostRedirects?: boolean;
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
/** Options for createRequester that are not part of the runtime configuration. */
export interface RequesterHooks {
  /** DNS resolver used by the SSRF check. Defaults to the system resolver. */
  resolver?: Resolver;
  /** TLS options for outbound connections, e.g. a pinned CA. */
  tls?: https.RequestOptions;
  /** TLS ports permitted by the SSRF check. Defaults to 443 only. */
  allowedPorts?: readonly string[];
  /** Socket factory, used by tests to reach a local server after validation. */
  connect?: (options: any) => import('node:stream').Duplex;
}

export function createRequester(config: Config, hooks: RequesterHooks = {}) {
  const allowlist = config.EGRESS_ALLOWED_HOSTS.split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  return async (value: string, options: RequestOptions = {}): Promise<ResponseData> => {
    const opts: RedirectOptions = {
      allowRedirects: options.allowRedirects ?? true,
      maxRedirects: options.maxRedirects ?? 5,
      redirectMethod: options.redirectMethod ?? 'DROP',
      sameHostRedirects: options.sameHostRedirects ?? false,
    };
    return doRequest(value, options, opts, allowlist, hooks, hooks.allowedPorts ?? ['443']);
  };
}

type RedirectOptions = Required<
  Pick<RequestOptions, 'allowRedirects' | 'maxRedirects' | 'redirectMethod' | 'sameHostRedirects'>
>;

/** Body-dependent headers are meaningless on a hop that carries no body. */
const BODY_HEADERS = ['content-type', 'content-length', 'transfer-encoding'];

/** Render a Location header for an error message without URL credentials. */
function safeTarget(location: string | undefined, current: URL): string {
  if (!location) return '(no Location header)';
  try {
    const target = new URL(location, current);
    target.username = '';
    target.password = '';
    return target.href;
  } catch {
    return '(invalid Location header)';
  }
}

/** Copy request headers without the named ones (case-insensitive). */
function withoutHeaders(headers: Record<string, string>, names: string[]): Record<string, string> {
  const dropped = names.map((name) => name.toLowerCase());
  return Object.fromEntries(
    Object.entries(headers).filter(([name]) => !dropped.includes(name.toLowerCase())),
  );
}

/**
 * Map a redirect response to the request that should follow it, or reject.
 * The target goes through the full SSRF gauntlet via `resolvePublic`.
 */
async function redirectTarget(
  status: number,
  location: string | undefined,
  current: URL,
  options: RequestOptions,
  opts: RedirectOptions,
  allowlist: string[],
  hooks: RequesterHooks,
  allowedPorts: readonly string[],
): Promise<{ href: string; options: RequestOptions; opts: RedirectOptions }> {
  // Every refusal names the redirect and its target. A bare "not permitted"
  // gave operators no way to tell a disabled policy from a blocked host, and
  // looked identical to the old unconditional rejection this code replaced.
  if (!opts.allowRedirects)
    throw new Error(`Redirects are not permitted (HTTP ${status} to ${safeTarget(location, current)})`);
  if (opts.maxRedirects <= 0)
    throw new Error(`Too many redirects (stopped at HTTP ${status} to ${safeTarget(location, current)})`);
  if (!location) throw new Error(`HTTP ${status} redirect without Location header`);
  let next: URL;
  try {
    next = new URL(location, current);
  } catch {
    throw new Error(`HTTP ${status} redirect has an invalid Location header`);
  }
  if (opts.sameHostRedirects && next.hostname.toLowerCase() !== current.hostname.toLowerCase())
    throw new Error(
      `Redirect to a different hostname is not permitted (${current.hostname} -> ${next.hostname}); add ${next.hostname} to EGRESS_ALLOWED_HOSTS and allow cross-host redirects for this feed`,
    );
  await resolvePublic(next, allowlist, hooks.resolver, allowedPorts);
  const method = options.method || 'GET';
  const staysPost = method === 'POST' && (status === 307 || status === 308);
  if (staysPost) {
    return {
      href: next.href,
      // A new URL means new path and query: a conditional GET's validator and
      // cached representation belong to the original resource, so drop them.
      options: { ...options, headers: withoutHeaders(options.headers ?? {}, ['if-none-match', 'if-modified-since']) },
      opts: { ...opts, maxRedirects: opts.maxRedirects - 1 },
    };
  }
  if (method === 'POST' && opts.redirectMethod !== 'GET')
    throw new Error(`HTTP ${status} redirect would discard the request body`);
  return {
    href: next.href,
    options: {
      ...options,
      method: 'GET',
      body: undefined,
      headers: withoutHeaders(options.headers ?? {}, [...BODY_HEADERS, 'if-none-match', 'if-modified-since']),
    },
    opts: { ...opts, maxRedirects: opts.maxRedirects - 1 },
  };
}

async function doRequest(
  value: string,
  options: RequestOptions,
  opts: RedirectOptions,
  allowlist: string[],
  hooks: RequesterHooks,
  allowedPorts: readonly string[],
): Promise<ResponseData> {
  const url = new URL(value),
    selected = await resolvePublic(url, allowlist, hooks.resolver, allowedPorts);
  return new Promise((resolve, reject) => {
    let deadline: ReturnType<typeof setTimeout>;
    const clearDeadline = () => clearTimeout(deadline);
    // Connect to the validated IP while preserving TLS hostname verification and SNI.
    const request = https.request(
      url,
      {
        ...hooks.tls,
        method: options.method || 'GET',
        headers: { 'user-agent': 'BA-Threat-Intel/1.0', accept: 'application/json', 'accept-encoding': 'gzip', ...options.headers },
        // Pin every connection to the validated address. A per-request agent
        // rather than `agent: false` keeps that pin in place when a POST body
        // is retried on a fresh socket, and is never reused across requests.
        agent: hooks.connect ? undefined : new Agent({ keepAlive: false }),
        ...(hooks.connect
          ? { createConnection: hooks.connect }
          : {
              // Pin the connection to the address that passed validation. Node's
              // lookup contract has two shapes: `all: true` expects an address
              // array, otherwise (host, family, callback). Always answering the
              // scalar form left the family undefined and the array absent, so
              // every request failed with "Invalid IP address: undefined".
              lookup: ((_hostname: string, lookupOptions: { all?: boolean } | number, callback: (...args: unknown[]) => void) =>
                (typeof lookupOptions === 'object' && lookupOptions?.all)
                  ? callback(null, [{ address: selected.address, family: selected.family }])
                  : callback(null, selected.address, selected.family)) as unknown as LookupFunction,
            }),
        timeout: options.socketTimeoutMs ?? 15000,
        maxHeaderSize: 16384,
      },
      (response) => {
        const status = response.statusCode || 0;
        // A redirect hop carries no useful body: decide the next request first
        // and discard the payload instead of reading (or size-limiting) it.
        // The deadline is deliberately left running so the caller's total
        // budget (see the feed duration limit) spans the whole redirect chain.
        if (status >= 300 && status < 400 && status !== 304) {
          response.resume();
          void redirectTarget(status, response.headers.location, url, options, opts, allowlist, hooks, allowedPorts)
            .then((hop) => doRequest(hop.href, hop.options, hop.opts, allowlist, hooks, allowedPorts))
            .then(resolve, reject);
          return;
        }
        const maxResponseBytes = options.maxResponseBytes ?? 8 * 1024 * 1024;
        void readResponseBody(response, response.headers['content-encoding'], maxResponseBytes)
          .then((body) => resolve({ status, body, headers: response.headers }), reject)
          .finally(clearDeadline);
      },
    );
    // Callers bound their timeout by a remaining-time budget (see the feed
    // duration limit), which can be at or below zero once the budget is spent.
    // A negative delay makes Node clamp the timer to 1ms and warn; reject
    // immediately instead, so the caller sees a normal timeout rather than an
    // attempt that was never going to be allowed to finish.
    const timeoutMs = options.timeoutMs ?? 20000;
    if (timeoutMs <= 0) {
      reject(new Error('Outbound request timed out'));
      request.destroy();
      return;
    }
    deadline = setTimeout(
      () => request.destroy(new Error('Outbound request timed out')),
      timeoutMs,
    );
    request.on('timeout', () => request.destroy(new Error('Outbound request timed out')));
    request.on('error', (error) => {
      clearDeadline();
      reject(error);
    });
    if (options.body) request.write(options.body);
    request.end();
  });
}
