import https from 'node:https';
import { lookup } from 'node:dns/promises';
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
export type Requester = (
  url: string,
  options?: { method?: 'GET' | 'POST'; headers?: Record<string, string>; body?: string },
) => Promise<ResponseData>;
export function createRequester(config: Config): Requester {
  const allowlist = config.EGRESS_ALLOWED_HOSTS.split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  return async (value, options = {}) => {
    const url = new URL(value),
      selected = await resolvePublic(url, allowlist);
    return new Promise((resolve, reject) => {
      // Connect to the validated IP while preserving TLS hostname verification and SNI.
      const request = https.request(
        url,
        {
          method: options.method || 'GET',
          headers: { 'user-agent': 'VulnStream/1.0', accept: 'application/json', ...options.headers },
          lookup: ((_host: string, opts: any, cb: any) =>
            opts?.all ? cb(null, [selected]) : cb(null, selected.address, selected.family)) as any,
          agent: false,
          timeout: 15000,
          maxHeaderSize: 16384,
        },
        (response) => {
          let bytes = 0;
          const chunks: Buffer[] = [];
          response.on('data', (chunk: Buffer) => {
            bytes += chunk.length;
            if (bytes > 8 * 1024 * 1024) {
              response.destroy(new Error('Response exceeds 8 MiB limit'));
              return;
            }
            chunks.push(chunk);
          });
          response.on('error', reject);
          response.on('end', () => {
            const status = response.statusCode || 0;
            if (status >= 300 && status < 400 && status !== 304) {
              reject(new Error('Redirects are not permitted'));
              return;
            }
            resolve({ status, body: Buffer.concat(chunks).toString('utf8'), headers: response.headers });
          });
        },
      );
      const deadline = setTimeout(() => request.destroy(new Error('Outbound request timed out')), 20000);
      request.on('close', () => clearTimeout(deadline));
      request.on('timeout', () => request.destroy(new Error('Outbound request timed out')));
      request.on('error', reject);
      if (options.body) request.write(options.body);
      request.end();
    });
  };
}
