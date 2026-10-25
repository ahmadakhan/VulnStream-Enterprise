import { z } from 'zod';
const databaseUrl = z
  .string()
  .min(1)
  .refine((value) => {
    try {
      const url = new URL(value);
      return ['postgres:', 'postgresql:'].includes(url.protocol) && Boolean(url.hostname);
    } catch {
      return false;
    }
  }, 'DATABASE_URL must be a valid PostgreSQL connection URL');
const trustProxy = z
  .string()
  .default('')
  .refine((value) => {
    const entries = value
      .split(',')
      .map((entry) => entry.trim())
      .filter(Boolean);
    if (!entries.length) return true;
    // Express accepts preset names, IPs, and CIDRs. Reject trust-all values:
    // a wildcard proxy setting lets any client spoof X-Forwarded-For and
    // bypass IP-based login throttling and audit attribution.
    return entries.every(
      (entry) =>
        !['true', '*', '0.0.0.0/0', '::/0'].includes(entry.toLowerCase()) &&
        (/^(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?$/.test(entry) ||
          /^[0-9a-f:]+(?:\/\d{1,3})?$/i.test(entry) ||
          ['loopback', 'linklocal', 'uniquelocal'].includes(entry.toLowerCase())),
    );
  }, 'TRUST_PROXY must list explicit proxy IPs, CIDRs, or presets (trust-all is not permitted)');
const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  METRICS_TOKEN: z.string().max(256).default('').refine(value=>!value || value.length>=32,'Metrics token must contain at least 32 characters'),
  PORT: z.coerce.number().int().min(1).max(65535).default(8080),
  DATABASE_URL: databaseUrl,
  APP_ORIGIN: z.url(),
  ENCRYPTION_KEY: z.string().regex(/^[A-Za-z0-9+/]{43}=$/, 'Must be a base64 encoded 32-byte key'),
  EGRESS_ALLOWED_HOSTS: z.string().default('raw.githubusercontent.com,services.nvd.nist.gov,www.cisa.gov,api.first.org,app.opencve.io,api.vulncheck.com,www.bleepingcomputer.com,isc.sans.edu,api.msrc.microsoft.com,api.mailgun.net,api.eu.mailgun.net,send.api.mailtrap.io,sandbox.api.mailtrap.io,api.sendgrid.com,smtp.sendgrid.net,api.postmarkapp.com,smtp.maileroo.com,smtp.lettr.com,in-v3.mailjet.com,api.mailjet.com,smtp.gmail.com,www.fortiguard.com,filestore.fortinet.com,www.cisa.gov,www.kb.cert.org,thehackernews.com,www.securityweek.com,www.rapid7.com,googleprojectzero.blogspot.com,krebsonsecurity.com,tools.cisco.com,security.paloaltonetworks.com'),
  TRUST_PROXY: trustProxy,
  SMTP_HOST: z.string().default(''),
  SMTP_PORT: z.coerce.number().int().min(1).max(65535).default(465),
  SMTP_USER: z.string().default(''),
  SMTP_PASSWORD: z.string().default(''),
  SMTP_FROM: z.union([z.email(), z.literal('')]).default(''),
  FEED_MAX_DURATION_SECONDS: z.coerce.number().int().min(1).max(7200).default(1800),
  WORKER_ENABLED: z.enum(['true', 'false']).default('true'),
  MAILJET_SANDBOX_MODE: z.enum(['true', 'false']).default('false'),
});
export type Config = z.infer<typeof schema>;
export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const config = schema.parse(env);
  const origin = new URL(config.APP_ORIGIN);
  if (origin.origin !== config.APP_ORIGIN) throw new Error('APP_ORIGIN must be an origin without a path');
  if (config.NODE_ENV === 'production' && origin.protocol !== 'https:')
    throw new Error('Production requires an HTTPS APP_ORIGIN');
  if (Buffer.from(config.ENCRYPTION_KEY, 'base64').length !== 32) throw new Error('Invalid encryption key');
  return config;
}
