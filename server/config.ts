import { z } from 'zod';
const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().min(1).max(65535).default(8080),
  DATABASE_URL: z.string().min(1),
  APP_ORIGIN: z.url(),
  ENCRYPTION_KEY: z.string().regex(/^[A-Za-z0-9+/]{43}=$/, 'Must be a base64 encoded 32-byte key'),
  EGRESS_ALLOWED_HOSTS: z.string().default('raw.githubusercontent.com,services.nvd.nist.gov,www.cisa.gov,api.first.org,app.opencve.io,api.vulncheck.com,www.bleepingcomputer.com,isc.sans.edu,api.msrc.microsoft.com,api.mailgun.net,api.eu.mailgun.net,send.api.mailtrap.io,sandbox.api.mailtrap.io,api.sendgrid.com,api.postmarkapp.com'),
  TRUST_PROXY: z.string().default(''),
  SMTP_HOST: z.string().default(''),
  SMTP_PORT: z.coerce.number().int().min(1).max(65535).default(465),
  SMTP_USER: z.string().default(''),
  SMTP_PASSWORD: z.string().default(''),
  SMTP_FROM: z.union([z.email(), z.literal('')]).default(''),
  FEED_MAX_DURATION_SECONDS: z.coerce.number().int().min(1).max(7200).default(1800),
  WORKER_ENABLED: z.enum(['true', 'false']).default('true'),
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
