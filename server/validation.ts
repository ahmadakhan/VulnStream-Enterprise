import { z } from 'zod';
import { FEED_TYPES, EMAIL_PROVIDERS, SMTP_EMAIL_PROVIDERS } from '../src/types/index.ts';
import { parseCPE23 } from '../src/utils/cpeMatcher.ts';
export const shortText = z.string().trim().min(1).max(200);
export const idSchema = z
  .string()
  .min(1)
  .max(150)
  .refine(
    (value) => !/[\u0000-\u001f\u007f]/.test(value),
    'Identifier must not contain control characters',
  );
const strings = z.array(z.string().max(2000)).max(100);
const httpsUrl = z
  .url()
  .max(2048)
  .refine((s) => {
    const u = new URL(s);
    return u.protocol === 'https:' && !u.username && !u.password;
  }, 'HTTPS URL without embedded credentials required');
const referenceUrl = z.union([
  z.literal(''),
  z
    .url()
    .max(2048)
    .refine((value) => {
      const url = new URL(value);
      return ['https:', 'http:'].includes(url.protocol) && !url.username && !url.password;
    }, 'HTTP(S) reference URL without embedded credentials required'),
]);
export const feedSchema = z.object({
  name: shortText,
  type: z.enum(FEED_TYPES),
  url: httpsUrl.refine(
    (s) =>
      !Array.from(new URL(s).searchParams.keys()).some((key) =>
        /token|password|passwd|secret|api.?key|access.?key|private.?key|signature|credential|(?:^|[_-])key(?:$|[_-])|(?:^|[_-])sig(?:$|[_-])/i.test(
          key,
        ),
      ),
    'Use the auth secret field rather than credentials in query parameters',
  ),
  authType: z.enum(['NONE', 'API_KEY', 'BEARER', 'BASIC']),
  authSecretKey: z.string().max(4096).optional(),
  rateLimitPerMin: z.number().int().min(1).max(600),
  requestTimeoutSeconds: z.number().int().min(5).max(120).optional(),
  recoveryDelayMinutes: z.number().int().min(1).max(60).default(5),
  enabled: z.boolean(),
  vendorSeed: z.boolean().default(false),
}).refine(feed => feed.type !== 'MITRE_CVE' || (feed.authType === 'NONE' && feed.url === 'https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json'), { message: 'MITRE CVE requires the official CVE List deltaLog.json URL and no authentication', path: ['url'] });
/** Bulk import shape: adds the stable identifier and the stored sync metadata. */
export const feedImportSchema = z
  .array(
    feedSchema.safeExtend({
      id: idSchema,
      lastSync: z.iso.datetime({ offset: true }).nullable().optional(),
      etag: z.string().max(200).optional(),
      itemCountLastRun: z.number().int().min(0).optional(),
      latencyMs: z.number().int().min(0).optional(),
    }),
  )
  .max(100);
const assetShape = z.object({
  vendor: shortText,
  product: shortText,
  version: z.string().max(100).optional(),
  cpes: z
    .array(
      z
        .string()
        .max(1000)
        .refine((s) => parseCPE23(s).isValid, 'Invalid CPE 2.3'),
    )
    .max(100),
  purls: z
    .array(
      z
        .string()
        .max(1000)
        .regex(/^pkg:[a-z][a-z0-9.+-]*\/.+/),
    )
    .max(100)
    .optional(),
  targetHw: z.string().max(100).optional(),
  assetTag: shortText,
  ownerGroup: shortText,
  active: z.boolean(),
  notes: z.string().max(4000).optional(),
});
export const assetSchema = assetShape.refine(
  (a) => a.cpes.length > 0 || !!a.purls?.length,
  'At least one CPE or PURL is required',
);
/** Bulk upsert shape for monitored inventory; keeps identifiers stable across reseeds. */
export const watchlistImportSchema = z
  .array(
    assetShape.extend({
      id: idSchema,
      createdAt: z.iso.datetime({ offset: true }).optional(),
      exposure: z.enum(['INTERNET_FACING', 'INTERNAL_CRITICAL', 'DMZ', 'LOW']).optional(),
    }),
  )
  .max(1000);
export const aliasSchema = z.object({
  scope: z.enum(['VENDOR', 'PRODUCT']),
  canonical: shortText.transform((s) => s.toLowerCase()),
  aliases: z
    .array(shortText.transform((s) => s.toLowerCase()))
    .min(1)
    .max(50)
    .refine((list) => new Set(list).size === list.length, 'Duplicate alias entries'),
  notes: z.string().max(500).optional(),
});
export const recipientSchema = z.object({
  name: shortText,
  email: z
    .email()
    .max(254)
    .transform((s) => s.toLowerCase()),
  role: shortText,
  deliveryGroup: z.enum(['SECURITY_TEAM', 'EVERYONE']).default('SECURITY_TEAM'),
  subscriptionTier: z.enum(['ALL_SEVERITIES', 'CRITICAL_HIGH_ONLY', 'CISA_KEV_ONLY']),
  enabled: z.boolean(),
});
export const webhookSchema = z
  .object({
    name: shortText,
    url: httpsUrl,
    provider: z.enum(['SLACK', 'TEAMS', 'GENERIC_HMAC']),
    secretToken: z.string().max(4096).default(''),
    enabled: z.boolean(),
    events: z
      .array(z.enum(['CRITICAL', 'CISA_KEV', 'ALL']))
      .min(1)
      .max(3),
  })
  .refine(
    (value) => value.provider !== 'GENERIC_HMAC' || value.secretToken.length >= 32,
    'Generic HMAC webhooks require a shared secret of at least 32 characters',
  );
export const rangeSchema = z.object({
  versionStartIncluding: z.string().max(100).optional(),
  versionStartExcluding: z.string().max(100).optional(),
  versionEndIncluding: z.string().max(100).optional(),
  versionEndExcluding: z.string().max(100).optional(),
});
export const cveSchema = z.object({
  cveId: z
    .string()
    .max(150)
    .trim()
    .toUpperCase()
    .regex(/^CVE-\d{4}-\d{4,}$/),
  title: z.string().min(1).max(500),
  description: z.string().max(30000),
  publishedDate: z.iso.datetime({ offset: true }),
  modifiedDate: z.iso.datetime({ offset: true }),
  cvss: z.object({
    version: z.enum(['3.1', '4.0', '2.0', 'UNKNOWN']),
    score: z.number().min(0).max(10),
    vector: z.string().max(300),
    severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']),
  }),
  cwe: strings,
  cpeMatches: z.array(z.string().refine((s) => parseCPE23(s).isValid)).max(1000),
  applicabilityRequiresReview: z.boolean().optional(),
  cpeMatchDetails: z
    .array(
      z.object({ criteria: z.string().refine((s) => parseCPE23(s).isValid), range: rangeSchema.optional() }),
    )
    .max(1000)
    .optional(),
  versionRange: rangeSchema.optional(),
  purls: strings.optional(),
  vex: z
    .object({
      status: z.enum(['affected', 'not_affected', 'fixed', 'under_investigation']),
      justification: z.string().max(4000).optional(),
      impactStatement: z.string().max(4000).optional(),
      source: z.string().max(300).optional(),
      scope: z
        .object({
          cpe: z.string().max(600).optional(),
          purl: z.string().max(600).optional(),
          vendor: z.string().max(200).optional(),
          product: z.string().max(200).optional(),
        })
        .optional(),
      signed: z.boolean().optional(),
      timestamp: z.iso.datetime({ offset: true }).optional(),
    })
    .optional(),
  vexStatements: z
    .array(
      z.object({
        status: z.enum(['affected', 'not_affected', 'fixed', 'under_investigation']),
        justification: z.string().max(4000).optional(),
        impactStatement: z.string().max(4000).optional(),
        source: z.string().max(300).optional(),
        scope: z
          .object({
            cpe: z.string().max(600).optional(),
            purl: z.string().max(600).optional(),
            vendor: z.string().max(200).optional(),
            product: z.string().max(200).optional(),
          })
          .optional(),
        signed: z.boolean().optional(),
        timestamp: z.iso.datetime({ offset: true }).optional(),
      }),
    )
    .max(100)
    .optional(),
  sourceFeeds: strings,
  epss: z.object({ score: z.number().min(0).max(1), percentile: z.number().min(0).max(1) }),
  cisaKev: z.object({
    isKev: z.boolean(),
    dateAdded: z.string().optional(),
    dueDate: z.string().optional(),
    requiredAction: z.string().max(4000).optional(),
    knownRansomwareCampaignUse: z.enum(['Known', 'Unknown']).optional(),
  }),
  exploitStatus: z.enum(['Active Weaponized', 'POC Available', 'Reported In Wild', 'None']),
  remediation: z.object({
    patchUrl: referenceUrl,
    vendorAdvisoryRef: referenceUrl,
    immediateActions: strings,
    workarounds: strings,
    rollbackPlan: z.string().max(4000),
    stepByStep: strings,
  }),
});
export const emailConfigSchema = z.object({
  provider: z.enum(EMAIL_PROVIDERS),
  fromEmail: z.union([z.email().max(254), z.literal('')]),
  fromName: z.string().trim().max(100).regex(/^[^\r\n]*$/),
  apiKey: z.string().trim().max(4096).regex(/^[^\r\n]*$/).default(''),
  apiEndpoint: z.string().trim().max(2048).default(''),
  apiHeaderKey: z.string().trim().max(100).regex(/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/).default('Authorization'),
  apiAuthPrefix: z.string().trim().max(40).regex(/^[A-Za-z0-9._~-]*$/).default('Bearer'),
  apiSourceDomain: z.string().trim().max(253).regex(/^[a-zA-Z0-9.-]*$/).default(''),
  smtpHost: z.string().trim().toLowerCase().max(253).regex(/^$|^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/).default(''),
  smtpPort: z.number().int().min(1).max(65535).default(587),
  smtpSecurity: z.enum(['IMPLICIT_TLS', 'STARTTLS']).default('STARTTLS'),
  smtpUsername: z.string().trim().max(254).regex(/^[^\r\n]*$/).default(''),
  smtpPassword: z.string().max(4096).regex(/^[^\r\n]*$/).default(''),
  mailgunDomain: z.string().trim().toLowerCase().max(253).regex(/^$|^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,63}$/),
  mailgunRegion: z.enum(['US', 'EU']),
  mailtrapMode: z.enum(['LIVE', 'SANDBOX']),
  mailtrapInboxId: z.string().max(20).regex(/^$|^[1-9]\d*$/),
  postmarkMessageStream: z.string().trim().max(100).regex(/^[a-zA-Z0-9_-]+$/),
  mailjetApiSecret: z.string().trim().max(4096).regex(/^[^\r\n]*$/).default(''),
}).superRefine((value, ctx) => {
  if (value.provider !== 'SMTP' && !value.fromEmail)
    ctx.addIssue({ code: 'custom', path: ['fromEmail'], message: 'A verified sender email is required' });
  if ((SMTP_EMAIL_PROVIDERS as readonly string[]).includes(value.provider)) {
    if (!value.smtpHost)
      ctx.addIssue({ code: 'custom', path: ['smtpHost'], message: 'SMTP host is required' });
    const presetRequiresAuth = value.provider !== 'SMTP_CUSTOM';
    if (presetRequiresAuth && !value.smtpUsername)
      ctx.addIssue({ code: 'custom', path: ['smtpUsername'], message: 'SMTP username is required' });
  }
  if (value.provider === 'API') {
    if (!value.apiEndpoint)
      ctx.addIssue({ code: 'custom', path: ['apiEndpoint'], message: 'API endpoint is required' });
    if (value.apiEndpoint) {
      try {
        const endpoint = new URL(value.apiEndpoint.replaceAll('{domain}', 'source-domain'));
        if (endpoint.protocol !== 'https:' || endpoint.username || endpoint.password || (endpoint.port && endpoint.port !== '443'))
          throw new Error('invalid endpoint');
      } catch {
        ctx.addIssue({ code: 'custom', path: ['apiEndpoint'], message: 'Use an HTTPS URL on port 443 without URL credentials' });
      }
    }
    if (value.apiEndpoint.includes('{domain}') && !value.apiSourceDomain)
      ctx.addIssue({ code: 'custom', path: ['apiSourceDomain'], message: 'Source / Domain is required when the endpoint contains {domain}' });
    if (['content-type', 'host', 'content-length', 'transfer-encoding', 'connection', 'user-agent', 'accept', 'accept-encoding'].includes(value.apiHeaderKey.toLowerCase()))
      ctx.addIssue({ code: 'custom', path: ['apiHeaderKey'], message: 'This header name is reserved' });
  }
  if (value.provider === 'SMTP' && !value.smtpHost && (value.smtpUsername || value.smtpPassword))
    ctx.addIssue({ code: 'custom', path: ['smtpHost'], message: 'Set an SMTP host to use custom SMTP credentials' });
  if (value.provider === 'MAILGUN' && !value.mailgunDomain)
    ctx.addIssue({ code: 'custom', path: ['mailgunDomain'], message: 'Mailgun sending domain is required' });
  if (value.provider === 'MAILTRAP' && value.mailtrapMode === 'SANDBOX' && !value.mailtrapInboxId)
    ctx.addIssue({ code: 'custom', path: ['mailtrapInboxId'], message: 'Mailtrap sandbox inbox ID is required' });
});
export const settingsSchema = z.object({
  scopeHours: z.number().int().min(1).max(2880),
  schedulerIntervalMinutes: z.number().int().min(5).max(10080),
  schedulerEnabled: z.boolean(),
  advisoryPrefix: z.string().regex(/^[A-Za-z0-9_-]{1,30}$/),
  autoDispatchEnabled: z.boolean(),
  autoDispatchConfidenceThreshold: z.number().int().min(0).max(100).default(90),
  // Digest coalescing is opt-in so existing deployments keep their current behavior.
  digestBatchingEnabled: z.boolean().default(false),
  digestWindowMinutes: z.number().int().min(1).max(1440),
  webhookSigningSecret: z.literal(''),
  authorityPrecedence: z.array(z.enum(['VENDOR_PSIRT', 'CISA_KEV', 'FIRST_EPSS', 'NVD_BATCH'])).max(4),
  ssrfProtection: z.object({
    blockPrivateIps: z.literal(true),
    blockLoopback: z.literal(true),
    allowRedirects: z.literal(false),
  }),
  securityPolicy: z.object({
    sessionTimeoutMins: z.number().int().min(5).max(60),
    csrfProtection: z.literal(true),
    minPasswordLen: z.number().int().min(14).max(128),
    maxLoginAttempts: z.literal(5),
    lockoutMins: z.literal(15),
  }),
  // Defaults to 'standard' so an older client that omits the field cannot
  // silently switch an installation into high-volume forensic logging.
  logVerbosity: z.enum(['standard', 'verbose']).default('standard'),
  ntpConfig: z.object({
    enabled: z.literal(false),
    server: z.literal(''),
    driftToleranceMs: z.number().min(0).max(1000),
  }),
  mailgunConfig: z.object({
    enabled: z.literal(false),
    apiKey: z.literal(''),
    domain: z.literal(''),
    fromEmail: z.literal(''),
  }),
  // Defaults keep settings stored before retention was configurable valid.
  retentionConfig: z
    .object({
      enabled: z.boolean(),
      retentionHours: z.number().int().min(1).max(8760),
      cleanupIntervalMinutes: z.number().int().min(1).max(1440),
      maxArchivedRecords: z.number().int().min(1000).max(1000000),
      autoCleanup: z.boolean(),
      retentionMode: z.enum(['strict', 'rolling', 'checkpoints']),
    })
    .default({
      enabled: false,
      retentionHours: 24,
      cleanupIntervalMinutes: 60,
      maxArchivedRecords: 10000,
      autoCleanup: true,
      retentionMode: 'rolling',
    }),
});
export class HttpError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export const templateSchema = z.object({
  fontFamily: z.enum(['sans', 'mono', 'serif', 'system']),
  fontColor: z.string().regex(/^#[0-9a-f]{6}$/i),
  headingColor: z.string().regex(/^#[0-9a-f]{6}$/i),
  accentColor: z.string().regex(/^#[0-9a-f]{6}$/i),
  canvasBg: z.string().regex(/^#[0-9a-f]{6}$/i),
  cardBg: z.string().regex(/^#[0-9a-f]{6}$/i),
  headerBg: z.string().regex(/^#[0-9a-f]{6}$/i),
  badgeStampColor: z.string().regex(/^#[0-9a-f]{6}$/i),
  badgeStampText: z.string().max(200),
  showStamp: z.boolean(),
  showClassificationBanner: z.boolean(),
  classificationText: z.string().max(300),
  borderStyle: z.enum(['solid', 'dashed', 'none']),
  borderRadius: z.string().regex(/^\d{1,3}(?:px|rem|%)$/),
});
