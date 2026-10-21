import { z } from 'zod';
import { FEED_TYPES } from '../src/types';
import { parseCPE23 } from '../src/utils/cpeMatcher';
export const shortText = z.string().trim().min(1).max(200);
export const idSchema = z.string().min(1).max(150);
const strings = z.array(z.string().max(2000)).max(100);
const httpsUrl = z
  .url()
  .max(2048)
  .refine((s) => {
    const u = new URL(s);
    return u.protocol === 'https:' && !u.username && !u.password;
  }, 'HTTPS URL without embedded credentials required');
export const feedSchema = z.object({
  name: shortText,
  type: z.enum(FEED_TYPES),
  url: httpsUrl.refine(
    (s) =>
      !Array.from(new URL(s).searchParams.keys()).some((key) =>
        /token|password|secret|api.?key|signature/i.test(key),
      ),
    'Use the auth secret field rather than credentials in query parameters',
  ),
  authType: z.enum(['NONE', 'API_KEY', 'BEARER', 'BASIC']),
  authSecretKey: z.string().max(4096).optional(),
  rateLimitPerMin: z.number().int().min(1).max(600),
  enabled: z.boolean(),
  vendorSeed: z.boolean().default(false),
});
/** Bulk import shape: adds the stable identifier and the stored sync metadata. */
export const feedImportSchema = z
  .array(
    feedSchema.extend({
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
export const recipientSchema = z.object({
  name: shortText,
  email: z
    .email()
    .max(254)
    .transform((s) => s.toLowerCase()),
  role: shortText,
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
    })
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
    patchUrl: z.string().max(2048),
    vendorAdvisoryRef: z.string().max(2048),
    immediateActions: strings,
    workarounds: strings,
    rollbackPlan: z.string().max(4000),
    stepByStep: strings,
  }),
});
export const settingsSchema = z.object({
  scopeHours: z.number().int().min(1).max(2880),
  schedulerIntervalMinutes: z.number().int().min(5).max(10080),
  schedulerEnabled: z.boolean(),
  advisoryPrefix: z.string().regex(/^[A-Za-z0-9_-]{1,30}$/),
  autoDispatchEnabled: z.boolean(),
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
});
export class HttpError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
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
