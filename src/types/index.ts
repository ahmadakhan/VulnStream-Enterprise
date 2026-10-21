import { NvdVersionRange } from '../utils/versionComparator';

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export type ExposureLevel = 'INTERNET_FACING' | 'INTERNAL_CRITICAL' | 'DMZ' | 'WORKSTATION' | 'CLOUD_INFRA';

export type ExploitRiskLevel =
  'CISA_KEV_EXPLOITED' | 'WEAPONIZED_EXPLOIT' | 'HIGH_EPSS_PROBABILITY' | 'ELEVATED' | 'STANDARD';

export type NotificationStatus =
  | 'AUTO_DISPATCHED'
  | 'QUEUED_FOR_DISPATCH'
  | 'DIGEST_BATCHED'
  | 'REVIEW_REQUIRED'
  | 'NOT_APPLICABLE'
  | 'SUPPRESSED_VEX_NOT_AFFECTED'
  | 'DELIVERED'
  | 'DELIVERY_FAILED';

export type FindingStatus =
  'MONITORED' | 'REMEDIATION_AVAILABLE' | 'PATCH_APPLIED' | 'RESOLVED' | 'FALSE_POSITIVE';

/**
 * Feed types the server can actually ingest. The runtime adapter set and this
 * list must stay identical: a feed that is not in this list cannot be polled.
 */
export const FEED_TYPES = ['JSON_SEARCH_API', 'NVD_API', 'CISA_KEV', 'EPSS_API'] as const;

export type FeedType = (typeof FEED_TYPES)[number];

export type FeedAuthType = 'NONE' | 'API_KEY' | 'BEARER' | 'BASIC';

export interface CVSSData {
  version: '3.1' | '4.0' | '2.0';
  score: number;
  vector: string;
  severity: Severity;
}

export interface EPSSData {
  score: number;
  percentile: number;
}

export interface CisaKevData {
  isKev: boolean;
  dateAdded?: string;
  dueDate?: string;
  requiredAction?: string;
  knownRansomwareCampaignUse?: 'Known' | 'Unknown';
}

export interface VexStatement {
  status: 'affected' | 'not_affected' | 'fixed' | 'under_investigation';
  justification?: string;
  impactStatement?: string;
}

export interface RemediationPlaybook {
  patchUrl: string;
  vendorAdvisoryRef: string;
  immediateActions: string[];
  workarounds: string[];
  rollbackPlan: string;
  stepByStep: string[];
}

export interface TemplateCustomization {
  fontFamily: 'sans' | 'mono' | 'serif' | 'system';
  fontColor: string;
  headingColor: string;
  accentColor: string;
  canvasBg: string;
  cardBg: string;
  headerBg: string;
  badgeStampText: string;
  badgeStampColor: string;
  showStamp: boolean;
  showClassificationBanner: boolean;
  classificationText: string;
  borderStyle: 'solid' | 'dashed' | 'none';
  borderRadius: string;
}

export interface NormalizedCVE {
  cveId: string; // Canonical CVE-YYYY-NNNNN
  title: string;
  description: string;
  publishedDate: string;
  modifiedDate: string;
  cvss: CVSSData;
  cwe: string[];
  cpeMatches: string[]; // CPE 2.3 formatted strings
  versionRange?: NvdVersionRange; // NVD Version Interval
  applicabilityRequiresReview?: boolean;
  cpeMatchDetails?: { criteria: string; range?: NvdVersionRange }[];
  purls?: string[]; // Package URLs (PURL)
  vex?: VexStatement; // CSAF 2.0 VEX status
  sourceFeeds: string[];
  epss: EPSSData;
  cisaKev: CisaKevData;
  exploitStatus: 'Active Weaponized' | 'POC Available' | 'Reported In Wild' | 'None';
  remediation: RemediationPlaybook;
}

export interface WatchListItem {
  id: string;
  vendor: string;
  product: string;
  version?: string;
  cpes: string[]; // Strict CPE 2.3 entries
  purls?: string[]; // Optional PURLs
  targetHw?: string; // Architecture e.g. x86_64, aarch64
  exposure?: ExposureLevel; // Deprecated: all products treated with uniform enterprise priority
  assetTag: string;
  ownerGroup: string;
  active: boolean;
  notes?: string;
  createdAt: string;
}

export interface Finding {
  id: string;
  cveId: string;
  cve: NormalizedCVE;
  matchedAssetId: string;
  matchedAssetName: string;
  matchedCpe: string;
  matchingMethod: string;
  matchingEvidence: string;
  exposure?: ExposureLevel; // Deprecated
  exploitRisk: ExploitRiskLevel;
  notificationStatus: NotificationStatus;
  status: FindingStatus;
  autoDispatchedAt: string | null;
  advisoryId: string | null;
  timeline: {
    timestamp: string;
    action: string;
    system: string;
    details: string;
  }[];
}

export interface ThreatFeed {
  id: string;
  name: string;
  type: FeedType;
  url: string;
  authType: FeedAuthType;
  authSecretKey?: string;
  rateLimitPerMin: number;
  enabled: boolean;
  healthStatus: 'HEALTHY' | 'DEGRADED' | 'DOWN' | 'UNTESTED';
  lastSync: string | null;
  latencyMs: number;
  vendorSeed: boolean;
  itemCountLastRun: number;
  errorLog?: string | null;
  ssrfValidated: boolean;
  etag?: string;
  consecutiveFailures?: number;
}

export interface Advisory {
  id: string;
  title: string;
  severity: Severity;
  cveIds: string[];
  findingIds: string[];
  createdDate: string;
  deliveryStatus: 'ACCEPTED' | 'DELIVERED' | 'PENDING' | 'FAILED' | 'RETRYING' | 'DRAFT';
  recipientCount: number;
  executiveSummary: string;
   remediationInstructions: string;
  affectedSystems: string[];
  isDigestBatch?: boolean;
  vendorLink?: string;
}

export interface PipelinePhase {
  name: string;
  status: 'PENDING' | 'RUNNING' | 'SUCCESS' | 'WARNING' | 'FAILED';
  durationMs: number;
  details: string;
  metrics?: Record<string, string | number>;
}

export interface PipelineExecution {
  id: string;
  startTime: string;
  endTime: string | null;
  status: 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'QUARANTINED';
  scopeHours: number;
  phases: PipelinePhase[];
  stats: {
    rawIngested: number;
    normalized: number;
    deduplicated: number;
    inRunDuplicatesDropped: number;
    matchedWatchlist: number;
    autoDispatchedNotifications: number;
    advisoriesDispatched: number;
    webhooksFired: number;
    vexSuppressedCount: number;
    notificationsQueued?: number;
    advisoriesQueued?: number;
  };
  logs: string[];
}

export interface AlertedCVE {
  cveId: string;
  firstAlertedAt: string;
  lastAlertedAt: string;
  advisoryId: string;
  recipientEmails: string[];
  status: 'DISPATCHED' | 'SUPPRESSED';
  dispatchCount: number;
  lastDispatchReason?: string;
  lastDispatchKey?: string;
}

export interface EmailRecipient {
  id: string;
  name: string;
  email: string;
  role: string;
  subscriptionTier: 'ALL_SEVERITIES' | 'CRITICAL_HIGH_ONLY' | 'CISA_KEV_ONLY';
  enabled: boolean;
  deliverySuccessRate: number;
}

export interface WebhookEndpoint {
  id: string;
  name: string;
  url: string;
  provider: 'SLACK' | 'TEAMS' | 'GENERIC_HMAC';
  secretToken: string;
  enabled: boolean;
  events: ('CRITICAL' | 'CISA_KEV' | 'ALL')[];
  deliveryCount: number;
}

export interface WebhookDeliveryLog {
  id: string;
  endpointId: string;
  endpointName: string;
  provider: 'SLACK' | 'TEAMS' | 'GENERIC_HMAC';
  advisoryId: string;
  cveId: string;
  status: 'SUCCESS' | 'FAILED' | 'QUEUED';
  statusCode: number;
  hmacSignature: string;
  sentAt: string;
}

export interface EmailDeliveryLog {
  id: string;
  recipientEmail: string;
  advisoryId: string;
  subject: string;
  provider: 'Mailgun' | 'SMTP_Relay' | 'Local_Mock';
  status: 'QUEUED' | 'ACCEPTED' | 'DELIVERED' | 'BOUNCED' | 'RETRYING' | 'FAILED';
  attemptCount: number;
  retrySchedule: string[];
  nextRetryTime: string | null;
  sentAt: string;
  errorMessage?: string;
}

export interface AuditLog {
  id: string;
  timestamp: string;
  category: 'PIPELINE' | 'SECURITY' | 'FEED' | 'WATCHLIST' | 'EMAIL' | 'WEBHOOK';
  level: 'INFO' | 'WARNING' | 'ERROR';
  event: string;
  details: string;
  actor: string;
  ipAddress: string;
  prevHash: string;
  hash: string;
}

export interface AppSettings {
  scopeHours: number;
  schedulerIntervalMinutes: number;
  schedulerEnabled: boolean;
  advisoryPrefix: string;
  autoDispatchEnabled: boolean;
  digestBatchingEnabled: boolean;
  digestWindowMinutes: number;
  webhookSigningSecret: string;
  authorityPrecedence: ('VENDOR_PSIRT' | 'CISA_KEV' | 'FIRST_EPSS' | 'NVD_BATCH')[];
  ssrfProtection: {
    blockPrivateIps: boolean;
    blockLoopback: boolean;
    allowRedirects: boolean;
  };
  securityPolicy: {
    sessionTimeoutMins: number;
    csrfProtection: boolean;
    minPasswordLen: number;
    maxLoginAttempts: number;
    lockoutMins: number;
  };
  ntpConfig: {
    enabled: boolean;
    server: string;
    driftToleranceMs: number;
  };
  mailgunConfig: {
    enabled: boolean;
    apiKey: string;
    domain: string;
    fromEmail: string;
  };
}
