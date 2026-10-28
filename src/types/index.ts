import { NvdVersionRange } from '../utils/versionComparator.ts';

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';

export type ExposureLevel = 'INTERNET_FACING' | 'INTERNAL_CRITICAL' | 'DMZ' | 'WORKSTATION' | 'CLOUD_INFRA';

export type ExploitRiskLevel =
  | 'CISA_KEV_EXPLOITED'
  | 'REPORTED_IN_WILD_EXPLOIT'
  | 'WEAPONIZED_EXPLOIT'
  | 'HIGH_EPSS_PROBABILITY'
  | 'ELEVATED'
  | 'STANDARD';

export type NotificationStatus =
  | 'AUTO_DISPATCHED'
  | 'QUEUED_FOR_DISPATCH'
  | 'DIGEST_BATCHED'
  | 'REVIEW_REQUIRED'
  | 'NOT_APPLICABLE'
  | 'SUPPRESSED_VEX_NOT_AFFECTED'
  | 'DELIVERED'
  | 'DELIVERY_FAILED'
  | 'SECURITY_REJECTED';

export type FindingStatus =
  'MONITORED' | 'REMEDIATION_AVAILABLE' | 'PATCH_APPLIED' | 'RESOLVED' | 'FALSE_POSITIVE';

/**
 * Feed types the server can actually ingest. The runtime adapter set and this
 * list must stay identical: a feed that is not in this list cannot be polled.
 */
export const FEED_TYPES = [
  'JSON_SEARCH_API',
  'NVD_API',
  'MITRE_CVE',
  'CISA_KEV',
  'EPSS_API',
  'OPENCVE_API',
  'VULNCHECK_KEV',
  'RSS_ATOM',
] as const;

export type FeedType = (typeof FEED_TYPES)[number];

export type FeedAuthType = 'NONE' | 'API_KEY' | 'BEARER' | 'BASIC';

export interface IntelligenceArticle {
  id: string;
  url: string;
  title: string;
  summary: string;
  publishedDate: string;
  modifiedDate: string;
  cveIds: string[];
  sourceFeeds: string[];
  /** True when the article describes a vulnerability without an assigned CVE ID (potential zero-day). */
  zeroDay?: boolean;
  /**
   * Pre-CVE cluster identity assigned by the correlation layer when this
   * article was ingested before a CVE existed. When the CVE is later
   * published, articles in the same cluster are linked to it so the
   * canonical identifier inherits the accumulated evidence and operator
   * dispositions instead of alerting as a brand-new incident.
   */
  clusterId?: string;
  /** CVE ID this cluster was resolved to by the CVE-publication linkage. */
  resolvedCveId?: string;
}
export interface IntelligenceMatch {
  id: string;
  cveId: string | null;
  assetId: string;
  assetName: string;
  articleIds: string[];
  status: 'CORROBORATED' | 'REVIEW_REQUIRED';
  evidence: string;
  findingId?: string;
  /** True when matched articles describe a vulnerability without an assigned CVE (potential zero-day). */
  zeroDay?: boolean;
  /** Credibility score: source feed weight × keyword confidence (0–100). */
  credibilityScore?: number;
}
export const EVENT_CATEGORIES = [
  'PIPELINE',
  'FEED',
  'MATCHING',
  'EMAIL',
  'SYSTEM',
  'ISSUE',
  'EVENT',
] as const;
export interface OperationalEvent {
  id: string;
  timestamp: string;
  category: (typeof EVENT_CATEGORIES)[number];
  level: 'INFO' | 'WARNING' | 'ERROR';
  code: string;
  message: string;
  runId?: string;
  context: Record<string, unknown>;
  /** Correlation-worker metadata, present only on telemetry-sourced events. */
  trackingId?: string;
  /** Raw telemetry event name (dot-namespaced), distinct from the pipeline `code`. */
  event?: string;
  /** Worker-local sequence; restarts per process, so it orders within a writer only. */
  sequence?: number;
  ingestionLatencyMs?: number;
  extractionLatencyMs?: number;
  totalDatabaseTimeMs?: number;
  /** Retry attempt number for transient database failures. */
  attempt?: number;
}

export interface CVSSData {
  version: '3.0' | '3.1' | '4.0' | '2.0' | 'UNKNOWN';
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

export type VexStatus = 'affected' | 'not_affected' | 'fixed' | 'under_investigation';

/**
 * VEX statements can be scoped to a single product/CPE/PURL. An unscoped
 * statement applies to the whole advisory; a scoped statement only applies to
 * findings whose matched inventory falls inside the declared scope.
 */
export interface VexScope {
  cpe?: string;
  purl?: string;
  vendor?: string;
  product?: string;
}

export interface VexStatement {
  status: VexStatus;
  justification?: string;
  impactStatement?: string;
  /** Feed/provider that supplied the statement. */
  source?: string;
  /** Optional product/package scope. */
  scope?: VexScope;
  /**
   * Only signed statements may suppress alerts. Legacy statements without this
   * field are treated as signed for backward compatibility; ingestion marks
   * unsigned generic-feed claims explicitly.
   */
  signed?: boolean;
  timestamp?: string;
}

export type ExploitabilityConflictState =
  | 'NONE'
  | 'CONSISTENT'
  | 'CONFLICT'
  | 'EXPLOIT_INTELLIGENCE_OVERRIDE'
  | 'UNDER_INVESTIGATION'
  | 'SCOPE_MISMATCH';

/** Result of the per-source exploitability lattice for one finding scope. */
export interface ExploitabilityAssessment {
  status: VexStatus | 'unknown';
  conflictState: ExploitabilityConflictState;
  suppressed: boolean;
  requiresReview: boolean;
  reason: string;
  sources: string[];
  applicableStatements: number;
  ignoredStatements: number;
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
  vex?: VexStatement; // CSAF 2.0 VEX status (legacy single-statement form)
  /** Per-source VEX statements. Resolved through the exploitability lattice. */
  vexStatements?: VexStatement[];
  sourceFeeds: string[];
  exploitationSources?: string[];
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
  matchedAssetVendor?: string;
  matchedAssetProduct?: string;
  /** PURLs of the matched inventory item, used to scope VEX statements. */
  matchedAssetPurls?: string[];
  matchedCpe: string;
  matchingMethod: string;
  matchingEvidence: string;
  exposure?: ExposureLevel; // Deprecated
  exploitRisk: ExploitRiskLevel;
  /** Per-source VEX lattice result captured at correlation time. */
  exploitability?: ExploitabilityAssessment;
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
  requestTimeoutSeconds?: number;
  recoveryDelayMinutes?: number;
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
  circuitOpenUntil?: string | null;
}

/**
 * A single CPE 2.3 entry returned by the NVD CPE dictionary search. These are
 * NVD-maintained official CPE names offered as verified alternatives when an
 * operator registers a monitored product.
 */
export interface NvdCpeSearchResult {
  cpeName: string;
  cpeNameId: string;
  part: string;
  vendor: string;
  product: string;
  version: string;
  update: string;
  targetSw: string;
  targetHw: string;
  /** Human-readable title from the NVD CPE dictionary, when available. */
  title?: string;
}

export interface NvdCpeSearchResponse {
  results: NvdCpeSearchResult[];
  totalResults: number;
}

export interface ThreatSearchHit {
  cve: NormalizedCVE;
  /** CPE 2.3 strings that matched the requested vendor/product. */
  matchingCpes: string[];
  /** Origin of the result: `NVD_API` for the CVE Search API, `KEYWORD_FALLBACK` for keyword-search results. */
  source: 'NVD_API' | 'KEYWORD_FALLBACK';
}

export interface ThreatSearchResponse {
  hits: ThreatSearchHit[];
  totalResults: number;
  vendor: string;
  product: string;
  rateLimited: boolean;
  retryAfter?: number;
  /** Whether an NVD API key was loaded and supplied with the request. */
  apiKeyUsed: boolean;
  /** ISO date string (YYYY-MM-DD) the scan was constrained to, when a start date was supplied. */
  startDate?: string;
}

/** Granularity for the analytics timeline buckets. */
export type TimelineBucket = 'day' | 'week' | 'month';

/** Selectable time windows for the Threat Analytics & Trends timeline. */
export type TimelineRange = '7d' | '30d' | '90d' | '365d' | 'all';

export interface TimelinePoint {
  label: string;
  cveCount: number;
  critical: number;
  high: number;
}

export interface SeverityDistribution {
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown: number;
}

export interface ExploitStatusDistribution {
  activeWeaponized: number;
  reportedInWild: number;
  pocAvailable: number;
  none: number;
}

export interface VendorAnalytics {
  vendor: string;
  cveCount: number;
  critical: number;
  high: number;
}

export interface CveScoreBin {
  range: string;
  count: number;
}

export interface ThreatAnalytics {
  totalCves: number;
  kevCount: number;
  timeline: TimelinePoint[];
  severityDistribution: SeverityDistribution;
  exploitStatusDistribution: ExploitStatusDistribution;
  topVendors: VendorAnalytics[];
  cvssScoreHistogram: CveScoreBin[];
  generatedAt: string;
}

/** Classification tiers for the severity classifier. */
export type SeverityTier = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';

export interface SeverityClassification {
  tier: SeverityTier;
  score: number;
  vector: string;
  source: string;
  rationale: string[];
}

export interface CpeParseComponent {
  field: string;
  value: string;
  isWildcard: boolean;
  isAmbiguous: boolean;
}

export interface CpeParseResult {
  cpe: string;
  parsed: {
    prefix: string;
    part: string;
    vendor: string;
    product: string;
    version: string;
    update: string;
    edition: string;
    language: string;
    swEdition: string;
    targetSw: string;
    targetHw: string;
    other: string;
    raw: string;
    isValid: boolean;
  } | null;
  components: CpeParseComponent[];
  errors: string[];
}

export interface AliasExpansion {
  canonical: string;
  scope: 'VENDOR' | 'PRODUCT';
  matchedAliases: string[];
  builtInMatches: boolean;
  customMatches: boolean;
}

export interface FalsePositiveCheck {
  name: string;
  passed: boolean;
  severity: 'BLOCK' | 'WARN';
  detail: string;
}

export interface CpeMatchSimulation {
  assetCpe: CpeParseResult;
  vulnerabilityCpe: CpeParseResult;
  assetVendorAlias: AliasExpansion | null;
  assetProductAlias: AliasExpansion | null;
  match: {
    matched: boolean;
    method: string;
    confidence: number;
    viaAlias: boolean;
    evidence: string;
    reason?: string;
  };
  versionRangeCheck: {
    inRange: boolean;
    reason: string;
  } | null;
  falsePositiveChecks: FalsePositiveCheck[];
  severity: SeverityClassification | null;
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
  status: 'PENDING' | 'RUNNING' | 'SUCCESS' | 'WARNING' | 'FAILED' | 'CANCELLED';
  durationMs: number;
  details: string;
  metrics?: Record<string, string | number>;
}

export interface PipelineExecution {
  id: string;
  /** Human-friendly label for this run, e.g. `Run 3add6860`. Absent on legacy rows. */
  name?: string;
  startTime: string;
  endTime: string | null;
  status: 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'QUARANTINED' | 'CANCELLED';
  stopRequestedAt?: string;
  scopeHours: number;
  /** Use a successfully committed source checkpoint instead of rescanning the full lookback. */
  incrementalFeeds?: boolean;
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
    /** Findings held for the digest window; they are queued by the delivery worker. */
    digestBuffered?: number;
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

/** An operator-managed addition to the matching engine's vendor/product alias
 * thesaurus (see src/utils/cpeMatcher.ts DEFAULT_VENDOR_ALIASES/DEFAULT_PRODUCT_ALIASES
 * for the built-in, code-reviewed baseline this only adds on top of). */
export interface AliasEntry {
  id: string;
  /** Whether this maps vendor or product names. */
  scope: 'VENDOR' | 'PRODUCT';
  /** The normalized name a CVE's CPE/PURL vendor or product field actually uses. */
  canonical: string;
  /** Alternate names that should resolve to `canonical` during matching. */
  aliases: string[];
  notes?: string;
  createdAt: string;
  /** MANUAL rows are operator-managed. AUTO rows are derived from current
   * inventory/confirmed-correlation evidence and expire when that evidence
   * lapses. REVOKED rows are operator tombstones: they are never used for
   * matching and they block the automatic lifecycle from re-learning the
   * relation. */
  source?: 'MANUAL' | 'AUTO' | 'REVOKED';
  /** How an automatic relation was learned. Operator rows are `OPERATOR`. */
  provenance?: 'INVENTORY' | 'CONFIRMED_CORRELATION' | 'OPERATOR';
  /** First time the automatic relation was observed. */
  firstSeenAt?: string;
  /** Last time current inventory/correlation evidence supported the row. */
  lastSeenAt?: string;
  /** Automatic rows are retained until this time, then removed. */
  expiresAt?: string;
  /** Number of distinct confirmed findings supporting a learned relation. */
  evidenceCount?: number;
  /** Pairs blocked by an operator revocation. Only present on REVOKED rows. */
  revokedAliases?: string[];
  revokedAt?: string;
}

export interface EmailRecipient {
  id: string;
  name: string;
  email: string;
  role: string;
  /** Legacy recipients without a group continue to receive automatic delivery. */
  deliveryGroup?: 'SECURITY_TEAM' | 'EVERYONE';
  subscriptionTier: 'ALL_SEVERITIES' | 'CRITICAL_HIGH_ONLY' | 'CISA_KEV_ONLY';
  enabled: boolean;
  deliverySuccessRate: number;
  /** Opt a recipient into the daily digest (daily summary + health report) subscription. */
  dailyDigest?: boolean;
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
  provider:
    'Mailgun' | 'Mailtrap' | 'SendGrid' | 'Postmark' | 'Custom API' | 'SMTP_Relay' | 'Local_Mock' | 'Mailjet';
  status:
    'REVIEW_REQUIRED' | 'QUEUED' | 'ACCEPTED' | 'DELIVERED' | 'BOUNCED' | 'RETRYING' | 'FAILED' | 'CANCELLED';
  attemptCount: number;
  retrySchedule: string[];
  nextRetryTime: string | null;
  sentAt: string;
  errorMessage?: string;
}

export interface EmailQueueItem {
  id: string;
  recipientEmail: string;
  advisoryId: string;
  subject: string;
  status: 'REVIEW' | 'QUEUED' | 'SENDING' | 'FAILED';
  attempts: number;
  nextAttemptAt: string | null;
  createdAt: string;
  error: string | null;
  preview?: string;
  cveIds?: string[];
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

export const SMTP_EMAIL_PROVIDERS = [
  'SMTP_CUSTOM',
  'MAILEROO_SMTP',
  'LETTR_SMTP',
  'MAILJET_SMTP',
  'SENDGRID_SMTP',
] as const;
export const EMAIL_PROVIDERS = [
  'SMTP',
  'API',
  ...SMTP_EMAIL_PROVIDERS,
  'MAILGUN',
  'MAILTRAP',
  'SENDGRID',
  'POSTMARK',
  'MAILJET_API',
] as const;
export type EmailProvider = (typeof EMAIL_PROVIDERS)[number];
export const isSmtpEmailProvider = (provider: EmailProvider) =>
  provider === 'SMTP' || (SMTP_EMAIL_PROVIDERS as readonly string[]).includes(provider);
export interface EmailConfiguration {
  provider: EmailProvider;
  fromEmail: string;
  fromName: string;
  /** Encrypted in storage; always blank in browser state. */
  apiKey: string;
  hasApiKey?: boolean;
  /** Generic API transport settings. Secrets are encrypted in storage. */
  apiEndpoint: string;
  apiHeaderKey: string;
  apiAuthPrefix: string;
  apiSourceDomain: string;
  smtpHost: string;
  smtpPort: number;
  smtpSecurity: 'IMPLICIT_TLS' | 'STARTTLS';
  smtpUsername: string;
  /** Encrypted in storage; always blank in browser state. */
  smtpPassword: string;
  hasSmtpPassword?: boolean;
  hasMailjetApiSecret?: boolean;
  mailgunDomain: string;
  mailgunRegion: 'US' | 'EU';
  mailtrapMode: 'LIVE' | 'SANDBOX';
  mailtrapInboxId: string;
  postmarkMessageStream: string;
  mailjetApiSecret: string;
}

export interface RetentionConfig {
  enabled: boolean;
  retentionHours: number;
  cleanupIntervalMinutes: number;
  maxArchivedRecords: number;
  autoCleanup: boolean;
  retentionMode: 'strict' | 'rolling' | 'checkpoints';
}

/** Record kinds the retention policy is allowed to delete. */
export type RetentionKind = 'cveData' | 'intelligenceArticles' | 'emailLogs' | 'webhookLogs' | 'executions';

export interface RetentionRunResult {
  ranAt: string;
  mode: RetentionConfig['retentionMode'];
  retentionHours: number;
  cutoff: string;
  scanned: number;
  deleted: number;
  unknownAge: number;
  byKind: Record<RetentionKind, number>;
  /** Transient queue/event rows removed by the same policy window. */
  system?: { outbox: number; events: number };
}

export interface RetentionPreviewRow {
  total: number;
  past: number;
  deletable: number;
}

export interface RetentionPreview {
  cutoff: string;
  records: Record<RetentionKind, RetentionPreviewRow>;
  protected: { findings: number; advisories: number; auditLogs: number };
  scanned: number;
}

export interface CorrelationSimulationMatch {
  cve: NormalizedCVE;
  method: string;
  confidence: number;
  evidence: string;
  autoAction: string;
  suppressed: boolean;
  suppressionReason?: string;
}

/** Result of the read-only matching simulator. The server evaluates the full
 * CVE cache so the browser never has to download it to preview a match. */
export interface CorrelationSimulation {
  testedAt: string;
  matchedCves: CorrelationSimulationMatch[];
  totalScanned: number;
  aliasExpanded: boolean;
  intervalEvaluated: boolean;
}

export interface AppSettings {
  scopeHours: number;
  schedulerIntervalMinutes: number;
  schedulerEnabled: boolean;
  advisoryPrefix: string;
  autoDispatchEnabled: boolean;
  /**
   * Minimum confidence (0–100) required for a finding to auto-dispatch without
   * manual review. Set to 0 to dispatch all findings regardless of confidence.
   * The default (90) matches the previous hardcoded threshold.
   */
  autoDispatchConfidenceThreshold: number;
  digestBatchingEnabled: boolean;
  digestWindowMinutes: number;
  /**
   * Durable retry policy for transient email transport failures. Retry is
   * enabled by default so a provider outage does not silently drop an alert.
   */
  emailRetryEnabled: boolean;
  /** Total delivery attempts, including the first send. */
  emailRetryMaxAttempts: number;
  /** Delay before the second attempt; doubles on each subsequent retry. */
  emailRetryInitialDelayMinutes: number;
  /** Upper bound for the exponential backoff delay. */
  emailRetryMaxDelayMinutes: number;
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
  /**
   * Operational logging detail level.
   *  - `standard`: lifecycle and security-relevant events only; the correlation
   *    worker's per-advisory telemetry is dropped at the source, so the table
   *    stays small and fast to search during an incident.
   *  - `verbose`: every correlation telemetry entry is persisted, including
   *    per-advisory extraction and database timings, for deep forensics.
   * Enforced server-side: selecting `standard` stops the rows being written at
   * all, rather than hiding them from the viewer after the fact.
   */
  logVerbosity: 'standard' | 'verbose';
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
  retentionConfig: RetentionConfig;
  /**
   * IANA timezone identifier (e.g. `America/New_York`) used for scheduling the
   * daily digest and for formatting human-readable dates server-side and client-side.
   * Defaults to `UTC`; an invalid value falls back to `UTC` at runtime.
   */
  timezone: string;
  /**
   * Daily digest subscription: a daily summary of findings plus an operational
   * health-check report sent to recipients that opt in, at `time` in `timezone`.
   */
  dailyDigest: {
    enabled: boolean;
    /** `HH:mm` 24h, e.g. `09:00`. */
    time: string;
    /** Include a server health-check snapshot in the daily report. */
    includeHealthReport: boolean;
  };
}

export interface SystemHealth {
  database: string;
  databaseLatencyMs: number;
  uptimeSeconds: number;
  heapBytes: number;
  workerEnabled: boolean;
  workerHeartbeat: string | null;
  workerStatus: 'DISABLED' | 'NOT_OBSERVED' | 'STALE' | 'HEALTHY';
  heartbeatAgeSeconds: number | null;
  deliveryQueue: {
    dueJobs: number;
    oldestDueCreatedAt: string | null;
    nextScheduledAttempt: string | null;
    expiredLeases: number;
  };
  lastScheduledRun: string | null;
  backlog: { status: string; count: number }[];
  emailProvider: string;
  emailConfigured: boolean;
  httpsRequired: boolean;
  csrfEnforced: boolean;
  ssrfEnforced: boolean;
  ntp: string;
  checkedAt: string;
}
