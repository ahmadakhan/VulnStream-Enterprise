import type {
  AppSettings,
  ThreatFeed,
  WatchListItem,
  NormalizedCVE,
  Finding,
  Advisory,
  AlertedCVE,
  EmailRecipient,
  WebhookEndpoint,
  WebhookDeliveryLog,
  EmailDeliveryLog,
  AuditLog,
  PipelineExecution,
  TemplateCustomization,
  EmailConfiguration,
  IntelligenceArticle,
  IntelligenceMatch,
  AliasEntry,
} from '../src/types/index.ts';
import { DEFAULT_TEMPLATE_CUSTOMIZATION, compileCustomizedTemplate } from '../src/utils/templateCompiler.ts';
export const DEFAULT_EMAIL_CONFIG: EmailConfiguration = {
  provider: 'SMTP', fromEmail: '', fromName: 'VulnStream', apiKey: '',
  apiEndpoint: '', apiHeaderKey: 'Authorization', apiAuthPrefix: 'Bearer', apiSourceDomain: '',
  smtpHost: '', smtpPort: 587, smtpSecurity: 'STARTTLS', smtpUsername: '', smtpPassword: '',
  mailgunDomain: '', mailgunRegion: 'US', mailtrapMode: 'LIVE', mailtrapInboxId: '',
  postmarkMessageStream: 'outbound',
};
export const DEFAULT_SETTINGS: AppSettings = {
  scopeHours: 24,
  schedulerIntervalMinutes: 60,
  schedulerEnabled: false,
  advisoryPrefix: 'ADV-',
  autoDispatchEnabled: false,
  digestBatchingEnabled: false,
  digestWindowMinutes: 5,
  webhookSigningSecret: '',
  authorityPrecedence: ['VENDOR_PSIRT', 'CISA_KEV', 'FIRST_EPSS', 'NVD_BATCH'],
  ssrfProtection: { blockPrivateIps: true, blockLoopback: true, allowRedirects: false },
  securityPolicy: {
    sessionTimeoutMins: 30,
    csrfProtection: true,
    minPasswordLen: 14,
    maxLoginAttempts: 5,
    lockoutMins: 15,
  },
  ntpConfig: { enabled: false, server: '', driftToleranceMs: 50 },
  mailgunConfig: { enabled: false, apiKey: '', domain: '', fromEmail: '' },
  retentionConfig: {
    enabled: false,
    retentionHours: 24,
    cleanupIntervalMinutes: 60,
    maxArchivedRecords: 10000,
    autoCleanup: true,
    retentionMode: 'rolling',
  },
};
export interface AppState {
  feeds: ThreatFeed[];
  watchlist: WatchListItem[];
  cveData: NormalizedCVE[];
  findings: Finding[];
  advisories: Advisory[];
  alertedCves: AlertedCVE[];
  recipients: EmailRecipient[];
  webhooks: WebhookEndpoint[];
  webhookLogs: WebhookDeliveryLog[];
  emailLogs: EmailDeliveryLog[];
  auditLogs: AuditLog[];
  executions: PipelineExecution[];
  settings: AppSettings;
  emailConfig: EmailConfiguration;
  intelligenceArticles: IntelligenceArticle[];
  intelligenceMatches: IntelligenceMatch[];
  templateCustomization: TemplateCustomization;
  advisoryTemplate: string;
  aliases: AliasEntry[];
}
export const emptyState = (): AppState => ({
  feeds: [],
  intelligenceArticles: [],
  intelligenceMatches: [],
  watchlist: [],
  cveData: [],
  findings: [],
  advisories: [],
  alertedCves: [],
  recipients: [],
  webhooks: [],
  webhookLogs: [],
  emailLogs: [],
  auditLogs: [],
  executions: [],
  aliases: [],
  settings: structuredClone(DEFAULT_SETTINGS),
  emailConfig: { ...DEFAULT_EMAIL_CONFIG },
  templateCustomization: { ...DEFAULT_TEMPLATE_CUSTOMIZATION },
  advisoryTemplate: compileCustomizedTemplate(DEFAULT_TEMPLATE_CUSTOMIZATION),
});
export type Role = 'ADMIN' | 'OPERATOR' | 'VIEWER';
export interface SessionInfo {
  username: string;
  role: Role;
  csrfToken: string;
  expiresAt: string;
}
