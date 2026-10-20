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
} from '../src/types';
import { DEFAULT_TEMPLATE_CUSTOMIZATION, compileCustomizedTemplate } from '../src/utils/templateCompiler';
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
  templateCustomization: TemplateCustomization;
  advisoryTemplate: string;
}
export const emptyState = (): AppState => ({
  feeds: [],
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
  settings: structuredClone(DEFAULT_SETTINGS),
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
