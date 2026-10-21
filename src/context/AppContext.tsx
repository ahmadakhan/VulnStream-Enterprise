import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { emptyState, type AppState, type SessionInfo } from '../../shared/state';
import type {
  ThreatFeed,
  WatchListItem,
  NormalizedCVE,
  Finding,
  Advisory,
  EmailRecipient,
  WebhookEndpoint,
  TemplateCustomization,
  AppSettings,
  PipelineExecution,
  AuditLog,
} from '../types';
import { compileCustomizedTemplate } from '../utils/templateCompiler';
function useApplication() {
  const [snapshot, setSnapshot] = useState<AppState>(emptyState);
  const [session, setSession] = useState<SessionInfo | null>(null),
    [loading, setLoading] = useState(true),
    [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState('dashboard'),
    [mobileNavOpen, setMobileNavOpen] = useState(false),
    [selectedFinding, setSelectedFinding] = useState<Finding | null>(null),
    [selectedAdvisory, setSelectedAdvisory] = useState<Advisory | null>(null);
  const [theme, setTheme] = useState<'dark' | 'light'>(() => {
    try {
      return localStorage.getItem('vulnstream_theme') === 'light' ? 'light' : 'dark';
    } catch {
      return 'dark';
    }
  });
  const [clock, setClock] = useState(Date.now()),
    [draft, setDraft] = useState<TemplateCustomization | null>(null),
    [pending, setPending] = useState(0);
  const sessionRef = useRef(session);
  sessionRef.current = session;
  const request = useCallback(
    async <T,>(url: string, body?: unknown, method = body === undefined ? 'GET' : 'POST'): Promise<T> => {
      const response = await fetch(`/api${url}`, {
        method,
        credentials: 'same-origin',
        headers: {
          'content-type': 'application/json',
          ...(sessionRef.current ? { 'x-csrf-token': sessionRef.current.csrfToken } : {}),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(30000),
      });
      const data = await response
        .json()
        .catch(() => ({ error: `Server returned an empty or non-JSON response (HTTP ${response.status})` }));
      if (!response.ok) {
        if (response.status === 401) {
          setSession(null);
          setSnapshot(emptyState());
        }
        throw new Error(
          data.error === 'Validation failed'
            ? `${data.error}: ${(data.details || []).map((d: any) => d.path.join('.') + ': ' + d.message).join('; ')}`
            : data.error || 'Request failed',
        );
      }
      return data;
    },
    [],
  );
  const refresh = useCallback(async () => setSnapshot(await request<AppState>('/state')), [request]);
  const safely = useCallback(async <T,>(fn: () => Promise<T>): Promise<T | undefined> => {
    setPending((p) => p + 1);
    try {
      setError(null);
      return await fn();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Operation failed');
      return undefined;
    } finally {
      setPending((p) => p - 1);
    }
  }, []);
  useEffect(() => {
    let mounted = true;
    request<SessionInfo>('/session')
      .then(async (value) => {
        if (mounted) {
          setSession(value);
          sessionRef.current = value;
          await refresh();
        }
      })
      .catch((e) => {
        if (mounted && e.message !== 'Authentication required' && e.message !== 'Session expired')
          setError(e.message);
      })
      .finally(() => {
        if (mounted) setLoading(false);
      });
    return () => {
      mounted = false;
    };
  }, [request, refresh]);
  useEffect(() => {
    if (!session) return;
    const timer = setInterval(() => {
      setClock(Date.now());
      if (sessionRef.current && Date.now() >= new Date(sessionRef.current.expiresAt).getTime()) {
        setSession(null);
        setSnapshot(emptyState());
      }
    }, 1000);
    return () => clearInterval(timer);
  }, [session]);
  useEffect(() => {
    if (!session) return;
    let active = true;
    const timer = setInterval(() => {
      if (active) void refresh().catch((e) => setError(e.message));
    }, 5000);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [!!session, refresh]);
  useEffect(() => {
    document.documentElement.classList.toggle('dark', theme === 'dark');
    document.documentElement.classList.toggle('light', theme === 'light');
    try {
      localStorage.setItem('vulnstream_theme', theme);
    } catch {}
  }, [theme]);
  const login = async (username: string, password: string) =>
    safely(async () => {
      const info = await request<SessionInfo>('/login', { username, password });
      sessionRef.current = info;
      setSession(info);
      await refresh();
      return true;
    });
  const logout = async () =>
    safely(async () => {
      await request('/logout', {});
      sessionRef.current = null;
      setSession(null);
      setSnapshot(emptyState());
      setDraft(null);
    });
  const command = async (action: string, data?: unknown, id?: string) =>
    safely(async () => {
      const result = await request<any>('/commands', { action, data, id });
      await refresh();
      return result;
    });
  const save = async (action: string, data: unknown, id?: string) => !!(await command(action, data, id));
  const call = async <T,>(url: string, body: unknown = {}) =>
    safely(async () => {
      const result = await request<T>(url, body);
      await refresh();
      return result;
    });
  const activeExecution = snapshot.executions.find((e) => ['RUNNING', 'QUEUED'].includes(e.status));
  const customization = draft || snapshot.templateCustomization;
  return {
    ...snapshot,
    activeTab,
    setActiveTab: (tab: string) => {
      setActiveTab(tab);
      setMobileNavOpen(false);
    },
    mobileNavOpen,
    setMobileNavOpen,
    theme,
    toggleTheme: () => setTheme((t) => (t === 'dark' ? 'light' : 'dark')),
    session,
    loading,
    error,
    clearError: () => setError(null),
    pending,
    login,
    logout,
    refresh,
    selectedFinding: snapshot.findings.find((f) => f.id === selectedFinding?.id) || selectedFinding,
    setSelectedFinding,
    selectedAdvisory,
    setSelectedAdvisory,
    csrfToken: session?.csrfToken || '',
    sessionTimeRemainingSec: session
      ? Math.max(0, Math.floor((new Date(session.expiresAt).getTime() - clock) / 1000))
      : 0,
    resetSessionTimeout: () =>
      safely(async () => {
        const result = await request<{ expiresAt: string }>('/session/renew', {});
        setSession((s) => (s ? { ...s, expiresAt: result.expiresAt } : null));
      }),
    changePassword: (currentPassword: string, newPassword: string) =>
      safely(async () => {
        await request('/password', { currentPassword, newPassword });
        setSession(null);
        setSnapshot(emptyState());
        return true;
      }),
    listUsers: () => safely(() => request<any[]>('/users')),
    createUser: (data: { username: string; password: string; role: string }) =>
      safely(() => request('/users', data)),
    updateUser: (id: string, data: { role: string; disabled: boolean }) =>
      safely(() => request(`/users/${encodeURIComponent(id)}`, data, 'PATCH')),
    health: () => safely(() => request<any>('/health')),
    ntpSyncStatus: { synchronized: false, driftMs: 0, lastChecked: '' },
    toggleFeedEnabled: (id: string) => command('feed.toggle', undefined, id),
    addFeed: (
      feed: Omit<
        ThreatFeed,
        'id' | 'healthStatus' | 'lastSync' | 'latencyMs' | 'itemCountLastRun' | 'ssrfValidated'
      >,
    ) => save('feed.save', feed),
    updateFeed: (feed: ThreatFeed) => save('feed.save', feed, feed.id),
    deleteFeed: (id: string) => command('feed.delete', undefined, id),
    testFeedConnectivity: async (id: string) =>
      (await call<{ success: boolean; latency: number; error?: string }>(
        `/feeds/${encodeURIComponent(id)}/test`,
      )) || { success: false, latency: 0, error: 'Connectivity test failed' },
    addWatchlistItem: (item: Omit<WatchListItem, 'id' | 'createdAt'>) => save('asset.save', item),
    updateWatchlistItem: (item: WatchListItem) => save('asset.save', item, item.id),
    deleteWatchlistItem: (id: string) => command('asset.delete', undefined, id),
    bulkImportWatchlist: async (items: unknown[]) =>
      (await command('asset.import', items)) || {
        imported: 0,
        errors: ['Import failed. See the error banner.'],
      },
    addCustomCve: (cve: NormalizedCVE) => save('cve.save', cve),
    updateFindingStatus: (id: string, status: Finding['status'], note?: string) =>
      command('finding.status', { status, note }, id),
    addRecipient: (rec: Omit<EmailRecipient, 'id' | 'deliverySuccessRate'>) => save('recipient.save', rec),
    toggleRecipientEnabled: (id: string) => command('recipient.toggle', undefined, id),
    deleteRecipient: (id: string) => command('recipient.delete', undefined, id),
    addWebhook: (hook: Omit<WebhookEndpoint, 'id' | 'deliveryCount'>) => save('webhook.save', hook),
    toggleWebhookEnabled: (id: string) => command('webhook.toggle', undefined, id),
    deleteWebhook: (id: string) => command('webhook.delete', undefined, id),
    testWebhook: async (id: string) =>
      (await call<{ success: boolean; statusCode: number; signature: string }>(
        `/webhooks/${encodeURIComponent(id)}/test`,
      )) || { success: false, statusCode: 0, signature: '' },
    resendNotification: (cveId: string, reason: string) => call('/resend', { cveId, reason }),
    retryEmailDelivery: (id: string) => call(`/email/${encodeURIComponent(id)}/retry`),
    isPipelineRunning: !!activeExecution,
    currentPipelinePhase: activeExecution ? `${activeExecution.status}: ${activeExecution.id}` : null,
    latestExecution: snapshot.executions[0] || null,
    triggerPipelineRun: async (scopeHours?: number) =>
      (await call<PipelineExecution>('/pipeline', { scopeHours })) || null,
    templateCustomization: customization,
    advisoryTemplate: draft ? compileCustomizedTemplate(draft) : snapshot.advisoryTemplate,
    updateTemplateCustomization: (update: Partial<TemplateCustomization>) =>
      setDraft((prev) => ({ ...snapshot.templateCustomization, ...prev, ...update })),
    saveTemplate: async () => {
      const success = await save('template.save', { templateCustomization: customization });
      if (success) setDraft(null);
      return success;
    },
    setAdvisoryTemplate: (advisoryTemplate: string) => save('template.save', { advisoryTemplate }),
    sendTestEmail: async (email: string) =>
      (await call<{ success: boolean; message: string }>('/test-email', { email })) || {
        success: false,
        message: 'Test could not be queued; see the error banner.',
      },
    updateSettings: (settings: Partial<AppSettings>) => save('settings.save', settings),
    // Audit events are recorded by server operations, never accepted as client claims.
    addAuditLog: (
      _category: AuditLog['category'],
      _level: AuditLog['level'],
      _event: string,
      _details: string,
    ) => {},
  };
}
type AppContextType = ReturnType<typeof useApplication>;
const AppContext = createContext<AppContextType | undefined>(undefined);
export const AppProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <AppContext.Provider value={useApplication()}>{children}</AppContext.Provider>
);
export function useApp() {
  const value = useContext(AppContext);
  if (!value) throw new Error('useApp requires AppProvider');
  return value;
}
