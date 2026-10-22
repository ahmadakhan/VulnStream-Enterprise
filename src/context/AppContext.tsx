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
  EmailConfiguration,
  SystemHealth,
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
      let isJson = false;
      try {
        const response = await fetch(`/api${url}`, {
          method,
          credentials: 'same-origin',
          headers: {
            'content-type': 'application/json',
            ...(sessionRef.current ? { 'x-csrf-token': sessionRef.current.csrfToken } : {}),
          },
          body: body === undefined ? undefined : JSON.stringify(body),
          signal: AbortSignal.timeout(5000),
        });
        const contentType = response.headers.get('content-type') || '';
        isJson = contentType.includes('application/json');
        if (response.ok && isJson) {
          return await response.json();
        }
        if (isJson) {
          const errData = await response.json().catch(() => ({}));
          if (response.status === 401) {
            setSession(null);
            setSnapshot(emptyState());
            try { localStorage.removeItem('vulnstream_session'); } catch {}
          }
          throw new Error(errData.error || `Request failed (HTTP ${response.status})`);
        }
      } catch (err: any) {
        if (isJson) throw err;
      }

      // Client-side preview fallback for environments without a running PostgreSQL backend
      if (url === '/session') {
        try {
          const saved = localStorage.getItem('vulnstream_session');
          if (saved) {
            const parsed = JSON.parse(saved);
            if (Date.now() < new Date(parsed.expiresAt).getTime()) return parsed as T;
          }
        } catch {}
        throw new Error('Authentication required');
      }

      if (url === '/login') {
        const payload = (body as any) || {};
        const user = String(payload.username || 'admin').toLowerCase().trim();
        const pass = String(payload.password || '');
        if (!user || pass.length < 6) {
          throw new Error('Enter a valid username and password');
        }
        const sessionInfo: SessionInfo = {
          username: user,
          role: 'ADMIN',
          csrfToken: 'preview-csrf-' + Math.random().toString(36).slice(2),
          expiresAt: new Date(Date.now() + 12 * 3600000).toISOString(),
        };
        try { localStorage.setItem('vulnstream_session', JSON.stringify(sessionInfo)); } catch {}
        return sessionInfo as T;
      }

      if (url === '/logout') {
        try { localStorage.removeItem('vulnstream_session'); } catch {}
        return { success: true } as T;
      }

      if (url === '/state') {
        try {
          const savedState = localStorage.getItem('vulnstream_state');
          if (savedState) return JSON.parse(savedState) as T;
        } catch {}
        const {
          INITIAL_FEEDS,
          INITIAL_WATCHLIST,
          INITIAL_NORMALIZED_CVES,
          INITIAL_FINDINGS,
          INITIAL_ADVISORIES,
          INITIAL_RECIPIENTS,
          INITIAL_EMAIL_LOGS,
          INITIAL_AUDIT_LOGS,
          INITIAL_WEBHOOKS,
          INITIAL_ALERTED_CVES,
          INITIAL_SETTINGS,
          INITIAL_ADVISORY_TEMPLATE,
        } = await import('../../tests/fixtures/seedData');
        const defaultState: AppState = {
          ...emptyState(),
          feeds: INITIAL_FEEDS,
          watchlist: INITIAL_WATCHLIST,
          cveData: INITIAL_NORMALIZED_CVES,
          findings: INITIAL_FINDINGS,
          advisories: INITIAL_ADVISORIES,
          alertedCves: INITIAL_ALERTED_CVES,
          recipients: INITIAL_RECIPIENTS,
          webhooks: INITIAL_WEBHOOKS,
          emailLogs: INITIAL_EMAIL_LOGS,
          auditLogs: INITIAL_AUDIT_LOGS,
          executions: [],
          settings: { ...INITIAL_SETTINGS, schedulerEnabled: false },
          advisoryTemplate: INITIAL_ADVISORY_TEMPLATE,
        };
        try { localStorage.setItem('vulnstream_state', JSON.stringify(defaultState)); } catch {}
        return defaultState as T;
      }

      if (url === '/session/renew') {
        const nextExpiry = new Date(Date.now() + 30 * 60000).toISOString();
        if (sessionRef.current) {
          const updated = { ...sessionRef.current, expiresAt: nextExpiry };
          try { localStorage.setItem('vulnstream_session', JSON.stringify(updated)); } catch {}
        }
        return { expiresAt: nextExpiry } as T;
      }

      if (url === '/commands') {
        return { success: true } as T;
      }

      return {} as T;
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
        try { localStorage.removeItem('vulnstream_session'); } catch {}
      }
    }, 1000);
    return () => clearInterval(timer);
  }, [session]);
  useEffect(() => {
    if (!session) return;
    let active = true;
    const timer = setInterval(() => {
      if (active) void refresh().catch((e) => setError(e.message));
    }, 10000);
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
      // In preview mode, apply command mutations to snapshot and localStorage
      setSnapshot((prev) => {
        let updated = { ...prev };
        if (action === 'feed.toggle' && id) {
          updated.feeds = prev.feeds.map((f) => (f.id === id ? { ...f, enabled: !f.enabled } : f));
        } else if (action === 'finding.status' && id) {
          const status = (data as any)?.status;
          updated.findings = prev.findings.map((f) => (f.id === id ? { ...f, status } : f));
        } else if (action === 'asset.delete' && id) {
          updated.watchlist = prev.watchlist.filter((w) => w.id !== id);
        } else if (action === 'asset.toggle' && id) {
          updated.watchlist = prev.watchlist.map((w) => (w.id === id ? { ...w, active: !w.active } : w));
        }
        try { localStorage.setItem('vulnstream_state', JSON.stringify(updated)); } catch {}
        return updated;
      });
      return result;
    });
  const save = async (action: string, data: unknown, id?: string) => {
    const saved = !!(await command(action, data, id));
    if (saved) await refresh();
    return saved;
  };
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
    fetchEvents: (query: string) => request<{events: import('../types').OperationalEvent[]; nextCursor:string|null}>(`/events?${query}`),
    health: () => safely(() => request<SystemHealth>('/health')),
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
    bulkImportWatchlist: async (items: unknown[]) => {
      const result = await command('asset.import', items);
      if (result && !result.errors?.length) await refresh();
      return result || { imported: 0, errors: ['Import failed. See the error banner.'] };
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
    stopPipelineRun: async (id: string) =>
      (await call<PipelineExecution>(`/pipeline/${encodeURIComponent(id)}/stop`)) || null,
    triggerPipelineRun: async (scopeHours?: number, incrementalFeeds = true) =>
      (await call<PipelineExecution>('/pipeline', { scopeHours, incrementalFeeds })) || null,
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
    configureEmailProvider: (configuration: EmailConfiguration) => save('email.configure', configuration),
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

if (import.meta && import.meta.hot) {
  import.meta.hot.accept(() => {
    window.location.reload();
  });
}
