import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { emptyState, type AppState, type SessionInfo, type CollectionKind, type CollectionPage } from '../../shared/state';
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
  EmailQueueItem,
   AliasEntry,
  RetentionRunResult,
  RetentionPreview,
  CorrelationSimulation,
  NvdCpeSearchResponse,
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
    [refreshVersion, setRefreshVersion] = useState(0),
    [pending, setPending] = useState(0);
  const sessionRef = useRef(session);
  sessionRef.current = session;
  // Monotonic id so an older snapshot response can never overwrite a newer one.
  const refreshId = useRef(0);
  const request = useCallback(
    async <T,>(url: string, body?: unknown, method = body === undefined ? 'GET' : 'POST'): Promise<T> => {
      let response: Response;
      for (let attempt = 0; ; attempt++) {
        response = await fetch(`/api${url}`, {
          method,
          credentials: 'same-origin',
          headers: {
            'content-type': 'application/json',
            ...(sessionRef.current ? { 'x-csrf-token': sessionRef.current.csrfToken } : {}),
          },
          body: body === undefined ? undefined : JSON.stringify(body),
          signal: AbortSignal.timeout(30000),
        });
        // Retry transient gateway errors only for idempotent state reads.
        if (method !== 'GET' || ![502, 503, 504].includes(response.status) || attempt >= 2) break;
        await new Promise((resolve) => setTimeout(resolve, 250 * 2 ** attempt));
      }
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
  const refresh = useCallback(async () => {
    const id = ++refreshId.current;
    let next: AppState;
    try {
      next = await request<AppState>('/state');
    } catch (error) {
      // A stale request that failed after a newer refresh succeeded must not
      // surface an error banner for state that is already current.
      if (refreshId.current !== id) return;
      throw error;
    }
    // Concurrent polls and post-mutation refreshes can resolve out of order.
    // Apply only the newest request so a slow response cannot roll state back.
    if (refreshId.current !== id) return;
    setSnapshot(next);
    // Signals bounded collection views to refetch their current page after a
    // mutation or poll, without duplicating heavy collections in the snapshot.
    setRefreshVersion((value) => value + 1);
  }, [request]);
  const fetchCollection = useCallback(
    <T,>(
      kind: CollectionKind,
      query: {
        page?: number;
        pageSize?: number;
        search?: string;
        sort?: string;
        order?: 'asc' | 'desc';
        filters?: Record<string, unknown>;
      } = {},
    ): Promise<CollectionPage<T>> => {
      const page = Math.max(1, Math.floor(query.page ?? 1));
      const pageSize = Math.max(1, Math.floor(query.pageSize ?? 50));
      const params = new URLSearchParams({
        limit: String(pageSize),
        offset: String((page - 1) * pageSize),
      });
      if (query.search) params.set('search', query.search);
      if (query.sort) params.set('sort', query.sort);
      if (query.order) params.set('order', query.order);
      for (const [key, value] of Object.entries(query.filters ?? {})) {
        if (value === undefined || value === null || value === '' || value === 'ALL') continue;
        if (Array.isArray(value)) {
          if (value.length) params.set(key, value.join(','));
        } else params.set(key, String(value));
      }
      return request<CollectionPage<T>>(`/collections/${encodeURIComponent(kind)}?${params}`);
    },
    [request],
  );
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
    const poll = () => {
      // Idle background tabs do not need the full snapshot every ten seconds.
      // Refresh immediately when the tab becomes visible again.
      if (active && document.visibilityState !== 'hidden')
        void refresh().catch((e) => setError(e.message));
    };
    const timer = setInterval(poll, 10000);
    const onVisibility = () => {
      if (document.visibilityState === 'visible') poll();
    };
    document.addEventListener('visibilitychange', onVisibility);
    return () => {
      active = false;
      clearInterval(timer);
      document.removeEventListener('visibilitychange', onVisibility);
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
      return result;
    });
  // A committed mutation is a success even if the follow-up snapshot refresh
  // fails. Surface the stale snapshot separately so destructive actions are not
  // retried blindly because of a transient GET failure.
  const refreshAfterMutation = async () => {
    try {
      await refresh();
    } catch (error) {
      setError(error instanceof Error ? error.message : 'State refresh failed');
    }
  };
  const save = async (action: string, data: unknown, id?: string) => {
    const saved = !!(await command(action, data, id));
    if (saved) await refreshAfterMutation();
    return saved;
  };
  const call = async <T,>(url: string, body: unknown = {}, method = 'POST') =>
    safely(async () => {
      const result = await request<T>(url, body, method);
      await refreshAfterMutation();
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
    refreshVersion,
    fetchCollection,
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
    fetchEvents: (query: string) =>
      request<{ events: import('../types').OperationalEvent[]; nextCursor: string | null }>(
        `/events?${query}`,
      ),
    health: () => safely(() => request<SystemHealth>('/health')),
    ntpSyncStatus: { synchronized: false, driftMs: 0, lastChecked: '' },
    toggleFeedEnabled: async (id: string) => {
      const result = await command('feed.toggle', undefined, id);
      if (result?.success) await refreshAfterMutation();
      return result?.success || false;
    },
    addFeed: (
      feed: Omit<
        ThreatFeed,
        'id' | 'healthStatus' | 'lastSync' | 'latencyMs' | 'itemCountLastRun' | 'ssrfValidated'
      >,
    ) => save('feed.save', feed),
    updateFeed: (feed: ThreatFeed) => save('feed.save', feed, feed.id),
    deleteFeed: async (id: string) => {
      const result = await command('feed.delete', undefined, id);
      if (result?.success) await refreshAfterMutation();
      return result?.success || false;
    },
    testFeedConnectivity: async (id: string) =>
      (await call<{ success: boolean; latency: number; error?: string }>(
        `/feeds/${encodeURIComponent(id)}/test`,
      )) || { success: false, latency: 0, error: 'Connectivity test failed' },
    runRetentionCleanup: () => call<RetentionRunResult>('/retention/run'),
    previewRetention: (policy: {
      enabled: boolean;
      retentionHours: number;
      maxArchivedRecords: number;
      retentionMode: 'strict' | 'rolling' | 'checkpoints';
    }) => safely(() => request<RetentionPreview>('/retention/preview', policy)),
    verifyAuditChainRemote: () => safely(() => request<{ verified: boolean }>('/audit/verify')),
    simulateCorrelation: (asset: {
      vendor: string;
      product: string;
      version?: string;
      cpes: string[];
      purls?: string[];
      targetHw?: string;
      assetTag?: string;
    }) => safely(() => request<CorrelationSimulation>('/correlation/simulate', asset)),
     addWatchlistItem: (item: Omit<WatchListItem, 'id' | 'createdAt'>) => save('asset.save', item),
    updateWatchlistItem: (item: WatchListItem) => save('asset.save', item, item.id),
    searchNvdCpes: async (vendor: string, product: string, limit = 50) => {
      const params = new URLSearchParams({ vendor, product, limit: String(limit) });
      return request<NvdCpeSearchResponse>(`/cpes/search?${params}`);
    },
    toggleWatchlistItemActive: async (id: string) => {
      const updated = !!(await command('asset.toggle', undefined, id));
      if (updated) await refreshAfterMutation();
      return updated;
    },
    deleteWatchlistItem: async (id: string) => {
      const result = await command('asset.delete', undefined, id);
      if (result?.success) await refreshAfterMutation();
      return result?.success || false;
    },
    bulkImportWatchlist: async (items: unknown[]) => {
      const result = await command('asset.import', items);
      if (result && !result.errors?.length) await refreshAfterMutation();
      return result || { imported: 0, errors: ['Import failed. See the error banner.'] };
    },
    addCustomCve: (cve: NormalizedCVE) => save('cve.save', cve),
    updateFindingStatus: async (id: string, status: Finding['status'], note?: string) => {
      const result = await command('finding.status', { status, note }, id);
      if (result?.success) await refreshAfterMutation();
      return result;
    },
    addRecipient: (rec: Omit<EmailRecipient, 'id' | 'deliverySuccessRate'>) => save('recipient.save', rec),
    toggleRecipientEnabled: async (id: string) => {
      const updated = !!(await command('recipient.toggle', undefined, id));
      if (updated) await refreshAfterMutation();
      return updated;
    },
    deleteRecipient: async (id: string) => {
      const result = await command('recipient.delete', undefined, id);
      if (result?.success) await refreshAfterMutation();
      return result?.success || false;
    },
    addWebhook: (hook: Omit<WebhookEndpoint, 'id' | 'deliveryCount'>) => save('webhook.save', hook),
    toggleWebhookEnabled: async (id: string) => {
      const updated = !!(await command('webhook.toggle', undefined, id));
      if (updated) await refreshAfterMutation();
      return updated;
    },
    deleteWebhook: async (id: string) => {
      const result = await command('webhook.delete', undefined, id);
      if (result?.success) await refreshAfterMutation();
      return result?.success || false;
    },
    testWebhook: async (id: string) =>
      (await call<{ success: boolean; statusCode: number; signature: string }>(
        `/webhooks/${encodeURIComponent(id)}/test`,
      )) || { success: false, statusCode: 0, signature: '' },
    addAlias: (entry: Omit<AliasEntry, 'id' | 'createdAt'>) => save('alias.save', entry),
    updateAlias: (entry: AliasEntry) => save('alias.save', entry, entry.id),
    deleteAlias: async (id: string) => {
      const result = await command('alias.delete', undefined, id);
      if (result?.success) await refreshAfterMutation();
      return result?.success || false;
    },
    promoteAlias: async (id: string) => {
      const result = await command('alias.promote', undefined, id);
      if (result?.success) await refreshAfterMutation();
      return result?.success || false;
    },
    revokeAlias: async (id: string) => {
      const result = await command('alias.revoke', undefined, id);
      if (result?.success) await refreshAfterMutation();
      return result?.success || false;
    },
    resendNotification: (cveId: string, reason: string) => call('/resend', { cveId, reason }),
    retryEmailDelivery: (id: string) => call(`/email/${encodeURIComponent(id)}/retry`),
    approveEmailDelivery: (id: string) => call(`/email/${encodeURIComponent(id)}/approve`),
    rejectEmailDelivery: (id: string) => call(`/email/${encodeURIComponent(id)}/reject`),
    listEmailQueue: () => safely(() => request<EmailQueueItem[]>('/email-queue')),
    deleteEmailQueueItem: (id: string) => call(`/email/${encodeURIComponent(id)}`, {}, 'DELETE'),
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
