import { PageHeading } from './PageHeading';
import React, { useState, useEffect } from 'react';
import { useApp } from '../context/AppContext';
import { EVENT_CATEGORIES, OperationalEvent, AuditLog } from '../types';
import {
  FileCode2,
  Search,
  Download,
  Filter,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  RotateCw,
  Cpu,
  LogOut,
} from 'lucide-react';
import { Pagination } from './Pagination';
import { csvCell } from '../utils/csv';
import { useCollection } from '../hooks/useCollection';
import { LogDetailModal } from './LogDetailModal';
import { formatEventContext } from '../utils/eventText';

const AuditTrailView: React.FC = () => {
  const { fetchCollection, refreshVersion, verifyAuditChainRemote } = useApp();
  const [searchTerm, setSearchTerm] = useState('');
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');
  const [levelFilter, setLevelFilter] = useState<string>('ALL');
  const [selectedLog, setSelectedLog] = useState<AuditLog | null>(null);

  // Cryptographic Chain Verification State
  const [verifyingChain, setVerifyingChain] = useState(false);
  const [chainVerified, setChainVerified] = useState<boolean | null>(null);

  // Verification always runs against the full server-side chain; the snapshot
  // only contains the newest capped slice and cannot prove global integrity.
  useEffect(() => setChainVerified(null), [refreshVersion]);

  const handleVerifyChain = async () => {
    setVerifyingChain(true);
    try {
      const result = await verifyAuditChainRemote();
      if (result) setChainVerified(result.verified);
    } finally {
      setVerifyingChain(false);
    }
  };

  // Pagination
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);

  const filters = { category: categoryFilter, level: levelFilter };
  const { items: paginatedLogs, total } = useCollection<AuditLog>('auditLogs', {
    page: currentPage,
    pageSize,
    search: searchTerm,
    filters,
  });

  useEffect(() => {
    const lastPage = Math.max(1, Math.ceil(total / pageSize));
    if (currentPage > lastPage) setCurrentPage(lastPage);
  }, [currentPage, total, pageSize]);

  /** Exports honor the active filters and walk every server page. */
  const loadAllLogs = async () => {
    const size = 1000;
    const first = await fetchCollection<AuditLog>('auditLogs', {
      page: 1,
      pageSize: size,
      search: searchTerm,
      filters,
    });
    const all = [...first.items];
    for (let page = 2; all.length < first.total; page++) {
      const next = await fetchCollection<AuditLog>('auditLogs', {
        page,
        pageSize: size,
        search: searchTerm,
        filters,
      });
      if (!next.items.length) break;
      all.push(...next.items);
    }
    return all;
  };

  const handleExportJson = async () => {
    try {
      const logs = await loadAllLogs();
      const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(logs, null, 2));
      const downloadAnchor = document.createElement('a');
      downloadAnchor.setAttribute('href', dataStr);
      downloadAnchor.setAttribute('download', `audit-trail-${new Date().toISOString().split('T')[0]}.json`);
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();
    } catch {
      // The request layer surfaces transport failures through the global banner.
    }
  };

  const handleExportCsv = async () => {
    try {
      const logs = await loadAllLogs();
      const headers = ['ID', 'Timestamp', 'Category', 'Level', 'Event', 'Details', 'Actor', 'IP'];
      const rows = logs.map((l) => [
        l.id,
        l.timestamp,
        l.category,
        l.level,
        l.event,
        l.details,
        l.actor,
        l.ipAddress,
      ]);
      const csvContent = [headers.join(','), ...rows.map((e) => e.map(csvCell).join(','))].join('\n');
      const downloadAnchor = document.createElement('a');
      downloadAnchor.setAttribute('href', 'data:text/csv;charset=utf-8,' + encodeURIComponent(csvContent));
      downloadAnchor.setAttribute('download', `audit-trail-${new Date().toISOString().split('T')[0]}.csv`);
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();
    } catch {
      // The request layer surfaces transport failures through the global banner.
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="ui-page-header">
        <PageHeading page="logs">
          Review administrative actions and verify the retained server-side record chain.
        </PageHeading>

        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => void handleVerifyChain()}
            disabled={verifyingChain}
            className="inline-flex items-center gap-2 rounded-xl border border-zinc-700 bg-zinc-900 px-3.5 py-2.5 text-xs font-medium text-zinc-200 transition hover:bg-zinc-800 disabled:opacity-60 light:border-zinc-300 light:bg-white light:text-zinc-800 light:hover:bg-zinc-100"
          >
            {verifyingChain ? (
              <RotateCw className="h-3.5 w-3.5 animate-spin text-zinc-400" />
            ) : chainVerified === true ? (
              <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
            ) : chainVerified === false ? (
              <AlertTriangle className="h-3.5 w-3.5 text-rose-400" />
            ) : (
              <ShieldCheck className="h-3.5 w-3.5 text-zinc-400" />
            )}
            <span>{verifyingChain ? 'Verifying chain…' : 'Verify chain'}</span>
          </button>
          <button
            onClick={() => void handleExportCsv()}
            className="inline-flex items-center gap-2 rounded-xl border border-zinc-700 bg-zinc-900 px-3.5 py-2.5 text-xs font-medium text-zinc-200 transition hover:bg-zinc-800 light:border-zinc-300 light:bg-white light:text-zinc-800 light:hover:bg-zinc-100"
          >
            <Download className="h-3.5 w-3.5" />
            <span>Export CSV</span>
          </button>
          <button
            onClick={() => void handleExportJson()}
            className="inline-flex items-center gap-2 rounded-xl border border-zinc-700 bg-zinc-900 px-3.5 py-2.5 text-xs font-medium text-zinc-200 transition hover:bg-zinc-800 light:border-zinc-300 light:bg-white light:text-zinc-800 light:hover:bg-zinc-100"
          >
            <Download className="h-3.5 w-3.5" />
            <span>Export JSON</span>
          </button>
        </div>
      </div>

      {chainVerified !== null && !verifyingChain && (
        <div
          role="status"
          className={`flex items-start gap-2.5 rounded-xl border px-4 py-3 text-xs ${chainVerified ? 'border-emerald-500/20 bg-emerald-500/[0.06] text-emerald-300 light:text-emerald-800' : 'border-rose-500/25 bg-rose-500/[0.06] text-rose-300 light:text-rose-800'}`}
        >
          {chainVerified ? (
            <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" />
          ) : (
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
          )}
          <div>
            <p className="font-semibold">
              {chainVerified ? 'Retained chain verified' : 'Audit chain verification failed'}
            </p>
            <p className="mt-0.5 opacity-80">
              The check covers the retained audit window of up to 500 entries.
            </p>
          </div>
        </div>
      )}

      {/* Filter Bar */}
      <div className="ui-panel rounded-2xl border border-zinc-800/80 bg-zinc-900/50 p-4 shadow-sm transition-colors light:border-zinc-200 light:bg-white">
        <div className="mb-3 flex items-center gap-2 text-[10px] font-semibold uppercase tracking-wider text-zinc-500">
          <Filter className="h-3.5 w-3.5" />
          Filter retained entries
        </div>
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-[minmax(280px,1fr)_220px_180px]">
          <div className="relative min-w-0">
            <Search className="absolute left-3 top-3 h-4 w-4 text-zinc-500" />
            <input
              type="text"
              aria-label="Search audit trail"
              placeholder="Search event, details, IP, or actor"
              value={searchTerm}
              onChange={(e) => {
                setSearchTerm(e.target.value);
                setCurrentPage(1);
              }}
              className="w-full rounded-xl border border-zinc-800 bg-zinc-950 py-2.5 pl-9 pr-3 text-xs text-zinc-100 placeholder-zinc-500 transition focus:border-blue-500 light:border-zinc-300 light:bg-zinc-50 light:text-zinc-900"
            />
          </div>

          <label className="flex min-w-0 flex-col gap-1.5 text-[11px] font-medium text-zinc-400 light:text-zinc-600">
            Category
            <select
              value={categoryFilter}
              onChange={(e) => {
                setCategoryFilter(e.target.value);
                setCurrentPage(1);
              }}
              className="w-full rounded-xl border border-zinc-800 bg-zinc-950 px-3 py-2.5 text-xs text-zinc-200 focus:border-blue-500 light:border-zinc-300 light:bg-zinc-50 light:text-zinc-800"
            >
              <option value="ALL">All Categories</option>
              <option value="PIPELINE">Pipeline</option>
              <option value="SECURITY">Security</option>
              <option value="FEED">Feed Ingestion</option>
              <option value="WATCHLIST">Watch-List</option>
              <option value="EMAIL">Email Dispatch</option>
            </select>
          </label>

          <label className="flex min-w-0 flex-col gap-1.5 text-[11px] font-medium text-zinc-400 light:text-zinc-600">
            Severity
            <select
              value={levelFilter}
              onChange={(e) => {
                setLevelFilter(e.target.value);
                setCurrentPage(1);
              }}
              className="w-full rounded-xl border border-zinc-800 bg-zinc-950 px-3 py-2.5 text-xs text-zinc-200 focus:border-blue-500 light:border-zinc-300 light:bg-zinc-50 light:text-zinc-800"
            >
              <option value="ALL">All Levels</option>
              <option value="INFO">Info</option>
              <option value="WARNING">Warning</option>
              <option value="ERROR">Error</option>
            </select>
          </label>
        </div>
      </div>

      {/* Logs Table */}
      <div className="ui-panel overflow-hidden rounded-2xl border border-zinc-800/80 bg-zinc-900/50 shadow-sm light:border-zinc-200 light:bg-white">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-zinc-800/70 px-4 py-3.5 light:border-zinc-200 sm:px-5">
          <div>
            <h2 className="text-sm font-semibold">Retained entries</h2>
            <p className="mt-0.5 text-[11px] text-zinc-500">Newest records first</p>
          </div>
          <span className="rounded-full border border-zinc-700/80 bg-zinc-950/60 px-2.5 py-1 text-[11px] tabular-nums text-zinc-400 light:border-zinc-200 light:bg-zinc-50 light:text-zinc-600">
            {total.toLocaleString()} matches
          </span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[900px] text-left text-xs">
            <thead className="border-b border-zinc-800/80 bg-zinc-950/80 font-mono text-[10px] uppercase tracking-wider text-zinc-500 light:border-zinc-200 light:bg-zinc-100 light:text-zinc-600">
              <tr>
                <th className="py-3 px-4">Timestamp (UTC)</th>
                <th className="py-3 px-4">Category</th>
                <th className="py-3 px-4">Level</th>
                <th className="py-3 px-4">Event &amp; Action Details</th>
                <th className="py-3 px-4">Actor</th>
                <th className="py-3 px-4 text-right">Source IP</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/60 font-mono light:divide-zinc-200">
              {paginatedLogs.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-14 text-center font-sans">
                    <span className="mx-auto grid h-10 w-10 place-items-center rounded-full border border-zinc-800 bg-zinc-950 text-zinc-500 light:border-zinc-200 light:bg-zinc-50">
                      <Search className="h-4 w-4" />
                    </span>
                    <p className="mt-3 text-sm font-medium text-zinc-300 light:text-zinc-700">
                      No audit entries found
                    </p>
                    <p className="mt-1 text-xs text-zinc-500">Try changing the search or filters.</p>
                  </td>
                </tr>
              ) : (
                paginatedLogs.map((log) => (
                  <tr
                    key={log.id}
                    onClick={() => setSelectedLog(log)}
                    className="cursor-pointer transition hover:bg-zinc-800/25 light:hover:bg-zinc-50"
                  >
                    <td className="whitespace-nowrap px-4 py-3.5 text-[11px] text-zinc-400 light:text-zinc-600">
                      {new Intl.DateTimeFormat(undefined, {
                        dateStyle: 'medium',
                        timeStyle: 'medium',
                        timeZone: 'UTC',
                      }).format(new Date(log.timestamp))}{' '}
                      <span className="text-zinc-600">UTC</span>
                    </td>
                    <td className="px-4 py-3.5 text-[11px] text-zinc-300 light:text-zinc-700">
                      <span className="rounded-md border border-zinc-700/70 bg-zinc-800/60 px-2 py-1 light:border-zinc-200 light:bg-zinc-100">
                        {log.category}
                      </span>
                    </td>
                    <td className="px-4 py-3.5">
                      <span
                        className={`inline-flex rounded-full border px-2 py-1 text-[10px] font-semibold ${log.level === 'ERROR' ? 'border-rose-500/20 bg-rose-500/10 text-rose-400 light:text-rose-700' : log.level === 'WARNING' ? 'border-amber-500/20 bg-amber-500/10 text-amber-400 light:text-amber-700' : 'border-blue-500/20 bg-blue-500/10 text-blue-300 light:text-blue-700'}`}
                      >
                        {log.level}
                      </span>
                    </td>
                    <td className="max-w-xl px-4 py-3.5 font-sans">
                      <div className="text-xs font-semibold text-zinc-200 light:text-zinc-900">
                        {log.event}
                      </div>
                      <div className="mt-1 line-clamp-2 text-[11px] leading-relaxed text-zinc-400 light:text-zinc-600">
                        {log.details}
                      </div>
                    </td>
                    <td className="max-w-40 truncate px-4 py-3.5 text-[11px] text-zinc-400 light:text-zinc-600">
                      {log.actor}
                    </td>
                    <td className="whitespace-nowrap px-4 py-3.5 text-right text-[11px] text-zinc-400 light:text-zinc-600">
                      {log.ipAddress}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        <div className="border-t border-zinc-800/70 light:border-zinc-200">
          <Pagination
            currentPage={currentPage}
            totalItems={total}
            pageSize={pageSize}
            onPageChange={setCurrentPage}
            onPageSizeChange={(size) => {
              setPageSize(size);
              setCurrentPage(1);
            }}
            pageSizeOptions={[10, 25, 50]}
          />
        </div>
      </div>

      {selectedLog && (
        <LogDetailModal
          icon={<FileCode2 className="h-4 w-4" />}
          eyebrow={selectedLog.category}
          title={selectedLog.event}
          level={selectedLog.level}
          timestamp={selectedLog.timestamp}
          onClose={() => setSelectedLog(null)}
          fields={[
            { label: 'Category', value: selectedLog.category, mono: true },
            { label: 'Actor', value: selectedLog.actor, mono: true },
            { label: 'Source IP', value: selectedLog.ipAddress, mono: true },
            { label: 'Entry ID', value: selectedLog.id, mono: true },
            { label: 'Details', value: selectedLog.details, block: true },
          ]}
        />
      )}
    </div>
  );
};

export const OperationalLogsView: React.FC = () => {
  const { fetchEvents } = useApp();
  const [tab, setTab] = useState<'events' | 'audit'>('events');
  const [category, setCategory] = useState('');
  const [level, setLevel] = useState('');
  const [query, setQuery] = useState('');
  const [cursor, setCursor] = useState('');
  const [runId, setRunId] = useState('');
  const [next, setNext] = useState<string | null>(null);
  const [events, setEvents] = useState<OperationalEvent[]>([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [refresh, setRefresh] = useState(0);
  const [selectedEvent, setSelectedEvent] = useState<OperationalEvent | null>(null);
  useEffect(() => {
    if (tab !== 'events') return;
    let disposed = false;
    const timer = setTimeout(() => {
      setLoading(true);
      setError('');
      fetchEvents(
        new URLSearchParams({
          ...(category && { category }),
          ...(level && { level }),
          ...(query && { q: query }),
          ...(runId && { runId }),
          ...(cursor && { before: cursor }),
        }).toString(),
      )
        .then((result) => {
          if (!disposed) {
            setEvents(result.events);
            setNext(result.nextCursor);
          }
        })
        .catch((error) => {
          if (!disposed) setError(error.message);
        })
        .finally(() => {
          if (!disposed) setLoading(false);
        });
    }, 250);
    return () => {
      disposed = true;
      clearTimeout(timer);
    };
  }, [tab, category, level, query, runId, cursor, refresh]);
  return (
    <div className="space-y-6">
      <div
        className="inline-flex rounded-xl border border-zinc-800 bg-zinc-950/70 p-1 light:border-zinc-200 light:bg-white"
        role="tablist"
        aria-label="System logs views"
      >
        <button
          role="tab"
          aria-selected={tab === 'events'}
          onClick={() => setTab('events')}
          className={`rounded-lg px-3.5 py-2 text-xs font-medium transition ${tab === 'events' ? 'bg-zinc-800 text-zinc-100 shadow-sm light:bg-blue-50 light:text-blue-800' : 'text-zinc-400 hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-900'}`}
        >
          Operational events
        </button>
        <button
          role="tab"
          aria-selected={tab === 'audit'}
          onClick={() => setTab('audit')}
          className={`rounded-lg px-3.5 py-2 text-xs font-medium transition ${tab === 'audit' ? 'bg-zinc-800 text-zinc-100 shadow-sm light:bg-blue-50 light:text-blue-800' : 'text-zinc-400 hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-900'}`}
        >
          Audit trail
        </button>
      </div>
      {tab === 'audit' ? (
        <AuditTrailView />
      ) : (
        <>
          <div className="ui-page-header">
            <PageHeading page="logs" title="Operational events">
              Pipeline, feeds, matching, delivery, system health, and issues. Search includes structured event
              context.
            </PageHeading>
            <div className="flex items-center gap-2 text-xs text-zinc-500">
              {loading && <RotateCw className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />}
              {events.length > 0 && !loading && error === '' && (
                <>
                  <span className="inline-flex items-center gap-1 rounded-full border border-rose-500/20 bg-rose-500/10 px-1.5 py-0.5 text-[10px] font-medium text-rose-300 light:text-rose-700">
                    {events.filter((e) => e.level === 'ERROR').length} errors
                  </span>
                  <span className="inline-flex items-center gap-1 rounded-full border border-amber-500/20 bg-amber-500/10 px-1.5 py-0.5 text-[10px] font-medium text-amber-400 light:text-amber-700">
                    {events.filter((e) => e.level === 'WARNING').length} warnings
                  </span>
                </>
              )}
              <span>{loading ? 'Loading events…' : `${events.length} events in this view`}</span>
            </div>
          </div>
          <div className="ui-panel rounded-2xl border border-zinc-800/80 bg-zinc-900/50 p-4 shadow-sm light:border-zinc-200 light:bg-white">
            <div className="mb-3 flex items-center gap-2 text-[10px] font-semibold uppercase tracking-wider text-zinc-500">
              <Filter className="h-3.5 w-3.5" />
              Search and filter
            </div>
            <div className="grid items-end gap-3 sm:grid-cols-2 xl:grid-cols-[minmax(240px,1fr)_190px_160px_minmax(220px,0.8fr)_auto]">
              <label className="flex min-w-0 flex-col gap-1.5 text-[11px] font-medium text-zinc-400 light:text-zinc-600">
                Search events
                <input
                  aria-label="Search operational events"
                  maxLength={200}
                  value={query}
                  onChange={(e) => {
                    setQuery(e.target.value);
                    setCursor('');
                  }}
                  className="w-full rounded-xl border border-zinc-800 bg-zinc-950 px-3 py-2.5 text-xs text-zinc-100 placeholder:text-zinc-500 focus:border-blue-500 light:border-zinc-300 light:bg-zinc-50 light:text-zinc-900"
                  placeholder="Code, message or context"
                />
              </label>
              <label className="flex min-w-0 flex-col gap-1.5 text-[11px] font-medium text-zinc-400 light:text-zinc-600">
                Category
                <select
                  value={category}
                  className="w-full rounded-xl border border-zinc-800 bg-zinc-950 px-3 py-2.5 text-xs text-zinc-200 focus:border-blue-500 light:border-zinc-300 light:bg-zinc-50 light:text-zinc-800"
                  onChange={(e) => {
                    setCategory(e.target.value);
                    setCursor('');
                  }}
                >
                  <option value="">All categories</option>
                  {EVENT_CATEGORIES.map((item) => (
                    <option key={item}>{item}</option>
                  ))}
                </select>
              </label>
              <label className="flex min-w-0 flex-col gap-1.5 text-[11px] font-medium text-zinc-400 light:text-zinc-600">
                Level
                <select
                  value={level}
                  className="w-full rounded-xl border border-zinc-800 bg-zinc-950 px-3 py-2.5 text-xs text-zinc-200 focus:border-blue-500 light:border-zinc-300 light:bg-zinc-50 light:text-zinc-800"
                  onChange={(e) => {
                    setLevel(e.target.value);
                    setCursor('');
                  }}
                >
                  <option value="">All levels</option>
                  {['INFO', 'WARNING', 'ERROR'].map((item) => (
                    <option key={item}>{item}</option>
                  ))}
                </select>
              </label>
              <label className="flex min-w-0 flex-col gap-1.5 text-[11px] font-medium text-zinc-400 light:text-zinc-600">
                Execution ID
                <input
                  aria-label="Filter by execution ID"
                  value={runId}
                  placeholder="Execution UUID"
                  maxLength={36}
                  className="w-full rounded-xl border border-zinc-800 bg-zinc-950 px-3 py-2.5 text-xs text-zinc-100 placeholder:text-zinc-500 focus:border-blue-500 light:border-zinc-300 light:bg-zinc-50 light:text-zinc-900"
                  onChange={(e) => {
                    setRunId(e.target.value);
                    setCursor('');
                  }}
                />
              </label>
              <button
                className="inline-flex h-[38px] items-center justify-center gap-2 rounded-xl border border-zinc-700 bg-zinc-800 px-3.5 text-xs font-medium text-zinc-100 transition hover:bg-zinc-700 light:border-zinc-300 light:bg-zinc-100 light:text-zinc-800 light:hover:bg-zinc-200"
                disabled={loading}
                onClick={() => {
                  setCursor('');
                  setRefresh((value) => value + 1);
                }}
              >
                <RotateCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
                Refresh
              </button>
            </div>
          </div>
          {error && (
            <div
              role="alert"
              className="flex items-start gap-2.5 rounded-xl border border-rose-500/20 bg-rose-500/[0.06] px-4 py-3 text-xs text-rose-300 light:text-rose-800"
            >
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
              <div>
                <p className="font-semibold">Could not load operational events</p>
                <p className="mt-0.5 opacity-80">{error}</p>
              </div>
            </div>
          )}
          <div aria-busy={loading} className="space-y-3">
            {events.length === 0 && !loading && !error && (
              <div className="p-8 text-center text-zinc-500">
                <LogOut className="mx-auto h-6 w-6" />
                <p className="mt-3 text-sm font-medium text-zinc-300 light:text-zinc-700">
                  No matching events.
                </p>
                <p className="mt-1 text-xs text-zinc-600">Adjust your search or filters to see results.</p>
              </div>
            )}
            {events.length > 0 && (
              <div className="ui-panel overflow-hidden rounded-2xl border border-zinc-800/80 bg-zinc-900/50 shadow-sm light:border-zinc-200 light:bg-white">
                <div className="overflow-x-auto">
                  <table className="w-full min-w-[1080px] table-fixed text-left text-xs">
                    <colgroup>
                      <col style={{ width: '11%' }} />
                      <col style={{ width: '11%' }} />
                      <col style={{ width: '10%' }} />
                      <col style={{ width: '12%' }} />
                      <col style={{ width: '32%' }} />
                      <col style={{ width: '24%' }} />
                    </colgroup>
                    <thead className="border-b border-zinc-800/80 bg-zinc-950/80 font-mono text-[10px] uppercase tracking-wider text-zinc-500 light:border-zinc-200 light:bg-zinc-100 light:text-zinc-600">
                      <tr>
                        <th className="py-3 px-4">Timestamp (UTC)</th>
                        <th className="py-3 px-4">Category</th>
                        <th className="py-3 px-4">Level</th>
                        <th className="py-3 px-4">Code</th>
                        <th className="py-3 px-4">Message &amp; Error Details</th>
                        <th className="py-3 px-4">Execution ID</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-zinc-800/60 font-mono light:divide-zinc-200">
                      {events.map((event) => (
                        <tr
                          key={event.id}
                          onClick={() => setSelectedEvent(event)}
                          className="cursor-pointer transition hover:bg-zinc-800/25 light:hover:bg-zinc-50"
                        >
                          <td className="whitespace-nowrap px-4 py-3.5 text-[11px] text-zinc-400 light:text-zinc-600">
                            {new Intl.DateTimeFormat(undefined, {
                              dateStyle: 'medium',
                              timeStyle: 'medium',
                              timeZone: 'UTC',
                            }).format(new Date(event.timestamp))}{' '}
                            <span className="text-zinc-600">UTC</span>
                          </td>
                          <td className="px-4 py-3.5 text-[11px] text-zinc-300 light:text-zinc-700">
                            <span className="rounded-md border border-zinc-700/70 bg-zinc-800/60 px-2 py-1 light:border-zinc-200 light:bg-zinc-100">
                              {event.category}
                            </span>
                          </td>
                          <td className="px-4 py-3.5">
                            <span
                              className={`inline-flex rounded-full border px-2 py-1 text-[10px] font-semibold ${
                                event.level === 'ERROR'
                                  ? 'border-rose-500/20 bg-rose-500/10 text-rose-400 light:text-rose-700'
                                  : event.level === 'WARNING'
                                    ? 'border-amber-500/20 bg-amber-500/10 text-amber-400 light:text-amber-700'
                                    : 'border-blue-500/20 bg-blue-500/10 text-blue-300 light:text-blue-700'
                              }`}
                            >
                              {event.level}
                            </span>
                          </td>
                          <td className="px-4 py-3.5 font-mono text-[11px] text-zinc-300 light:text-zinc-700">
                            <span className="rounded-md bg-zinc-800/70 px-1.5 py-1 light:bg-zinc-100">
                              {event.code}
                            </span>
                          </td>
                          <td className="max-w-xs px-4 py-3.5 font-sans">
                            <div className="text-xs font-semibold text-zinc-200 light:text-zinc-900">
                              {event.message}
                            </div>
                            {event.level === 'ERROR' && (
                              <div className="mt-1 space-y-1">
                                {event.context?.error !== undefined && (
                                  <pre className="max-h-36 overflow-auto whitespace-pre-wrap break-all rounded-lg border border-rose-500/15 bg-rose-950/20 p-2 text-[10px] text-rose-300 light:text-rose-800">
                                    {String(event.context.error as unknown as string)}
                                  </pre>
                                )}
                                {event.context?.errorType !== undefined && (
                                  <div className="text-[10px] text-zinc-400 light:text-zinc-600">
                                    Error type{' '}
                                    <span className="font-medium text-rose-300 light:text-rose-700">
                                      {event.context.errorType as string}
                                    </span>
                                  </div>
                                )}
                                {event.context?.component !== undefined && (
                                  <div className="text-[10px] text-zinc-400 light:text-zinc-600">
                                    Component{' '}
                                    <span className="font-medium text-zinc-300 light:text-zinc-800">
                                      {event.context.component as string}
                                    </span>
                                  </div>
                                )}
                              </div>
                            )}
                            {event.context && Object.keys(event.context).length > 0 && (
                              <details className="mt-1" onClick={(e) => e.stopPropagation()}>
                                <summary className="cursor-pointer text-[10px] font-medium text-blue-300 underline decoration-blue-300/30 underline-offset-2 light:text-blue-700">
                                  View event details
                                </summary>
                                <pre className="mt-2 max-h-64 overflow-auto whitespace-pre-wrap break-words rounded-lg border border-zinc-700/50 bg-zinc-950/80 p-3 text-[11px] leading-relaxed text-zinc-300 light:border-zinc-200 light:bg-zinc-50 light:text-zinc-700">
                                  {formatEventContext(event.context)}
                                </pre>
                              </details>
                            )}
                          </td>
                          <td className="truncate px-4 py-3.5 font-mono text-[11px] text-zinc-400 light:text-zinc-600">
                            {event.runId ? (
                              <span className="inline-flex items-center gap-1">
                                <Cpu className="h-3 w-3 text-indigo-400 light:text-indigo-600" />
                                {event.runId}
                              </span>
                            ) : (
                              '—'
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-zinc-800/70 bg-zinc-900/30 px-4 py-3 light:border-zinc-200 light:bg-white/70">
            <p className="text-[11px] text-zinc-500">
              {cursor ? 'Viewing an older page' : 'Showing the latest events'}
            </p>
            <div className="flex gap-2">
              <button
                className="inline-flex items-center gap-1.5 rounded-lg border border-zinc-700 px-3 py-2 text-xs font-medium text-zinc-300 transition hover:bg-zinc-800 disabled:cursor-not-allowed disabled:opacity-40 light:border-zinc-300 light:text-zinc-700 light:hover:bg-zinc-100"
                disabled={!cursor || loading}
                onClick={() => setCursor('')}
              >
                <RotateCw className="h-3.5 w-3.5" />
                Latest
              </button>
              <button
                className="inline-flex items-center gap-1.5 rounded-lg border border-zinc-700 px-3 py-2 text-xs font-medium text-zinc-300 transition hover:bg-zinc-800 disabled:cursor-not-allowed disabled:opacity-40 light:border-zinc-300 light:text-zinc-700 light:hover:bg-zinc-100"
                disabled={!next || loading}
                onClick={() => setCursor(next!)}
              >
                Older events <span aria-hidden="true">→</span>
              </button>
            </div>
          </div>
        </>
      )}

      {selectedEvent && (
        <LogDetailModal
          icon={<Cpu className="h-4 w-4" />}
          eyebrow={selectedEvent.category}
          title={selectedEvent.message}
          level={selectedEvent.level}
          timestamp={selectedEvent.timestamp}
          onClose={() => setSelectedEvent(null)}
          fields={[
            { label: 'Code', value: selectedEvent.code, mono: true },
            { label: 'Execution ID', value: selectedEvent.runId || '—', mono: true },
            { label: 'Entry ID', value: selectedEvent.id, mono: true },
            {
              label: 'Event details',
              value: formatEventContext(selectedEvent.context),
              block: true,
              hidden: !selectedEvent.context || Object.keys(selectedEvent.context).length === 0,
            },
          ]}
        />
      )}
    </div>
  );
};
