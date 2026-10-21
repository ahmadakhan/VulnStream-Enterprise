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
} from 'lucide-react';
import { Pagination } from './Pagination';
import { csvCell } from '../utils/csv';
import { verifyAuditChain } from '../utils/cryptoChain';

const AuditTrailView: React.FC = () => {
  const { auditLogs } = useApp();
  const [searchTerm, setSearchTerm] = useState('');
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');
  const [levelFilter, setLevelFilter] = useState<string>('ALL');

  // Cryptographic Chain Verification State
  const [verifyingChain, setVerifyingChain] = useState(false);
  const [chainVerified, setChainVerified] = useState<boolean | null>(null);

  useEffect(() => setChainVerified(null), [auditLogs]);

  const handleVerifyChain = async () => {
    setVerifyingChain(true);

    setChainVerified(verifyAuditChain(auditLogs));
    setVerifyingChain(false);
  };

  // Pagination
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);

  const filteredLogs = auditLogs.filter((log) => {
    const matchesSearch =
      log.event.toLowerCase().includes(searchTerm.toLowerCase()) ||
      log.details.toLowerCase().includes(searchTerm.toLowerCase()) ||
      log.actor.toLowerCase().includes(searchTerm.toLowerCase()) ||
      log.ipAddress.includes(searchTerm);

    const matchesCategory = categoryFilter === 'ALL' || log.category === categoryFilter;
    const matchesLevel = levelFilter === 'ALL' || log.level === levelFilter;

    return matchesSearch && matchesCategory && matchesLevel;
  });

  const paginatedLogs = filteredLogs.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  const handleExportJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(auditLogs, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `audit-trail-${new Date().toISOString().split('T')[0]}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const handleExportCsv = () => {
    const headers = ['ID', 'Timestamp', 'Category', 'Level', 'Event', 'Details', 'Actor', 'IP'];
    const rows = auditLogs.map((l) => [
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
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 tracking-tight flex items-center gap-2">
            <FileCode2 className="w-5 h-5 text-zinc-300 dark:text-zinc-300 light:text-zinc-700" />
            Operational &amp; Ingestion Audit Trail
          </h1>
          <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mt-1">
            Server audit trail (latest 500 entries). Verification checks content and links in this window.
            Keep external checkpoints to detect wholesale replacement.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={handleVerifyChain}
            disabled={verifyingChain}
            className="text-xs px-3 py-1.5 rounded-xl bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 hover:bg-zinc-700 dark:hover:bg-zinc-700 light:hover:bg-zinc-300 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 border border-zinc-700 dark:border-zinc-700 light:border-zinc-300 font-medium transition flex items-center space-x-1.5"
          >
            {verifyingChain ? (
              <RotateCw className="w-3.5 h-3.5 animate-spin text-zinc-400" />
            ) : chainVerified === true ? (
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
            ) : chainVerified === false ? (
              <AlertTriangle className="w-3.5 h-3.5 text-red-400" />
            ) : (
              <ShieldCheck className="w-3.5 h-3.5 text-zinc-400" />
            )}
            <span>
              {verifyingChain
                ? 'Verifying SHA-256 Chain...'
                : chainVerified === true
                  ? 'Retained Chain Valid'
                  : 'Verify Hash Chain'}
            </span>
          </button>
          <button
            onClick={handleExportCsv}
            className="text-xs px-3 py-1.5 rounded-xl bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 hover:bg-zinc-700 dark:hover:bg-zinc-700 light:hover:bg-zinc-300 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 border border-zinc-700 dark:border-zinc-700 light:border-zinc-300 font-medium transition flex items-center space-x-1"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export CSV</span>
          </button>
          <button
            onClick={handleExportJson}
            className="text-xs px-3 py-1.5 rounded-xl bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 hover:bg-zinc-700 dark:hover:bg-zinc-700 light:hover:bg-zinc-300 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 border border-zinc-700 dark:border-zinc-700 light:border-zinc-300 font-medium transition flex items-center space-x-1"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export JSON</span>
          </button>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="bg-zinc-900/50 dark:bg-zinc-900/50 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl p-4 flex flex-wrap items-center justify-between gap-3 shadow-sm transition-colors">
        <div className="relative w-full sm:w-80">
          <Search className="w-4 h-4 text-zinc-500 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search logs by event, details, IP, or actor..."
            value={searchTerm}
            onChange={(e) => {
              setSearchTerm(e.target.value);
              setCurrentPage(1);
            }}
            className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl pl-9 pr-3 py-1.5 text-xs text-zinc-100 dark:text-zinc-100 light:text-zinc-900 placeholder-zinc-500 focus:outline-none focus:border-zinc-600 transition"
          />
        </div>

        <div className="flex flex-wrap items-center gap-3 text-xs">
          {/* Category Filter */}
          <div className="flex items-center space-x-1.5 text-zinc-400 dark:text-zinc-400 light:text-zinc-600">
            <span>Category:</span>
            <select
              value={categoryFilter}
              onChange={(e) => {
                setCategoryFilter(e.target.value);
                setCurrentPage(1);
              }}
              className="bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl px-2.5 py-1 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 focus:outline-none"
            >
              <option value="ALL">All Categories</option>
              <option value="PIPELINE">Pipeline</option>
              <option value="SECURITY">Security</option>
              <option value="FEED">Feed Ingestion</option>
              <option value="WATCHLIST">Watch-List</option>
              <option value="EMAIL">Email Dispatch</option>
            </select>
          </div>

          {/* Level Filter */}
          <div className="flex items-center space-x-1.5 text-zinc-400 dark:text-zinc-400 light:text-zinc-600">
            <span>Level:</span>
            <select
              value={levelFilter}
              onChange={(e) => {
                setLevelFilter(e.target.value);
                setCurrentPage(1);
              }}
              className="bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl px-2.5 py-1 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 focus:outline-none"
            >
              <option value="ALL">All Levels</option>
              <option value="INFO">Info</option>
              <option value="WARNING">Warning</option>
              <option value="ERROR">Error</option>
            </select>
          </div>
        </div>
      </div>

      {/* Logs Table */}
      <div className="bg-zinc-900/50 dark:bg-zinc-900/50 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl overflow-hidden shadow-sm transition-colors">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-zinc-950/80 dark:bg-zinc-950/80 light:bg-zinc-100 border-b border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 text-zinc-400 dark:text-zinc-400 light:text-zinc-600 font-mono uppercase text-[11px]">
              <tr>
                <th className="py-3 px-4">Timestamp (UTC)</th>
                <th className="py-3 px-4">Category</th>
                <th className="py-3 px-4">Level</th>
                <th className="py-3 px-4">Event &amp; Action Details</th>
                <th className="py-3 px-4">Actor</th>
                <th className="py-3 px-4 text-right">Source IP</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/60 dark:divide-zinc-800/60 light:divide-zinc-200 font-mono">
              {paginatedLogs.map((log) => (
                <tr
                  key={log.id}
                  className="hover:bg-zinc-800/30 dark:hover:bg-zinc-800/30 light:hover:bg-zinc-50 transition"
                >
                  <td className="py-2.5 px-4 text-zinc-400 dark:text-zinc-400 light:text-zinc-500 text-[11px]">
                    {new Date(log.timestamp).toISOString().replace('T', ' ').slice(0, 19)}
                  </td>
                  <td className="py-2.5 px-4 text-zinc-300 dark:text-zinc-300 light:text-zinc-800 text-[11px]">
                    {log.category}
                  </td>
                  <td className="py-2.5 px-4">
                    <span className="text-[10px] px-2 py-0.2 rounded-full font-medium bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 text-zinc-300 dark:text-zinc-300 light:text-zinc-800 border border-zinc-700 dark:border-zinc-700 light:border-zinc-300">
                      {log.level}
                    </span>
                  </td>
                  <td className="py-2.5 px-4 font-sans max-w-md">
                    <div className="font-semibold text-zinc-200 dark:text-zinc-200 light:text-zinc-900 text-xs">
                      {log.event}
                    </div>
                    <div className="text-[11px] text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mt-0.5 line-clamp-2">
                      {log.details}
                    </div>
                  </td>
                  <td className="py-2.5 px-4 text-zinc-400 dark:text-zinc-400 light:text-zinc-600 text-[11px]">
                    {log.actor}
                  </td>
                  <td className="py-2.5 px-4 text-right text-zinc-400 dark:text-zinc-400 light:text-zinc-500 text-[11px]">
                    {log.ipAddress}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        <Pagination
          currentPage={currentPage}
          totalItems={filteredLogs.length}
          pageSize={pageSize}
          onPageChange={setCurrentPage}
          onPageSizeChange={setPageSize}
          pageSizeOptions={[10, 25, 50]}
        />
      </div>
    </div>
  );
};

export const OperationalLogsView: React.FC = () => {
  const { fetchEvents } = useApp();
  const [tab, setTab] = useState('events');
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
      <div className="flex gap-2">
        <button onClick={() => setTab('events')} aria-pressed={tab === 'events'} className="btn-secondary">
          Operational events
        </button>
        <button onClick={() => setTab('audit')} aria-pressed={tab === 'audit'} className="btn-secondary">
          Audit trail
        </button>
      </div>
      {tab === 'audit' ? (
        <AuditTrailView />
      ) : (
        <>
          <div>
            <h2 className="text-2xl font-semibold">Operational events</h2>
            <p className="text-sm text-slate-500 mt-2">
              Pipeline, feeds, matching, delivery, system health and issues. Search includes structured
              context; newest events appear first.
            </p>
          </div>
          <div className="flex flex-wrap gap-3 items-end">
            <label className="flex flex-col gap-1 flex-1 min-w-48">
              Search events
              <input
                aria-label="Search operational events"
                maxLength={200}
                value={query}
                onChange={(e) => {
                  setQuery(e.target.value);
                  setCursor('');
                }}
                className="w-full"
                placeholder="Code, message or context"
              />
            </label>
            <label className="flex flex-col gap-1">
              Category
              <select
                value={category}
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
            <label className="flex flex-col gap-1">
              Level
              <select
                value={level}
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
            <label className="flex flex-col gap-1">
              Execution ID
              <input
                aria-label="Filter by execution ID"
                value={runId}
                placeholder="Execution UUID"
                maxLength={36}
                onChange={(e) => {
                  setRunId(e.target.value);
                  setCursor('');
                }}
              />
            </label>
            <button
              className="btn-secondary"
              onClick={() => {
                setCursor('');
                setRefresh((value) => value + 1);
              }}
            >
              Refresh
            </button>
          </div>
          {error && (
            <p role="alert" className="text-red-500">
              {error}
            </p>
          )}
          <div aria-busy={loading} className="space-y-3">
            {events.map((event) => (
              <article key={event.id} className="p-4 rounded-xl border border-slate-500/20 bg-slate-500/5">
                <div className="flex flex-wrap gap-3 text-xs text-slate-500">
                  <time>{new Date(event.timestamp).toLocaleString()}</time>
                  <span>{event.category}</span>
                  <span
                    className={
                      event.level === 'ERROR'
                        ? 'text-red-500'
                        : event.level === 'WARNING'
                          ? 'text-amber-500'
                          : ''
                    }
                  >
                    {event.level}
                  </span>
                  <code>{event.code}</code>
                </div>
                <p className="mt-2 font-medium">{event.message}</p>
                <details className="mt-2 text-sm">
                  <summary className="cursor-pointer">
                    Context{event.runId ? ` · Execution ${event.runId}` : ''}
                  </summary>
                  <pre className="mt-2 whitespace-pre-wrap break-all text-xs">
                    {JSON.stringify(event.context, null, 2)}
                  </pre>
                </details>
              </article>
            ))}
            {!events.length && !loading && !error && (
              <p className="p-8 text-center text-slate-500">No matching events.</p>
            )}
          </div>
          <div className="flex gap-3">
            <button className="btn-secondary" disabled={!cursor || loading} onClick={() => setCursor('')}>
              Latest events
            </button>
            <button className="btn-secondary" disabled={!next || loading} onClick={() => setCursor(next!)}>
              Older events
            </button>
          </div>
        </>
      )}
    </div>
  );
};
