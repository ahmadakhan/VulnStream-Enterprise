import React, { useState } from 'react';
import { useApp } from '../context/AppContext';
import { NormalizedCVE } from '../types';
import {
  Database,
  Search,
  Flame,
  FileJson,
  X,
  Copy,
  Check,
  Calendar,
  Clock,
  ArrowUpDown,
  Filter,
} from 'lucide-react';
import { Pagination } from './Pagination';

export const ThreatDataView: React.FC = () => {
  const { cveData, settings } = useApp();
  const [searchTerm, setSearchTerm] = useState('');
  const [kevFilter, setKevFilter] = useState<'ALL' | 'KEV_ONLY'>('ALL');
  const [epssFilter, setEpssFilter] = useState<'ALL' | 'HIGH_EPSS'>('ALL');
  const [dateFilter, setDateFilter] = useState<'ALL' | 'SCOPE_24H' | 'RECENT_MODIFIED' | 'RECENT_PUBLISHED'>(
    'ALL',
  );
  const [sortBy, setSortBy] = useState<'score' | 'published' | 'modified'>('modified');
  const [sortOrder, setSortOrder] = useState<'desc' | 'asc'>('desc');
  const [inspectCve, setInspectCve] = useState<NormalizedCVE | null>(null);
  const [copied, setCopied] = useState(false);

  // Pagination state
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);

  const now = new Date().getTime();
  const scopeMillis = (settings.scopeHours || 24) * 60 * 60 * 1000;

  const filteredCves = cveData
    .filter((cve) => {
      const matchesSearch =
        cve.cveId.toLowerCase().includes(searchTerm.toLowerCase()) ||
        cve.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
        cve.sourceFeeds.some((s) => s.toLowerCase().includes(searchTerm.toLowerCase())) ||
        cve.cpeMatches.some((c) => c.toLowerCase().includes(searchTerm.toLowerCase()));

      const matchesKev = kevFilter === 'ALL' || cve.cisaKev.isKev;
      const matchesEpss = epssFilter === 'ALL' || cve.epss.score >= 0.4;

      const pubTime = new Date(cve.publishedDate).getTime();
      const modTime = new Date(cve.modifiedDate).getTime();

      let matchesDate = true;
      if (dateFilter === 'SCOPE_24H') {
        const inScope = now - pubTime <= scopeMillis || now - modTime <= scopeMillis;
        matchesDate = inScope;
      } else if (dateFilter === 'RECENT_MODIFIED') {
        matchesDate = now - modTime <= 7 * 24 * 60 * 60 * 1000;
      } else if (dateFilter === 'RECENT_PUBLISHED') {
        matchesDate = now - pubTime <= 7 * 24 * 60 * 60 * 1000;
      }

      return matchesSearch && matchesKev && matchesEpss && matchesDate;
    })
    .sort((a, b) => {
      let comparison = 0;
      if (sortBy === 'score') {
        comparison = b.cvss.score - a.cvss.score;
      } else if (sortBy === 'published') {
        comparison = new Date(b.publishedDate).getTime() - new Date(a.publishedDate).getTime();
      } else {
        comparison = new Date(b.modifiedDate).getTime() - new Date(a.modifiedDate).getTime();
      }
      return sortOrder === 'desc' ? comparison : -comparison;
    });

  const paginatedCves = filteredCves.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  const handleCopyJson = () => {
    if (inspectCve) {
      navigator.clipboard.writeText(JSON.stringify(inspectCve, null, 2));
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const toggleSort = (col: 'score' | 'published' | 'modified') => {
    if (sortBy === col) {
      setSortOrder((prev) => (prev === 'desc' ? 'asc' : 'desc'));
    } else {
      setSortBy(col);
      setSortOrder('desc');
    }
    setCurrentPage(1);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 tracking-tight flex items-center gap-2">
            <Database className="w-5 h-5 text-zinc-300 dark:text-zinc-300 light:text-zinc-700" />
            Threat Intelligence Feed Cache
          </h1>
          <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mt-1">
            Normalized CVE cache unified from NVD, OpenCVE, FIRST.org EPSS, CISA KEV, and VulnCheck exploitation intelligence.
            CVEs are correlated by both <strong>published date</strong> and{' '}
            <strong>last modified date</strong>.
          </p>
        </div>

        <div className="flex items-center space-x-2 text-xs font-mono text-zinc-400 dark:text-zinc-400 light:text-zinc-600 bg-zinc-900/60 dark:bg-zinc-900/60 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 px-3 py-1.5 rounded-xl shadow-sm">
          <Clock className="w-3.5 h-3.5 text-emerald-400" />
          <span>Timeline Scope: {settings.scopeHours}h (Published &amp; Modified)</span>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="bg-zinc-900/50 dark:bg-zinc-900/50 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl p-4 flex flex-wrap items-center justify-between gap-3 shadow-sm transition-colors">
        <div className="relative w-full sm:w-80">
          <Search className="w-4 h-4 text-zinc-500 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search normalized cache by CVE, title, or CPE..."
            value={searchTerm}
            onChange={(e) => {
              setSearchTerm(e.target.value);
              setCurrentPage(1);
            }}
            className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl pl-9 pr-3 py-1.5 text-xs text-zinc-100 dark:text-zinc-100 light:text-zinc-900 placeholder-zinc-500 focus:outline-none focus:border-zinc-600 transition"
          />
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Date Scope Filter */}
          <div className="flex items-center space-x-1 bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl px-2 py-1">
            <Calendar className="w-3.5 h-3.5 text-zinc-400" />
            <select
              value={dateFilter}
              onChange={(e) => {
                setDateFilter(e.target.value as any);
                setCurrentPage(1);
              }}
              className="bg-transparent text-xs text-zinc-200 dark:text-zinc-200 light:text-zinc-800 font-medium focus:outline-none"
            >
              <option value="ALL">All Timeline Windows</option>
              <option value="SCOPE_24H">In Pipeline Scope ({settings.scopeHours}h)</option>
              <option value="RECENT_MODIFIED">Modified &lt; 7 Days</option>
              <option value="RECENT_PUBLISHED">Published &lt; 7 Days</option>
            </select>
          </div>

          {/* CISA KEV Filter */}
          <button
            onClick={() => {
              setKevFilter((k) => (k === 'ALL' ? 'KEV_ONLY' : 'ALL'));
              setCurrentPage(1);
            }}
            className={`px-3 py-1.5 rounded-xl text-xs font-medium flex items-center space-x-1.5 transition border ${
              kevFilter === 'KEV_ONLY'
                ? 'bg-zinc-800 text-zinc-100 border-zinc-600 dark:bg-zinc-800 dark:text-zinc-100 light:bg-zinc-200 light:text-zinc-900'
                : 'bg-zinc-950 dark:bg-zinc-950 light:bg-white border-zinc-800 dark:border-zinc-800 light:border-zinc-300 text-zinc-400 dark:text-zinc-400 light:text-zinc-600 hover:text-zinc-200'
            }`}
          >
            <Flame className="w-3.5 h-3.5 text-amber-500/80" />
            <span>CISA KEV Only</span>
          </button>

          {/* EPSS Filter */}
          <button
            onClick={() => {
              setEpssFilter((e) => (e === 'ALL' ? 'HIGH_EPSS' : 'ALL'));
              setCurrentPage(1);
            }}
            className={`px-3 py-1.5 rounded-xl text-xs font-medium flex items-center space-x-1.5 transition border ${
              epssFilter === 'HIGH_EPSS'
                ? 'bg-zinc-800 text-zinc-100 border-zinc-600 dark:bg-zinc-800 dark:text-zinc-100 light:bg-zinc-200 light:text-zinc-900'
                : 'bg-zinc-950 dark:bg-zinc-950 light:bg-white border-zinc-800 dark:border-zinc-800 light:border-zinc-300 text-zinc-400 dark:text-zinc-400 light:text-zinc-600 hover:text-zinc-200'
            }`}
          >
            <span>EPSS &gt; 0.40</span>
          </button>
        </div>
      </div>

      {/* Table */}
      <div className="bg-zinc-900/50 dark:bg-zinc-900/50 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl overflow-hidden shadow-sm transition-colors">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-zinc-950/80 dark:bg-zinc-950/80 light:bg-zinc-100 border-b border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 text-zinc-400 dark:text-zinc-400 light:text-zinc-600 font-mono uppercase text-[11px]">
              <tr>
                <th className="py-3 px-4">Canonical CVE</th>
                <th aria-sort={sortBy === 'score' ? (sortOrder === 'asc' ? 'ascending' : 'descending') : 'none'} className="py-3 px-4">
                  <button type="button" onClick={() => toggleSort('score')} className="flex items-center space-x-1 hover:text-zinc-200 transition select-none">
                    <span>CVSS Score</span>
                    <ArrowUpDown className="w-3 h-3" />
                  </button>
                </th>
                <th className="py-3 px-4">EPSS Percentile</th>
                <th aria-sort={sortBy === 'published' ? (sortOrder === 'asc' ? 'ascending' : 'descending') : 'none'} className="py-3 px-4">
                  <button type="button" onClick={() => toggleSort('published')} className="flex items-center space-x-1 hover:text-zinc-200 transition select-none">
                    <span>Published Date</span>
                    <ArrowUpDown className="w-3 h-3" />
                  </button>
                </th>
                <th aria-sort={sortBy === 'modified' ? (sortOrder === 'asc' ? 'ascending' : 'descending') : 'none'} className="py-3 px-4">
                  <button type="button" onClick={() => toggleSort('modified')} className="flex items-center space-x-1 hover:text-zinc-200 transition select-none">
                    <span>Last Modified Date</span>
                    <ArrowUpDown className="w-3 h-3" />
                  </button>
                </th>
                <th className="py-3 px-4">Exploit Status</th>
                <th className="py-3 px-4">Sources Ingested</th>
                <th className="py-3 px-4 text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/60 dark:divide-zinc-800/60 light:divide-zinc-200">
              {paginatedCves.map((cve) => {
                const pubTime = new Date(cve.publishedDate).getTime();
                const modTime = new Date(cve.modifiedDate).getTime();
                const pubInScope = now - pubTime <= scopeMillis;
                const modInScope = now - modTime <= scopeMillis;

                return (
                  <tr
                    key={cve.cveId}
                    className="hover:bg-zinc-800/30 dark:hover:bg-zinc-800/30 light:hover:bg-zinc-50 transition"
                  >
                    {/* Canonical CVE */}
                    <td className="py-3 px-4">
                      <div className="flex items-center space-x-2">
                        <span className="font-mono font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 text-sm">
                          {cve.cveId}
                        </span>
                        {cve.cisaKev.isKev && (
                          <span className="bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 text-zinc-300 dark:text-zinc-300 light:text-zinc-800 border border-zinc-700 dark:border-zinc-700 light:border-zinc-300 px-2 py-0.2 rounded-full font-mono text-[10px] font-medium flex items-center gap-1">
                            <Flame className="w-3 h-3 text-amber-500" />
                            KEV
                          </span>
                        )}
                      </div>
                      <div className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 line-clamp-1 max-w-xs mt-0.5">
                        {cve.title}
                      </div>
                    </td>

                    {/* CVSS Score */}
                    <td className="py-3 px-4 font-mono">
                      <div className="flex items-center space-x-1.5">
                        <span className="font-bold text-sm text-zinc-200 dark:text-zinc-200 light:text-zinc-900">
                          {cve.cvss.version === 'UNKNOWN' ? 'Unscored' : cve.cvss.score.toFixed(1)}
                        </span>
                        <span className="text-[10px] text-zinc-500 dark:text-zinc-500 light:text-zinc-600">
                          ({cve.cvss.severity})
                        </span>
                      </div>
                      <div
                        className="text-[10px] text-zinc-500 dark:text-zinc-500 light:text-zinc-600 truncate max-w-[130px]"
                        title={cve.cvss.vector}
                      >
                        {cve.cvss.vector}
                      </div>
                    </td>

                    {/* EPSS */}
                    <td className="py-3 px-4 font-mono">
                      <div className="text-zinc-300 dark:text-zinc-300 light:text-zinc-800 font-medium">
                        {(cve.epss.score * 100).toFixed(2)}%
                      </div>
                      <div className="text-[10px] text-zinc-500">{cve.epss.percentile}th Pct</div>
                    </td>

                    {/* Published Date */}
                    <td className="py-3 px-4 font-mono text-[11px]">
                      <div className="text-zinc-300 dark:text-zinc-300 light:text-zinc-800 flex items-center space-x-1">
                        <span>{new Date(cve.publishedDate).toLocaleDateString()}</span>
                        {pubInScope && (
                          <span
                            className="w-1.5 h-1.5 rounded-full bg-emerald-500"
                            title="Matched inside current pipeline scope window"
                          />
                        )}
                      </div>
                      <div className="text-[10px] text-zinc-500">
                        {new Date(cve.publishedDate).toLocaleTimeString([], {
                          hour: '2-digit',
                          minute: '2-digit',
                        })}
                      </div>
                    </td>

                    {/* Last Modified Date */}
                    <td className="py-3 px-4 font-mono text-[11px]">
                      <div className="text-zinc-300 dark:text-zinc-300 light:text-zinc-800 flex items-center space-x-1">
                        <span>{new Date(cve.modifiedDate).toLocaleDateString()}</span>
                        {modInScope && (
                          <span
                            className="w-1.5 h-1.5 rounded-full bg-sky-500"
                            title="Matched by last modified date within pipeline scope"
                          />
                        )}
                      </div>
                      <div className="text-[10px] text-zinc-500">
                        {new Date(cve.modifiedDate).toLocaleTimeString([], {
                          hour: '2-digit',
                          minute: '2-digit',
                        })}
                      </div>
                    </td>

                    {/* Exploit Status */}
                    <td className="py-3 px-4">
                      <span className="text-[10px] px-2 py-0.5 rounded-full font-medium font-mono bg-zinc-800/80 dark:bg-zinc-800/80 light:bg-zinc-200 text-zinc-300 dark:text-zinc-300 light:text-zinc-800 border border-zinc-700/60 dark:border-zinc-700/60 light:border-zinc-300">
                        {cve.exploitStatus}
                      </span>
                    </td>

                    {/* Ingestion Sources */}
                    <td className="py-3 px-4">
                      <div className="flex flex-wrap gap-1">
                        {cve.sourceFeeds.map((src, i) => (
                          <span
                            key={i}
                            className="bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 text-zinc-400 dark:text-zinc-400 light:text-zinc-700 px-1.5 py-0.2 rounded text-[10px] font-mono"
                          >
                            {src}
                          </span>
                        ))}
                      </div>
                    </td>

                    {/* Action */}
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => setInspectCve(cve)}
                        className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 hover:text-zinc-200 dark:hover:text-zinc-200 light:hover:text-zinc-900 font-medium inline-flex items-center space-x-1 bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 px-2.5 py-1 rounded-xl border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 transition"
                      >
                        <FileJson className="w-3.5 h-3.5" />
                        <span>JSON</span>
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        <Pagination
          currentPage={currentPage}
          totalItems={filteredCves.length}
          pageSize={pageSize}
          onPageChange={setCurrentPage}
          onPageSizeChange={setPageSize}
          pageSizeOptions={[10, 25, 50]}
        />
      </div>

      {/* Raw JSON Modal */}
      {inspectCve && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-3xl w-full p-6 shadow-2xl relative">
            <button
              onClick={() => setInspectCve(null)}
              className="absolute top-4 right-4 text-zinc-500 hover:text-zinc-200 dark:hover:text-zinc-200 light:hover:text-zinc-900"
            >
              <X className="w-5 h-5" />
            </button>

            <div className="flex items-center justify-between mb-4">
              <h2 className="text-base font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-mono flex items-center gap-2">
                <FileJson className="w-5 h-5 text-zinc-400" />
                Normalized Ingestion Record: {inspectCve.cveId}
              </h2>
              <button
                onClick={handleCopyJson}
                className="text-xs bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 hover:bg-zinc-700 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 px-2.5 py-1 rounded-xl border border-zinc-700 dark:border-zinc-700 light:border-zinc-300 flex items-center space-x-1"
              >
                {copied ? (
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                ) : (
                  <Copy className="w-3.5 h-3.5" />
                )}
                <span>{copied ? 'Copied' : 'Copy JSON'}</span>
              </button>
            </div>

            <div className="flex items-center space-x-4 mb-3 text-xs font-mono text-zinc-400">
              <span>Published: {inspectCve.publishedDate}</span>
              <span>•</span>
              <span>Last Modified: {inspectCve.modifiedDate}</span>
            </div>

            <pre className="bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-xl p-4 font-mono text-[11px] text-zinc-300 dark:text-zinc-300 light:text-zinc-800 max-h-96 overflow-y-auto leading-relaxed">
              {JSON.stringify(inspectCve, null, 2)}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
};
