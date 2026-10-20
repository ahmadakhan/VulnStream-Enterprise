import React from 'react';
import { useApp } from '../context/AppContext';
import {
  Shield,
  Flame,
  Radio,
  FileText,
  Server,
  ArrowUpRight,
  Zap,
  Cpu,
  MailCheck,
  Send,
  ExternalLink,
  Layers,
  ChevronRight,
  Database,
  Bell,
  Code,
  Package,
  CheckCircle2,
} from 'lucide-react';
import { Finding } from '../types';

export const DashboardView: React.FC = () => {
  const {
    findings,
    watchlist,
    feeds,
    advisories,
    setActiveTab,
    setSelectedFinding,
    triggerPipelineRun,
    isPipelineRunning,
    emailLogs,
    webhooks,
    settings,
  } = useApp();

  const activeVulnerabilities = findings.filter(
    f => f.status !== 'RESOLVED' && f.status !== 'FALSE_POSITIVE'
  );
  const kevFindings = findings.filter(f => f.cve.cisaKev.isKev);
  const criticalFindings = findings.filter(f => f.cve.cvss.severity === 'CRITICAL');
  const deliveredEmails = emailLogs.filter(e => ['ACCEPTED', 'DELIVERED'].includes(e.status)).length;

  const totalCpesCount = watchlist.reduce((acc, curr) => acc + curr.cpes.length, 0);
  const totalPurlsCount = watchlist.reduce((acc, curr) => acc + (curr.purls ? curr.purls.length : 0), 0);

  const handleSelectFinding = (finding: Finding) => {
    setSelectedFinding(finding);
    setActiveTab('findings');
  };

  return (
    <div className="space-y-6">
      {/* Hero Welcome Card */}
      <div className="bg-zinc-900/60 dark:bg-zinc-900/60 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl p-6 shadow-sm relative overflow-hidden transition-colors">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center space-x-2 text-xs font-mono text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-1">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
              <span>SCHEDULER {settings.schedulerEnabled ? 'ENABLED' : 'DISABLED'} • CPE &amp; PURL CORRELATION</span>
            </div>
            <h1 className="text-xl font-bold tracking-tight text-zinc-100 dark:text-zinc-100 light:text-zinc-900">
              Product Vulnerability Tracking &amp; Notification System
            </h1>
            <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 max-w-2xl mt-1 leading-relaxed">
              Ingest configured NVD, CISA KEV, EPSS and normalized JSON feeds, correlate them with inventory, and queue notifications when automatic dispatch is enabled. Review uncertain applicability before remediation.
            </p>
          </div>
          <div className="flex items-center space-x-2.5 shrink-0">
            <button
              onClick={() => setActiveTab('watchlist')}
              className="text-xs px-3.5 py-2 rounded-xl bg-zinc-800/80 hover:bg-zinc-700/80 dark:bg-zinc-800/80 dark:hover:bg-zinc-700/80 light:bg-zinc-100 light:hover:bg-zinc-200 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 border border-zinc-700/50 dark:border-zinc-700/50 light:border-zinc-300 font-medium transition"
            >
              Monitored Products ({watchlist.length})
            </button>
            <button
              onClick={() => triggerPipelineRun()}
              disabled={isPipelineRunning}
              className="text-xs px-4 py-2 rounded-xl bg-zinc-100 hover:bg-zinc-200 dark:bg-zinc-100 dark:hover:bg-zinc-200 light:bg-zinc-900 light:hover:bg-zinc-800 text-zinc-900 dark:text-zinc-900 light:text-zinc-50 font-semibold transition flex items-center space-x-2 shadow-sm"
            >
              <Zap className="w-3.5 h-3.5 fill-current" />
              <span>Trigger Ingestion</span>
            </button>
          </div>
        </div>
      </div>

      {/* ALL KPI Cards CLICKABLE with direct navigation */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        {/* 1. Monitored Products -> Watchlist */}
        <div
          onClick={() => setActiveTab('watchlist')}
          className="group cursor-pointer bg-zinc-900/40 dark:bg-zinc-900/40 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl p-4 hover:border-zinc-600 dark:hover:border-zinc-600 light:hover:border-zinc-400 hover:bg-zinc-900/70 transition shadow-sm"
          title="Click to view and manage Monitored Products"
        >
          <div className="flex items-center justify-between text-zinc-400 dark:text-zinc-400 light:text-zinc-500 text-xs mb-1.5">
            <span className="group-hover:text-zinc-200 transition">Products</span>
            <Server className="w-3.5 h-3.5 text-zinc-400 group-hover:text-zinc-200 transition" />
          </div>
          <div className="text-2xl font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-mono flex items-center justify-between">
            <span>{watchlist.length}</span>
            <ChevronRight className="w-4 h-4 text-zinc-600 group-hover:text-zinc-300 group-hover:translate-x-0.5 transition" />
          </div>
          <div className="text-[11px] text-zinc-500 mt-1 font-medium">
            {totalCpesCount} Strict CPEs
          </div>
        </div>

        {/* 2. Active Vulnerabilities -> Findings */}
        <div
          onClick={() => setActiveTab('findings')}
          className="group cursor-pointer bg-zinc-900/40 dark:bg-zinc-900/40 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl p-4 hover:border-zinc-600 dark:hover:border-zinc-600 light:hover:border-zinc-400 hover:bg-zinc-900/70 transition shadow-sm"
          title="Click to review correlated product vulnerabilities"
        >
          <div className="flex items-center justify-between text-zinc-400 dark:text-zinc-400 light:text-zinc-500 text-xs mb-1.5">
            <span className="group-hover:text-zinc-200 transition">Vulnerabilities</span>
            <Shield className="w-3.5 h-3.5 text-zinc-400 group-hover:text-zinc-200 transition" />
          </div>
          <div className="text-2xl font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-mono flex items-center justify-between">
            <span>{activeVulnerabilities.length}</span>
            <ChevronRight className="w-4 h-4 text-zinc-600 group-hover:text-zinc-300 group-hover:translate-x-0.5 transition" />
          </div>
          <div className="text-[11px] text-zinc-500 mt-1 font-medium">
            {criticalFindings.length} Critical Impact
          </div>
        </div>

        {/* 3. CISA KEV In Wild -> Findings */}
        <div
          onClick={() => setActiveTab('findings')}
          className="group cursor-pointer bg-zinc-900/40 dark:bg-zinc-900/40 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl p-4 hover:border-amber-600/60 dark:hover:border-amber-600/60 light:hover:border-amber-400 hover:bg-zinc-900/70 transition shadow-sm"
          title="Click to view CISA KEV actively exploited items"
        >
          <div className="flex items-center justify-between text-zinc-400 dark:text-zinc-400 light:text-zinc-500 text-xs mb-1.5">
            <span className="group-hover:text-amber-400 transition">CISA KEV</span>
            <Flame className="w-3.5 h-3.5 text-amber-500/80" />
          </div>
          <div className="text-2xl font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-mono flex items-center justify-between">
            <span className="text-amber-400/90">{kevFindings.length}</span>
            <ChevronRight className="w-4 h-4 text-zinc-600 group-hover:text-amber-300 group-hover:translate-x-0.5 transition" />
          </div>
          <div className="text-[11px] text-amber-500/80 mt-1 font-medium">
            Active in Wild
          </div>
        </div>

        {/* 4. Automated Notifications -> Email / Webhook Log */}
        <div
          onClick={() => setActiveTab('emails')}
          className="group cursor-pointer bg-zinc-900/40 dark:bg-zinc-900/40 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl p-4 hover:border-emerald-600/60 dark:hover:border-emerald-600/60 light:hover:border-emerald-400 hover:bg-zinc-900/70 transition shadow-sm"
          title="Click to view automated email & notification log"
        >
          <div className="flex items-center justify-between text-zinc-400 dark:text-zinc-400 light:text-zinc-500 text-xs mb-1.5">
            <span className="group-hover:text-emerald-400 transition">Auto-Dispatched</span>
            <MailCheck className="w-3.5 h-3.5 text-emerald-500/80" />
          </div>
          <div className="text-2xl font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-mono flex items-center justify-between">
            <span className="text-emerald-400/90">{deliveredEmails}</span>
            <ChevronRight className="w-4 h-4 text-zinc-600 group-hover:text-emerald-300 group-hover:translate-x-0.5 transition" />
          </div>
          <div className="text-[11px] text-zinc-500 mt-1 font-medium">
            Provider Accepted
          </div>
        </div>

        {/* 5. Threat Feeds -> Threat Feeds View */}
        <div
          onClick={() => setActiveTab('feeds')}
          className="group cursor-pointer bg-zinc-900/40 dark:bg-zinc-900/40 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl p-4 hover:border-zinc-600 dark:hover:border-zinc-600 light:hover:border-zinc-400 hover:bg-zinc-900/70 transition shadow-sm"
          title="Click to inspect and manage Threat Feeds"
        >
          <div className="flex items-center justify-between text-zinc-400 dark:text-zinc-400 light:text-zinc-500 text-xs mb-1.5">
            <span className="group-hover:text-zinc-200 transition">Threat Feeds</span>
            <Radio className="w-3.5 h-3.5 text-zinc-400 group-hover:text-zinc-200 transition" />
          </div>
          <div className="text-2xl font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-mono flex items-center justify-between">
            <span>{feeds.filter(f => f.enabled).length}/{feeds.length}</span>
            <ChevronRight className="w-4 h-4 text-zinc-600 group-hover:text-zinc-300 group-hover:translate-x-0.5 transition" />
          </div>
          <div className="text-[11px] text-zinc-500 mt-1 font-medium">
            SSRF Guard Active
          </div>
        </div>

        {/* 6. Generated Advisories -> Advisories View */}
        <div
          onClick={() => setActiveTab('advisories')}
          className="group cursor-pointer bg-zinc-900/40 dark:bg-zinc-900/40 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl p-4 hover:border-zinc-600 dark:hover:border-zinc-600 light:hover:border-zinc-400 hover:bg-zinc-900/70 transition shadow-sm"
          title="Click to view generated security advisories"
        >
          <div className="flex items-center justify-between text-zinc-400 dark:text-zinc-400 light:text-zinc-500 text-xs mb-1.5">
            <span className="group-hover:text-zinc-200 transition">Advisories</span>
            <FileText className="w-3.5 h-3.5 text-zinc-400 group-hover:text-zinc-200 transition" />
          </div>
          <div className="text-2xl font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-mono flex items-center justify-between">
            <span>{advisories.length}</span>
            <ChevronRight className="w-4 h-4 text-zinc-600 group-hover:text-zinc-300 group-hover:translate-x-0.5 transition" />
          </div>
          <div className="text-[11px] text-zinc-500 mt-1 font-medium">
            Generated &amp; Logged
          </div>
        </div>
      </div>

      {/* Two Column Section: Correlated Vulnerabilities + Monitored Product Protection Telemetry */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Monitored Product Vulnerabilities (2 cols) */}
        <div className="lg:col-span-2 bg-zinc-900/50 dark:bg-zinc-900/50 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl p-5 shadow-sm transition-colors">
          <div className="flex items-center justify-between mb-4 pb-3 border-b border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200">
            <div className="flex items-center space-x-2">
              <Shield className="w-4 h-4 text-zinc-300 dark:text-zinc-300 light:text-zinc-700" />
              <h2 className="text-xs font-semibold text-zinc-200 dark:text-zinc-200 light:text-zinc-800 uppercase tracking-wider">
                Correlated Product Vulnerabilities
              </h2>
            </div>
            <button
              onClick={() => setActiveTab('findings')}
              className="text-xs text-zinc-400 hover:text-zinc-200 dark:text-zinc-400 dark:hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-900 font-medium flex items-center space-x-1"
            >
              <span>View All Vulnerabilities</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="space-y-2.5">
            {findings.slice(0, 4).map(finding => {
              const isKev = finding.cve.cisaKev.isKev;

              return (
                <div
                  key={finding.id}
                  onClick={() => handleSelectFinding(finding)}
                  className="p-3.5 rounded-xl border border-zinc-800/70 dark:border-zinc-800/70 light:border-zinc-200 bg-zinc-950/40 dark:bg-zinc-950/40 light:bg-zinc-50 hover:bg-zinc-900/60 dark:hover:bg-zinc-900/60 light:hover:bg-zinc-100 hover:border-zinc-700 dark:hover:border-zinc-700 light:hover:border-zinc-400 transition cursor-pointer flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-sm"
                  title="Click to inspect vulnerability playbook"
                >
                  <div className="space-y-1">
                    <div className="flex items-center space-x-2">
                      <span className="font-mono font-bold text-sm text-zinc-100 dark:text-zinc-100 light:text-zinc-900">
                        {finding.cveId}
                      </span>
                      {isKev && (
                        <span className="text-[10px] font-medium bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 text-zinc-300 dark:text-zinc-300 light:text-zinc-800 border border-zinc-700 dark:border-zinc-700 light:border-zinc-300 px-2 py-0.5 rounded-full flex items-center gap-1">
                          <Flame className="w-3 h-3 text-amber-500" />
                          CISA KEV
                        </span>
                      )}
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-zinc-800/80 dark:bg-zinc-800/80 light:bg-zinc-200 text-zinc-300 dark:text-zinc-300 light:text-zinc-800 border border-zinc-700/60 dark:border-zinc-700/60 light:border-zinc-300">
                        CVSS {finding.cve.cvss.score.toFixed(1)} ({finding.cve.cvss.severity})
                      </span>
                    </div>
                    <div className="text-xs text-zinc-300 dark:text-zinc-300 light:text-zinc-700 line-clamp-1">
                      {finding.cve.title}
                    </div>
                    <div className="text-[11px] text-zinc-400 dark:text-zinc-400 light:text-zinc-500 font-mono flex items-center gap-2">
                      <span>Product: <strong className="text-zinc-200 dark:text-zinc-200 light:text-zinc-800">{finding.matchedAssetName}</strong></span>
                      <span>•</span>
                      <span>Protection: <span className="text-emerald-400 font-medium">Uniform Continuous Monitoring</span></span>
                    </div>
                  </div>

                  <div className="sm:text-right shrink-0">
                    <span className="inline-flex items-center gap-1 text-[11px] font-medium px-2 py-0.5 rounded-full bg-zinc-800/80 dark:bg-zinc-800/80 light:bg-zinc-200 text-zinc-300 dark:text-zinc-300 light:text-zinc-800 border border-zinc-700/60 dark:border-zinc-700/60 light:border-zinc-300">
                      <Send className="w-3 h-3 text-emerald-400" />
                      <span>{finding.notificationStatus.replace(/_/g, ' ')}</span>
                    </span>
                    <div className="text-[10px] text-zinc-500 font-mono mt-1">
                      Auto-Dispatched on Match
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Monitored Products Protection Status (All products treated equally) */}
        <div className="bg-zinc-900/50 dark:bg-zinc-900/50 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl p-5 shadow-sm flex flex-col justify-between transition-colors">
          <div>
            <div className="flex items-center space-x-2 mb-4 pb-3 border-b border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200">
              <Server className="w-4 h-4 text-zinc-300 dark:text-zinc-300 light:text-zinc-700" />
              <h2 className="text-xs font-semibold text-zinc-200 dark:text-zinc-200 light:text-zinc-800 uppercase tracking-wider">
                Product Inventory Protection Telemetry
              </h2>
            </div>

            <div className="space-y-3">
              <div
                onClick={() => setActiveTab('watchlist')}
                className="cursor-pointer p-3 rounded-xl bg-zinc-950/60 dark:bg-zinc-950/60 light:bg-zinc-50 border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 hover:border-zinc-700 transition"
              >
                <div className="flex items-center justify-between text-xs">
                  <span className="text-zinc-300 dark:text-zinc-300 light:text-zinc-700 font-medium flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                    <span>Protected Product Assets</span>
                  </span>
                  <span className="font-mono text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-bold text-sm">
                    {watchlist.length} Assets
                  </span>
                </div>
                <div className="text-[11px] text-zinc-500 light:text-zinc-600 mt-1 pl-6">
                  All enterprise software products treated with uniform priority.
                </div>
              </div>

              <div
                onClick={() => setActiveTab('watchlist')}
                className="cursor-pointer p-3 rounded-xl bg-zinc-950/60 dark:bg-zinc-950/60 light:bg-zinc-50 border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 hover:border-zinc-700 transition"
              >
                <div className="flex items-center justify-between text-xs">
                  <span className="text-zinc-300 dark:text-zinc-300 light:text-zinc-700 font-medium flex items-center gap-2">
                    <Code className="w-4 h-4 text-sky-400 shrink-0" />
                    <span>Active Strict CPE 2.3 Strings</span>
                  </span>
                  <span className="font-mono text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-bold text-sm">
                    {totalCpesCount}
                  </span>
                </div>
                <div className="text-[11px] text-zinc-500 light:text-zinc-600 mt-1 pl-6">
                  Precise component matching across Vendor, Product, and SemVer ranges.
                </div>
              </div>

              <div
                onClick={() => setActiveTab('watchlist')}
                className="cursor-pointer p-3 rounded-xl bg-zinc-950/60 dark:bg-zinc-950/60 light:bg-zinc-50 border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 hover:border-zinc-700 transition"
              >
                <div className="flex items-center justify-between text-xs">
                  <span className="text-zinc-300 dark:text-zinc-300 light:text-zinc-700 font-medium flex items-center gap-2">
                    <Package className="w-4 h-4 text-purple-400 shrink-0" />
                    <span>Supply Chain PURLs Monitored</span>
                  </span>
                  <span className="font-mono text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-bold text-sm">
                    {totalPurlsCount}
                  </span>
                </div>
                <div className="text-[11px] text-zinc-500 light:text-zinc-600 mt-1 pl-6">
                  Maven, NPM, PyPI, and Golang dependency signatures.
                </div>
              </div>

              <div
                onClick={() => setActiveTab('pipeline')}
                className="cursor-pointer p-3 rounded-xl bg-zinc-950/60 dark:bg-zinc-950/60 light:bg-zinc-50 border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 hover:border-zinc-700 transition"
              >
                <div className="flex items-center justify-between text-xs">
                  <span className="text-zinc-300 dark:text-zinc-300 light:text-zinc-700 font-medium flex items-center gap-2">
                    <Cpu className="w-4 h-4 text-emerald-400 shrink-0" />
                    <span>Autonomous Detection Engine</span>
                  </span>
                  <span className="font-mono text-emerald-400 font-bold text-xs bg-emerald-950/50 px-2 py-0.5 rounded border border-emerald-800/60">
                    {settings.schedulerEnabled ? 'Scheduled' : 'Manual'}
                  </span>
                </div>
                <div className="text-[11px] text-zinc-500 light:text-zinc-600 mt-1 pl-6">
                  Server scheduler • Configure interval in Settings.
                </div>
              </div>
            </div>
          </div>

          <div className="mt-5 pt-4 border-t border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200">
            <button
              onClick={() => setActiveTab('watchlist')}
              className="w-full text-xs py-2 bg-zinc-800/70 hover:bg-zinc-700/70 dark:bg-zinc-800/70 dark:hover:bg-zinc-700/70 light:bg-zinc-100 light:hover:bg-zinc-200 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 rounded-xl font-medium border border-zinc-700/40 dark:border-zinc-700/40 light:border-zinc-300 transition text-center"
            >
              Configure Monitored Products →
            </button>
          </div>
        </div>
      </div>

      {/* Autonomous Pipeline Steps (CLICKABLE CARDS) */}
      <div className="bg-zinc-900/50 dark:bg-zinc-900/50 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl p-5 shadow-sm transition-colors">
        <div className="flex items-center justify-between mb-4 pb-3 border-b border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200">
          <div className="flex items-center space-x-2">
            <Cpu className="w-4 h-4 text-zinc-300 dark:text-zinc-300 light:text-zinc-700" />
            <h2 className="text-xs font-semibold text-zinc-200 dark:text-zinc-200 light:text-zinc-800 uppercase tracking-wider">
              Autonomous Pipeline Architecture (Click Step to Inspect)
            </h2>
          </div>
          <span className="text-[11px] font-mono text-zinc-400 dark:text-zinc-400 light:text-zinc-500">
            Interval: {settings.schedulerIntervalMinutes}m • Auto-Dispatch: {settings.autoDispatchEnabled ? 'Enabled' : 'Disabled'}
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
          {[
            { phase: '1. Ingress & SSRF', desc: 'Configured HTTPS feed adapters', targetTab: 'feeds' },
            { phase: '2. Deduplication', desc: 'Canonical CVE IDs, O(1) set check', targetTab: 'alerted-cves' },
            { phase: '3. Auto-Enrichment', desc: 'NVD CVSS, EPSS & CISA KEV', targetTab: 'threat-data' },
            { phase: '4. Product Match', desc: 'Strict component matching & PURL', targetTab: 'watchlist' },
            { phase: '5. Auto-Dispatch', desc: 'Durable SMTP & webhook outbox', targetTab: 'emails' },
          ].map((step, idx) => (
            <div
              key={idx}
              onClick={() => setActiveTab(step.targetTab)}
              className="group cursor-pointer bg-zinc-950/60 dark:bg-zinc-950/60 light:bg-zinc-50 border border-zinc-800/70 dark:border-zinc-800/70 light:border-zinc-200 rounded-xl p-3 hover:border-zinc-600 dark:hover:border-zinc-600 light:hover:border-zinc-400 hover:bg-zinc-900/60 dark:hover:bg-zinc-900/60 light:hover:bg-zinc-100 transition relative shadow-sm"
              title={`Click to open ${step.phase}`}
            >
              <div className="text-[10px] font-mono text-zinc-400 dark:text-zinc-400 light:text-zinc-500 flex items-center justify-between">
                <span>PHASE {idx + 1}</span>
                <ChevronRight className="w-3.5 h-3.5 text-zinc-600 group-hover:text-zinc-300 group-hover:translate-x-0.5 transition" />
              </div>
              <div className="font-semibold text-xs text-zinc-200 dark:text-zinc-200 light:text-zinc-900 mt-1 group-hover:text-zinc-100">
                {step.phase}
              </div>
              <div className="text-[11px] text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mt-1 leading-snug">
                {step.desc}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
