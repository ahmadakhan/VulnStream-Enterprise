import React, { useEffect, useState } from 'react';
import { useApp } from '../context/AppContext';
import {
  RotateCw,
  Play,
  ChevronDown,
  CheckCircle2,
  Clock,
  Radio,
  Cpu,
  Sun,
  Moon,
  Search,
  Menu,
} from 'lucide-react';

const TAB_TITLES: Record<string, { section: string; title: string }> = {
  dashboard: { section: 'OPERATIONS', title: 'Intelligence Dashboard' },
  watchlist: { section: 'OPERATIONS', title: 'Monitored Product Inventory' },
  findings: { section: 'OPERATIONS', title: 'Product Vulnerability Tracker' },
  'threat-data': { section: 'OPERATIONS', title: 'Normalized Threat Cache' },
  advisories: { section: 'OPERATIONS', title: 'Generated Security Bulletins' },
  pipeline: { section: 'AUTONOMOUS PIPELINE', title: 'Execution Telemetry' },
  'alerted-cves': { section: 'AUTONOMOUS PIPELINE', title: 'Sent Alert Registry' },
  feeds: { section: 'AUTONOMOUS PIPELINE', title: 'Threat Feed Sources' },
  recipients: { section: 'AUTONOMOUS PIPELINE', title: 'Notification Channels & Webhooks' },
  template: { section: 'AUTONOMOUS PIPELINE', title: 'HTML Template Studio' },
  emails: { section: 'AUTONOMOUS PIPELINE', title: 'Email Delivery Audit' },
  logs: { section: 'SYSTEM & AUDIT', title: 'Operational Logs & Audit' },
  health: { section: 'SYSTEM & AUDIT', title: 'Infrastructure & Readiness Health' },
  settings: { section: 'SYSTEM & AUDIT', title: 'Engine Configuration & Policies' },
};

export const TopHeader: React.FC = () => {
  const {
    activeTab,
    isPipelineRunning,
    currentPipelinePhase,
    triggerPipelineRun,
    feeds,
    session,
    theme,
    toggleTheme,
    settings,
    mobileNavOpen,
    setMobileNavOpen,
  } = useApp();

  const [scopeDropdownOpen, setScopeDropdownOpen] = useState(false);
  const [selectedScope, setSelectedScope] = useState(settings.scopeHours || 24);

  useEffect(() => {
    setSelectedScope(settings.scopeHours || 24);
  }, [settings.scopeHours]);

  const handleRunPipeline = async () => {
    setScopeDropdownOpen(false);
    await triggerPipelineRun(selectedScope);
  };

  const meta = TAB_TITLES[activeTab] || { section: 'OPERATIONS', title: 'Vulnerability Intelligence' };

  return (
    <header className="border-b border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 bg-zinc-950/80 dark:bg-zinc-950/80 light:bg-white/80 backdrop-blur-md sticky top-0 z-20 transition-colors duration-200">
      <div className="px-3 sm:px-6 py-3.5 flex items-center justify-between gap-2">
        {/* Active View Breadcrumb Title */}
        <div className="flex items-center gap-2 min-w-0">
          <button
            type="button"
            onClick={() => setMobileNavOpen(!mobileNavOpen)}
            className="md:hidden shrink-0 p-2 rounded-lg text-zinc-300 hover:bg-zinc-800 focus-visible:outline focus-visible:outline-2 focus-visible:outline-zinc-400"
            aria-label={mobileNavOpen ? 'Close navigation menu' : 'Open navigation menu'}
            aria-expanded={mobileNavOpen}
            aria-controls="primary-navigation"
          >
            <Menu className="w-4 h-4" />
          </button>
          <div className="min-w-0">
            <div className="text-[10px] font-mono text-zinc-500 uppercase font-semibold tracking-wider">
              {meta.section}
            </div>
            <h1 className="text-sm sm:text-base font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 tracking-tight truncate">
              {meta.title}
            </h1>
          </div>
        </div>

        {/* Center / Right Telemetry & Actions */}
        <div className="flex items-center gap-2 sm:gap-3 shrink-0">
          {/* Status chips */}
          <div className="hidden lg:flex items-center space-x-2 text-xs">
            <div className="flex items-center space-x-1.5 bg-zinc-900/60 dark:bg-zinc-900/60 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 px-2.5 py-1 rounded-full text-zinc-300 dark:text-zinc-300 light:text-zinc-700">
              <span className={`w-1.5 h-1.5 rounded-full ${feeds.some((feed) => feed.enabled) ? 'bg-emerald-500' : 'bg-zinc-500'}`} />
              <span className="text-[11px] font-mono">
                {feeds.filter((f) => f.enabled).length} Feeds Enabled
              </span>
            </div>

            <div className="flex items-center space-x-1.5 bg-zinc-900/60 dark:bg-zinc-900/60 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 px-2.5 py-1 rounded-full text-zinc-400 dark:text-zinc-400 light:text-zinc-600">
              <Cpu className="w-3 h-3" />
              <span className="text-[11px]">
                {settings.schedulerEnabled ? 'Scheduler enabled' : 'Scheduler disabled'}
              </span>
            </div>

            <div className="flex items-center space-x-1.5 bg-zinc-900/60 dark:bg-zinc-900/60 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 px-2.5 py-1 rounded-full text-zinc-400 dark:text-zinc-400 light:text-zinc-600">
              <Clock className="w-3 h-3" />
              <span className="font-mono text-[11px]">{session?.role}</span>
            </div>
          </div>

          {/* Quick Theme Toggle Icon */}
          <button
            onClick={toggleTheme}
            className="p-1.5 rounded-xl border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 bg-zinc-900/80 dark:bg-zinc-900/80 light:bg-zinc-100 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 hover:text-zinc-100 dark:hover:text-zinc-100 light:hover:text-zinc-900 transition"
            title={theme === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
            aria-label={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
            aria-pressed={theme === 'light'}
          >
            {theme === 'dark' ? (
              <Sun className="w-4 h-4 text-amber-400" />
            ) : (
              <Moon className="w-4 h-4 text-zinc-600" />
            )}
          </button>

          {/* Run Pipeline Button & Scope Selector */}
          <div className="relative">
            <div className="flex rounded-xl overflow-hidden shadow-sm border border-zinc-700/80 dark:border-zinc-700/80 light:border-zinc-300">
              <button
                onClick={() => void handleRunPipeline()}
                disabled={isPipelineRunning}
                className={`inline-flex items-center space-x-1.5 px-3.5 py-1.5 text-xs font-semibold transition ${
                  isPipelineRunning
                    ? 'bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 text-zinc-400 cursor-not-allowed'
                    : 'bg-zinc-100 dark:bg-zinc-100 light:bg-zinc-900 text-zinc-900 dark:text-zinc-900 light:text-zinc-50 hover:bg-zinc-200 dark:hover:bg-zinc-200 light:hover:bg-zinc-800'
                }`}
              >
                {isPipelineRunning ? (
                  <>
                    <RotateCw className="w-3 h-3 animate-spin text-zinc-400" />
                    <span>Pipeline pending...</span>
                  </>
                ) : (
                  <>
                    <Play className="w-3 h-3 fill-current" />
                    <span className="hidden sm:inline">Run Pipeline ({selectedScope}h)</span>
                    <span className="sm:hidden">Run</span>
                  </>
                )}
              </button>
              <button
                onClick={() => setScopeDropdownOpen((prev) => !prev)}
                disabled={isPipelineRunning}
                className="bg-indigo-600 hover:bg-indigo-500 text-white border-l border-indigo-400/60 px-2 text-xs flex items-center justify-center transition disabled:opacity-50"
                title="Change Processing Scope Window"
                aria-label="Choose pipeline time window"
                aria-expanded={scopeDropdownOpen}
                aria-controls="pipeline-scope-options"
              >
                <ChevronDown className="w-3 h-3" />
              </button>
            </div>

            {scopeDropdownOpen && (
              <div id="pipeline-scope-options" className="absolute right-0 mt-2 w-48 bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-xl shadow-xl py-1 z-50 text-xs">
                <div className="px-3 py-1.5 text-[10px] font-semibold text-zinc-500 uppercase tracking-wider font-mono">
                  Timeline Window
                </div>
                {[6, 12, 24, 48, 72, 168].map((hrs) => (
                  <button
                    key={hrs}
                    onClick={() => {
                      setSelectedScope(hrs);
                      setScopeDropdownOpen(false);
                    }}
                    className={`w-full text-left px-3 py-1.5 hover:bg-zinc-800 dark:hover:bg-zinc-800 light:hover:bg-zinc-100 flex items-center justify-between ${
                      selectedScope === hrs
                        ? 'text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-semibold bg-zinc-800/40 dark:bg-zinc-800/40 light:bg-zinc-200/50'
                        : 'text-zinc-400 dark:text-zinc-400 light:text-zinc-600'
                    }`}
                  >
                    <span>Past {hrs} Hours</span>
                    {selectedScope === hrs && (
                      <CheckCircle2 className="w-3.5 h-3.5 text-zinc-300 dark:text-zinc-300 light:text-zinc-800" />
                    )}
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Running Pipeline Progress Banner */}
      {isPipelineRunning && (
        <div className="px-6 py-2 border-t border-zinc-800/60 dark:border-zinc-800/60 light:border-zinc-200 flex items-center justify-between text-xs bg-zinc-900/60 dark:bg-zinc-900/60 light:bg-zinc-100 text-zinc-300 dark:text-zinc-300 light:text-zinc-700">
          <div className="flex items-center space-x-2">
            <RotateCw className="w-3.5 h-3.5 animate-spin text-zinc-400" />
            <span className="font-mono font-medium">{currentPipelinePhase}</span>
          </div>
          <span className="text-[11px] text-zinc-500 font-mono">Server-managed execution</span>
        </div>
      )}
    </header>
  );
};
