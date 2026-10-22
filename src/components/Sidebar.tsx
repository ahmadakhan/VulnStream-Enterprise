import React, { useEffect, useState } from 'react';
import { useApp } from '../context/AppContext';
import {
  LayoutDashboard,
  Server,
  ShieldAlert,
  Database,
  FileText,
  Activity,
  Bell,
  Radio,
  Users,
  FileCode,
  Mail,
  Inbox,
  FileCode2,
  Cpu,
  Settings,
  Shield,
  Sun,
  Moon,
  Clock,
  KeyRound,
  RotateCw,
} from 'lucide-react';

export const Sidebar: React.FC = () => {
  const [isMobileView, setIsMobileView] = useState(
    () => typeof window !== 'undefined' && window.matchMedia('(max-width: 767px)').matches,
  );
  const {
    activeTab,
    setActiveTab,
    mobileNavOpen,
    setMobileNavOpen,
    findings,
    watchlist,
    feeds,
    theme,
    toggleTheme,
    sessionTimeRemainingSec,
    resetSessionTimeout,
  } = useApp();

  const activeFindingsCount = findings.filter(
    (f) =>
      !['RESOLVED', 'FALSE_POSITIVE', 'PATCH_APPLIED'].includes(f.status) &&
      f.notificationStatus !== 'NOT_APPLICABLE',
  ).length;

  const sessionMins = Math.floor(sessionTimeRemainingSec / 60);
  const sessionSecs = sessionTimeRemainingSec % 60;

  useEffect(() => {
    const media = window.matchMedia('(max-width: 767px)');
    const update = () => setIsMobileView(media.matches);
    media.addEventListener('change', update);
    return () => media.removeEventListener('change', update);
  }, []);

  const navSections = [
    {
      title: 'OPERATIONS',
      items: [
        { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
        { id: 'watchlist', label: 'Monitored Products', icon: Server, count: watchlist.length },
        { id: 'findings', label: 'Vulnerabilities', icon: ShieldAlert, count: activeFindingsCount },
        { id: 'threat-data', label: 'Threat Cache', icon: Database },
        { id: 'advisories', label: 'Advisories', icon: FileText },
      ],
    },
    {
      title: 'AUTONOMOUS PIPELINE',
      items: [
        { id: 'pipeline', label: 'Executions', icon: Activity },
        { id: 'alerted-cves', label: 'Sent History', icon: Bell },
        { id: 'feeds', label: 'Threat Feeds', icon: Radio, count: feeds.length },
        { id: 'recipients', label: 'Recipients & Webhooks', icon: Users },
        { id: 'template', label: 'HTML Template', icon: FileCode },
        { id: 'emails', label: 'Delivery Log', icon: Mail },
        { id: 'email-queue', label: 'Email Queue', icon: Inbox },
      ],
    },
    {
      title: 'SYSTEM & AUDIT',
      items: [
        { id: 'logs', label: 'Logs & Audit', icon: FileCode2 },
        { id: 'health', label: 'System Health', icon: Cpu },
        { id: 'settings', label: 'Settings', icon: Settings },
      ],
    },
  ];

  return (
    <>
    {mobileNavOpen && (
      <button
        type="button"
        aria-label="Close navigation menu"
        className="fixed inset-0 z-30 bg-black/60 md:hidden"
        onClick={() => setMobileNavOpen(false)}
      />
    )}
    <aside id="primary-navigation" aria-hidden={isMobileView && !mobileNavOpen} inert={isMobileView && !mobileNavOpen} className={`fixed inset-y-0 left-0 z-40 w-64 bg-zinc-950 dark:bg-zinc-950 light:bg-white border-r border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 flex flex-col shrink-0 select-none transition-transform duration-200 md:sticky md:top-0 md:h-screen md:translate-x-0 md:z-30 ${mobileNavOpen ? 'translate-x-0' : '-translate-x-full'}`}>
      {/* Brand Header */}
      <div className="p-4 border-b border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200">
        <button
          type="button"
          onClick={() => setActiveTab('dashboard')}
          className="flex items-center space-x-3 text-left cursor-pointer group"
          aria-label="VulnStream dashboard"
        >
          <div className="w-9 h-9 rounded-2xl bg-blue-500/15 border border-blue-400/25 flex items-center justify-center text-blue-200 shadow-sm transition group-hover:border-blue-400/50">
            <Shield className="w-4 h-4 text-blue-300" />
          </div>
          <div>
            <div className="flex items-center space-x-1.5">
              <span className="text-sm font-bold tracking-tight text-zinc-100 dark:text-zinc-100 light:text-zinc-900">
                Vuln<span className="text-zinc-400 dark:text-zinc-400 light:text-zinc-500">Stream</span>
              </span>
              <span className="text-[10px] font-semibold bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 px-1.5 py-0.2 rounded">
                Auto
              </span>
            </div>
            <div className="text-[10px] text-zinc-500 font-mono tracking-tight">
              Vulnerability Operations
            </div>
          </div>
        </button>
      </div>

      {/* Nav List with Sections & SVG Icons */}
      <nav aria-label="Primary navigation" className="flex-1 overflow-y-auto px-3 py-4 space-y-6">
        {navSections.map(section => (
          <div key={section.title}>
            <div className="px-3 mb-2 text-[10px] font-bold tracking-wider text-zinc-500 font-mono uppercase">
              {section.title}
            </div>
            <div className="space-y-0.5">
              {section.items.map(item => {
                const Icon = item.icon;
                const isActive = activeTab === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => setActiveTab(item.id)}
                    aria-current={isActive ? 'page' : undefined}
                    className={`w-full flex items-center justify-between px-3 py-2 rounded-xl text-xs font-medium transition duration-150 ${
                      isActive
                        ? 'bg-zinc-800 text-zinc-100 dark:bg-zinc-800 dark:text-zinc-100 light:bg-zinc-200 light:text-zinc-900 font-semibold shadow-sm'
                        : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900/60 dark:hover:bg-zinc-900/60 light:text-zinc-600 light:hover:text-zinc-900 light:hover:bg-zinc-100'
                    }`}
                  >
                    <div className="flex items-center space-x-2.5">
                      <Icon
                        className={`w-4 h-4 shrink-0 ${
                          isActive
                            ? 'text-zinc-200 dark:text-zinc-200 light:text-zinc-900'
                            : 'text-zinc-500 light:text-zinc-400'
                        }`}
                      />
                      <span className="truncate">{item.label}</span>
                    </div>

                    {item.count !== undefined && (
                      <span
                        className={`text-[10px] font-mono px-1.5 py-0.2 rounded-full ${
                          isActive
                            ? 'bg-zinc-700 text-zinc-100 dark:bg-zinc-700 dark:text-zinc-100 light:bg-zinc-300 light:text-zinc-900 font-bold'
                            : 'bg-zinc-900 text-zinc-500 dark:bg-zinc-900 dark:text-zinc-500 light:bg-zinc-200 light:text-zinc-600'
                        }`}
                      >
                        {item.count}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </nav>

      {/* Sidebar Footer: Theme Toggle & Session Security */}
      <div className="p-3 border-t border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 space-y-2 bg-zinc-950/60 dark:bg-zinc-950/60 light:bg-zinc-50">
        {/* Light / Dark Mode Toggle Button */}
        <button
          onClick={toggleTheme}
          className="w-full flex items-center justify-between px-3 py-1.5 rounded-xl text-xs text-zinc-400 hover:text-zinc-200 bg-zinc-900/80 dark:bg-zinc-900/80 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 light:text-zinc-700 light:hover:text-zinc-900 transition shadow-sm"
          title="Toggle light and dark mode"
          aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
          aria-pressed={theme === 'light'}
        >
          <div className="flex items-center space-x-2">
            {theme === 'dark' ? (
              <Moon className="w-3.5 h-3.5 text-zinc-300" />
            ) : (
              <Sun className="w-3.5 h-3.5 text-amber-500" />
            )}
            <span className="font-medium text-[11px]">
              {theme === 'dark' ? 'Dark Mode' : 'Light Mode'}
            </span>
          </div>
          <span className="text-[10px] font-mono text-zinc-500 uppercase">
            {theme === 'dark' ? 'Switch Light' : 'Switch Dark'}
          </span>
        </button>

        {/* Session Security Indicator */}
        <button
          type="button"
          onClick={() => void resetSessionTimeout()}
          className="w-full flex items-center justify-between px-3 py-1.5 rounded-xl text-[11px] font-mono text-zinc-500 bg-zinc-900/40 dark:bg-zinc-900/40 light:bg-zinc-100 hover:text-zinc-300 transition focus-visible:outline focus-visible:outline-2 focus-visible:outline-zinc-400"
          title="Renew session"
          aria-label={`Renew session, ${sessionMins} minutes and ${sessionSecs} seconds remaining`}
        >
          <div className="flex items-center space-x-1.5">
            <KeyRound className="w-3 h-3 text-zinc-500" />
            <span>Session:</span>
          </div>
          <span className="text-zinc-300 dark:text-zinc-300 light:text-zinc-700 font-bold">
            {String(sessionMins).padStart(2, '0')}:{String(sessionSecs).padStart(2, '0')}
          </span>
        </button>

        {/* NTP & Live Status */}
        <div className="flex items-center justify-between px-3 py-1 text-[10px] font-mono text-zinc-500">
          <div className="flex items-center space-x-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
            <span>Server-backed session</span>
          </div>
          <span>Authenticated</span>
        </div>
      </div>
    </aside>
    </>
  );
};
