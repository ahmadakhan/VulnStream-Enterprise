import React from 'react';
import { LoginView } from './components/LoginView';
import { AppProvider, useApp } from './context/AppContext';
import { ErrorBoundary } from './components/ErrorBoundary';
import { Sidebar } from './components/Sidebar';
import { TopHeader } from './components/TopHeader';
import { DashboardView } from './components/DashboardView';
import { WatchListView } from './components/WatchListView';
import { FindingsView } from './components/FindingsView';
import { ThreatDataView } from './components/ThreatDataView';
import { AdvisoriesView } from './components/AdvisoriesView';
import { PipelineExecutionsView } from './components/PipelineExecutionsView';
import { AlertedCVEsView } from './components/AlertedCVEsView';
import { ThreatFeedsView } from './components/ThreatFeedsView';
import { RecipientsView } from './components/RecipientsView';
import { AdvisoryTemplateView } from './components/AdvisoryTemplateView';
import { EmailHistoryView } from './components/EmailHistoryView';
import { OperationalLogsView } from './components/OperationalLogsView';
import { SystemHealthView } from './components/SystemHealthView';
import { SettingsView } from './components/SettingsView';

const MainContent: React.FC = () => {
  const { activeTab } = useApp();

  return (
    <main className="flex-1 px-4 sm:px-6 lg:px-8 py-6 pb-16 overflow-y-auto">
      {activeTab === 'dashboard' && <DashboardView />}
      {activeTab === 'watchlist' && <WatchListView />}
      {activeTab === 'findings' && <FindingsView />}
      {activeTab === 'threat-data' && <ThreatDataView />}
      {activeTab === 'advisories' && <AdvisoriesView />}
      {activeTab === 'pipeline' && <PipelineExecutionsView />}
      {activeTab === 'alerted-cves' && <AlertedCVEsView />}
      {activeTab === 'feeds' && <ThreatFeedsView />}
      {activeTab === 'recipients' && <RecipientsView />}
      {activeTab === 'template' && <AdvisoryTemplateView />}
      {activeTab === 'emails' && <EmailHistoryView />}
      {activeTab === 'logs' && <OperationalLogsView />}
      {activeTab === 'health' && <SystemHealthView />}
      {activeTab === 'settings' && <SettingsView />}
    </main>
  );
};

const Footer: React.FC = () => {
  return (
    <footer className="border-t border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 bg-zinc-950/80 dark:bg-zinc-950/80 light:bg-white py-4 text-xs text-zinc-500 transition-colors duration-200">
      <div className="px-6 flex flex-col sm:flex-row items-center justify-between gap-3 font-mono text-[11px]">
        <div className="flex items-center space-x-2">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
          <span className="text-zinc-400 dark:text-zinc-400 light:text-zinc-600">
            VulnStream Enterprise
          </span>
          <span>•</span>
          <span>PostgreSQL persistence</span>
        </div>
        <div className="flex items-center space-x-3 text-zinc-500">
          <span>Server scheduler</span>
          <span>•</span>
          <span>Strict CPE 2.3 + PURL</span>
          <span>•</span>
          <span>Role-based access</span>
        </div>
      </div>
    </footer>
  );
};

const AppShell: React.FC = () => {
  const { theme, session, loading, error, clearError, logout, pending } = useApp();
  if (loading || !session) return <LoginView />;

  return (
    <div
      className={`min-h-screen flex selection:bg-zinc-800 selection:text-zinc-100 transition-colors duration-200 ${
        theme === 'dark' ? 'dark bg-[#09090b] text-zinc-100' : 'light bg-zinc-50 text-zinc-900'
      }`}
    >
      {/* Left Side Panel Navigation */}
      <Sidebar />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 min-h-screen">
        <TopHeader />
        <div className="px-6 py-2 flex justify-between text-xs border-b border-zinc-700">
          <span>{session.username} · {session.role}{pending > 0 ? ' · Saving…' : ''}</span>
          <button onClick={() => void logout()}>Sign out</button>
        </div>
        {error && <div role="alert" className="px-6 py-3 bg-red-950 text-red-100">{error} <button onClick={clearError} className="underline ml-3">Dismiss</button></div>}
        <div className="flex-1 flex flex-col max-w-7xl w-full mx-auto">
          <MainContent />
          <Footer />
        </div>
      </div>
    </div>
  );
};

export default function App() {
  return (
    <ErrorBoundary>
      <AppProvider>
        <AppShell />
      </AppProvider>
    </ErrorBoundary>
  );
}
