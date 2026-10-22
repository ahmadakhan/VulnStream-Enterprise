import React, { useState, useEffect } from 'react';
import { useApp } from '../context/AppContext';
import { Archive, Calendar, Clock, RotateCw, Settings, AlertCircle, CheckCircle } from 'lucide-react';

interface RetentionConfig {
  enabled: boolean;
  retentionHours: number;
  cleanupIntervalMinutes: number;
  maxArchivedRecords: number;
  autoCleanup: boolean;
  retentionMode: 'strict' | 'rolling' | 'checkpoints';
}

interface ArchiveStats {
  totalArchived: number;
  oldestRecord: string;
  newestRecord: string;
  storageSize: number;
  lastCleanup: string;
}

export const ArchiveRetentionView: React.FC = () => {
  const { settings, updateSettings } = useApp();
  const [config, setConfig] = useState<RetentionConfig>(
    settings?.retentionConfig || {
      enabled: false,
      retentionHours: 24,
      cleanupIntervalMinutes: 60,
      maxArchivedRecords: 10000,
      autoCleanup: true,
      retentionMode: 'rolling',
    }
  );
  const [isLoading, setIsLoading] = useState(false);
  const [lastOperation, setLastOperation] = useState<string>('');
  const [stats, setStats] = useState<ArchiveStats | null>(null);
  const [isDirty, setIsDirty] = useState(false);

  useEffect(() => {
    loadStats();
  }, []);

  const loadStats = async () => {
    try {
      // This would call an API to get archive stats
      // For now, simulating the API call
      const simulatedStats: ArchiveStats = {
        totalArchived: Math.floor(Math.random() * 50000),
        oldestRecord: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000).toISOString(),
        newestRecord: new Date(Date.now() - Math.random() * 60 * 60 * 1000).toISOString(),
        storageSize: Math.floor(Math.random() * 2000) / 10, // GB
        lastCleanup: new Date(Date.now() - Math.random() * 24 * 60 * 60 * 1000).toISOString(),
      };
      setStats(simulatedStats);
    } catch (error) {
      console.error('Failed to load archive stats:', error);
    }
  };

  const handleConfigChange = (field: keyof RetentionConfig, value: any) => {
    setConfig(prev => ({ ...prev, [field]: value }));
    setIsDirty(true);
  };

  const handleSaveConfig = async () => {
    setIsLoading(true);
    try {
      // This would call an API to save the config
      await new Promise(resolve => setTimeout(resolve, 1000));
      setLastOperation('Configuration saved successfully');
      setIsDirty(false);
    } catch (error) {
      setLastOperation('Failed to save configuration');
    } finally {
      setIsLoading(false);
    }
  };

  const handleManualCleanup = async () => {
    setIsLoading(true);
    try {
      // This would call an API to trigger manual cleanup
      await new Promise(resolve => setTimeout(resolve, 2000));
      await loadStats();
      setLastOperation('Manual cleanup completed successfully');
    } catch (error) {
      setLastOperation('Manual cleanup failed');
    } finally {
      setIsLoading(false);
    }
  };

  const formatDateTime = (dateString: string) => {
    return new Date(dateString).toLocaleString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 flex items-center gap-2">
            <Archive className="w-6 h-6 text-zinc-400" />
            Archive & Retention Management
          </h1>
          <p className="text-sm text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mt-1">
            Manage data retention policies, archive configurations, and automatic cleanup schedules.
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={handleManualCleanup}
            disabled={isLoading || !config.enabled}
            className="px-4 py-2 bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 hover:bg-zinc-700 dark:hover:bg-zinc-700 light:hover:bg-zinc-300 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 border border-zinc-700 dark:border-zinc-700 light:border-zinc-300 rounded-xl font-medium transition disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
          >
            <RotateCw className="w-4 h-4" />
            Manual Cleanup
          </button>
          <button
            onClick={handleSaveConfig}
            disabled={isLoading || !isDirty}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-xl font-medium transition disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
          >
            <Settings className="w-4 h-4" />
            Save Configuration
          </button>
        </div>
      </div>

      {/* Status Message */}
      {lastOperation && (
        <div className={`rounded-lg border px-4 py-3 text-sm ${lastOperation.includes('successfully') ? 'border-emerald-800 bg-emerald-950/40 text-emerald-300' : 'border-rose-800 bg-rose-950/40 text-rose-300'}`}
        role={lastOperation.includes('successfully') ? 'status' : 'alert'}
        >
          <div className="flex items-center gap-2">
            {lastOperation.includes('successfully') ? (
              <CheckCircle className="w-4 h-4" />
            ) : (
              <AlertCircle className="w-4 h-4" />
            )}
            {lastOperation}
          </div>
        </div>
      )}

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Configuration Panel */}
        <div className="lg:col-span-2 bg-zinc-900/50 dark:bg-zinc-900/50 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl p-6 shadow-sm transition-colors">
          <h2 className="text-lg font-semibold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 mb-4 flex items-center gap-2">
            <Settings className="w-5 h-5 text-zinc-400" />
            Retention Configuration
          </h2>

          <div className="space-y-5">
            {/* General Settings */}
            <div className="space-y-3">
              <h3 className="text-sm font-medium text-zinc-200 dark:text-zinc-200 light:text-zinc-800">General Settings</h3>
              <div className="grid grid-cols-2 gap-4">
                <label className="space-y-1.5">
                  <span className="block text-xs font-medium text-zinc-300">Retention Period (Hours)</span>
                  <input
                    type="number"
                    min="1"
                    max="8760"
                    value={config.retentionHours}
                    onChange={(e) => handleConfigChange('retentionHours', Number(e.target.value))}
                    className="w-full px-3 py-2 bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl text-sm text-zinc-100 focus:border-blue-500 focus:outline-none transition"
                  />
                </label>
                <label className="space-y-1.5">
                  <span className="block text-xs font-medium text-zinc-300">Max Archived Records</span>
                  <input
                    type="number"
                    min="1000"
                    max="1000000"
                    value={config.maxArchivedRecords}
                    onChange={(e) => handleConfigChange('maxArchivedRecords', Number(e.target.value))}
                    className="w-full px-3 py-2 bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl text-sm text-zinc-100 focus:border-blue-500 focus:outline-none transition"
                  />
                </label>
              </div>
            </div>

            {/* Cleanup Schedule */}
            <div className="space-y-3">
              <h3 className="text-sm font-medium text-zinc-200 dark:text-zinc-200 light:text-zinc-800">Cleanup Schedule</h3>
              <div className="space-y-3">
                <label className="flex items-center space-x-2">
                  <input
                    type="checkbox"
                    checked={config.enabled}
                    onChange={(e) => handleConfigChange('enabled', e.target.checked)}
                    className="w-4 h-4 rounded border-zinc-700 bg-zinc-950 focus:ring-blue-500 focus:ring-2"
                  />
                  <span className="text-sm text-zinc-300">Enable automatic cleanup</span>
                </label>
                <label className="space-y-1.5">
                  <span className="block text-xs font-medium text-zinc-300">Cleanup Interval (Minutes)</span>
                  <input
                    type="number"
                    min="1"
                    max="1440"
                    value={config.cleanupIntervalMinutes}
                    onChange={(e) => handleConfigChange('cleanupIntervalMinutes', Number(e.target.value))}
                    disabled={!config.enabled}
                    className="w-full px-3 py-2 bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl text-sm text-zinc-100 focus:border-blue-500 focus:outline-none transition disabled:opacity-50 disabled:cursor-not-allowed"
                  />
                </label>
                <div className="flex gap-3">
                  <label className="flex items-center space-x-2">
                    <input
                      type="radio"
                      name="retentionMode"
                      value="strict"
                      checked={config.retentionMode === 'strict'}
                      onChange={() => handleConfigChange('retentionMode', 'strict')}
                      className="w-4 h-4 border-zinc-700 bg-zinc-950 focus:ring-blue-500 focus:ring-2"
                    />
                    <span className="text-sm text-zinc-300">Strict</span>
                  </label>
                  <label className="flex items-center space-x-2">
                    <input
                      type="radio"
                      name="retentionMode"
                      value="rolling"
                      checked={config.retentionMode === 'rolling'}
                      onChange={() => handleConfigChange('retentionMode', 'rolling')}
                      className="w-4 h-4 border-zinc-700 bg-zinc-950 focus:ring-blue-500 focus:ring-2"
                    />
                    <span className="text-sm text-zinc-300">Rolling</span>
                  </label>
                  <label className="flex items-center space-x-2">
                    <input
                      type="radio"
                      name="retentionMode"
                      value="checkpoints"
                      checked={config.retentionMode === 'checkpoints'}
                      onChange={() => handleConfigChange('retentionMode', 'checkpoints')}
                      className="w-4 h-4 border-zinc-700 bg-zinc-950 focus:ring-blue-500 focus:ring-2"
                    />
                    <span className="text-sm text-zinc-300">Checkpoints</span>
                  </label>
                </div>
              </div>
            </div>

            {/* Auto Cleanup Toggle */}
            <div className="space-y-3">
              <h3 className="text-sm font-medium text-zinc-200 dark:text-zinc-200 light:text-zinc-800">Auto Cleanup Settings</h3>
              <label className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  checked={config.autoCleanup}
                  onChange={(e) => handleConfigChange('autoCleanup', e.target.checked)}
                  className="w-4 h-4 rounded border-zinc-700 bg-zinc-950 focus:ring-blue-500 focus:ring-2"
                />
                <span className="text-sm text-zinc-300">Enable automatic cleanup</span>
              </label>
            </div>
          </div>
        </div>

        {/* Stats Panel */}
        <div className="space-y-4">
          <div className="bg-zinc-900/50 dark:bg-zinc-900/50 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl p-5 shadow-sm transition-colors">
            <h2 className="text-lg font-semibold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 mb-4 flex items-center gap-2">
              <Calendar className="w-5 h-5 text-zinc-400" />
              Archive Statistics
            </h2>
            {stats ? (
              <div className="space-y-4">
                <div className="flex justify-between items-center">
                  <span className="text-sm text-zinc-400">Total Archived Records</span>
                  <span className="text-sm font-medium text-zinc-200">{stats.totalArchived.toLocaleString()}</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-sm text-zinc-400">Storage Size</span>
                  <span className="text-sm font-medium text-zinc-200">{stats.storageSize.toFixed(1)} GB</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-sm text-zinc-400">Oldest Record</span>
                  <span className="text-sm font-medium text-zinc-200">{formatDateTime(stats.oldestRecord)}</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-sm text-zinc-400">Newest Record</span>
                  <span className="text-sm font-medium text-zinc-200">{formatDateTime(stats.newestRecord)}</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-sm text-zinc-400">Last Cleanup</span>
                  <span className="text-sm font-medium text-emerald-400">{formatDateTime(stats.lastCleanup)}</span>
                </div>
              </div>
            ) : (
              <div className="text-center py-8">
                <Clock className="w-8 h-8 text-zinc-600 mx-auto mb-2" />
                <p className="text-sm text-zinc-500">Statistics loading...</p>
              </div>
            )}
          </div>

          <div className="bg-zinc-900/50 dark:bg-zinc-900/50 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl p-5 shadow-sm transition-colors">
            <h2 className="text-lg font-semibold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 mb-4">
              Retention Modes
            </h2>
            <div className="space-y-3 text-sm">
              <div className="p-3 bg-zinc-950/50 dark:bg-zinc-950/50 light:bg-zinc-100 rounded-lg border border-zinc-800 dark:border-zinc-800 light:border-zinc-300">
                <div className="font-medium text-zinc-200 mb-1">Strict Mode</div>
                <div className="text-xs text-zinc-400">Delete records older than configured retention period without exception.</div>
              </div>
              <div className="p-3 bg-zinc-950/50 dark:bg-zinc-950/50 light:bg-zinc-100 rounded-lg border border-zinc-800 dark:border-zinc-800 light:border-zinc-300">
                <div className="font-medium text-zinc-200 mb-1">Rolling Mode</div>
                <div className="text-xs text-zinc-400">Delete oldest records when approaching max limit.</div>
              </div>
              <div className="p-3 bg-zinc-950/50 dark:bg-zinc-950/50 light:bg-zinc-100 rounded-lg border border-zinc-800 dark:border-zinc-800 light:border-zinc-300">
                <div className="font-medium text-zinc-200 mb-1">Checkpoint Mode</div>
                <div className="text-xs text-zinc-400">Preserve checkpoints and delete only data between checkpoints.</div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Information Panel */}
      <div className="bg-blue-950/20 dark:bg-blue-950/20 light:bg-blue-50 border border-blue-800/50 dark:border-blue-800/50 light:border-blue-300 rounded-2xl p-5">
        <div className="flex items-start gap-3">
          <AlertCircle className="w-5 h-5 text-blue-400 mt-0.5" />
          <div className="text-sm">
            <div className="font-medium text-blue-300 mb-1">Archive & Retention Features</div>
            <div className="text-blue-200 space-y-1">
              <p>• Automatic cleanup of old records based on retention policies</p>
              <p>• Configurable retention periods (1 hour to 1 year)</p>
              <p>• Multiple retention modes (strict, rolling, checkpoints)</p>
             “• Scheduled cleanup jobs to optimize storage usage
              <p>• Monitoring and statistics for archive management</p>
              <p>• Manual cleanup triggers for emergency situations</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
