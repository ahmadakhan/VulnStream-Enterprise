import React, { useState } from 'react';
import { useApp } from '../context/AppContext';
import { ThreatFeed, FeedType, FeedAuthType } from '../types';
import {
  Radio,
  Plus,
  CheckCircle2,
  Lock,
  Trash2,
  Edit2,
  Search,
  RotateCw,
  ShieldCheck,
  X,
  Zap,
} from 'lucide-react';

export const ThreatFeedsView: React.FC = () => {
  const {
    feeds,
    toggleFeedEnabled,
    testFeedConnectivity,
    addFeed,
    updateFeed,
    deleteFeed,
  } = useApp();

  const [searchTerm, setSearchTerm] = useState('');
  const [testingId, setTestingId] = useState<string | null>(null);
  const [testMessage, setTestMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [showAddModal, setShowAddModal] = useState(false);
  const [editingFeed, setEditingFeed] = useState<ThreatFeed | null>(null);
  const [deletingFeed, setDeletingFeed] = useState<ThreatFeed | null>(null);

  const [formData, setFormData] = useState({
    name: '',
    type: 'JSON_SEARCH_API' as FeedType,
    url: '',
    authType: 'NONE' as FeedAuthType,
    authSecretKey: '',
    rateLimitPerMin: 60,
    enabled: true,
  });

  const [formError, setFormError] = useState<string | null>(null);

  const filteredFeeds = feeds.filter(feed =>
    feed.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    feed.type.toLowerCase().includes(searchTerm.toLowerCase()) ||
    feed.url.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const handleTest = async (feedId: string) => {
    const feed = feeds.find((f) => f.id === feedId);
    setTestingId(feedId);
    setTestMessage(null);
    const result = await testFeedConnectivity(feedId);
    setTestingId(null);
    if (result?.success) {
      setTestMessage({
        type: 'success',
        text: `${feed?.name || 'Feed'} connectivity OK (${result.latency}ms)`,
      });
    } else if (result?.error) {
      setTestMessage({
        type: 'error',
        text: `${feed?.name || 'Feed'} test failed: ${result.error}`,
      });
    } else {
      setTestMessage({
        type: 'error',
        text: `${feed?.name || 'Feed'} test failed. See error banner for details.`,
      });
    }
    setTimeout(() => setTestMessage(null), 8000);
  };

  const handleOpenAdd = () => {
    setFormData({
      name: '',
      type: 'JSON_SEARCH_API',
      url: 'https://',
      authType: 'NONE',
      authSecretKey: '',
      rateLimitPerMin: 60,
      enabled: true,
    });
    setEditingFeed(null);
    setFormError(null);
    setShowAddModal(true);
  };

  const handleOpenEdit = (feed: ThreatFeed) => {
    setFormData({
      name: feed.name,
      type: feed.type,
      url: feed.url,
      authType: feed.authType,
      authSecretKey: feed.authSecretKey || '',
      rateLimitPerMin: feed.rateLimitPerMin,
      enabled: feed.enabled,
    });
    setEditingFeed(feed);
    setFormError(null);
    setShowAddModal(true);
  };

  const handleSaveFeed = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);

    if (editingFeed) {
      const ok = await updateFeed({
        ...editingFeed,
        name: formData.name,
        type: formData.type,
        url: formData.url,
        authType: formData.authType,
        authSecretKey: formData.authSecretKey || undefined,
        rateLimitPerMin: formData.rateLimitPerMin,
        enabled: formData.enabled,
      });
      if (ok) {
        setShowAddModal(false);
      } else {
        setFormError('Failed to update feed. Please check the form values and try again.');
      }
    } else {
      const ok = await addFeed({
        name: formData.name,
        type: formData.type,
        url: formData.url,
        authType: formData.authType,
        authSecretKey: formData.authSecretKey || undefined,
        rateLimitPerMin: formData.rateLimitPerMin,
        enabled: formData.enabled,
        vendorSeed: false,
      });
      if (ok) {
        setShowAddModal(false);
      } else {
        setFormError('Failed SSRF validation: URL must not point to private/loopback IP address or include credentials.');
      }
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 tracking-tight flex items-center gap-2">
            <Radio className="w-5 h-5 text-zinc-300 dark:text-zinc-300 light:text-zinc-700" />
            Configurable Threat Feed Ingestion Sources
          </h1>
          <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mt-1">
            Pre-seeded with 16 vendor feeds plus NVD, CISA KEV, and EPSS. Autonomous scheduler polls active feeds without human intervention.
          </p>
        </div>

        <button
          onClick={handleOpenAdd}
          className="text-xs px-3.5 py-1.5 rounded-xl bg-zinc-100 hover:bg-zinc-200 dark:bg-zinc-100 dark:hover:bg-zinc-200 light:bg-zinc-900 light:hover:bg-zinc-800 text-zinc-900 dark:text-zinc-900 light:text-zinc-50 font-semibold transition flex items-center space-x-1.5 shadow-sm"
        >
          <Plus className="w-3.5 h-3.5" />
          <span>Add Threat Feed</span>
        </button>
      </div>

      {/* Search & Stats Bar */}
      <div className="bg-zinc-900/50 dark:bg-zinc-900/50 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl p-4 flex flex-col sm:flex-row items-center justify-between gap-3 shadow-sm transition-colors">
        <div className="relative w-full sm:w-80">
          <Search className="w-4 h-4 text-zinc-500 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search feeds by vendor, protocol, or URL..."
            value={searchTerm}
            onChange={e => setSearchTerm(e.target.value)}
            className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl pl-9 pr-3 py-1.5 text-xs text-zinc-100 dark:text-zinc-100 light:text-zinc-900 placeholder-zinc-500 focus:outline-none focus:border-zinc-600 transition"
          />
        </div>

        <div className="flex items-center space-x-4 text-xs font-mono">
          <div className="flex items-center space-x-1.5 text-emerald-400">
            <CheckCircle2 className="w-3.5 h-3.5" />
            <span className="text-zinc-300 dark:text-zinc-300 light:text-zinc-700">{feeds.filter(f => f.enabled).length} Active Feeds</span>
          </div>
          <div className="flex items-center space-x-1.5 text-zinc-400 dark:text-zinc-400 light:text-zinc-600">
            <ShieldCheck className="w-3.5 h-3.5 text-zinc-400" />
            <span>SSRF Guard: Enforced</span>
          </div>
        </div>
      </div>

      {testMessage && (
        <div
          className={`mb-4 px-4 py-2.5 rounded-xl text-xs font-mono flex items-center space-x-2 ${
            testMessage.type === 'success'
              ? 'bg-emerald-950/40 border border-emerald-800 text-emerald-300'
              : 'bg-red-950/40 border border-red-800 text-red-300'
          }`}
        >
          <Zap className="w-3.5 h-3.5 flex-shrink-0" />
          <span>{testMessage.text}</span>
        </div>
      )}

      {/* Threat Feeds Table */}
      <div className="bg-zinc-900/50 dark:bg-zinc-900/50 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl overflow-hidden shadow-sm transition-colors">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-zinc-950/80 dark:bg-zinc-950/80 light:bg-zinc-100 border-b border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 text-zinc-400 dark:text-zinc-400 light:text-zinc-600 font-mono uppercase text-[11px]">
              <tr>
                <th className="py-3 px-4">Feed Source / Vendor</th>
                <th className="py-3 px-4">Protocol &amp; Format</th>
                <th className="py-3 px-4">Endpoint URL</th>
                <th className="py-3 px-4">Auth &amp; Rate Limit</th>
                <th className="py-3 px-4">Health &amp; Latency</th>
                <th className="py-3 px-4">Active</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/60 dark:divide-zinc-800/60 light:divide-zinc-200">
              {filteredFeeds.map(feed => {
                const isTesting = testingId === feed.id;

                return (
                  <tr key={feed.id} className="hover:bg-zinc-800/30 dark:hover:bg-zinc-800/30 light:hover:bg-zinc-50 transition">
                    {/* Feed Name */}
                    <td className="py-3 px-4 font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900">
                      <div className="flex items-center space-x-2">
                        <span>{feed.name}</span>
                        {feed.vendorSeed && (
                          <span className="text-[9px] bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 text-zinc-400 dark:text-zinc-400 light:text-zinc-600 px-1.5 py-0.2 rounded font-mono">
                            Seed
                          </span>
                        )}
                      </div>
                      <div className="text-[10px] text-zinc-500 font-mono mt-0.5">
                        Last Run Ingested: {feed.itemCountLastRun || 0} items
                      </div>
                    </td>

                    {/* Format */}
                    <td className="py-3 px-4 font-mono text-[11px] text-zinc-300 dark:text-zinc-300 light:text-zinc-700">
                      {feed.type}
                    </td>

                    {/* URL */}
                    <td className="py-3 px-4 max-w-xs truncate font-mono text-[11px] text-zinc-400 dark:text-zinc-400 light:text-zinc-600" title={feed.url}>
                      {feed.url}
                    </td>

                    {/* Auth */}
                    <td className="py-3 px-4 font-mono text-[11px]">
                      <div className="flex items-center space-x-1 text-zinc-300 dark:text-zinc-300 light:text-zinc-700">
                        {feed.authType !== 'NONE' && <Lock className="w-3 h-3 text-zinc-400" />}
                        <span>{feed.authType}</span>
                      </div>
                      <div className="text-[10px] text-zinc-500">
                        Max {feed.rateLimitPerMin} req/min
                      </div>
                    </td>

                      {/* Health & Latency */}
                      <td className="py-3 px-4 font-mono">
                        <div className="flex items-center space-x-1.5">
                          <span
                            className={`w-2 h-2 rounded-full ${
                              feed.healthStatus === 'HEALTHY'
                                ? 'bg-emerald-500'
                                : 'bg-zinc-500'
                            }`}
                          />
                          <span className="text-zinc-200 dark:text-zinc-200 light:text-zinc-900 font-semibold text-[11px]">
                            {feed.healthStatus}
                          </span>
                          <span className="text-zinc-500 text-[10px]">
                            ({feed.latencyMs}ms)
                          </span>
                        </div>
                        {feed.healthStatus !== 'HEALTHY' && feed.errorLog && (
                          <div className="text-[10px] text-red-400 mt-0.5 max-w-xs truncate" title={feed.errorLog}>
                            {feed.errorLog}
                          </div>
                        )}
                      </td>

                    {/* Active toggle */}
                    <td className="py-3 px-4">
                      <button
                        onClick={() => toggleFeedEnabled(feed.id)}
                        className={`w-8 h-4 flex items-center rounded-full p-0.5 transition ${
                          feed.enabled ? 'bg-zinc-200 dark:bg-zinc-200 light:bg-zinc-900 justify-end' : 'bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-300 justify-start'
                        }`}
                        title={feed.enabled ? 'Disable Feed' : 'Enable Feed'}
                      >
                        <span className="bg-zinc-950 dark:bg-zinc-950 light:bg-white w-3 h-3 rounded-full shadow-sm" />
                      </button>
                    </td>

                    {/* Actions */}
                    <td className="py-3 px-4 text-right space-x-1.5">
                      <button
                        onClick={() => handleTest(feed.id)}
                        disabled={isTesting}
                        className="px-2.5 py-1 rounded-xl bg-zinc-800 hover:bg-zinc-700 dark:bg-zinc-800 dark:hover:bg-zinc-700 light:bg-zinc-200 light:hover:bg-zinc-300 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 border border-zinc-700 dark:border-zinc-700 light:border-zinc-300 text-[11px] font-medium transition inline-flex items-center space-x-1"
                        title="Ping Endpoint & Test SSRF"
                      >
                        {isTesting ? (
                          <RotateCw className="w-3 h-3 animate-spin text-zinc-400" />
                        ) : (
                          <Zap className="w-3 h-3 text-zinc-400" />
                        )}
                        <span>{isTesting ? 'Testing...' : 'Test'}</span>
                      </button>
                      <button
                        onClick={() => handleOpenEdit(feed)}
                        className="p-1 text-zinc-400 hover:text-zinc-200 dark:hover:text-zinc-200 light:hover:text-zinc-900 transition"
                        title="Edit Feed"
                      >
                        <Edit2 className="w-3.5 h-3.5" />
                      </button>
                      {!feed.vendorSeed && (
                        <button
                          onClick={() => setDeletingFeed(feed)}
                          className="p-1 text-zinc-400 hover:text-red-400 transition"
                          title="Delete Feed"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add / Edit Custom Feed Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="bg-zinc-900 border border-zinc-800 rounded-2xl max-w-lg w-full p-6 shadow-2xl relative">
            <button
              onClick={() => setShowAddModal(false)}
              className="absolute top-4 right-4 text-zinc-500 hover:text-zinc-200"
            >
              <X className="w-5 h-5" />
            </button>

            <h2 className="text-base font-bold text-zinc-100 mb-1 flex items-center gap-2">
              <Radio className="w-4 h-4 text-zinc-300" />
              {editingFeed ? 'Edit Threat Feed Source' : 'Register Custom Threat Feed'}
            </h2>
            <p className="text-xs text-zinc-400 mb-4">
              Endpoints are protected against SSRF attacks. Secrets are encrypted with AES-256-GCM. Destination hosts must be allowed by the deployment administrator.
            </p>

            {formError && (
              <div className="bg-zinc-950 border border-zinc-700 text-zinc-300 text-xs p-3 rounded-xl mb-4">
                {formError}
              </div>
            )}

            <form onSubmit={handleSaveFeed} className="space-y-4 text-xs">
              <div>
                <label className="block text-zinc-400 mb-1 font-mono">Feed Name *</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Mandiant Threat Intel Stream"
                  value={formData.name}
                  onChange={e => setFormData({ ...formData, name: e.target.value })}
                  className="w-full bg-zinc-950 border border-zinc-800 rounded-xl p-2.5 text-zinc-100 font-mono focus:border-zinc-600 focus:outline-none"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-zinc-400 mb-1 font-mono">Protocol / Format *</label>
                  <select
                    value={formData.type}
                    onChange={e => setFormData({ ...formData, type: e.target.value as FeedType })}
                    className="w-full bg-zinc-950 border border-zinc-800 rounded-xl p-2.5 text-zinc-200 font-mono focus:border-zinc-600 focus:outline-none"
                  >
                    <option value="JSON_SEARCH_API">Normalized CVE JSON array</option>
                    <option value="NVD_API">NVD CVE API 2.0</option>
                    <option value="CISA_KEV">CISA KEV JSON catalog</option>
                    <option value="EPSS_API">FIRST EPSS API</option>
                  </select>
                </div>

                <div>
                  <label className="block text-zinc-400 mb-1 font-mono">Rate Limit (req/min)</label>
                  <input
                    type="number"
                    min={1}
                    max={600}
                    value={formData.rateLimitPerMin}
                    onChange={e => setFormData({ ...formData, rateLimitPerMin: Number(e.target.value) })}
                    className="w-full bg-zinc-950 border border-zinc-800 rounded-xl p-2.5 text-zinc-100 font-mono focus:border-zinc-600 focus:outline-none"
                  />
                </div>
              </div>

              <div>
                <label className="block text-zinc-400 mb-1 font-mono">Endpoint URL *</label>
                <input
                  type="url"
                  required
                  placeholder="https://feed.provider.org/threats.json"
                  value={formData.url}
                  onChange={e => setFormData({ ...formData, url: e.target.value })}
                  className="w-full bg-zinc-950 border border-zinc-800 rounded-xl p-2.5 text-zinc-100 font-mono focus:border-zinc-600 focus:outline-none"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-zinc-400 mb-1 font-mono">Authentication Type</label>
                  <select
                    value={formData.authType}
                    onChange={e => setFormData({ ...formData, authType: e.target.value as FeedAuthType })}
                    className="w-full bg-zinc-950 border border-zinc-800 rounded-xl p-2.5 text-zinc-200 font-mono focus:border-zinc-600 focus:outline-none"
                  >
                    <option value="NONE">None (Public)</option>
                    <option value="API_KEY">API Key Header</option>
                    <option value="BEARER">Bearer Token</option>
                    <option value="BASIC">HTTP Basic Auth</option>
                  </select>
                </div>

                <div>
                  <label className="block text-zinc-400 mb-1 font-mono">Secret Key / Token</label>
                  <input
                    type="password"
                    placeholder={formData.authType === 'NONE' ? 'Not required' : formData.authType === 'BASIC' ? 'username:password' : editingFeed ? 'Leave blank to retain existing secret' : 'Enter key...'}
                    disabled={formData.authType === 'NONE'}
                    value={formData.authSecretKey}
                    onChange={e => setFormData({ ...formData, authSecretKey: e.target.value })}
                    className="w-full bg-zinc-950 border border-zinc-800 rounded-xl p-2.5 text-zinc-100 font-mono focus:border-zinc-600 focus:outline-none disabled:opacity-40"
                  />
                </div>
              </div>

              <div className="flex justify-end space-x-2 pt-3 border-t border-zinc-800">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-3 py-1.5 rounded-xl bg-zinc-800 hover:bg-zinc-700 text-zinc-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded-xl bg-zinc-100 hover:bg-zinc-200 text-zinc-900 font-semibold"
                >
                  {editingFeed ? 'Save Changes' : 'Save Feed'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Delete Feed Confirmation Modal */}
      {deletingFeed && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="bg-zinc-900 border border-zinc-800 rounded-2xl max-w-sm w-full p-6 shadow-2xl relative">
            <h3 className="text-sm font-bold text-zinc-100 mb-2">Delete Threat Feed Source?</h3>
            <p className="text-xs text-zinc-400 leading-relaxed mb-6">
              Are you sure you want to remove <strong>{deletingFeed.name}</strong>? Automated polling for this endpoint will terminate immediately.
            </p>
            <div className="flex justify-end space-x-2">
              <button
                type="button"
                onClick={() => setDeletingFeed(null)}
                className="px-3 py-1.5 rounded-xl bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-xs font-medium"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => {
                  deleteFeed(deletingFeed.id);
                  setDeletingFeed(null);
                }}
                className="px-3 py-1.5 rounded-xl bg-red-600 hover:bg-red-500 text-white text-xs font-semibold"
              >
                Delete Feed
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
