import React, { useState } from 'react';
import { useApp } from '../context/AppContext';
import { EmailRecipient, WebhookEndpoint } from '../types';
import {
  Users,
  Plus,
  Trash2,
  Mail,
  AlertCircle,
  X,
  Search,
  Webhook,
  Send,
  CheckCircle2,
  ShieldCheck,
  Zap,
  Lock,
} from 'lucide-react';

export const RecipientsView: React.FC = () => {
  const {
    recipients,
    addRecipient,
    toggleRecipientEnabled,
    deleteRecipient,
    webhooks,
    addWebhook,
    toggleWebhookEnabled,
    deleteWebhook,
    testWebhook,
  } = useApp();

  const [activeTab, setActiveTab] = useState<'email' | 'webhooks'>('email');
  const [searchTerm, setSearchTerm] = useState('');
  const [showAddEmailModal, setShowAddEmailModal] = useState(false);
  const [showAddWebhookModal, setShowAddWebhookModal] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const [deletingRecipientId, setDeletingRecipientId] = useState<string | null>(null);
  const [deletingWebhookId, setDeletingWebhookId] = useState<string | null>(null);

  // Email form state
  const [emailForm, setEmailForm] = useState({
    name: '',
    email: '',
    role: '',
    subscriptionTier: 'CRITICAL_HIGH_ONLY' as EmailRecipient['subscriptionTier'],
    enabled: true,
  });

  // Webhook form state
  const [webhookForm, setWebhookForm] = useState({
    name: '',
    url: '',
    provider: 'SLACK' as WebhookEndpoint['provider'],
    secretToken: '',
    events: ['CRITICAL', 'CISA_KEV'] as ('CRITICAL' | 'CISA_KEV' | 'ALL')[],
    enabled: true,
  });

  // Webhook test modal state
  const [testResult, setTestResult] = useState<{
    endpointName: string;
    statusCode: number;
    signature: string;
  } | null>(null);

  const filteredRecipients = recipients.filter(
    (r) =>
      r.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      r.email.toLowerCase().includes(searchTerm.toLowerCase()) ||
      r.role.toLowerCase().includes(searchTerm.toLowerCase()),
  );

  const filteredWebhooks = webhooks.filter(
    (w) =>
      w.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      w.url.toLowerCase().includes(searchTerm.toLowerCase()) ||
      w.provider.toLowerCase().includes(searchTerm.toLowerCase()),
  );

  const handleAddEmailSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    const ok = await addRecipient({
      name: emailForm.name.trim(),
      email: emailForm.email.trim(),
      role: emailForm.role.trim() || 'Security Engineer',
      subscriptionTier: emailForm.subscriptionTier,
      enabled: emailForm.enabled,
    });

    if (ok) {
      setShowAddEmailModal(false);
      setEmailForm({
        name: '',
        email: '',
        role: '',
        subscriptionTier: 'CRITICAL_HIGH_ONLY',
        enabled: true,
      });
    } else {
      setErrorMsg('Invalid email format. Please check and try again.');
    }
  };

  const handleAddWebhookSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    if (!webhookForm.name.trim() || !webhookForm.url.trim()) {
      setErrorMsg('Please provide a name and webhook URL.');
      return;
    }

    const ok = await addWebhook({
      name: webhookForm.name.trim(),
      url: webhookForm.url.trim(),
      provider: webhookForm.provider,
      secretToken: webhookForm.secretToken.trim(),
      events: webhookForm.events,
      enabled: webhookForm.enabled,
    });

    if (!ok) return;
    setShowAddWebhookModal(false);
    setWebhookForm({
      name: '',
      url: '',
      provider: 'SLACK',
      secretToken: '',
      events: ['CRITICAL', 'CISA_KEV'],
      enabled: true,
    });
  };

  const handleRunWebhookTest = async (endpoint: WebhookEndpoint) => {
    const res = await testWebhook(endpoint.id);
    if (res.success) {
      setTestResult({
        endpointName: endpoint.name,
        statusCode: res.statusCode,
        signature: res.signature,
      });
    }
  };

  return (
    <div className="space-y-6">
      {/* Header & Sub-Tab Navigation */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 tracking-tight flex items-center gap-2">
            <Users className="w-5 h-5 text-zinc-300 dark:text-zinc-300 light:text-zinc-700" />
            Autonomous Notification Channels &amp; Recipients
          </h1>
          <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mt-1">
            Enterprise distribution lists and webhook pipelines receiving automated alerts with zero human
            intervention.
          </p>
        </div>

        <div className="flex items-center space-x-2">
          {activeTab === 'email' ? (
            <button
              onClick={() => {
                setErrorMsg(null);
                setShowAddEmailModal(true);
              }}
              className="text-xs px-3.5 py-2 rounded-xl bg-zinc-100 hover:bg-zinc-200 dark:bg-zinc-100 dark:hover:bg-zinc-200 light:bg-zinc-900 light:hover:bg-zinc-800 text-zinc-900 dark:text-zinc-900 light:text-zinc-50 font-semibold transition flex items-center space-x-1.5 shadow-sm"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Add Email Recipient</span>
            </button>
          ) : (
            <button
              onClick={() => {
                setErrorMsg(null);
                setShowAddWebhookModal(true);
              }}
              className="text-xs px-3.5 py-2 rounded-xl bg-zinc-100 hover:bg-zinc-200 dark:bg-zinc-100 dark:hover:bg-zinc-200 light:bg-zinc-900 light:hover:bg-zinc-800 text-zinc-900 dark:text-zinc-900 light:text-zinc-50 font-semibold transition flex items-center space-x-1.5 shadow-sm"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Register Webhook</span>
            </button>
          )}
        </div>
      </div>

      {/* Channel Switcher Tabs (NextUI Style) */}
      <div className="flex items-center justify-between border-b border-zinc-800 dark:border-zinc-800 light:border-zinc-200 pb-3">
        <div className="flex items-center space-x-1.5 bg-zinc-900 dark:bg-zinc-900 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 p-1 rounded-xl">
          <button
            onClick={() => setActiveTab('email')}
            className={`px-3 py-1.5 text-xs font-medium rounded-lg transition flex items-center space-x-1.5 ${
              activeTab === 'email'
                ? 'bg-zinc-800 dark:bg-zinc-800 light:bg-white text-zinc-100 dark:text-zinc-100 light:text-zinc-900 shadow-sm'
                : 'text-zinc-400 dark:text-zinc-400 light:text-zinc-600 hover:text-zinc-200 dark:hover:text-zinc-200 light:hover:text-zinc-900'
            }`}
          >
            <Mail className="w-3.5 h-3.5" />
            <span>Email Distribution Lists ({recipients.length})</span>
          </button>
          <button
            onClick={() => setActiveTab('webhooks')}
            className={`px-3 py-1.5 text-xs font-medium rounded-lg transition flex items-center space-x-1.5 ${
              activeTab === 'webhooks'
                ? 'bg-zinc-800 dark:bg-zinc-800 light:bg-white text-zinc-100 dark:text-zinc-100 light:text-zinc-900 shadow-sm'
                : 'text-zinc-400 dark:text-zinc-400 light:text-zinc-600 hover:text-zinc-200 dark:hover:text-zinc-200 light:hover:text-zinc-900'
            }`}
          >
            <Webhook className="w-3.5 h-3.5" />
            <span>Autonomous Webhooks ({webhooks.length})</span>
          </button>
        </div>

        <div className="relative w-72 hidden md:block">
          <Search className="w-3.5 h-3.5 text-zinc-500 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder={activeTab === 'email' ? 'Search recipients...' : 'Search webhooks...'}
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl pl-8 pr-3 py-1.5 text-xs text-zinc-100 dark:text-zinc-100 light:text-zinc-900 placeholder-zinc-500 focus:outline-none focus:border-zinc-600 transition"
          />
        </div>
      </div>

      {/* TAB 1: Email Recipients */}
      {activeTab === 'email' && (
        <div className="space-y-4">
          <div className="bg-zinc-900/50 dark:bg-zinc-900/50 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl overflow-hidden shadow-sm transition-colors">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-zinc-950/80 dark:bg-zinc-950/80 light:bg-zinc-100 border-b border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 text-zinc-400 dark:text-zinc-400 light:text-zinc-600 font-mono uppercase text-[11px]">
                  <tr>
                    <th className="py-3 px-4">Recipient Name</th>
                    <th className="py-3 px-4">Email Address</th>
                    <th className="py-3 px-4">Role / Team</th>
                    <th className="py-3 px-4">Subscription Tier</th>
                    <th className="py-3 px-4">Success Rate</th>
                    <th className="py-3 px-4">Status</th>
                    <th className="py-3 px-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800/60 dark:divide-zinc-800/60 light:divide-zinc-200">
                  {filteredRecipients.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="py-8 text-center text-zinc-500">
                        No recipients match the filter.
                      </td>
                    </tr>
                  ) : (
                    filteredRecipients.map((r) => (
                      <tr key={r.id} className="hover:bg-zinc-800/30 transition">
                        <td className="py-3 px-4 font-semibold text-zinc-100 flex items-center space-x-2">
                          <div className="w-6 h-6 rounded-full bg-zinc-800 border border-zinc-700/60 flex items-center justify-center text-[10px] text-zinc-300">
                            {r.name.slice(0, 1)}
                          </div>
                          <span>{r.name}</span>
                        </td>
                        <td className="py-3 px-4 font-mono text-zinc-300">{r.email}</td>
                        <td className="py-3 px-4 text-zinc-400">{r.role}</td>
                        <td className="py-3 px-4">
                          <span
                            className={`px-2 py-0.5 rounded-full text-[10px] font-semibold border ${
                              r.subscriptionTier === 'ALL_SEVERITIES'
                                ? 'bg-zinc-800 text-zinc-200 border-zinc-600'
                                : r.subscriptionTier === 'CISA_KEV_ONLY'
                                  ? 'bg-zinc-800/80 text-zinc-100 border-zinc-500 font-bold'
                                  : 'bg-zinc-900 text-zinc-300 border-zinc-700'
                            }`}
                          >
                            {r.subscriptionTier.replace(/_/g, ' ')}
                          </span>
                        </td>
                        <td className="py-3 px-4 font-mono text-zinc-300">
                          {r.deliverySuccessRate.toFixed(1)}%
                        </td>
                        <td className="py-3 px-4">
                          <button
                            onClick={() => toggleRecipientEnabled(r.id)}
                            className={`px-2 py-0.5 rounded-full text-[10px] font-mono border transition ${
                              r.enabled
                                ? 'bg-emerald-950/40 text-emerald-300 border-emerald-800/60'
                                : 'bg-zinc-900 text-zinc-500 border-zinc-800'
                            }`}
                          >
                            {r.enabled ? 'ACTIVE' : 'MUTED'}
                          </button>
                        </td>
                        <td className="py-3 px-4 text-right">
                          <button
                            onClick={() => setDeletingRecipientId(r.id)}
                            className="p-1 rounded hover:bg-zinc-800 text-zinc-400 hover:text-zinc-200 dark:hover:text-zinc-200 light:hover:text-zinc-900 transition"
                            title="Delete"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: Autonomous Webhooks */}
      {activeTab === 'webhooks' && (
        <div className="space-y-4">
          <div className="bg-zinc-900/50 dark:bg-zinc-900/50 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl overflow-hidden shadow-sm">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-zinc-950/80 dark:bg-zinc-950/80 light:bg-zinc-100 border-b border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 text-zinc-400 dark:text-zinc-400 light:text-zinc-600 font-mono uppercase text-[11px]">
                  <tr>
                    <th className="py-3 px-4">Endpoint Name</th>
                    <th className="py-3 px-4">Provider</th>
                    <th className="py-3 px-4">Webhook Target URL</th>
                    <th className="py-3 px-4">Events</th>
                    <th className="py-3 px-4">Deliveries</th>
                    <th className="py-3 px-4">State</th>
                    <th className="py-3 px-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800/60">
                  {filteredWebhooks.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="py-8 text-center text-zinc-500">
                        No webhooks configured. Register a Slack, Teams, or SIEM webhook above.
                      </td>
                    </tr>
                  ) : (
                    filteredWebhooks.map((w) => (
                      <tr key={w.id} className="hover:bg-zinc-800/30 transition">
                        <td className="py-3 px-4 font-semibold text-zinc-100 flex items-center space-x-2">
                          <Webhook className="w-3.5 h-3.5 text-zinc-400" />
                          <span>{w.name}</span>
                        </td>
                        <td className="py-3 px-4">
                          <span className="font-mono text-[11px] bg-zinc-950 px-2 py-0.5 rounded border border-zinc-800 text-zinc-300">
                            {w.provider}
                          </span>
                        </td>
                        <td className="py-3 px-4 font-mono text-zinc-400 max-w-xs truncate" title={w.url}>
                          {w.url}
                        </td>
                        <td className="py-3 px-4 font-mono text-[10px] text-zinc-300">
                          {w.events.join(', ')}
                        </td>
                        <td className="py-3 px-4 font-mono text-zinc-300">{w.deliveryCount} sent</td>
                        <td className="py-3 px-4">
                          <button
                            onClick={() => toggleWebhookEnabled(w.id)}
                            className={`px-2 py-0.5 rounded-full text-[10px] font-mono border transition ${
                              w.enabled
                                ? 'bg-emerald-950/40 text-emerald-300 border-emerald-800/60'
                                : 'bg-zinc-900 text-zinc-500 border-zinc-800'
                            }`}
                          >
                            {w.enabled ? 'ENABLED' : 'PAUSED'}
                          </button>
                        </td>
                        <td className="py-3 px-4 text-right">
                          <div className="flex items-center justify-end space-x-2">
                            <button
                              onClick={() => handleRunWebhookTest(w)}
                              className="px-2.5 py-1 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-[11px] font-medium transition flex items-center space-x-1"
                              title="Send Test Ping"
                            >
                              <Send className="w-3 h-3" />
                              <span>Test</span>
                            </button>
                            <button
                              onClick={() => setDeletingWebhookId(w.id)}
                              className="p-1 rounded hover:bg-zinc-800 text-zinc-400 hover:text-red-400 transition"
                              title="Delete"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Webhook Test Result Modal */}
      {testResult && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="bg-zinc-900 border border-zinc-800 rounded-2xl max-w-md w-full p-6 shadow-2xl relative">
            <button
              onClick={() => setTestResult(null)}
              className="absolute top-4 right-4 text-zinc-500 hover:text-zinc-200"
            >
              <X className="w-5 h-5" />
            </button>

            <div className="flex items-center space-x-2 text-emerald-400 mb-2">
              <CheckCircle2 className="w-5 h-5" />
              <h2 className="text-sm font-bold text-zinc-100">Webhook Test Queued</h2>
            </div>
            <p className="text-xs text-zinc-400 mb-4">
              A test notification was queued for{' '}
              <strong className="text-zinc-200">{testResult.endpointName}</strong>.
            </p>

            <div className="bg-zinc-950 border border-zinc-800 rounded-xl p-3 font-mono text-[11px] space-y-2 text-zinc-300">
              <div className="flex justify-between">
                <span className="text-zinc-500">HTTP Status:</span>
                <span className="text-emerald-400 font-bold">{testResult.statusCode} Queued</span>
              </div>
              <div className="flex justify-between">
                <span className="text-zinc-500">Delivery:</span>
                <span className="text-zinc-200">Pending worker acceptance</span>
              </div>
              <div>
                <span className="text-zinc-500 block mb-1">Signature:</span>
                <span className="text-zinc-400 text-[10px] break-all bg-zinc-900 p-1.5 rounded block">
                  {testResult.signature || 'Generated when the worker sends the request'}
                </span>
              </div>
            </div>

            <div className="mt-4 flex justify-end">
              <button
                onClick={() => setTestResult(null)}
                className="px-4 py-1.5 rounded-xl bg-zinc-100 hover:bg-zinc-200 text-zinc-900 font-semibold text-xs transition"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Add Email Recipient Modal */}
      {showAddEmailModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="bg-zinc-900 border border-zinc-800 rounded-2xl max-w-md w-full p-6 shadow-2xl relative">
            <button
              onClick={() => setShowAddEmailModal(false)}
              className="absolute top-4 right-4 text-zinc-500 hover:text-zinc-200"
            >
              <X className="w-5 h-5" />
            </button>

            <h2 className="text-base font-bold text-zinc-100 mb-1 flex items-center gap-2">
              <Mail className="w-4 h-4 text-zinc-300" />
              Add Security Email Recipient
            </h2>
            <p className="text-xs text-zinc-400 mb-4">
              Register a team member or distribution group to receive autonomous security bulletins.
            </p>

            {errorMsg && (
              <div className="mb-3 p-2.5 bg-zinc-950 border border-rose-800/60 rounded-xl text-xs text-rose-300 flex items-center space-x-1.5">
                <AlertCircle className="w-4 h-4" />
                <span>{errorMsg}</span>
              </div>
            )}

            <form onSubmit={handleAddEmailSubmit} className="space-y-3.5 text-xs">
              <div>
                <label className="block text-zinc-400 mb-1 font-mono">Recipient Name *</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Lead DevSecOps"
                  value={emailForm.name}
                  onChange={(e) => setEmailForm({ ...emailForm, name: e.target.value })}
                  className="w-full bg-zinc-950 border border-zinc-800 rounded-xl p-2.5 text-zinc-100 focus:border-zinc-600 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-zinc-400 mb-1 font-mono">Email Address *</label>
                <input
                  type="email"
                  required
                  placeholder="e.g. secops-team@enterprise.org"
                  value={emailForm.email}
                  onChange={(e) => setEmailForm({ ...emailForm, email: e.target.value })}
                  className="w-full bg-zinc-950 border border-zinc-800 rounded-xl p-2.5 text-zinc-100 focus:border-zinc-600 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-zinc-400 mb-1 font-mono">Role / Designation</label>
                <input
                  type="text"
                  placeholder="e.g. SOC Tier 3 Responder"
                  value={emailForm.role}
                  onChange={(e) => setEmailForm({ ...emailForm, role: e.target.value })}
                  className="w-full bg-zinc-950 border border-zinc-800 rounded-xl p-2.5 text-zinc-100 focus:border-zinc-600 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-zinc-400 mb-1 font-mono">Subscription Filter Tier</label>
                <select
                  value={emailForm.subscriptionTier}
                  onChange={(e) =>
                    setEmailForm({
                      ...emailForm,
                      subscriptionTier: e.target.value as EmailRecipient['subscriptionTier'],
                    })
                  }
                  className="w-full bg-zinc-950 border border-zinc-800 rounded-xl p-2.5 text-zinc-100 focus:border-zinc-600 focus:outline-none"
                >
                  <option value="CRITICAL_HIGH_ONLY">Critical &amp; High Only (Standard)</option>
                  <option value="CISA_KEV_ONLY">CISA KEV Actively Exploited Only</option>
                  <option value="ALL_SEVERITIES">All Severities (Includes Low / Medium)</option>
                </select>
              </div>

              <div className="flex justify-end space-x-2 pt-3 border-t border-zinc-800">
                <button
                  type="button"
                  onClick={() => setShowAddEmailModal(false)}
                  className="px-3 py-1.5 rounded-xl bg-zinc-800 hover:bg-zinc-700 text-zinc-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded-xl bg-zinc-100 hover:bg-zinc-200 text-zinc-900 font-semibold"
                >
                  Save Recipient
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Add Webhook Modal */}
      {showAddWebhookModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="bg-zinc-900 border border-zinc-800 rounded-2xl max-w-md w-full p-6 shadow-2xl relative">
            <button
              onClick={() => setShowAddWebhookModal(false)}
              className="absolute top-4 right-4 text-zinc-500 hover:text-zinc-200"
            >
              <X className="w-5 h-5" />
            </button>

            <h2 className="text-base font-bold text-zinc-100 mb-1 flex items-center gap-2">
              <Webhook className="w-4 h-4 text-zinc-300" />
              Register Autonomous Webhook Channel
            </h2>
            <p className="text-xs text-zinc-400 mb-4">
              Dispatches JSON payloads with HMAC-SHA256 signature immediately upon vulnerability correlation.
            </p>

            {errorMsg && (
              <div className="mb-3 p-2.5 bg-zinc-950 border border-rose-800/60 rounded-xl text-xs text-rose-300 flex items-center space-x-1.5">
                <AlertCircle className="w-4 h-4" />
                <span>{errorMsg}</span>
              </div>
            )}

            <form onSubmit={handleAddWebhookSubmit} className="space-y-3.5 text-xs">
              <div>
                <label className="block text-zinc-400 mb-1 font-mono">Channel Name *</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. SecOps Alerts (Slack)"
                  value={webhookForm.name}
                  onChange={(e) => setWebhookForm({ ...webhookForm, name: e.target.value })}
                  className="w-full bg-zinc-950 border border-zinc-800 rounded-xl p-2.5 text-zinc-100 focus:border-zinc-600 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-zinc-400 mb-1 font-mono">Provider Format</label>
                <select
                  value={webhookForm.provider}
                  onChange={(e) =>
                    setWebhookForm({
                      ...webhookForm,
                      provider: e.target.value as WebhookEndpoint['provider'],
                    })
                  }
                  className="w-full bg-zinc-950 border border-zinc-800 rounded-xl p-2.5 text-zinc-100 focus:border-zinc-600 focus:outline-none"
                >
                  <option value="SLACK">Slack Incoming Webhook</option>
                  <option value="TEAMS">Microsoft Teams Connector</option>
                  <option value="GENERIC_HMAC">Enterprise SIEM / SOAR (HMAC-SHA256)</option>
                </select>
              </div>

              <div>
                <label className="block text-zinc-400 mb-1 font-mono">Webhook URL *</label>
                <input
                  type="url"
                  required
                  placeholder="https://hooks.slack.com/services/..."
                  value={webhookForm.url}
                  onChange={(e) => setWebhookForm({ ...webhookForm, url: e.target.value })}
                  className="w-full bg-zinc-950 border border-zinc-800 rounded-xl p-2.5 text-zinc-100 font-mono text-[11px] focus:border-zinc-600 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-zinc-400 mb-1 font-mono">
                  HMAC shared secret (32+ characters for Generic HMAC)
                </label>
                <input
                  type="password"
                  placeholder="Required for Generic HMAC receivers"
                  value={webhookForm.secretToken}
                  onChange={(e) => setWebhookForm({ ...webhookForm, secretToken: e.target.value })}
                  className="w-full bg-zinc-950 border border-zinc-800 rounded-xl p-2.5 text-zinc-100 font-mono focus:border-zinc-600 focus:outline-none"
                />
              </div>

              <div className="flex justify-end space-x-2 pt-3 border-t border-zinc-800">
                <button
                  type="button"
                  onClick={() => setShowAddWebhookModal(false)}
                  className="px-3 py-1.5 rounded-xl bg-zinc-800 hover:bg-zinc-700 text-zinc-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded-xl bg-zinc-100 hover:bg-zinc-200 text-zinc-900 font-semibold"
                >
                  Register Webhook
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Delete Recipient Confirmation */}
      {deletingRecipientId && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="bg-zinc-900 border border-zinc-800 rounded-2xl max-w-sm w-full p-6 shadow-2xl">
            <h3 className="text-sm font-bold text-zinc-100 mb-2">Remove Recipient?</h3>
            <p className="text-xs text-zinc-400 leading-relaxed mb-6">
              This recipient will stop receiving automated vulnerability notifications.
            </p>
            <div className="flex justify-end space-x-2">
              <button
                onClick={() => setDeletingRecipientId(null)}
                className="px-3 py-1.5 rounded-xl bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-xs font-medium"
              >
                Cancel
              </button>
              <button
                onClick={() => {
                  deleteRecipient(deletingRecipientId);
                  setDeletingRecipientId(null);
                }}
                className="px-3 py-1.5 rounded-xl bg-red-600 hover:bg-red-500 text-white text-xs font-semibold"
              >
                Remove
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Delete Webhook Confirmation */}
      {deletingWebhookId && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="bg-zinc-900 border border-zinc-800 rounded-2xl max-w-sm w-full p-6 shadow-2xl">
            <h3 className="text-sm font-bold text-zinc-100 mb-2">Remove Webhook Endpoint?</h3>
            <p className="text-xs text-zinc-400 leading-relaxed mb-6">
              Automated payload delivery to this endpoint will be terminated.
            </p>
            <div className="flex justify-end space-x-2">
              <button
                onClick={() => setDeletingWebhookId(null)}
                className="px-3 py-1.5 rounded-xl bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-xs font-medium"
              >
                Cancel
              </button>
              <button
                onClick={() => {
                  deleteWebhook(deletingWebhookId);
                  setDeletingWebhookId(null);
                }}
                className="px-3 py-1.5 rounded-xl bg-red-600 hover:bg-red-500 text-white text-xs font-semibold"
              >
                Remove
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
