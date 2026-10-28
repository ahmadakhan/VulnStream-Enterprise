import { PageHeading } from './PageHeading';
import React, { useEffect, useState } from 'react';
import {
  Check,
  Mail,
  ChevronRight,
  RotateCcw,
  Save,
  AlertCircle,
  LoaderCircle,
  KeyRound,
  LockKeyhole,
  Pencil,
   Plus,
   Settings2,
   ShieldCheck,
   SlidersHorizontal,
   Users,
   Clock,
   Trash2,
 } from 'lucide-react';
import { useApp } from '../context/AppContext';
import { EmailProviderSettings } from './EmailProviderSettings';
import type { AppSettings } from '../types';
import './settings.css';

const field = 'ui-field';

/** Older persisted settings may predate the retry policy fields. */
const withEmailRetryDefaults = (value: AppSettings): AppSettings => ({
  ...value,
  emailRetryEnabled: value.emailRetryEnabled ?? true,
  emailRetryMaxAttempts: value.emailRetryMaxAttempts ?? 6,
  emailRetryInitialDelayMinutes: value.emailRetryInitialDelayMinutes ?? 1,
  emailRetryMaxDelayMinutes: value.emailRetryMaxDelayMinutes ?? 60,
});

function SectionHeading({
  icon: Icon,
  title,
  description,
  id,
}: {
  icon: typeof Settings2;
  title: string;
  description: string;
  id?: string;
}) {
  return (
    <div className="settings-section-heading flex items-start gap-3.5">
      <span className="ui-section-icon">
        <Icon className="h-4 w-4" aria-hidden="true" />
      </span>
      <div>
        <h2 id={id} className="ui-card-title">
          {title}
        </h2>
        <p className="ui-description mt-1">{description}</p>
      </div>
    </div>
  );
}

export function SettingsView() {
  const { settings, updateSettings, changePassword, session, listUsers, createUser, updateUser, deleteUser, resetUserPassword, pending } =
    useApp();
  const [form, setForm] = useState<AppSettings>(() => withEmailRetryDefaults(settings));
  const [securityForm, setSecurityForm] = useState<AppSettings['securityPolicy']>(settings.securityPolicy);
  const [message, setMessage] = useState('');
  const [securityMessage, setSecurityMessage] = useState('');
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [users, setUsers] = useState<any[]>([]);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('VIEWER');
  const [accountMessage, setAccountMessage] = useState('');
  const [usersLoading, setUsersLoading] = useState(true);
  const [usersError, setUsersError] = useState('');
  const [resetUserId, setResetUserId] = useState<string | null>(null);
  const [disablingUserId, setDisablingUserId] = useState<string | null>(null);
  const [deleteUserId, setDeleteUserId] = useState<string | null>(null);
  const [resetPassword, setResetPassword] = useState('');
  const [email, setEmail] = useState('');
  // The account being edited in the popup form, or null when the form is closed.
  const [editingUser, setEditingUser] = useState<any | null>(null);
  const [editForm, setEditForm] = useState({ username: '', role: 'VIEWER', email: '', disabled: false });
  const [editMessage, setEditMessage] = useState('');
  const admin = session?.role === 'ADMIN';
  const [activeSection, setActiveSection] = useState(admin ? 'processing' : 'security');
  const processingDirty =
    form.scopeHours !== settings.scopeHours ||
    form.schedulerIntervalMinutes !== settings.schedulerIntervalMinutes ||
    form.advisoryPrefix !== settings.advisoryPrefix ||
    (form.logVerbosity ?? 'standard') !== (settings.logVerbosity ?? 'standard') ||
    form.schedulerEnabled !== settings.schedulerEnabled ||
     form.autoDispatchEnabled !== settings.autoDispatchEnabled ||
     (form.autoDispatchConfidenceThreshold ?? 90) !==
       (settings.autoDispatchConfidenceThreshold ?? 90) ||
     (form.digestBatchingEnabled ?? false) !== (settings.digestBatchingEnabled ?? false) ||
     (form.digestWindowMinutes ?? 5) !== (settings.digestWindowMinutes ?? 5) ||
     (form.emailRetryEnabled ?? true) !== (settings.emailRetryEnabled ?? true) ||
     (form.emailRetryMaxAttempts ?? 6) !== (settings.emailRetryMaxAttempts ?? 6) ||
     (form.emailRetryInitialDelayMinutes ?? 1) !==
       (settings.emailRetryInitialDelayMinutes ?? 1) ||
      (form.emailRetryMaxDelayMinutes ?? 60) !== (settings.emailRetryMaxDelayMinutes ?? 60);
  const securityDirty =
    securityForm.sessionTimeoutMins !== settings.securityPolicy.sessionTimeoutMins ||
    securityForm.minPasswordLen !== settings.securityPolicy.minPasswordLen ||
    securityForm.maxLoginAttempts !== settings.securityPolicy.maxLoginAttempts ||
    securityForm.lockoutMins !== settings.securityPolicy.lockoutMins;
  const sections = [
    ...(admin
      ? [
          {
            id: 'processing',
            title: 'Processing',
            description: 'Scheduling & dispatch',
            icon: SlidersHorizontal,
          },
          { id: 'email', title: 'Email delivery', description: 'Providers & sender identity', icon: Mail },
        ]
      : []),
    { id: 'security', title: 'Account security', description: 'Password & sign-in', icon: ShieldCheck },
    ...(admin
      ? [{ id: 'access', title: 'Workspace access', description: 'Accounts & permissions', icon: Users }]
      : []),
  ];

  const reloadUsers = async () => {
    setUsersLoading(true);
    setUsersError('');
    try {
      const result = await listUsers();
      if (result) setUsers(result);
      else setUsersError('Workspace accounts could not be loaded.');
    } finally {
      setUsersLoading(false);
    }
  };

  useEffect(() => {
    if (admin) void reloadUsers();
  }, [admin]);

  return (
    <div className="settings-page space-y-6 text-zinc-100 light:text-zinc-900">
      <header className="ui-page-header">
        <PageHeading page="settings">
          Configure processing, email delivery, account security, and workspace access.
        </PageHeading>
        <span className="settings-role-badge">
          <ShieldCheck size={14} />
          {admin ? 'Administrator access' : 'Personal settings'}
        </span>
      </header>

      <div className="settings-layout">
        <aside className="settings-sidebar">
          <div className="settings-nav-label">Workspace settings</div>
          <nav aria-label="Settings sections" className="settings-section-nav">
            {sections.map(({ id, title, description, icon: Icon }) => (
              <button
                key={id}
                type="button"
                aria-pressed={activeSection === id}
                aria-controls={`settings-${id}`}
                onClick={() => setActiveSection(id)}
              >
                <Icon size={17} aria-hidden="true" />
                <span>
                  <strong>{title}</strong>
                  <small>{description}</small>
                </span>
                <ChevronRight size={13} aria-hidden="true" />
              </button>
            ))}
          </nav>
          <div className="settings-identity">
            <div className="settings-avatar">{session?.username.slice(0, 1).toUpperCase()}</div>
            <div>
              <strong>{session?.username}</strong>
              <span>{session?.role.toLowerCase()} account</span>
            </div>
          </div>
        </aside>
        <div className="settings-content">
          {admin && (
            <div id="settings-email" hidden={activeSection !== 'email'}>
              <EmailProviderSettings />
            </div>
          )}

          {admin && (
            <div id="settings-processing" hidden={activeSection !== 'processing'}>
              <form
                className="ui-card space-y-5"
                aria-labelledby="processing-settings-title"
                onChangeCapture={() => setMessage('')}
                onSubmit={async (e) => {
                  e.preventDefault();
                  setMessage('');
                   if (await updateSettings({ ...form, securityPolicy: settings.securityPolicy }))
                     setMessage('Settings saved successfully.');
                }}
              >
                <SectionHeading
                  icon={SlidersHorizontal}
                  id="processing-settings-title"
                  title="Processing and dispatch"
                  description="Control ingestion windows, scheduled processing, and automatic notifications."
                />

                <div className="grid gap-x-5 gap-y-4 sm:grid-cols-2">
                  <label className="block text-xs font-medium text-zinc-300 light:text-zinc-700">
                    Scope window
                    <span className="ml-1 font-normal text-zinc-500">(hours)</span>
                    <input
                      type="number"
                      min={1}
                      max={2880}
                      required
                      className={field}
                      value={form.scopeHours}
                      onChange={(e) => setForm({ ...form, scopeHours: Number(e.target.value) })}
                    />
                    <span className="ui-description mt-1.5 block">
                      How far back each ingestion run checks for updates.
                    </span>
                  </label>
                  <label className="block text-xs font-medium text-zinc-300 light:text-zinc-700">
                    Schedule interval
                    <span className="ml-1 font-normal text-zinc-500">(minutes)</span>
                    <input
                      type="number"
                      min={5}
                      max={10080}
                      required
                      className={field}
                      value={form.schedulerIntervalMinutes}
                      onChange={(e) => setForm({ ...form, schedulerIntervalMinutes: Number(e.target.value) })}
                    />
                    <span className="ui-description mt-1.5 block">
                      The delay between scheduled pipeline runs.
                    </span>
                  </label>
                  <label className="block text-xs font-medium text-zinc-300 light:text-zinc-700">
                    Advisory prefix
                    <input
                      required
                      pattern="[A-Za-z0-9_-]{1,30}"
                      className={field}
                      value={form.advisoryPrefix}
                      onChange={(e) => setForm({ ...form, advisoryPrefix: e.target.value })}
                    />
                    <span className="ui-description mt-1.5 block">
                      Prefix used when generating advisory identifiers.
                    </span>
                  </label>
                  <label className="block text-xs font-medium text-zinc-300 light:text-zinc-700">
                    Operational log detail
                    <select
                      className={field}
                      value={form.logVerbosity ?? 'standard'}
                      onChange={(e) =>
                        setForm({ ...form, logVerbosity: e.target.value as AppSettings['logVerbosity'] })
                      }
                    >
                      <option value="standard">Standard — lifecycle &amp; security events</option>
                      <option value="verbose">Verbose — full forensic telemetry</option>
                    </select>
                    <span className="ui-description mt-1.5 block">
                      Standard records pipeline, feed, matching, delivery and security events, plus every
                      warning and error. Verbose additionally persists per-advisory correlation telemetry
                      (extraction and database timings). Warnings and errors are never suppressed. Applied
                      to the next advisory without a restart.
                    </span>
                  </label>
                </div>

                <div className="grid gap-3 sm:grid-cols-2">
                  <label className="settings-toggle-card ui-check-row cursor-pointer text-xs leading-relaxed">
                    <input
                      type="checkbox"
                      checked={form.schedulerEnabled}
                      onChange={(e) => setForm({ ...form, schedulerEnabled: e.target.checked })}
                    />
                    <span>
                      <span className="block font-medium text-zinc-200 light:text-zinc-800">
                        Enable server scheduler
                      </span>
                      <span className="ui-description mt-0.5 block">
                        Allow the server to start scheduled pipeline runs.
                      </span>
                    </span>
                  </label>
                  <label className="settings-toggle-card ui-check-row cursor-pointer text-xs leading-relaxed">
                    <input
                      type="checkbox"
                      checked={form.autoDispatchEnabled}
                      onChange={(e) => setForm({ ...form, autoDispatchEnabled: e.target.checked })}
                    />
                    <span>
                      <span className="block font-medium text-zinc-200 light:text-zinc-800">
                        Automatic dispatch
                      </span>
                       <span className="ui-description mt-0.5 block">
                        Send confirmed findings to security teams automatically; everyone recipients wait in
                        Email Queue for security review.
                      </span>
                    </span>
                  </label>
                  <label className="settings-toggle-card ui-check-row cursor-pointer text-xs leading-relaxed">
                    <div className="flex items-center gap-3">
                      <input
                        type="number"
                        min="0"
                        max="100"
                        value={form.autoDispatchConfidenceThreshold ?? 90}
                        onChange={(e) =>
                          setForm({
                            ...form,
                            autoDispatchConfidenceThreshold: parseInt(e.target.value) || 0,
                          })
                        }
                        className="mt-1 w-16 rounded-md border border-zinc-700 bg-zinc-800 px-2 py-1 text-xs text-zinc-100 focus:border-zinc-500 focus:outline-none light:border-zinc-300 light:bg-white light:text-zinc-900"
                      />
                      <span>
                        <span className="block font-medium text-zinc-200 light:text-zinc-800">
                          Auto-dispatch confidence threshold
                        </span>
                        <span className="ui-description mt-0.5 block">
                          Minimum confidence (0-100) for automatic email dispatch. Set to 0 to send all
                          findings regardless of confidence level.
                        </span>
                      </span>
                    </div>
                  </label>
                  <label className="settings-toggle-card ui-check-row cursor-pointer text-xs leading-relaxed">
                    <input
                      type="checkbox"
                      checked={form.digestBatchingEnabled ?? false}
                      onChange={(e) =>
                        setForm({ ...form, digestBatchingEnabled: e.target.checked })
                      }
                    />
                    <span>
                      <span className="block font-medium text-zinc-200 light:text-zinc-800">
                        Combine threats into one email
                      </span>
                      <span className="ui-description mt-0.5 block">
                        Buffer detections for the window and send one combined email per recipient.
                        Each recipient only receives the findings permitted by its subscription tier.
                      </span>
                    </span>
                  </label>
                  <label className="settings-toggle-card ui-check-row cursor-pointer text-xs leading-relaxed">
                    <div className="flex items-center gap-3">
                      <input
                        type="number"
                        min="1"
                        max="1440"
                        value={form.digestWindowMinutes ?? 5}
                        onChange={(e) =>
                          setForm({
                            ...form,
                            digestWindowMinutes: Math.max(1, parseInt(e.target.value) || 1),
                          })
                        }
                        className="mt-1 w-16 rounded-md border border-zinc-700 bg-zinc-800 px-2 py-1 text-xs text-zinc-100 focus:border-zinc-500 focus:outline-none light:border-zinc-300 light:bg-white light:text-zinc-900"
                      />
                      <span>
                        <span className="block font-medium text-zinc-200 light:text-zinc-800">
                          Digest window (minutes)
                        </span>
                        <span className="ui-description mt-0.5 block">
                          How long to collect detections before sending the combined email.
                        </span>
                      </span>
                    </div>
                  </label>
                  <div className="sm:col-span-2 mt-1 border-t border-zinc-800/70 pt-4 light:border-zinc-200">
                    <h3 className="text-xs font-semibold text-zinc-200 light:text-zinc-800">
                      Email retry policy
                    </h3>
                    <p className="ui-description mt-1">
                      Transient provider or network failures are retried automatically. Permanent provider
                      rejections (for example, an invalid recipient or credentials) still require operator
                      correction.
                    </p>
                  </div>
                  <label className="settings-toggle-card ui-check-row cursor-pointer text-xs leading-relaxed">
                    <input
                      type="checkbox"
                      checked={form.emailRetryEnabled ?? true}
                      onChange={(e) => setForm({ ...form, emailRetryEnabled: e.target.checked })}
                    />
                    <span>
                      <span className="block font-medium text-zinc-200 light:text-zinc-800">
                        Enable automatic email retry
                      </span>
                      <span className="ui-description mt-0.5 block">
                        Keep failed deliveries queued with exponential backoff instead of marking them
                        failed after the first transport error.
                      </span>
                    </span>
                  </label>
                  <label className="settings-toggle-card ui-check-row cursor-pointer text-xs leading-relaxed">
                    <div className="flex items-center gap-3">
                      <input
                        type="number"
                        min="1"
                        max="20"
                        disabled={!form.emailRetryEnabled}
                        value={form.emailRetryMaxAttempts ?? 6}
                        onChange={(e) =>
                          setForm({
                            ...form,
                            emailRetryMaxAttempts: Math.min(
                              20,
                              Math.max(1, parseInt(e.target.value) || 1),
                            ),
                          })
                        }
                        className="mt-1 w-16 rounded-md border border-zinc-700 bg-zinc-800 px-2 py-1 text-xs text-zinc-100 focus:border-zinc-500 focus:outline-none disabled:opacity-50 light:border-zinc-300 light:bg-white light:text-zinc-900"
                      />
                      <span>
                        <span className="block font-medium text-zinc-200 light:text-zinc-800">
                          Maximum attempts
                        </span>
                        <span className="ui-description mt-0.5 block">
                          Total sends per email, including the first attempt. A value of 1 disables
                          automatic retries while keeping the initial delivery.
                        </span>
                      </span>
                    </div>
                  </label>
                  <label className="settings-toggle-card ui-check-row cursor-pointer text-xs leading-relaxed">
                    <div className="flex items-center gap-3">
                      <input
                        type="number"
                        min="1"
                        max="1440"
                        disabled={!form.emailRetryEnabled}
                        value={form.emailRetryInitialDelayMinutes ?? 1}
                        onChange={(e) => {
                          const initial = Math.min(
                            1440,
                            Math.max(1, parseInt(e.target.value) || 1),
                          );
                          setForm({
                            ...form,
                            emailRetryInitialDelayMinutes: initial,
                            // Keep the ceiling valid without a server round-trip.
                            emailRetryMaxDelayMinutes: Math.max(
                              initial,
                              form.emailRetryMaxDelayMinutes ?? 60,
                            ),
                          });
                        }}
                        className="mt-1 w-16 rounded-md border border-zinc-700 bg-zinc-800 px-2 py-1 text-xs text-zinc-100 focus:border-zinc-500 focus:outline-none disabled:opacity-50 light:border-zinc-300 light:bg-white light:text-zinc-900"
                      />
                      <span>
                        <span className="block font-medium text-zinc-200 light:text-zinc-800">
                          Initial backoff (minutes)
                        </span>
                        <span className="ui-description mt-0.5 block">
                          Delay before the second attempt. The delay doubles after each failed try.
                        </span>
                      </span>
                    </div>
                  </label>
                  <label className="settings-toggle-card ui-check-row cursor-pointer text-xs leading-relaxed">
                    <div className="flex items-center gap-3">
                      <input
                        type="number"
                        min={form.emailRetryInitialDelayMinutes ?? 1}
                        max="10080"
                        disabled={!form.emailRetryEnabled}
                        value={form.emailRetryMaxDelayMinutes ?? 60}
                        onChange={(e) =>
                          setForm({
                            ...form,
                            emailRetryMaxDelayMinutes: Math.max(
                              form.emailRetryInitialDelayMinutes ?? 1,
                              Math.min(10080, Math.max(1, parseInt(e.target.value) || 1)),
                            ),
                          })
                        }
                        className="mt-1 w-16 rounded-md border border-zinc-700 bg-zinc-800 px-2 py-1 text-xs text-zinc-100 focus:border-zinc-500 focus:outline-none disabled:opacity-50 light:border-zinc-300 light:bg-white light:text-zinc-900"
                      />
                      <span>
                        <span className="block font-medium text-zinc-200 light:text-zinc-800">
                          Maximum backoff (minutes)
                        </span>
                        <span className="ui-description mt-0.5 block">
                          Upper bound for the exponential delay between delivery attempts.
                        </span>
                      </span>
                    </div>
                  </label>
                </div>

                <p className="rounded-xl border border-zinc-800 bg-zinc-950/30 px-4 py-3 text-xs leading-relaxed text-zinc-400 light:border-zinc-200 light:bg-zinc-50 light:text-zinc-600">
                  Outbound host permissions are managed by the deployment administrator. Host clock
                  synchronization, CSRF protection, and private-network safeguards are enforced at runtime.
                </p>

                <div className="ui-actions justify-between">
                  {message ? (
                    <p role="status" className="ui-success inline-flex items-center gap-2">
                      <Check className="h-3.5 w-3.5" aria-hidden="true" /> {message}
                    </p>
                  ) : (
                    <span className="settings-save-state">
                      <span className={processingDirty ? 'is-dirty' : ''} />
                      {processingDirty ? 'Unsaved changes' : 'Settings are up to date'}
                    </span>
                  )}
                  <div className="settings-action-buttons">
                    {processingDirty && (
                      <button
                        type="button"
                        className="ui-secondary"
                        disabled={pending > 0}
                        onClick={() => {
                          setForm(withEmailRetryDefaults(settings));
                          setMessage('');
                        }}
                      >
                        <RotateCcw size={14} />
                        Reset changes
                      </button>
                    )}
                    <button type="submit" disabled={pending > 0 || !processingDirty} className="ui-primary">
                      {pending > 0 ? <LoaderCircle size={14} className="animate-spin" /> : <Save size={14} />}
                      {pending > 0 ? 'Saving…' : 'Save settings'}
                    </button>
                  </div>
                </div>
              </form>
            </div>
          )}

           <div id="settings-security" hidden={activeSection !== 'security'} className="space-y-6">
              {admin && (
                <form
                  className="ui-card space-y-5"
                  aria-labelledby="account-security-policy-title"
                  onChangeCapture={() => setSecurityMessage('')}
                  onSubmit={async (e) => {
                    e.preventDefault();
                    setSecurityMessage('');
                    if (await updateSettings({ securityPolicy: securityForm }))
                      setSecurityMessage('Security policy saved successfully.');
                  }}
                >
                  <SectionHeading
                    icon={Clock}
                    id="account-security-policy-title"
                    title="Login timeout & password policy"
                    description="Session expiry, password strength, and brute-force lockout for operator accounts."
                  />

                  <div className="grid gap-x-5 gap-y-4 sm:grid-cols-2">
                    <label className="block text-xs font-medium text-zinc-300 light:text-zinc-700">
                      Session timeout
                      <span className="ml-1 font-normal text-zinc-500">(minutes)</span>
                      <input
                        type="number"
                        min={5}
                        max={60}
                        required
                        className={field}
                        value={securityForm.sessionTimeoutMins}
                        onChange={(e) =>
                          setSecurityForm({
                            ...securityForm,
                            sessionTimeoutMins: Math.min(60, Math.max(5, Number(e.target.value) || 5)),
                          })
                        }
                      />
                      <span className="ui-description mt-1.5 block">
                        Inactive authenticated sessions are signed out after this period. Applied on the
                        next login.
                      </span>
                    </label>
                    <label className="block text-xs font-medium text-zinc-300 light:text-zinc-700">
                      Minimum password length
                      <span className="ml-1 font-normal text-zinc-500">(characters)</span>
                      <input
                        type="number"
                        min={14}
                        max={128}
                        required
                        className={field}
                        value={securityForm.minPasswordLen}
                        onChange={(e) =>
                          setSecurityForm({
                            ...securityForm,
                            minPasswordLen: Math.min(128, Math.max(14, Number(e.target.value) || 14)),
                          })
                        }
                      />
                      <span className="ui-description mt-1.5 block">
                        Length enforced for new and changed passwords. Existing passwords are unaffected
                        until the operator updates them.
                      </span>
                    </label>
                  </div>

                  <div className="sm:col-span-2 mt-1 border-t border-zinc-800/70 pt-4 light:border-zinc-200">
                    <h3 className="text-xs font-semibold text-zinc-200 light:text-zinc-800">
                      Login attempt limits
                    </h3>
                    <p className="ui-description mt-1">
                      Repeated failed sign-ins are blocked for a cooling-off period. The threshold is
                      tracked per account and per source IP to resist distributed guessing.
                    </p>
                  </div>
                  <div className="grid gap-x-5 gap-y-4 sm:grid-cols-2">
                    <label className="block text-xs font-medium text-zinc-300 light:text-zinc-700">
                      Failed attempts before lockout
                      <input
                        type="number"
                        min={1}
                        max={20}
                        required
                        className={field}
                        value={securityForm.maxLoginAttempts}
                        onChange={(e) =>
                          setSecurityForm({
                            ...securityForm,
                            maxLoginAttempts: Math.min(20, Math.max(1, Number(e.target.value) || 1)),
                          })
                        }
                      />
                      <span className="ui-description mt-1.5 block">
                        Consecutive failed sign-ins against a single account before it is temporarily locked.
                      </span>
                    </label>
                    <label className="block text-xs font-medium text-zinc-300 light:text-zinc-700">
                      Lockout duration
                      <span className="ml-1 font-normal text-zinc-500">(minutes)</span>
                      <input
                        type="number"
                        min={1}
                        max={60}
                        required
                        className={field}
                        value={securityForm.lockoutMins}
                        onChange={(e) =>
                          setSecurityForm({
                            ...securityForm,
                            lockoutMins: Math.min(60, Math.max(1, Number(e.target.value) || 1)),
                          })
                        }
                      />
                      <span className="ui-description mt-1.5 block">
                        How long a locked account stays locked before another sign-in can be attempted.
                      </span>
                    </label>
                  </div>

                  <p className="rounded-xl border border-zinc-800 bg-zinc-950/30 px-4 py-3 text-xs leading-relaxed text-zinc-400 light:border-zinc-200 light:bg-zinc-50 light:text-zinc-600">
                    CSRF protection, secure cookie attributes, and HTTP security headers are enforced at
                    runtime and cannot be relaxed from the application.
                  </p>

                  <div className="ui-actions justify-between">
                    {securityMessage ? (
                      <p role="status" className="ui-success inline-flex items-center gap-2">
                        <Check className="h-3.5 w-3.5" aria-hidden="true" /> {securityMessage}
                      </p>
                    ) : (
                      <span className="settings-save-state">
                        <span className={securityDirty ? 'is-dirty' : ''} />
                        {securityDirty ? 'Unsaved changes' : 'Settings are up to date'}
                      </span>
                    )}
                    <div className="settings-action-buttons">
                      {securityDirty && (
                        <button
                          type="button"
                          className="ui-secondary"
                          disabled={pending > 0}
                          onClick={() => {
                            setSecurityForm(settings.securityPolicy);
                            setSecurityMessage('');
                          }}
                        >
                          <RotateCcw size={14} />
                          Reset changes
                        </button>
                      )}
                      <button type="submit" disabled={pending > 0 || !securityDirty} className="ui-primary">
                        {pending > 0 ? <LoaderCircle size={14} className="animate-spin" /> : <Save size={14} />}
                        {pending > 0 ? 'Saving…' : 'Save policy'}
                      </button>
                    </div>
                  </div>
                </form>
              )}

              <form
                className="ui-card space-y-5"
                aria-labelledby="account-security-title"
                onSubmit={async (e) => {
                  e.preventDefault();
                  const changed = await changePassword(currentPassword, newPassword);
                  // Keep the fields intact when the change failed so the operator can
                  // correct the current password instead of retyping both values.
                  if (changed) {
                    setCurrentPassword('');
                    setNewPassword('');
                  }
                }}
              >
                <SectionHeading
                  icon={ShieldCheck}
                  id="account-security-title"
                  title="Change password"
                  description="Update the password used to sign in to this account."
                />
                <div className="grid gap-4 sm:grid-cols-2">
                  <label className="block text-xs font-medium text-zinc-300 light:text-zinc-700">
                    Current password
                    <input
                      type="password"
                      autoComplete="current-password"
                      required
                      maxLength={128}
                      className={field}
                      value={currentPassword}
                      onChange={(e) => setCurrentPassword(e.target.value)}
                    />
                  </label>
                  <label className="block text-xs font-medium text-zinc-300 light:text-zinc-700">
                    New password
                    <input
                      type="password"
                      autoComplete="new-password"
                      required
                      minLength={settings.securityPolicy.minPasswordLen}
                      maxLength={128}
                      className={field}
                      value={newPassword}
                      onChange={(e) => setNewPassword(e.target.value)}
                    />
                    <span className="ui-description mt-1.5 block">
                      Use at least {settings.securityPolicy.minPasswordLen} characters.
                    </span>
                  </label>
                </div>
                <div className="ui-actions justify-between">
                  <p className="inline-flex items-center gap-2 text-xs text-zinc-400 light:text-zinc-600">
                    <LockKeyhole className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                    Changing your password signs out all active sessions.
                  </p>
                  <button type="submit" disabled={pending > 0} className="ui-primary">
                    <KeyRound className="h-3.5 w-3.5" aria-hidden="true" />
                    Change password
                  </button>
                </div>
              </form>
            </div>

          {admin && (
            <section
              id="settings-access"
              hidden={activeSection !== 'access'}
              className="ui-card space-y-5"
              aria-labelledby="operator-accounts-title"
            >
              <SectionHeading
                icon={Users}
                id="operator-accounts-title"
                title="Workspace access"
                description="Manage who can access this workspace and what they can do."
              />
              <details className="settings-role-guide">
                <summary>
                  <ShieldCheck size={14} />
                  Understand access roles
                  <ChevronRight size={13} />
                </summary>{' '}
                <div className="grid gap-2 sm:grid-cols-3">
                  {[
                    ['Admin', 'Configuration and account management'],
                    ['Operator', 'Inventory and pipeline runs'],
                    ['Viewer', 'Read-only workspace access'],
                  ].map(([name, description]) => (
                    <div
                      key={name}
                      className="rounded-xl border border-zinc-800/80 bg-zinc-950/25 px-3.5 py-3 light:border-zinc-200 light:bg-zinc-50"
                    >
                      <p className="text-xs font-semibold">{name}</p>
                      <p className="ui-description mt-1">{description}</p>
                    </div>
                  ))}
                </div>
              </details>
              <div className="grid grid-cols-3 gap-2" aria-label="Account totals">
                {[
                  [
                    'Active',
                    users.filter((user) => !user.disabled).length,
                    'text-emerald-300 light:text-emerald-700',
                  ],
                  ['Disabled', users.filter((user) => user.disabled).length, 'text-zinc-400'],
                  [
                    'Admins',
                    users.filter((user) => user.role === 'ADMIN').length,
                    'text-blue-300 light:text-blue-700',
                  ],
                ].map(([label, count, color]) => (
                  <div
                    key={String(label)}
                    className="rounded-xl border border-zinc-800/80 bg-zinc-950/25 px-3 py-2.5 light:border-zinc-200 light:bg-zinc-50"
                  >
                    <p className="text-[10px] font-medium uppercase tracking-wider text-zinc-500">{label}</p>
                    <p className={`mt-1 text-lg font-semibold tabular-nums ${color}`}>{count}</p>
                  </div>
                ))}
              </div>

              <details className="settings-create-account">
                <summary>
                  <span>
                    <Plus size={15} />
                    Add workspace account
                  </span>
                  <ChevronRight size={14} />
                </summary>
                <form
                  className="grid gap-4 rounded-xl border border-zinc-800/80 bg-zinc-950/25 p-4 sm:grid-cols-2 xl:grid-cols-2 xl:items-end light:border-zinc-200 light:bg-zinc-50"
                  onSubmit={async (e) => {
                    e.preventDefault();
                    if (!username.trim() || !password || !role) {
                      setAccountMessage('Username, password, and role are required.');
                      return;
                    }
                    // Without an address there is nowhere to send a reset code,
                    // so it is part of what makes an account usable.
                    if (!email.trim()) {
                      setAccountMessage('An email address is required for password reset.');
                      return;
                    }
                    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
                      setAccountMessage('Enter a valid email address, for example name@company.com.');
                      return;
                    }
                    if (password.length < 14) {
                      setAccountMessage('Password must be at least 14 characters.');
                      return;
                    }
                    if (!/^[a-zA-Z0-9._@-]{3,100}$/.test(username)) {
                      setAccountMessage(
                        'Username can only contain letters, numbers, periods, underscores, at signs, and hyphens.',
                      );
                      return;
                    }
                    setAccountMessage('');
                    if (await createUser({ username, password, role, email: email.trim() })) {
                      setUsername('');
                      setPassword('');
                      setRole('VIEWER');
                      setEmail('');
                      await reloadUsers();
                      setAccountMessage('Operator created successfully.');
                    } else {
                      setAccountMessage('Failed to create operator.');
                    }
                  }}
                >
                  <label className="block text-xs font-medium text-zinc-300 light:text-zinc-700">
                    Username
                    <input
                      required
                      pattern="[a-zA-Z0-9._@-]{3,100}"
                      autoComplete="username"
                      className={field}
                      value={username}
                      onChange={(e) => {
                        setUsername(e.target.value);
                        setAccountMessage('');
                      }}
                    />
                  </label>
                  <label className="block text-xs font-medium text-zinc-300 light:text-zinc-700">
                    Initial password
                    <input
                      type="password"
                      autoComplete="new-password"
                      required
                      minLength={14}
                      maxLength={128}
                      className={field}
                      value={password}
                      onChange={(e) => {
                        setPassword(e.target.value);
                        setAccountMessage('');
                      }}
                    />
                  </label>
                  <label className="block text-xs font-medium text-zinc-300 light:text-zinc-700">
                    Reset email address
                    <input
                      type="email"
                      required
                      autoComplete="email"
                      maxLength={254}
                      placeholder="name@company.com"
                      className={field}
                      value={email}
                      onChange={(e) => {
                        setEmail(e.target.value);
                        setAccountMessage('');
                      }}
                    />
                  </label>
                  <label className="block text-xs font-medium text-zinc-300 light:text-zinc-700">
                    Access role
                    <select
                      className={field}
                      value={role}
                      onChange={(e) => {
                        setRole(e.target.value);
                        setAccountMessage('');
                      }}
                    >
                      <option>VIEWER</option>
                      <option>OPERATOR</option>
                      <option>ADMIN</option>
                    </select>
                  </label>
                  <button type="submit" disabled={pending > 0} className="ui-primary lg:mb-0">
                    <Plus className="h-3.5 w-3.5" aria-hidden="true" />
                    Create account
                  </button>
                  {accountMessage && (
                    <p
                      role="status"
                      className={`text-xs sm:col-span-2 xl:col-span-2 ${accountMessage.includes('successfully') ? 'text-emerald-400 light:text-emerald-700' : 'text-rose-400 light:text-rose-700'}`}
                    >
                      {accountMessage}
                    </p>
                  )}
                </form>
              </details>

              <div>
                <div className="mb-2 flex items-center justify-between gap-3">
                  <h3 className="text-xs font-semibold">Workspace accounts</h3>
                  <span className="ui-description">
                    {usersLoading ? '…' : users.length} {users.length === 1 ? 'account' : 'accounts'}
                  </span>
                </div>
                {usersLoading ? (
                  <div className="settings-empty">
                    <LoaderCircle size={22} className="animate-spin" />
                    <p>Loading workspace accounts…</p>
                  </div>
                ) : usersError ? (
                  <div className="settings-empty" role="alert">
                    <AlertCircle size={22} />
                    <p>{usersError}</p>
                    <button type="button" className="ui-secondary" onClick={() => void reloadUsers()}>
                      Retry
                    </button>
                  </div>
                ) : users.length ? (
                  <ul className="divide-y divide-zinc-800/80 overflow-hidden rounded-xl border border-zinc-800/80 light:divide-zinc-200 light:border-zinc-200">
                    {[...users]
                      .sort(
                        (a, b) =>
                          Number(a.disabled) - Number(b.disabled) || a.username.localeCompare(b.username),
                      )
                      .map((user) => (
                        <li
                          key={user.id}
                          className="flex flex-col gap-3 px-4 py-3 sm:flex-row sm:items-center sm:justify-between"
                        >
                          <div className="settings-user-identity">
                            <span className="settings-user-avatar">
                              {user.username.slice(0, 1).toUpperCase()}
                            </span>
                            <div className="min-w-0">
                              <p className="truncate text-sm font-medium">{user.username}</p>
                              <p className="truncate text-[11px] text-zinc-500 light:text-zinc-600">
                                {user.email || 'No reset email set'}
                              </p>
                              <div className="mt-1.5 flex flex-wrap items-center gap-2">
                                <span
                                  className={`rounded-full border px-2 py-0.5 text-[10px] font-medium ${
                                    user.role === 'ADMIN'
                                      ? 'border-blue-500/25 bg-blue-500/10 text-blue-300 light:text-blue-700'
                                      : user.role === 'OPERATOR'
                                        ? 'border-violet-500/25 bg-violet-500/10 text-violet-300 light:text-violet-700'
                                        : 'border-zinc-700/80 bg-zinc-800/60 text-zinc-300 light:border-zinc-200 light:bg-zinc-100 light:text-zinc-700'
                                  }`}
                                >
                                  {user.role}
                                </span>
                                <span
                                  className={`inline-flex items-center gap-1.5 text-[10px] ${user.disabled ? 'text-zinc-500' : 'text-emerald-400 light:text-emerald-700'}`}
                                >
                                  <span
                                    className={`h-1.5 w-1.5 rounded-full ${user.disabled ? 'bg-zinc-500' : 'bg-emerald-400'}`}
                                  />
                                  {user.disabled ? 'Disabled' : 'Active'}
                                </span>
                                {user.username === session?.username && (
                                  <span className="text-[10px] text-zinc-500">You</span>
                                )}
                              </div>
                            </div>
                          </div>
                          <div className="flex items-center gap-1.5">
                          <button
                            type="button"
                            className="min-h-8 rounded-lg border border-zinc-700 px-3 py-1.5 text-[11px] font-medium text-zinc-300 hover:bg-zinc-800 transition light:border-zinc-300 light:text-zinc-700 light:hover:bg-zinc-100"
                            onClick={() => {
                              setEditingUser(user);
                              setEditForm({
                                username: user.username,
                                role: user.role,
                                email: user.email || '',
                                disabled: !!user.disabled,
                              });
                              setEditMessage('');
                            }}
                          >
                            <Pencil className="h-3 w-3 inline mr-1" />
                            Edit
                          </button>
                          {user.username !== session?.username && !user.disabled && (
                            <button
                              type="button"
                              className="min-h-8 rounded-lg border border-zinc-700 px-3 py-1.5 text-[11px] font-medium text-zinc-300 hover:bg-zinc-800 transition light:border-zinc-300 light:text-zinc-700 light:hover:bg-zinc-100"
                              onClick={() => {
                                setResetUserId(user.id);
                                setResetPassword('');
                              }}
                            >
                              <KeyRound className="h-3 w-3 inline mr-1" />
                              Reset password
                            </button>
                          )}
                          {user.username !== session?.username && (
                            <button
                              type="button"
                              className={`min-h-8 rounded-lg border px-3 py-1.5 text-[11px] font-medium transition ${
                                user.disabled
                                  ? 'border-emerald-500/25 text-emerald-300 hover:bg-emerald-500/10 light:text-emerald-700'
                                  : 'border-zinc-700 text-zinc-300 hover:bg-zinc-800 light:border-zinc-300 light:text-zinc-700 light:hover:bg-zinc-100'
                              }`}
                              disabled={pending > 0}
                              onClick={async () => {
                                if (!user.disabled) {
                                  setDisablingUserId(user.id);
                                  return;
                                }
                                await updateUser(user.id, { role: user.role, disabled: !user.disabled });
                                await reloadUsers();
                              }}
                            >
                               {user.disabled ? 'Enable account' : 'Disable account'}
                             </button>
                           )}
                           {user.username !== session?.username && (
                             <button
                               type="button"
                               className="min-h-8 rounded-lg border border-rose-500/25 px-3 py-1.5 text-[11px] font-medium text-rose-300 hover:bg-rose-500/10 transition light:border-rose-200 light:text-rose-700 light:hover:bg-rose-100"
                               disabled={pending > 0}
                               onClick={() => setDeleteUserId(user.id)}
                             >
                               <Trash2 className="h-3 w-3 inline mr-1" />
                               Delete account
                             </button>
                           )}
                         </div>
                        </li>
                      ))}
                  </ul>
                ) : (
                  <p className="rounded-xl border border-dashed border-zinc-700 px-4 py-8 text-center text-xs text-zinc-500 light:border-zinc-300">
                    No operator accounts found.
                  </p>
                )}
              </div>
            </section>
          )}
        </div>
      </div>

      {resetUserId && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-sm w-full p-6 shadow-2xl relative">
            <button
              aria-label="Close"
              onClick={() => setResetUserId(null)}
              className="absolute top-4 right-4 text-zinc-500 hover:text-zinc-200 dark:text-zinc-500 dark:hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-800"
            >
              <span className="text-xl">×</span>
            </button>
            <h3 className="text-sm font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 mb-4">
              Reset password
            </h3>
            <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-4">
              Enter a new password for this operator. All active sessions will be signed out.
            </p>
            <input
              type="password"
              autoComplete="new-password"
              required
              minLength={14}
              maxLength={128}
              className={field}
              value={resetPassword}
              onChange={(e) => setResetPassword(e.target.value)}
              placeholder="New password (min 14 characters)"
            />
            <div className="flex justify-end gap-2 mt-4">
              <button
                type="button"
                className="px-3.5 py-2 rounded-xl bg-zinc-800 hover:bg-zinc-700 dark:bg-zinc-800 dark:hover:bg-zinc-700 light:bg-zinc-100 light:hover:bg-zinc-200 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 text-xs font-medium transition"
                onClick={() => setResetUserId(null)}
              >
                Cancel
              </button>
              <button
                type="button"
                className="px-3.5 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold disabled:opacity-50 transition"
                disabled={pending > 0 || resetPassword.length < 14}
                onClick={async () => {
                  const ok = await resetUserPassword(resetUserId!, resetPassword);
                  if (ok) {
                    await reloadUsers();
                    setResetUserId(null);
                    setResetPassword('');
                  }
                }}
              >
                Reset
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Edit Account Modal */}
      {editingUser && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <form
            className="ui-panel bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-md w-full p-6 shadow-2xl relative space-y-4"
            aria-labelledby="edit-account-title"
            onSubmit={async (e) => {
              e.preventDefault();
              const address = editForm.email.trim();
              if (!address) {
                setEditMessage('An email address is required for password reset.');
                return;
              }
              if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(address)) {
                setEditMessage('Enter a valid email address, for example name@company.com.');
                return;
              }
              setEditMessage('');
              const ok = await updateUser(editingUser.id, {
                role: editForm.role,
                email: address,
                disabled: editForm.disabled,
              });
              if (!ok) {
                setEditMessage('The account could not be updated.');
                return;
              }
              await reloadUsers();
              setEditingUser(null);
            }}
          >
            <div className="flex items-start justify-between gap-4">
              <div>
                <h3
                  id="edit-account-title"
                  className="text-sm font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900"
                >
                  Edit workspace account
                </h3>
                <p className="mt-1 text-xs text-zinc-400 light:text-zinc-600">
                  The username <strong>{editForm.username}</strong> is the login and cannot be changed. Use
                  Reset password to set a new one.
                </p>
              </div>
              <button
                type="button"
                aria-label="Close"
                onClick={() => setEditingUser(null)}
                className="text-zinc-500 hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-800"
              >
                <span className="text-xl">×</span>
              </button>
            </div>
            <label className="block text-xs font-medium text-zinc-300 light:text-zinc-700">
              Reset email address
              <input
                type="email"
                required
                maxLength={254}
                className={field}
                value={editForm.email}
                onChange={(e) => {
                  setEditForm((f) => ({ ...f, email: e.target.value }));
                  setEditMessage('');
                }}
              />
            </label>
            <label className="block text-xs font-medium text-zinc-300 light:text-zinc-700">
              Access role
              <select
                className={field}
                value={editForm.role}
                // The server refuses to demote or disable your own account; the
                // control is locked here so the reason is visible before saving.
                disabled={editingUser.id === users.find((u) => u.username === session?.username)?.id}
                onChange={(e) => setEditForm((f) => ({ ...f, role: e.target.value }))}
              >
                <option>VIEWER</option>
                <option>OPERATOR</option>
                <option>ADMIN</option>
              </select>
            </label>
            <label className="flex items-center gap-2 text-xs text-zinc-300 light:text-zinc-700">
              <input
                type="checkbox"
                checked={editForm.disabled}
                disabled={editingUser.id === users.find((u) => u.username === session?.username)?.id}
                onChange={(e) => setEditForm((f) => ({ ...f, disabled: e.target.checked }))}
              />
              Account disabled (cannot sign in; active sessions are revoked)
            </label>
            {editMessage && (
              <p role="alert" className="text-xs text-rose-400 light:text-rose-700">
                {editMessage}
              </p>
            )}
            <div className="flex justify-end gap-2 pt-1">
              <button
                type="button"
                onClick={() => setEditingUser(null)}
                className="px-3.5 py-2 rounded-xl bg-zinc-800 hover:bg-zinc-700 dark:bg-zinc-800 dark:hover:bg-zinc-700 light:bg-zinc-100 light:hover:bg-zinc-200 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 text-xs font-medium transition"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={pending > 0}
                className="px-3.5 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold disabled:opacity-50 transition"
              >
                {pending > 0 ? 'Saving…' : 'Save changes'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Disable Account Confirmation Modal */}
      {disablingUserId && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="ui-panel bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-sm w-full p-6 shadow-2xl relative">
            <h3 className="text-sm font-bold text-rose-300 dark:text-rose-300 light:text-rose-700 mb-2">
              Disable Operator Account?
            </h3>
            <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 leading-relaxed mb-6">
              Are you sure you want to disable this account? The operator will be unable to sign in until the
              account is re-enabled, and any active sessions are revoked.
            </p>
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setDisablingUserId(null)}
                className="px-3.5 py-2 rounded-xl bg-zinc-800 hover:bg-zinc-700 dark:bg-zinc-800 dark:hover:bg-zinc-700 light:bg-zinc-100 light:hover:bg-zinc-200 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 text-xs font-medium transition"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={async () => {
                  const target = users.find((u) => u.id === disablingUserId);
                  if (!target) {
                    setDisablingUserId(null);
                    return;
                  }
                  await updateUser(target.id, { role: target.role, disabled: true });
                  await reloadUsers();
                  setDisablingUserId(null);
                }}
                disabled={pending > 0}
                className="px-3.5 py-2 rounded-xl bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold disabled:opacity-50 transition"
              >
                {pending > 0 ? 'Disabling…' : 'Disable Account'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Delete Account Confirmation Modal */}
      {deleteUserId && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="ui-panel bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-sm w-full p-6 shadow-2xl relative">
            <h3 className="text-sm font-bold text-rose-300 dark:text-rose-300 light:text-rose-700 mb-2">
              Delete Operator Account?
            </h3>
            <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 leading-relaxed mb-6">
              This action is permanent. The operator will be removed from the workspace and all active
              sessions will be revoked. This cannot be undone.
            </p>
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setDeleteUserId(null)}
                className="px-3.5 py-2 rounded-xl bg-zinc-800 hover:bg-zinc-700 dark:bg-zinc-800 dark:hover:bg-zinc-700 light:bg-zinc-100 light:hover:bg-zinc-200 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 text-xs font-medium transition"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={async () => {
                  const target = users.find((u) => u.id === deleteUserId);
                  if (!target) {
                    setDeleteUserId(null);
                    return;
                  }
                  await deleteUser(target.id);
                  await reloadUsers();
                  setDeleteUserId(null);
                }}
                disabled={pending > 0}
                className="px-3.5 py-2 rounded-xl bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold disabled:opacity-50 transition"
              >
                {pending > 0 ? 'Deleting…' : 'Delete Account'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
