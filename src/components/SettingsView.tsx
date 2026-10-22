import React, { useEffect, useState } from 'react';
import {
  Check,
  KeyRound,
  LockKeyhole,
  Plus,
  Settings2,
  ShieldCheck,
  SlidersHorizontal,
  Users,
} from 'lucide-react';
import { useApp } from '../context/AppContext';
import { EmailProviderSettings } from './EmailProviderSettings';

const field = 'ui-field';

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
    <div className="flex items-start gap-3.5">
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
  const { settings, updateSettings, changePassword, session, listUsers, createUser, updateUser, pending } =
    useApp();
  const [form, setForm] = useState(settings);
  const [message, setMessage] = useState('');
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [users, setUsers] = useState<any[]>([]);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('VIEWER');
  const [accountMessage, setAccountMessage] = useState('');
  const admin = session?.role === 'ADMIN';

  const reloadUsers = async () => {
    const result = await listUsers();
    if (result) setUsers(result);
  };

  useEffect(() => {
    if (admin) void reloadUsers();
  }, [admin]);

  return (
    <div className="mx-auto max-w-5xl space-y-6 text-zinc-100 light:text-zinc-900">
      <header>
        <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-zinc-500">Workspace</p>
        <h1 className="mt-1 flex items-center gap-2.5 text-2xl font-semibold tracking-tight">
          <span className="grid h-9 w-9 place-items-center rounded-xl border border-blue-500/20 bg-blue-500/10 text-blue-300 light:text-blue-700">
            <Settings2 className="h-4 w-4" aria-hidden="true" />
          </span>
          Settings
        </h1>
        <p className="ui-description mt-2 max-w-2xl text-sm">
          Configure processing, email delivery, account security, and workspace access.
        </p>
      </header>

      {admin && <EmailProviderSettings />}

      {admin && (
        <form
          className="ui-card space-y-5"
          aria-labelledby="processing-settings-title"
          onSubmit={async (e) => {
            e.preventDefault();
            setMessage('');
            if (await updateSettings(form)) setMessage('Settings saved successfully.');
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
              <span className="ui-description mt-1.5 block">The delay between scheduled pipeline runs.</span>
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
              Session timeout
              <span className="ml-1 font-normal text-zinc-500">(minutes)</span>
              <input
                type="number"
                min={5}
                max={60}
                required
                className={field}
                value={form.securityPolicy.sessionTimeoutMins}
                onChange={(e) =>
                  setForm({
                    ...form,
                    securityPolicy: { ...form.securityPolicy, sessionTimeoutMins: Number(e.target.value) },
                  })
                }
              />
              <span className="ui-description mt-1.5 block">Inactive sessions expire after this period.</span>
            </label>
          </div>

          <div className="grid gap-3 sm:grid-cols-2">
            <label className="ui-check-row cursor-pointer text-xs leading-relaxed">
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
            <label className="ui-check-row cursor-pointer text-xs leading-relaxed">
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
                  Send confirmed findings to security teams automatically; everyone recipients wait in Email Queue for security review.
                </span>
              </span>
            </label>
          </div>

          <p className="rounded-xl border border-zinc-800 bg-zinc-950/30 px-4 py-3 text-xs leading-relaxed text-zinc-400 light:border-zinc-200 light:bg-zinc-50 light:text-zinc-600">
            Outbound host permissions are managed by the deployment administrator. Host clock synchronization,
            CSRF protection, and private-network safeguards are enforced at runtime.
          </p>

          <div className="ui-actions justify-between">
            {message ? (
              <p role="status" className="ui-success inline-flex items-center gap-2">
                <Check className="h-3.5 w-3.5" aria-hidden="true" /> {message}
              </p>
            ) : (
              <span className="ui-description">Changes apply to future processing runs.</span>
            )}
            <button type="submit" disabled={pending > 0} className="ui-primary">
              {pending > 0 ? 'Saving…' : 'Save settings'}
            </button>
          </div>
        </form>
      )}

      <form
        className="ui-card space-y-5"
        aria-labelledby="account-security-title"
        onSubmit={async (e) => {
          e.preventDefault();
          await changePassword(currentPassword, newPassword);
          setCurrentPassword('');
          setNewPassword('');
        }}
      >
        <SectionHeading
          icon={ShieldCheck}
          id="account-security-title"
          title="Account security"
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

      {admin && (
        <section className="ui-card space-y-5" aria-labelledby="operator-accounts-title">
          <SectionHeading
            icon={Users}
            id="operator-accounts-title"
            title="Operator accounts"
            description="Manage who can access this workspace and what they can do."
          />
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

          <div className="grid grid-cols-3 gap-2" aria-label="Account totals">
            {[
              ['Active', users.filter((user) => !user.disabled).length, 'text-emerald-300 light:text-emerald-700'],
              ['Disabled', users.filter((user) => user.disabled).length, 'text-zinc-400'],
              ['Admins', users.filter((user) => user.role === 'ADMIN').length, 'text-blue-300 light:text-blue-700'],
            ].map(([label, count, color]) => (
              <div key={String(label)} className="rounded-xl border border-zinc-800/80 bg-zinc-950/25 px-3 py-2.5 light:border-zinc-200 light:bg-zinc-50">
                <p className="text-[10px] font-medium uppercase tracking-wider text-zinc-500">{label}</p>
                <p className={`mt-1 text-lg font-semibold tabular-nums ${color}`}>{count}</p>
              </div>
            ))}
          </div>

          <form
            className="grid gap-4 rounded-xl border border-zinc-800/80 bg-zinc-950/25 p-4 sm:grid-cols-2 lg:grid-cols-[1.1fr_1.1fr_0.8fr_auto] lg:items-end light:border-zinc-200 light:bg-zinc-50"
            onSubmit={async (e) => {
              e.preventDefault();
              if (!username.trim() || !password || !role) {
                setAccountMessage('Username, password, and role are required.');
                return;
              }
              if (password.length < 14) {
                setAccountMessage('Password must be at least 14 characters.');
                return;
              }
              if (!/^[a-zA-Z0-9._@-]{3,100}$/.test(username)) {
                setAccountMessage('Username can only contain letters, numbers, periods, underscores, at signs, and hyphens.');
                return;
              }
              setAccountMessage('');
              if (await createUser({ username, password, role })) {
                setUsername('');
                setPassword('');
                setRole('VIEWER');
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
                className={`text-xs sm:col-span-2 lg:col-span-4 ${accountMessage.includes('successfully') ? 'text-emerald-400 light:text-emerald-700' : 'text-rose-400 light:text-rose-700'}`}
              >
                {accountMessage}
              </p>
            )}
          </form>

          <div>
            <div className="mb-2 flex items-center justify-between gap-3">
              <h3 className="text-xs font-semibold">Workspace accounts</h3>
              <span className="ui-description">
                {users.length} {users.length === 1 ? 'account' : 'accounts'}
              </span>
            </div>
            {users.length ? (
              <ul className="divide-y divide-zinc-800/80 overflow-hidden rounded-xl border border-zinc-800/80 light:divide-zinc-200 light:border-zinc-200">
                {[...users].sort((a, b) => Number(a.disabled) - Number(b.disabled) || a.username.localeCompare(b.username)).map((user) => (
                  <li
                    key={user.id}
                    className="flex flex-col gap-3 px-4 py-3 sm:flex-row sm:items-center sm:justify-between"
                  >
                    <div className="min-w-0">
                      <p className="truncate text-sm font-medium">{user.username}</p>
                      <div className="mt-1.5 flex flex-wrap items-center gap-2">
                        <span className={`rounded-full border px-2 py-0.5 text-[10px] font-medium ${
                          user.role === 'ADMIN'
                            ? 'border-blue-500/25 bg-blue-500/10 text-blue-300 light:text-blue-700'
                            : user.role === 'OPERATOR'
                              ? 'border-violet-500/25 bg-violet-500/10 text-violet-300 light:text-violet-700'
                              : 'border-zinc-700/80 bg-zinc-800/60 text-zinc-300 light:border-zinc-200 light:bg-zinc-100 light:text-zinc-700'
                        }`}>
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
                    {user.username !== session?.username && (
                      <button
                        type="button"
                        className={`min-h-8 rounded-lg border px-3 py-1.5 text-[11px] font-medium transition ${user.disabled
                          ? 'border-emerald-500/25 text-emerald-300 hover:bg-emerald-500/10 light:text-emerald-700'
                          : 'border-zinc-700 text-zinc-300 hover:bg-zinc-800 light:border-zinc-300 light:text-zinc-700 light:hover:bg-zinc-100'
                        }`}
                        disabled={pending > 0}
                        onClick={async () => {
                          await updateUser(user.id, { role: user.role, disabled: !user.disabled });
                          await reloadUsers();
                        }}
                      >
                        {user.disabled ? 'Enable account' : 'Disable account'}
                      </button>
                    )}
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
  );
}
