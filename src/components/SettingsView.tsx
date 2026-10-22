import React, { useEffect, useState } from 'react';
import { useApp } from '../context/AppContext';
import { Settings2, ShieldCheck, SlidersHorizontal, Users } from 'lucide-react';
import { EmailProviderSettings } from './EmailProviderSettings';
const field = 'ui-field';
export function SettingsView() {
  const { settings, updateSettings, changePassword, session, listUsers, createUser, updateUser, pending } =
    useApp();
  const [form, setForm] = useState(settings),
    [message, setMessage] = useState(''),
    [currentPassword, setCurrentPassword] = useState(''),
    [newPassword, setNewPassword] = useState('');
  const [users, setUsers] = useState<any[]>([]),
    [username, setUsername] = useState(''),
    [password, setPassword] = useState(''),
    [role, setRole] = useState('VIEWER');
  const admin = session?.role === 'ADMIN';
  const reloadUsers = async () => {
    const result = await listUsers();
    if (result) setUsers(result);
  };
  useEffect(() => {
    if (admin) void reloadUsers();
  }, [admin]);
  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      <div>
        <h1 className="flex items-center gap-2.5 text-xl font-bold tracking-tight">
          <Settings2 className="h-5 w-5 text-zinc-400" />
          Settings
        </h1>
        <p className="ui-description mt-1.5">
          Manage processing, email delivery, and access to your workspace.
        </p>
      </div>
      {admin && <EmailProviderSettings />}
      {admin && (
        <form
          className="ui-card space-y-5"
          onSubmit={async (e) => {
            e.preventDefault();
            setMessage('');
            if (await updateSettings(form)) setMessage('Settings saved.');
          }}
        >
          <div className="flex items-start gap-3">
            <span className="ui-section-icon">
              <SlidersHorizontal className="h-4 w-4" />
            </span>
            <div>
              <h2 className="ui-card-title">Processing and dispatch</h2>
              <p className="ui-description mt-1">
                Set ingestion windows, scheduling, and automatic notifications.
              </p>
            </div>
          </div>
          <div className="grid sm:grid-cols-2 gap-4">
            <label>
              Scope (hours)
              <input
                type="number"
                min={1}
                max={2880}
                required
                className={field}
                value={form.scopeHours}
                onChange={(e) => setForm({ ...form, scopeHours: Number(e.target.value) })}
              />
            </label>
            <label>
              Schedule interval (minutes)
              <input
                type="number"
                min={5}
                max={10080}
                required
                className={field}
                value={form.schedulerIntervalMinutes}
                onChange={(e) => setForm({ ...form, schedulerIntervalMinutes: Number(e.target.value) })}
              />
            </label>
            <label>
              Advisory prefix
              <input
                required
                pattern="[A-Za-z0-9_-]{1,30}"
                className={field}
                value={form.advisoryPrefix}
                onChange={(e) => setForm({ ...form, advisoryPrefix: e.target.value })}
              />
            </label>
            <label>
              Session timeout (minutes)
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
            </label>
          </div>
          <label className="ui-check-row">
            <input
              type="checkbox"
              checked={form.schedulerEnabled}
              onChange={(e) => setForm({ ...form, schedulerEnabled: e.target.checked })}
            />{' '}
            Enable server scheduler
          </label>
          <label className="ui-check-row">
            <input
              type="checkbox"
              checked={form.autoDispatchEnabled}
              onChange={(e) => setForm({ ...form, autoDispatchEnabled: e.target.checked })}
            />{' '}
            Automatically queue confirmed correlations to enabled recipients and webhooks
          </label>
          <p className="text-sm text-zinc-400">
            Outbound host permissions are configured by the deployment administrator. Clock synchronization is
            managed by the host. CSRF and private-network protections are always enforced.
          </p>
          <button disabled={pending > 0} className="ui-primary">
            Save settings
          </button>
          {message && (
            <p role="status" className="ui-success">
              {message}
            </p>
          )}
        </form>
      )}
      <form
        className="ui-card space-y-4"
        onSubmit={async (e) => {
          e.preventDefault();
          await changePassword(currentPassword, newPassword);
          setCurrentPassword('');
          setNewPassword('');
        }}
      >
        <div className="flex items-center gap-3">
          <span className="ui-section-icon">
            <ShieldCheck className="h-4 w-4" />
          </span>
          <h2 className="ui-card-title">Account security</h2>
        </div>
        <p className="text-sm text-zinc-400">
          Changing your password revokes every session. Sign in again afterward.
        </p>
        <label className="block">
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
        <label className="block">
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
        </label>
        <button disabled={pending > 0} className="ui-primary">
          Change password
        </button>
      </form>
      {admin && (
          <section className="ui-card space-y-6">
            <div className="flex items-center gap-3">
              <span className="ui-section-icon">
                <Users className="h-4 w-4" />
              </span>
              <div>
                <h2 className="ui-card-title">Operator accounts</h2>
                <p className="ui-description mt-1">
                  Administrators manage configuration and accounts. Operators manage inventory and runs. Viewers
                  have read-only access.
                </p>
              </div>
            </div>
            <form
              className="space-y-5"
              onSubmit={async (e) => {
                e.preventDefault();
                if (!username.trim() || !password || !role) {
                  setMessage('Username, password, and role are required');
                  return;
                }
                if (password.length < 14) {
                  setMessage('Password must be at least 14 characters');
                  return;
                }
                if (!/^[a-zA-Z0-9._@-]{3,100}$/.test(username)) {
                  setMessage('Username can only contain letters, numbers, periods, underscores, at signs, and hyphens');
                  return;
                }
                setMessage('');
                if (await createUser({ username, password, role })) {
                  setUsername('');
                  setPassword('');
                  setRole('VIEWER');
                  await reloadUsers();
                  setMessage('Operator created successfully');
                } else {
                  setMessage('Failed to create operator');
                }
              }}
            >
              <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-5">
                <div className="space-y-1.5">
                  <label htmlFor="username-input" className="block text-sm font-medium text-zinc-300">
                    Username
                  </label>
                  <input
                    id="username-input"
                    required
                    pattern="[a-zA-Z0-9._@-]{3,100}"
                    className="w-full rounded-xl border border-zinc-700 bg-zinc-950 px-4 py-2.5 text-sm text-zinc-100 placeholder:text-zinc-500 focus:border-blue-500 focus:outline-none transition"
                    value={username}
                    onChange={(e) => {
                      setUsername(e.target.value);
                      if (message.includes('Username')) setMessage('');
                    }}
                    placeholder="operator@example.com"
                  />
                  {message && message.includes('Username') && (
                    <p className="text-xs text-red-400">{message}</p>
                  )}
                </div>
                <div className="space-y-1.5">
                  <label htmlFor="password-input" className="block text-sm font-medium text-zinc-300">
                    Initial password
                  </label>
                  <input
                    id="password-input"
                    type="password"
                    autoComplete="new-password"
                    required
                    minLength={14}
                    maxLength={128}
                    className="w-full rounded-xl border border-zinc-700 bg-zinc-950 px-4 py-2.5 text-sm text-zinc-100 placeholder:text-zinc-500 focus:border-blue-500 focus:outline-none transition"
                    value={password}
                    onChange={(e) => {
                      setPassword(e.target.value);
                      if (message.includes('Password')) setMessage('');
                    }}
                    placeholder="••••••••••••••••"
                  />
                  {message && message.includes('Password') && (
                    <p className="text-xs text-red-400">{message}</p>
                  )}
                </div>
                <div className="space-y-1.5">
                  <label htmlFor="role-select" className="block text-sm font-medium text-zinc-300">
                    Role
                  </label>
                  <select
                    id="role-select"
                    className="w-full rounded-xl border border-zinc-700 bg-zinc-950 px-4 py-2.5 text-sm text-zinc-100 focus:border-blue-500 focus:outline-none transition"
                    value={role}
                    onChange={(e) => {
                      setRole(e.target.value);
                      if (message.includes('Username')) setMessage('');
                    }}
                  >
                    <option value="VIEWER">Viewer (read-only)</option>
                    <option value="OPERATOR">Operator (manages inventory and runs)</option>
                    <option value="ADMIN">Admin (full access)</option>
                  </select>
                </div>
                <div className="sm:col-span-2 lg:col-span-1 flex items-end">
                  <button
                    type="submit"
                    disabled={pending > 0}
                    className="w-full rounded-xl bg-blue-600 px-6 py-2.5 text-sm font-medium text-white transition hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    Create operator
                  </button>
                </div>
              </div>
              {message && !message.includes('Username') && !message.includes('Password') && (
                <p
                  role="status"
                  className={`text-sm ${message.includes('successfully') ? 'text-green-400' : 'text-red-400'}`}
                >
                  {message}
                </p>
              )}
            </form>
            <div className="space-y-4">
              <h3 className="text-sm font-semibold text-zinc-300">Current operators ({users.length})</h3>
              {users.length === 0 && (
                <div className="rounded-lg border border-zinc-800 bg-zinc-900/50 p-6 text-center">
                  <p className="text-sm text-zinc-400">No operator accounts exist.</p>
                </div>
              )}
              <ul className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
                {users.map((user) => (
                  <li
                    key={user.id}
                    className="rounded-lg border border-zinc-800 bg-zinc-900/30 p-4 transition hover:bg-zinc-800/50"
                  >
                    <div className="space-y-3">
                      <div className="flex items-start justify-between">
                        <div className="flex-1 min-w-0">
                          <p className="truncate text-sm font-medium text-zinc-100">{user.username}</p>
                          <p className="text-xs text-zinc-400">Role: {user.role}</p>
                        </div>
                        <span
                          className={`rounded-full px-2 py-0.5 text-xs font-medium ${user.disabled ? 'bg-red-900/30 text-red-400' : 'bg-green-900/30 text-green-400'}`}
                        >
                          {user.disabled ? 'Disabled' : 'Enabled'}
                        </span>
                      </div>
                      {user.username !== session?.username && (
                        <button
                          type="button"
                          className="w-full rounded-lg border border-zinc-700 bg-zinc-800/50 px-3 py-1.5 text-xs font-medium text-zinc-200 transition hover:bg-zinc-700 hover:text-white"
                          onClick={async () => {
                            await updateUser(user.id, { role: user.role, disabled: !user.disabled });
                            await reloadUsers();
                          }}
                          disabled={pending > 0}
                        >
                          {user.disabled ? 'Enable' : 'Disable'}
                        </button>
                      )}
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          </section>
      )}
    </div>
  );
}
