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
        <section className="ui-card space-y-4">
          <div className="flex items-center gap-3">
            <span className="ui-section-icon">
              <Users className="h-4 w-4" />
            </span>
            <h2 className="ui-card-title">Operator accounts</h2>
          </div>
          <p className="text-sm text-zinc-400">
            Administrators manage configuration and accounts. Operators manage inventory and runs. Viewers
            have read-only access.
          </p>
          <form
            className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4"
            onSubmit={async (e) => {
              e.preventDefault();
              if (await createUser({ username, password, role })) {
                setUsername('');
                setPassword('');
                await reloadUsers();
              }
            }}
          >
            <label>
              Username
              <input
                required
                pattern="[a-zA-Z0-9._@-]{3,100}"
                className={field}
                value={username}
                onChange={(e) => setUsername(e.target.value)}
              />
            </label>
            <label>
              Initial password
              <input
                type="password"
                autoComplete="new-password"
                required
                minLength={14}
                maxLength={128}
                className={field}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </label>
            <label>
              Role
              <select className={field} value={role} onChange={(e) => setRole(e.target.value)}>
                <option>VIEWER</option>
                <option>OPERATOR</option>
                <option>ADMIN</option>
              </select>
            </label>
            <button disabled={pending > 0} className="ui-primary self-end">
              Create operator
            </button>
          </form>
          <ul className="space-y-3">
            {users.map((user) => (
              <li key={user.id} className="flex flex-wrap gap-4 items-center border-t border-zinc-700 pt-3">
                <span>{user.username}</span>
                <span>{user.role}</span>
                <span>{user.disabled ? 'Disabled' : 'Enabled'}</span>
                {user.username !== session?.username && (
                  <button
                    className="underline"
                    onClick={async () => {
                      await updateUser(user.id, { role: user.role, disabled: !user.disabled });
                      await reloadUsers();
                    }}
                  >
                    {user.disabled ? 'Enable' : 'Disable'}
                  </button>
                )}
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}
