import React, { useEffect, useState } from 'react';
import { useApp } from '../context/AppContext';
const field = 'block w-full rounded border border-zinc-600 bg-transparent p-2 mt-1';
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
    <div className="space-y-6 max-w-4xl">
      <h1 className="text-xl font-bold">Configuration and operator accounts</h1>
      {admin && (
        <form
          className="rounded-xl border border-zinc-700 p-5 space-y-4"
          onSubmit={async (e) => {
            e.preventDefault();
            setMessage('');
            if (await updateSettings(form)) setMessage('Settings saved.');
          }}
        >
          <h2 className="font-semibold">Processing and dispatch</h2>
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
          <label className="block">
            <input
              type="checkbox"
              checked={form.schedulerEnabled}
              onChange={(e) => setForm({ ...form, schedulerEnabled: e.target.checked })}
            />{' '}
            Enable server scheduler
          </label>
          <label className="block">
            <input
              type="checkbox"
              checked={form.autoDispatchEnabled}
              onChange={(e) => setForm({ ...form, autoDispatchEnabled: e.target.checked })}
            />{' '}
            Automatically queue confirmed correlations to enabled recipients and webhooks
          </label>
          <p className="text-sm text-zinc-400">
            SMTP and outbound host permissions are configured by the deployment administrator. Clock
            synchronization is managed by the host. CSRF and private-network protections are always enforced.
          </p>
          <button disabled={pending > 0} className="bg-blue-600 rounded px-4 py-2">
            Save settings
          </button>
          {message && <p role="status">{message}</p>}
        </form>
      )}
      <form
        className="rounded-xl border border-zinc-700 p-5 space-y-4"
        onSubmit={async (e) => {
          e.preventDefault();
          await changePassword(currentPassword, newPassword);
          setCurrentPassword('');
          setNewPassword('');
        }}
      >
        <h2 className="font-semibold">Change password</h2>
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
        <button disabled={pending > 0} className="bg-blue-600 rounded px-4 py-2">
          Change password
        </button>
      </form>
      {admin && (
        <section className="rounded-xl border border-zinc-700 p-5 space-y-4">
          <h2 className="font-semibold">Operator accounts</h2>
          <p className="text-sm text-zinc-400">
            Administrators manage configuration and accounts. Operators manage inventory and runs. Viewers
            have read-only access.
          </p>
          <form
            className="grid sm:grid-cols-4 gap-3"
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
            <button disabled={pending > 0} className="bg-blue-600 rounded px-4 py-2 self-end">
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
