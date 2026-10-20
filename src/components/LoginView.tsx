import React, { useState } from 'react';
import { useApp } from '../context/AppContext';
export function LoginView() {
  const { login, error, pending, loading } = useApp();
  const [username, setUsername] = useState(''),
    [password, setPassword] = useState('');
  return (
    <main className="min-h-screen bg-zinc-950 text-zinc-100 flex items-center justify-center p-6">
      <form
        className="w-full max-w-sm bg-zinc-900 border border-zinc-700 rounded-xl p-8 space-y-5"
        onSubmit={async (e) => {
          e.preventDefault();
          await login(username, password);
          setPassword('');
        }}
      >
        <h1 className="text-2xl font-bold">VulnStream Enterprise</h1>
        <p className="text-zinc-400">Sign in with your operator account.</p>
        {loading ? (
          <p>Connecting to server…</p>
        ) : (
          <>
            <label className="block">
              Username
              <input
                className="block w-full rounded border border-zinc-600 p-2 mt-1"
                autoComplete="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                maxLength={100}
              />
            </label>
            <label className="block">
              Password
              <input
                className="block w-full rounded border border-zinc-600 p-2 mt-1"
                autoComplete="current-password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                maxLength={128}
              />
            </label>
            <button className="bg-blue-600 rounded px-5 py-2 disabled:opacity-50" disabled={pending > 0}>
              {pending ? 'Signing in…' : 'Sign in'}
            </button>
          </>
        )}
        {error && (
          <p role="alert" className="text-red-300">
            {error}
          </p>
        )}
      </form>
    </main>
  );
}
