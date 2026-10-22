import React, { useState } from 'react';
import { ArrowRight, KeyRound, LoaderCircle, Moon, ShieldCheck, Sun } from 'lucide-react';
import { useApp } from '../context/AppContext';

export function LoginView() {
  const { login, error, pending, loading, theme, toggleTheme } = useApp();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');

  return (
    <main className={`login-screen ${theme}`}>
      <div className="login-grid" aria-hidden="true" />
      <button
        type="button"
        onClick={toggleTheme}
        className="login-theme-toggle"
        aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
        title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
      >
        {theme === 'dark' ? <Sun size={17} /> : <Moon size={17} />}
      </button>

      <section className="login-card" aria-labelledby="login-heading">
        <div className="login-brand-row">
          <div className="login-brand-mark"><ShieldCheck size={23} strokeWidth={1.8} /></div>
          <div>
            <div className="login-brand-name">VulnStream</div>
            <div className="login-brand-caption">THREAT INTELLIGENCE OPERATIONS</div>
          </div>
          <span className="login-edition">ENTERPRISE</span>
        </div>

        <div className="login-heading-block">
          <p className="login-eyebrow">SECURE OPERATOR ACCESS</p>
          <h1 id="login-heading">Welcome back</h1>
          <p className="login-subtitle">Sign in to monitor vulnerabilities and manage your response workflow.</p>
        </div>

        <form
          className="login-form"
          onSubmit={async (event) => {
            event.preventDefault();
            const success = await login(username.trim(), password);
            if (success) setPassword('');
          }}
        >
          {loading ? (
            <div className="login-connecting" role="status">
              <LoaderCircle className="animate-spin" size={18} />
              <span>Connecting to your secure workspace…</span>
            </div>
          ) : (
            <>
              <label className="login-field">
                <span>Username</span>
                <input
                  autoComplete="username"
                  autoCapitalize="none"
                  spellCheck={false}
                  value={username}
                  onChange={(event) => setUsername(event.target.value)}
                  required
                  maxLength={100}
                  placeholder="Enter your username"
                  disabled={pending > 0}
                />
              </label>

              <label className="login-field">
                <span>Password</span>
                <input
                  autoComplete="current-password"
                  type="password"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  required
                  maxLength={128}
                  placeholder="Enter your password"
                  disabled={pending > 0}
                />
              </label>

              <button className="login-submit" disabled={pending > 0}>
                <span>{pending ? 'Signing in…' : 'Sign in securely'}</span>
                {pending ? <LoaderCircle className="animate-spin" size={17} /> : <ArrowRight size={17} />}
              </button>
            </>
          )}

          {error && <p role="alert" className="login-error">{error}</p>}
        </form>

        <div className="login-card-footer">
          <span><KeyRound size={14} /> Protected operator session</span>
          <span className="login-status"><i /> Protected sign-in</span>
        </div>
      </section>

      <footer className="login-page-footer">
        VulnStream Enterprise <span>·</span> Vulnerability intelligence and response
      </footer>
    </main>
  );
}
