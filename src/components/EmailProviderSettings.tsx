import React, { useEffect, useState } from 'react';
import { CheckCircle2, KeyRound, Mail, Save, Send } from 'lucide-react';
import { useApp } from '../context/AppContext';
import { isSmtpEmailProvider, type EmailConfiguration, type EmailProvider } from '../types';

const methodName = (provider: EmailProvider) => isSmtpEmailProvider(provider) ? 'SMTP' : 'Email API';
const initialForm = (configuration: EmailConfiguration): EmailConfiguration => ({
  ...configuration,
  provider: isSmtpEmailProvider(configuration.provider) ? configuration.provider : 'API',
  apiKey: '',
  apiEndpoint: configuration.apiEndpoint || '',
  apiHeaderKey: configuration.apiHeaderKey || 'Authorization',
  apiAuthPrefix: configuration.apiAuthPrefix ?? 'Bearer',
  apiSourceDomain: configuration.apiSourceDomain || '',
  smtpHost: configuration.smtpHost || '',
  smtpPort: configuration.smtpPort || 587,
  smtpSecurity: configuration.smtpSecurity || 'STARTTLS',
  smtpUsername: configuration.smtpUsername || '',
  smtpPassword: '',
});

export function EmailProviderSettings() {
  const { emailConfig, configureEmailProvider, sendTestEmail, pending } = useApp();
  const [form, setForm] = useState<EmailConfiguration>(() => initialForm(emailConfig));
  const [dirty, setDirty] = useState(false);
  const [message, setMessage] = useState('');
  const [testEmail, setTestEmail] = useState('');
  const savedVersion = JSON.stringify(emailConfig);
  useEffect(() => {
    setForm(initialForm(emailConfig));
    setDirty(false);
  }, [savedVersion]);
  const update = (value: Partial<EmailConfiguration>) => {
    setForm((old) => ({ ...old, ...value }));
    setDirty(true);
    setMessage('');
  };
  const isSmtp = isSmtpEmailProvider(form.provider);
  const hasSavedApiKey = form.provider === emailConfig.provider && !!emailConfig.hasApiKey;
  const hasSavedSmtpPassword = form.provider === emailConfig.provider && !!emailConfig.hasSmtpPassword;

  return (
    <section className="ui-card space-y-5" aria-labelledby="email-settings-heading">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="flex items-start gap-3">
          <span className="ui-section-icon"><Mail className="h-4 w-4" /></span>
          <div>
            <h2 id="email-settings-heading" className="ui-card-title">Email delivery</h2>
            <p className="ui-description mt-1">Choose SMTP relay or a custom HTTPS email API.</p>
          </div>
        </div>
        <span className="inline-flex items-center gap-1.5 rounded-full border border-zinc-700 light:border-zinc-200 px-2.5 py-1 text-[11px] text-zinc-400">
          <CheckCircle2 className="h-3.5 w-3.5" /> Active: {methodName(emailConfig.provider)}
        </span>
      </div>

      <form
        className="space-y-5"
        onSubmit={async (event) => {
          event.preventDefault();
          setMessage('');
          if (await configureEmailProvider(form)) {
            setForm((old) => ({ ...old, apiKey: '', smtpPassword: '' }));
            setDirty(false);
            setMessage(`${methodName(form.provider)} configuration saved.`);
          }
        }}
      >
        <div className="grid gap-4 sm:grid-cols-2">
          <label htmlFor="email-provider">
            Delivery method
            <select
              id="email-provider"
              className="ui-field"
              value={isSmtp ? 'SMTP' : 'API'}
              onChange={(event) => {
                const provider = event.target.value === 'SMTP' ? 'SMTP' : 'API';
                update({ provider, apiKey: '', smtpPassword: '' });
              }}
            >
              <option value="SMTP">SMTP</option>
              <option value="API">Email API</option>
            </select>
          </label>
          <label htmlFor="email-from-name">
            Sender name
            <input id="email-from-name" className="ui-field" value={form.fromName} maxLength={100}
              placeholder="VulnStream Security" onChange={(event) => update({ fromName: event.target.value })} />
          </label>
          <label htmlFor="email-from-address" className="sm:col-span-2">
            Sender email
            <input id="email-from-address" className="ui-field" type="email" value={form.fromEmail}
              maxLength={254} required={isSmtp ? !!form.smtpHost : true}
              placeholder={isSmtp && !form.smtpHost ? 'Use the deployment sender address' : 'security@your-domain.com'}
              onChange={(event) => update({ fromEmail: event.target.value })} />
            <span className="ui-description mt-1.5 block">Use an address verified by your email service.</span>
          </label>

          {isSmtp ? (
            <>
              <label htmlFor="smtp-host">
                SMTP host
                <input id="smtp-host" className="ui-field" value={form.smtpHost} maxLength={253}
                  placeholder="smtp.example.com" onChange={(event) => update({
                    smtpHost: event.target.value,
                    ...(event.target.value ? {} : { smtpUsername: '', smtpPassword: '' }),
                  })} />
                <span className="ui-description mt-1.5 block">
                  Optional. Leave blank to use SMTP_HOST and related deployment settings. A custom host must be in EGRESS_ALLOWED_HOSTS.
                </span>
              </label>
              <div className="flex items-end">
                <button type="button" className="ui-secondary" onClick={() => update({
                  smtpHost: 'smtp.gmail.com', smtpPort: 587, smtpSecurity: 'STARTTLS',
                })}>
                  Use Gmail SMTP settings
                </button>
              </div>
              {form.smtpHost && <>
                <label htmlFor="smtp-port">
                  SMTP port
                  <input id="smtp-port" type="number" min={1} max={65535} className="ui-field"
                    value={form.smtpPort} onChange={(event) => update({ smtpPort: Number(event.target.value) })} />
                </label>
                <label htmlFor="smtp-security">
                  SMTP encryption
                  <select id="smtp-security" className="ui-field" value={form.smtpSecurity}
                    onChange={(event) => update({ smtpSecurity: event.target.value as EmailConfiguration['smtpSecurity'] })}>
                    <option value="STARTTLS">STARTTLS</option>
                    <option value="IMPLICIT_TLS">Implicit TLS</option>
                  </select>
                </label>
                <label htmlFor="smtp-username">
                  SMTP username
                  <input id="smtp-username" className="ui-field" autoComplete="username" value={form.smtpUsername}
                    placeholder="SMTP username" onChange={(event) => update({ smtpUsername: event.target.value })} />
                </label>
                <label htmlFor="smtp-password" className="sm:col-span-2">
                  SMTP password
                  <input id="smtp-password" type="password" autoComplete="new-password" spellCheck={false}
                    className="ui-field" value={form.smtpPassword} maxLength={4096}
                    required={!!form.smtpUsername && !hasSavedSmtpPassword}
                    placeholder={hasSavedSmtpPassword ? 'Credential saved — leave blank to keep it' : 'Enter SMTP password'}
                    onChange={(event) => update({ smtpPassword: event.target.value })} />
                  <span className="ui-description mt-1.5 flex items-center gap-1.5">
                    <KeyRound className="h-3 w-3" /> Encrypted on the server. Leave blank to keep a saved credential.
                  </span>
                </label>
              </>}
              <p className="ui-description sm:col-span-2">
                Gmail: use your full Gmail address as the username and a generated 16-character App Password. Port 587 uses STARTTLS (recommended); port 465 uses implicit TLS. SMTP also supports Maileroo, Lettr, Mailjet, and other relays.
              </p>
            </>
          ) : (
            <>
              <label htmlFor="email-api-endpoint" className="sm:col-span-2">
                API endpoint
                <input id="email-api-endpoint" type="url" className="ui-field" value={form.apiEndpoint}
                  maxLength={2048} required placeholder="https://api.example.com/v1/email/send"
                  onChange={(event) => update({ apiEndpoint: event.target.value })} />
                <span className="ui-description mt-1.5 block">
                  HTTPS endpoint on port 443. Its hostname must be included in the server EGRESS_ALLOWED_HOSTS allowlist.
                </span>
              </label>
              <label htmlFor="email-api-domain">
                Source / Domain
                <input id="email-api-domain" className="ui-field" value={form.apiSourceDomain} maxLength={253}
                  placeholder="mg.example.com" onChange={(event) => update({ apiSourceDomain: event.target.value })} />
                <span className="ui-description mt-1.5 block">Use {`{domain}`} in the endpoint URL to insert this value safely.</span>
              </label>
              <label htmlFor="email-api-header-key">
                Header key
                <input id="email-api-header-key" className="ui-field" value={form.apiHeaderKey} maxLength={100}
                  required pattern="[!#$%&'*+.^_`|~0-9A-Za-z-]+" placeholder="Authorization"
                  onChange={(event) => update({ apiHeaderKey: event.target.value })} />
              </label>
              <label htmlFor="email-api-prefix">
                Authentication prefix
                <input id="email-api-prefix" className="ui-field" value={form.apiAuthPrefix} maxLength={40}
                  placeholder="Bearer" onChange={(event) => update({ apiAuthPrefix: event.target.value })} />
                <span className="ui-description mt-1.5 block">Default header: Authorization: Bearer &lt;key&gt;</span>
              </label>
              <label htmlFor="email-api-key" className="sm:col-span-2">
                Authentication Key
                <input id="email-api-key" type="password" autoComplete="new-password" spellCheck={false}
                  className="ui-field" value={form.apiKey} maxLength={4096} required={!hasSavedApiKey}
                  placeholder={hasSavedApiKey ? 'Secret API Key saved — leave blank to keep it' : 'Secret API Key'}
                  onChange={(event) => update({ apiKey: event.target.value })} />
                <span className="ui-description mt-1.5 flex items-center gap-1.5">
                  <KeyRound className="h-3 w-3" /> Encrypted on the server. Saved keys are never displayed.
                </span>
              </label>
            </>
          )}
        </div>
        <div className="ui-actions">
          <button type="submit" className="ui-primary" disabled={pending > 0}>
            <Save className="h-3.5 w-3.5" /> Save email settings
          </button>
          <span className="ui-description">Changes apply to subsequent delivery attempts.</span>
        </div>
      </form>

      <form className="space-y-3 border-t border-zinc-700 light:border-zinc-200 pt-5"
        onSubmit={async (event) => {
          event.preventDefault();
          setMessage('');
          const result = await sendTestEmail(testEmail);
          if (result.success) setMessage('Test email queued. Check Email History for provider acceptance.');
        }}>
        <label htmlFor="email-test-recipient" className="block">Send a test email</label>
        <div className="flex flex-col gap-3 sm:flex-row sm:items-start">
          <input id="email-test-recipient" aria-label="Test email recipient" type="email" className="ui-field flex-1"
            style={{ marginTop: 0 }} required maxLength={254} placeholder="you@your-domain.com" value={testEmail}
            onChange={(event) => setTestEmail(event.target.value)} />
          <button type="submit" className="ui-secondary shrink-0" disabled={pending > 0 || dirty}>
            <Send className="h-3.5 w-3.5" /> Queue test email
          </button>
        </div>
        <p className="ui-description">
          {dirty ? 'Save your delivery settings before sending a test.' : `Uses the saved ${methodName(emailConfig.provider)} configuration and background delivery queue.`}
        </p>
      </form>
      {message && <p className="ui-success" role="status">{message}</p>}
    </section>
  );
}
