import React, { useEffect, useState } from 'react';
import { CheckCircle2, KeyRound, Mail, Save, Send } from 'lucide-react';
import { useApp } from '../context/AppContext';
import { EMAIL_PROVIDERS, type EmailConfiguration } from '../types';

const names = {
  SMTP: 'SMTP relay',
  MAILGUN: 'Mailgun',
  MAILTRAP: 'Mailtrap',
  SENDGRID: 'SendGrid',
  POSTMARK: 'Postmark',
};
const guides = {
  MAILGUN: 'https://documentation.mailgun.com/docs/mailgun/user-manual/sending-messages/send-http',
  MAILTRAP: 'https://docs.mailtrap.io/email-api-smtp/setup',
  SENDGRID: 'https://www.twilio.com/docs/sendgrid/for-developers/sending-email/api-getting-started',
  POSTMARK: 'https://postmarkapp.com/developer/get-started',
};
export function EmailProviderSettings() {
  const { emailConfig, configureEmailProvider, sendTestEmail, pending } = useApp();
  const [form, setForm] = useState<EmailConfiguration>({ ...emailConfig, apiKey: '' });
  const [dirty, setDirty] = useState(false);
  const [message, setMessage] = useState('');
  const [testEmail, setTestEmail] = useState('');
  const savedVersion = JSON.stringify(emailConfig);
  useEffect(() => {
    setForm({ ...emailConfig, apiKey: '' });
    setDirty(false);
  }, [savedVersion]);
  const update = (value: Partial<EmailConfiguration>) => {
    setForm((old) => ({ ...old, ...value }));
    setDirty(true);
    setMessage('');
  };
  const hasSavedToken = form.provider === emailConfig.provider && emailConfig.hasApiKey;
  return (
    <section className="ui-card space-y-5" aria-labelledby="email-settings-heading">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="flex items-start gap-3">
          <span className="ui-section-icon">
            <Mail className="h-4 w-4" />
          </span>
          <div>
            <h2 id="email-settings-heading" className="ui-card-title">
              Email delivery
            </h2>
            <p className="ui-description mt-1">
              Choose the provider used for advisories and notification emails.
            </p>
          </div>
        </div>
        <span className="inline-flex items-center gap-1.5 rounded-full border border-zinc-700 light:border-zinc-200 px-2.5 py-1 text-[11px] text-zinc-400">
          <CheckCircle2 className="h-3.5 w-3.5" /> Active: {names[emailConfig.provider]}
        </span>
      </div>
      <form
        className="space-y-5"
        onSubmit={async (event) => {
          event.preventDefault();
          setMessage('');
          if (await configureEmailProvider(form)) {
            setForm((old) => ({ ...old, apiKey: '' }));
            setDirty(false);
            setMessage(`${names[form.provider]} configuration saved.`);
          }
        }}
      >
        <div className="grid gap-4 sm:grid-cols-2">
          <label htmlFor="email-provider">
            Email provider
            <select
              id="email-provider"
              className="ui-field"
              value={form.provider}
              onChange={(event) =>
                update({ provider: event.target.value as EmailConfiguration['provider'], apiKey: '' })
              }
            >
              {EMAIL_PROVIDERS.map((provider) => (
                <option key={provider} value={provider}>
                  {names[provider]}
                </option>
              ))}
            </select>
          </label>
          <label htmlFor="email-from-name">
            Sender name
            <input
              id="email-from-name"
              className="ui-field"
              value={form.fromName}
              maxLength={100}
              placeholder="VulnStream Security"
              onChange={(event) => update({ fromName: event.target.value })}
            />
          </label>
          <label htmlFor="email-from-address" className="sm:col-span-2">
            Sender email
            <input
              id="email-from-address"
              className="ui-field"
              type="email"
              value={form.fromEmail}
              maxLength={254}
              required={form.provider !== 'SMTP'}
              placeholder={
                form.provider === 'SMTP' ? 'Use the deployment sender address' : 'security@your-domain.com'
              }
              onChange={(event) => update({ fromEmail: event.target.value })}
            />
            <span className="ui-description mt-1.5 block">
              Use a sender address verified with your provider.
            </span>
          </label>
          {form.provider !== 'SMTP' && (
            <label htmlFor="email-api-key" className="sm:col-span-2">
              {form.provider === 'POSTMARK' ? 'Server API token' : 'API token'}
              <input
                id="email-api-key"
                type="password"
                autoComplete="new-password"
                spellCheck={false}
                className="ui-field"
                value={form.apiKey}
                maxLength={4096}
                required={!hasSavedToken}
                placeholder={
                  hasSavedToken ? 'Token saved — leave blank to keep it' : 'Enter your provider API token'
                }
                onChange={(event) => update({ apiKey: event.target.value })}
              />
              <span className="ui-description mt-1.5 flex items-center gap-1.5">
                <KeyRound className="h-3 w-3" />
                Encrypted on the server. Saved tokens are never displayed.
              </span>
            </label>
          )}
          {form.provider === 'MAILGUN' && (
            <>
              <label htmlFor="mailgun-domain">
                Sending domain
                <input
                  id="mailgun-domain"
                  className="ui-field"
                  value={form.mailgunDomain}
                  required
                  placeholder="mg.your-domain.com"
                  onChange={(event) => update({ mailgunDomain: event.target.value })}
                />
              </label>
              <label htmlFor="mailgun-region">
                Mailgun region
                <select
                  id="mailgun-region"
                  className="ui-field"
                  value={form.mailgunRegion}
                  onChange={(event) => update({ mailgunRegion: event.target.value as 'US' | 'EU' })}
                >
                  <option value="US">United States</option>
                  <option value="EU">European Union</option>
                </select>
              </label>
            </>
          )}
          {form.provider === 'MAILTRAP' && (
            <>
              <label htmlFor="mailtrap-mode">
                Delivery mode
                <select
                  id="mailtrap-mode"
                  className="ui-field"
                  value={form.mailtrapMode}
                  onChange={(event) => update({ mailtrapMode: event.target.value as 'LIVE' | 'SANDBOX' })}
                >
                  <option value="LIVE">Live email sending</option>
                  <option value="SANDBOX">Email sandbox</option>
                </select>
              </label>
              {form.mailtrapMode === 'SANDBOX' && (
                <label htmlFor="mailtrap-inbox">
                  Sandbox inbox ID
                  <input
                    id="mailtrap-inbox"
                    className="ui-field"
                    inputMode="numeric"
                    pattern="[1-9][0-9]*"
                    required
                    value={form.mailtrapInboxId}
                    placeholder="1234567"
                    onChange={(event) => update({ mailtrapInboxId: event.target.value })}
                  />
                </label>
              )}
              {form.mailtrapMode === 'SANDBOX' && (
                <p className="ui-description sm:col-span-2">
                  Sandbox messages are captured in your Mailtrap inbox. They do not reach recipient inboxes.
                </p>
              )}
            </>
          )}
          {form.provider === 'POSTMARK' && (
            <label htmlFor="postmark-stream" className="sm:col-span-2">
              Message stream
              <input
                id="postmark-stream"
                className="ui-field"
                value={form.postmarkMessageStream}
                required
                pattern="[a-zA-Z0-9_-]+"
                placeholder="outbound"
                onChange={(event) => update({ postmarkMessageStream: event.target.value })}
              />
              <span className="ui-description mt-1.5 block">
                Use a transactional message stream for security alerts.
              </span>
            </label>
          )}
        </div>
        {form.provider === 'SMTP' ? (
          <p className="ui-description rounded-xl border border-zinc-700 light:border-zinc-200 bg-zinc-950 light:bg-zinc-50 p-3">
            SMTP host, port, and credentials use the deployment’s SMTP configuration. Connections require TLS.
          </p>
        ) : (
          <p className="ui-description">
            <a
              className="underline underline-offset-4"
              href={guides[form.provider]}
              target="_blank"
              rel="noreferrer"
            >
              {names[form.provider]} setup guide ↗
            </a>
          </p>
        )}
        <div className="ui-actions">
          <button type="submit" className="ui-primary" disabled={pending > 0}>
            <Save className="h-3.5 w-3.5" />
            Save email provider
          </button>
          <span className="ui-description">Changes apply to subsequent delivery attempts.</span>
        </div>
      </form>
      <form
        className="space-y-3 border-t border-zinc-700 light:border-zinc-200 pt-5"
        onSubmit={async (event) => {
          event.preventDefault();
          setMessage('');
          const result = await sendTestEmail(testEmail);
          if (result.success) setMessage('Test email queued. Check Email History for provider acceptance.');
        }}
      >
        <label htmlFor="email-test-recipient" className="block">
          Send a test email
        </label>
        <div className="flex flex-col gap-3 sm:flex-row sm:items-start">
          <input
            id="email-test-recipient"
            aria-label="Test email recipient"
            type="email"
            className="ui-field flex-1"
            style={{ marginTop: 0 }}
            required
            maxLength={254}
            placeholder="you@your-domain.com"
            value={testEmail}
            onChange={(event) => setTestEmail(event.target.value)}
          />
          <button type="submit" className="ui-secondary shrink-0" disabled={pending > 0 || dirty}>
            <Send className="h-3.5 w-3.5" />
            Queue test email
          </button>
        </div>
        <p className="ui-description">
          {dirty
            ? 'Save your provider changes before sending a test.'
            : `Uses the saved ${names[emailConfig.provider]} configuration and the background delivery queue.`}
        </p>
      </form>
      {message && (
        <p className="ui-success" role="status">
          {message}
        </p>
      )}
    </section>
  );
}
