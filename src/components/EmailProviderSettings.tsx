import React, { useEffect, useState } from 'react';
import { CheckCircle2, KeyRound, Mail, Save, Send } from 'lucide-react';
import { useApp } from '../context/AppContext';
import { EMAIL_PROVIDERS, isSmtpEmailProvider, type EmailConfiguration, type EmailProvider } from '../types';

const names: Record<EmailProvider, string> = {
  SMTP: 'SMTP relay (deployment settings)',
  SMTP_CUSTOM: 'Custom SMTP host',
  MAILEROO_SMTP: 'Maileroo SMTP',
  LETTR_SMTP: 'Lettr SMTP',
  MAILJET_SMTP: 'Mailjet SMTP',
  MAILGUN: 'Mailgun',
  MAILTRAP: 'Mailtrap',
  SENDGRID: 'SendGrid',
  POSTMARK: 'Postmark',
};
const guides: Partial<Record<EmailProvider, string>> = {
  MAILEROO_SMTP: 'https://maileroo.com/docs/smtp-relay/server-configuration',
  LETTR_SMTP: 'https://lettr.com/glossary/smtp/',
  MAILJET_SMTP: 'https://dev.mailjet.com/docs/smtp-relay/configuration',
  MAILGUN: 'https://documentation.mailgun.com/docs/mailgun/user-manual/sending-messages/send-http',
  MAILTRAP: 'https://docs.mailtrap.io/email-api-smtp/setup',
  SENDGRID: 'https://www.twilio.com/docs/sendgrid/for-developers/sending-email/api-getting-started',
  POSTMARK: 'https://postmarkapp.com/developer/get-started',
};
const smtpPresets: Partial<
  Record<EmailProvider, Pick<EmailConfiguration, 'smtpHost' | 'smtpPort' | 'smtpSecurity' | 'smtpUsername'>>
> = {
  SMTP_CUSTOM: { smtpHost: '', smtpPort: 587, smtpSecurity: 'STARTTLS', smtpUsername: '' },
  MAILEROO_SMTP: { smtpHost: 'smtp.maileroo.com', smtpPort: 587, smtpSecurity: 'STARTTLS', smtpUsername: '' },
  LETTR_SMTP: { smtpHost: 'smtp.lettr.com', smtpPort: 465, smtpSecurity: 'IMPLICIT_TLS', smtpUsername: 'lettr' },
  MAILJET_SMTP: { smtpHost: 'in-v3.mailjet.com', smtpPort: 587, smtpSecurity: 'STARTTLS', smtpUsername: '' },
};
export function EmailProviderSettings() {
  const { emailConfig, configureEmailProvider, sendTestEmail, pending } = useApp();
  const [form, setForm] = useState<EmailConfiguration>({
    ...emailConfig,
    apiKey: '',
    smtpHost: emailConfig.smtpHost || '',
    smtpPort: emailConfig.smtpPort || 587,
    smtpSecurity: emailConfig.smtpSecurity || 'STARTTLS',
    smtpUsername: emailConfig.smtpUsername || '',
    smtpPassword: '',
  });
  const [dirty, setDirty] = useState(false);
  const [message, setMessage] = useState('');
  const [testEmail, setTestEmail] = useState('');
  const savedVersion = JSON.stringify(emailConfig);
  useEffect(() => {
    setForm({
      ...emailConfig,
      apiKey: '',
      smtpHost: emailConfig.smtpHost || '',
      smtpPort: emailConfig.smtpPort || 587,
      smtpSecurity: emailConfig.smtpSecurity || 'STARTTLS',
      smtpUsername: emailConfig.smtpUsername || '',
      smtpPassword: '',
    });
    setDirty(false);
  }, [savedVersion]);
  const update = (value: Partial<EmailConfiguration>) => {
    setForm((old) => ({ ...old, ...value }));
    setDirty(true);
    setMessage('');
  };
  const hasSavedToken = !isSmtpEmailProvider(form.provider) && form.provider === emailConfig.provider && emailConfig.hasApiKey;
  const hasSavedSmtpPassword = form.provider === emailConfig.provider && emailConfig.hasSmtpPassword;
  const smtpProvider = isSmtpEmailProvider(form.provider);
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
            setForm((old) => ({ ...old, apiKey: '', smtpPassword: '' }));
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
              onChange={(event) => {
                const provider = event.target.value as EmailProvider;
                const savedSmtpSettings = provider === emailConfig.provider
                  ? {
                      smtpHost: emailConfig.smtpHost || '',
                      smtpPort: emailConfig.smtpPort || 587,
                      smtpSecurity: emailConfig.smtpSecurity || 'STARTTLS',
                      smtpUsername: emailConfig.smtpUsername || '',
                    }
                  : {};
                update({
                  provider,
                  apiKey: '',
                  smtpPassword: '',
                  ...(smtpPresets[provider] || {
                    smtpHost: '',
                    smtpPort: 587,
                    smtpSecurity: 'STARTTLS' as const,
                    smtpUsername: '',
                  }),
                  ...savedSmtpSettings,
                });
              }}
            >
              <optgroup label="SMTP">
                {EMAIL_PROVIDERS.filter(isSmtpEmailProvider).map((provider) => (
                  <option key={provider} value={provider}>
                    {names[provider]}
                  </option>
                ))}
              </optgroup>
              <optgroup label="Email API">
                {EMAIL_PROVIDERS.filter((provider) => !isSmtpEmailProvider(provider)).map((provider) => (
                  <option key={provider} value={provider}>
                    {names[provider]}
                  </option>
                ))}
              </optgroup>
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
          {!smtpProvider && (
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
          {smtpProvider && form.provider !== 'SMTP' && (
            <>
              <label htmlFor="smtp-host">
                SMTP host
                <input
                  id="smtp-host"
                  className="ui-field"
                  value={form.smtpHost}
                  readOnly={form.provider !== 'SMTP_CUSTOM'}
                  required
                  placeholder="smtp.example.com"
                  onChange={(event) => update({ smtpHost: event.target.value })}
                />
                {form.provider === 'SMTP_CUSTOM' && (
                  <span className="ui-description mt-1.5 block">
                    Custom SMTP hosts must be included in the server EGRESS_ALLOWED_HOSTS allowlist.
                  </span>
                )}
              </label>
              <label htmlFor="smtp-port">
                SMTP port
                <input
                  id="smtp-port"
                  type="number"
                  min={1}
                  max={65535}
                  className="ui-field"
                  value={form.smtpPort}
                  required
                  onChange={(event) => update({ smtpPort: Number(event.target.value) })}
                />
              </label>
              <label htmlFor="smtp-security">
                SMTP encryption
                <select
                  id="smtp-security"
                  className="ui-field"
                  value={form.smtpSecurity}
                  onChange={(event) => update({ smtpSecurity: event.target.value as EmailConfiguration['smtpSecurity'] })}
                >
                  <option value="STARTTLS">STARTTLS</option>
                  <option value="IMPLICIT_TLS">Implicit TLS</option>
                </select>
              </label>
              <label htmlFor="smtp-username">
                SMTP username
                <input
                  id="smtp-username"
                  className="ui-field"
                  autoComplete="username"
                  value={form.smtpUsername}
                  required={form.provider !== 'SMTP_CUSTOM'}
                  placeholder={form.provider === 'MAILJET_SMTP' ? 'Mailjet API key' : 'SMTP username'}
                  onChange={(event) => update({ smtpUsername: event.target.value })}
                />
              </label>
              <label htmlFor="smtp-password" className="sm:col-span-2">
                SMTP password or API secret
                <input
                  id="smtp-password"
                  type="password"
                  autoComplete="new-password"
                  spellCheck={false}
                  className="ui-field"
                  value={form.smtpPassword}
                  maxLength={4096}
                  required={!hasSavedSmtpPassword && form.provider !== 'SMTP_CUSTOM'}
                  placeholder={hasSavedSmtpPassword ? 'Credential saved — leave blank to keep it' : 'Enter SMTP password or provider secret'}
                  onChange={(event) => update({ smtpPassword: event.target.value })}
                />
                <span className="ui-description mt-1.5 flex items-center gap-1.5">
                  <KeyRound className="h-3 w-3" />
                  Encrypted on the server. Saved credentials are never displayed.
                </span>
              </label>
              {form.provider === 'MAILJET_SMTP' && (
                <p className="ui-description sm:col-span-2">
                  Enter your Mailjet API key as the username and its secret key as the password.
                </p>
              )}
              {form.provider === 'LETTR_SMTP' && (
                <p className="ui-description sm:col-span-2">
                  Lettr uses the username “lettr” and your Lettr API key as the password.
                </p>
              )}
              {form.provider === 'MAILEROO_SMTP' && (
                <p className="ui-description sm:col-span-2">
                  Maileroo expects the SMTP account email address as the username.
                </p>
              )}
            </>
          )}
        </div>
        {form.provider === 'SMTP' ? (
          <p className="ui-description rounded-xl border border-zinc-700 light:border-zinc-200 bg-zinc-950 light:bg-zinc-50 p-3">
            SMTP host, port, and credentials use the deployment’s SMTP configuration. Connections require TLS.
          </p>
        ) : guides[form.provider] ? (
          <p className="ui-description">
            <a
              className="underline underline-offset-4"
              href={guides[form.provider]}
              target="_blank"
              rel="noopener noreferrer"
            >
              {names[form.provider]} setup guide ↗
            </a>
          </p>
        ) : (
          <p className="ui-description">
            Custom SMTP requires a host permitted by the server EGRESS_ALLOWED_HOSTS allowlist. Use STARTTLS or implicit TLS.
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
