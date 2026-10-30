import { test } from 'node:test';
import assert from 'node:assert/strict';
import { resolveChromeExecutablePath, renderAdvisoryPdf, closePdfRenderer } from '../server/pdf.ts';
import { renderAdvisory } from '../server/advisoryRender.ts';
import { advisoryFilename } from '../server/pdf.ts';
import { compileCustomizedTemplate, DEFAULT_TEMPLATE_CUSTOMIZATION } from '../src/utils/templateCompiler.ts';
import { DEFAULT_EMAIL_CONFIG } from '../shared/state.ts';
import { sendProviderEmail } from '../server/emailProviders.ts';
import type { Advisory, EmailConfiguration } from '../src/types/index.ts';

const chrome = resolveChromeExecutablePath();

test('advisoryFilename extracts the ADV-ddMMMyyyy prefix from advisory IDs', () => {
  assert.equal(advisoryFilename('ADV-05Oct2026-A1B2C3D4'), 'ADV-05Oct2026.pdf');
  assert.equal(advisoryFilename('ADV-15Jan2025-ABCD1234'), 'ADV-15Jan2025.pdf');
  assert.equal(advisoryFilename('ADV-31Dec2099-99999999'), 'ADV-31Dec2099.pdf');
});

test('advisoryFilename falls back to the raw ID for non-standard advisory IDs', () => {
  assert.equal(advisoryFilename('ADV-2026-0001'), 'ADV-2026-0001.pdf');
  assert.equal(advisoryFilename('CUSTOM-2026'), 'CUSTOM-2026.pdf');
});

const advisory = {
  id: 'ADV-05Oct2026-A1B2C3D4',
  title: 'Test vulnerability advisory',
  severity: 'CRITICAL',
  cveIds: ['CVE-2026-12345', 'CVE-2026-67890'],
  affectedSystems: ['web-01', 'db-02'],
  executiveSummary: 'A critical test vulnerability affects monitored systems.',
  remediationInstructions: 'Apply the vendor patch and verify inventory coverage.',
  vendorLink: 'https://example.com/advisory/2026-0001',
} as unknown as Advisory;

test('renderAdvisoryPdf renders the compiled advisory HTML to a PDF', { skip: !chrome }, async () => {
  const template = compileCustomizedTemplate(DEFAULT_TEMPLATE_CUSTOMIZATION);
  const html = renderAdvisory(template, advisory);
  assert.ok(html.includes('CVE-2026-12345'));
  assert.ok(!html.includes('{{advisory_id}}'));

  const pdf = await renderAdvisoryPdf(html);
  try {
    assert.equal(Buffer.from(pdf).slice(0, 5).toString(), '%PDF-');
    assert.ok(pdf.length > 2000, 'PDF should contain rendered content');
  } finally {
    await closePdfRenderer();
  }
});

test('rendered advisory PDF is attached to provider messages', { skip: !chrome }, async () => {
  const template = compileCustomizedTemplate(DEFAULT_TEMPLATE_CUSTOMIZATION);
  const html = renderAdvisory(template, advisory);
  const pdf = await renderAdvisoryPdf(html);
  const attachment = {
    filename: advisoryFilename('ADV-05Oct2026-A1B2C3D4'),
    content: Buffer.from(pdf),
    contentType: 'application/pdf' as const,
  };
  const base64 = attachment.content.toString('base64');
  const config: EmailConfiguration = { ...DEFAULT_EMAIL_CONFIG, provider: 'SENDGRID', fromEmail: 'security@example.invalid' };
  const job = {
    id: 'test-job',
    dedupe_key: 'test',
    channel: 'email',
    target_id: 'recipient',
    advisory_id: 'ADV-05Oct2026-A1B2C3D4',
    attempts: 1,
    lock_token: 'test',
    payload: { subject: 'Security notice', text: 'see html', html, recipientEmail: 'recipient@example.invalid', cveIds: ['CVE-2026-12345'] },
  };
  let capturedBody: string | undefined;
  await sendProviderEmail(
    config,
    'token',
    job as any,
    async (_url, options) => {
      capturedBody = options?.body;
      return { status: 202, headers: { 'x-message-id': 'id' }, body: '' };
    },
    false,
    attachment,
  );
  await closePdfRenderer();

  assert.ok(capturedBody);
  const payload = JSON.parse(capturedBody!);
  assert.equal(payload.attachments[0].type, 'application/pdf');
  assert.equal(payload.attachments[0].filename, 'ADV-05Oct2026.pdf');
  assert.equal(payload.attachments[0].disposition, 'attachment');
  assert.equal(payload.attachments[0].content, base64);
  assert.ok(base64.length > 1000);
});
