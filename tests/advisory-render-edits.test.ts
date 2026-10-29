import { test } from 'node:test';
import assert from 'node:assert/strict';
import { renderAdvisory } from '../server/advisoryRender.ts';
import { compileCustomizedTemplate } from '../src/utils/templateCompiler.ts';
import type { Advisory } from '../src/types/index.ts';

const baseAdvisory: Advisory = {
  id: 'ADV-2026-001',
  title: 'Test vulnerability advisory',
  severity: 'CRITICAL',
  cveIds: ['CVE-2026-12345'],
  findingIds: ['finding-1'],
  createdDate: new Date().toISOString(),
  deliveryStatus: 'PENDING',
  recipientCount: 1,
  executiveSummary: 'A test vulnerability affects monitored systems.',
  affectedSystems: ['web-server-01'],
  remediationInstructions: 'Apply the vendor patch immediately.',
  vendorLink: 'https://example.com/advisory/12345',
};

test('renderAdvisory without edits uses default audience notice', () => {
  const template = compileCustomizedTemplate({
    fontFamily: 'sans',
    fontColor: '#334155',
    headingColor: '#0f172a',
    accentColor: '#2563eb',
    canvasBg: '#f1f5f9',
    cardBg: '#ffffff',
    headerBg: '#0f172a',
    badgeStampText: 'SECURITY OPERATIONS',
    badgeStampColor: '#2563eb',
    showStamp: true,
    showClassificationBanner: false,
    classificationText: '',
    borderStyle: 'solid',
    borderRadius: '12px',
  });
  const html = renderAdvisory(template, baseAdvisory);
  assert.ok(html.includes('{{') === false, 'no unrendered tokens');
  assert.ok(
    html.includes('This advisory is being distributed to all recipients per the EVERYONE delivery policy.'),
    'default audience notice should appear',
  );
  assert.ok(!html.includes('Reviewer note'), 'reviewer comment should not appear without edits');
});

test('renderAdvisory with edits renders audience notice and reviewer comment', () => {
  const template = compileCustomizedTemplate({
    fontFamily: 'sans',
    fontColor: '#334155',
    headingColor: '#0f172a',
    accentColor: '#2563eb',
    canvasBg: '#f1f5f9',
    cardBg: '#ffffff',
    headerBg: '#0f172a',
    badgeStampText: 'SECURITY OPERATIONS',
    badgeStampColor: '#2563eb',
    showStamp: true,
    showClassificationBanner: false,
    classificationText: '',
    borderStyle: 'solid',
    borderRadius: '12px',
  });
  const advisory: Advisory = {
    ...baseAdvisory,
    edits: {
      audienceNotice: 'This is a broad-distribution advisory.',
      reviewerComment: 'Reviewed by security team',
      reviewerName: 'sec-op-1',
    },
  };
  const html = renderAdvisory(template, advisory);
  assert.ok(!html.includes('{{'), 'no unrendered tokens');
  assert.ok(html.includes('This is a broad-distribution advisory.'), 'custom audience notice should appear');
  assert.ok(html.includes('Reviewed by security team'), 'reviewer comment should appear');
  assert.ok(html.includes('by sec-op-1'), 'reviewer name should appear in comment');
});

test('renderAdvisory with edits escapes XSS in audience notice and reviewer comment', () => {
  const template = compileCustomizedTemplate({
    fontFamily: 'sans',
    fontColor: '#334155',
    headingColor: '#0f172a',
    accentColor: '#2563eb',
    canvasBg: '#f1f5f9',
    cardBg: '#ffffff',
    headerBg: '#0f172a',
    badgeStampText: 'SECURITY OPERATIONS',
    badgeStampColor: '#2563eb',
    showStamp: true,
    showClassificationBanner: false,
    classificationText: '',
    borderStyle: 'solid',
    borderRadius: '12px',
  });
  const advisory: Advisory = {
    ...baseAdvisory,
    edits: {
      audienceNotice: '<img src=x onerror=alert(1)>',
      reviewerComment: '<script>alert("xss")</script>',
      reviewerName: 'test',
    },
  };
  const html = renderAdvisory(template, advisory);
  assert.ok(!html.includes('<img src=x'), 'XSS in audience notice should be escaped');
  assert.ok(!html.includes('<script>'), 'XSS in reviewer comment should be escaped');
  assert.ok(html.includes('&lt;img'), 'audience notice should be escaped');
  assert.ok(html.includes('&lt;script&gt;'), 'reviewer comment should be escaped');
});
