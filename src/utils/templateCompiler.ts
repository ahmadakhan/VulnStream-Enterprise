import { TemplateCustomization } from '../types/index.ts';

export const DEFAULT_TEMPLATE_CUSTOMIZATION: TemplateCustomization = {
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
};

export function getFontFamilyCss(family: TemplateCustomization['fontFamily']): string {
  switch (family) {
    case 'mono':
      return '"JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace';
    case 'serif':
      return 'Georgia, Cambria, "Times New Roman", Times, serif';
    case 'system':
      return '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif';
    case 'sans':
    default:
      return '"Plus Jakarta Sans", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif';
  }
}

export function compileCustomizedTemplate(config: TemplateCustomization): string {
  // Customization fields are text/CSS values, never arbitrary HTML or CSS.
  config = { ...DEFAULT_TEMPLATE_CUSTOMIZATION, ...config };
  for (const key of [
    'fontColor',
    'headingColor',
    'accentColor',
    'canvasBg',
    'cardBg',
    'headerBg',
    'badgeStampColor',
  ] as const) {
    if (!/^#[0-9a-f]{3}(?:[0-9a-f]{3})?$/i.test(config[key]))
      config[key] = DEFAULT_TEMPLATE_CUSTOMIZATION[key];
  }
  if (!['solid', 'dashed', 'none'].includes(config.borderStyle)) config.borderStyle = 'solid';
  if (!/^\d{1,3}(?:px|rem|%)$/.test(config.borderRadius)) config.borderRadius = '12px';
  const escapeHtml = (value: string) =>
    String(value).replace(
      /[&<>"']/g,
      (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]!,
    );
  config.badgeStampText = escapeHtml(config.badgeStampText);
  config.classificationText = escapeHtml(config.classificationText);
  const fontCss = getFontFamilyCss(config.fontFamily);

  const headerHex = config.headerBg.slice(1);
  const expanded = headerHex.length === 3 ? [...headerHex].map((ch) => ch + ch).join('') : headerHex;
  const luminance = [0, 2, 4]
    .map((offset) => parseInt(expanded.slice(offset, offset + 2), 16) / 255)
    .map((channel) => (channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4))
    .reduce((sum, channel, index) => sum + channel * [0.2126, 0.7152, 0.0722][index], 0);
  const headerText = luminance > 0.179 ? '#0f172a' : '#ffffff';
  const headerMuted = luminance > 0.179 ? '#334155' : '#cbd5e1';
  const stampHtml = config.showStamp
    ? `<p style="margin:0 0 12px;font-size:11px;line-height:18px;letter-spacing:1.5px;font-weight:700;color:${config.badgeStampColor};">${config.badgeStampText}</p>`
    : '';
  const classificationBanner = config.showClassificationBanner
    ? `<tr><td style="padding:12px 28px;background:${config.canvasBg};color:${config.fontColor};font-size:10px;line-height:16px;letter-spacing:1px;text-align:center;">${config.classificationText}</td></tr>`
    : '';
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>Security advisory</title>
<style>
  body,table,td,a { -webkit-text-size-adjust:100%; -ms-text-size-adjust:100%; }
  table,td { mso-table-lspace:0pt; mso-table-rspace:0pt; }
  table { border-collapse:collapse; }
   a { overflow-wrap:anywhere; word-break:break-word; }
   .ms-rteTableEvenCol-default { font-weight:700;color:${escapeHtml(config.headingColor)}; }
   .sev-critical { background:#ef4444;color:#ffffff; }
   .sev-high { background:#f59e0b;color:#ffffff; }
   .sev-medium { background:#eab308;color:#1e293b; }
   .sev-low { background:#10b981;color:#ffffff; }
   .sev-badge { display:inline-block;padding:2px 10px;border-radius:4px;font-size:11px;line-height:16px;font-weight:700;letter-spacing:0.5px; }
  @media only screen and (max-width:600px) {
    .outer { padding:16px 8px !important; }
    .ms-rteTableEvenCol-default { width:30% !important; }
  }
</style>
</head>
<body style="margin:0;padding:0;background:${config.canvasBg};color:${config.fontColor};font-family:${escapeHtml(fontCss)};">
<p>​​​​​​​​<br/></p>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;background:${config.canvasBg};">
<tr><td class="outer" align="center" style="padding:36px 16px;">
<!--[if mso]><table role="presentation" width="680" align="center"><tr><td><![endif]-->
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;max-width:680px;background:${config.cardBg};border:1px ${config.borderStyle} #cbd5e1;border-radius:${config.borderRadius};">
${classificationBanner}
 <tr><td class="section" style="padding:20px 32px;background:${config.headerBg};border-top:4px solid ${config.accentColor};">
 <p style="margin:0 0 12px;color:${headerMuted};font-size:10px;line-height:14px;font-weight:700;letter-spacing:2px;">VULNSTREAM / THREAT INTELLIGENCE</p>
 <p style="margin:0 0 6px;"><span style="display:inline-block;padding:4px 10px;background:#ffffff;color:#0f172a;font-size:10px;line-height:14px;letter-spacing:1px;font-weight:700;border-radius:4px;">{{severity}}</span></p>
 <h1 class="advisory-title" style="margin:0 0 8px;font-size:24px;line-height:30px;font-weight:700;letter-spacing:-.25px;color:${headerText};">{{advisory_title}}</h1>
 <p style="margin:0;font-size:11px;line-height:18px;color:${headerMuted};">{{advisory_id}}<br>Date: {{dispatch_date}}</p>
 </td></tr>
<tr><td class="section" style="padding:24px 32px;font-size:14px;line-height:24px;color:${config.fontColor};">
${stampHtml}
<p>​​​​​​​​<br/></p>
<table class="ms-rteTable-default" cellspacing="0" style="width:100%;">
<tbody>

<tr class="ms-rteTableEvenRow-default">
<td class="ms-rteTableEvenCol-default" style="width:11%;">Vulnerability Name</td>
<td class="ms-rteTableOddCol-default">
{{executive_summary}}
</td>
</tr>

<tr class="ms-rteTableOddRow-default">
<td class="ms-rteTableEvenCol-default">CVE ID​​​​​</td>
<td class="ms-rteTableOddCol-default">
{{cve_id_links}}
</td>
</tr>

<tr class="ms-rteTableEvenRow-default">
<td class="ms-rteTableEvenCol-default">Severity</td>
<td class="ms-rteTableOddCol-default">
<font class="ms-rteForeColor-2"><strong>{{severity}}</strong></font>
</td>
</tr>

<tr class="ms-rteTableOddRow-default">
<td class="ms-rteTableEvenCol-default">Date of Release</td>
<td class="ms-rteTableOddCol-default">{{dispatch_date}}</td>
</tr>

<tr class="ms-rteTableEvenRow-default">
<td class="ms-rteTableEvenCol-default">Date of Update</td>
<td class="ms-rteTableOddCol-default">{{dispatch_date}}</td>
</tr>

<tr class="ms-rteTableOddRow-default">
<td class="ms-rteTableEvenCol-default">
<a name="zero_day" id="zero_day"><span style="color:#f8f8f8;">Vulnerability Details</span></a>
</td>
<td class="ms-rteTableOddCol-default">
{{cve_details}}
</td>
</tr>

<tr class="ms-rteTableEvenRow-default">
<td class="ms-rteTableEvenCol-default">Affected Products and Versions</td>
<td class="ms-rteTableOddCol-default">
<ul>
{{affected_systems_html}}
</ul>
</td>
</tr>

<tr class="ms-rteTableOddRow-default">
<td class="ms-rteTableEvenCol-default">
<a name="fix_section" id="fix_section"><span style="color:#f8f8f8;">Fix</span></a>
</td>
<td class="ms-rteTableOddCol-default">
<ol>
<li><strong>Remediation:</strong> <div style="margin-top:8px;border-left:3px solid ${config.accentColor};padding:8px 0 8px 12px;white-space:pre-wrap;overflow-wrap:anywhere;">{{remediation_steps}}</div></li>
</ol>
<a href="{{vendor_link}}" target="_blank">Click for details</a>
</td>
</tr>

<tr class="ms-rteTableEvenRow-default">
<td class="ms-rteTableEvenCol-default">
<a name="mitigation" id="mitigation"><span style="color:#f8f8f8;">Workaround/Temporary fix/Mitigation</span></a>
</td>
<td class="ms-rteTableOddCol-default">
{{mitigation_steps}}
</td>
</tr>

<tr class="ms-rteTableOddRow-default">
<td class="ms-rteTableEvenCol-default">Resource</td>
<td class="ms-rteTableOddCol-default">
<ul>
<li><a href="{{vendor_link}}" target="_blank">Vendor Security Advisory</a></li>
</ul>
</td>
</tr>

<tr class="ms-rteTableEvenRow-default">
<td class="ms-rteTableEvenCol-default">Honeywell Recommended Action</td>
<td class="ms-rteTableOddCol-default">
{{recommended_actions}}
</td>
</tr>

</tbody>
</table>
<br/>
<br/>
<br/>
<br/>
</td></tr>
<tr><td class="section" style="padding:20px 32px;border-top:1px solid #cbd5e1;font-size:11px;line-height:18px;color:${config.fontColor};">
<p style="margin:0 0 8px;font-weight:700;">BA Threat Intel · Security Operations</p>
<p style="margin:0;">Generated from monitored inventory and threat intelligence. Validate applicability and follow your approved change process before remediation.</p>
</td></tr>
</table>
<!--[if mso]></td></tr></table><![endif]-->
</td></tr></table>
</body>
</html>`;
}

export const DEFAULT_DAILY_DIGEST_CUSTOMIZATION: TemplateCustomization = {
  ...DEFAULT_TEMPLATE_CUSTOMIZATION,
  badgeStampText: 'DAILY DIGEST',
};

export interface DigestFinding {
  cveId: string;
  severity: string;
  assetName: string;
  vendor?: string;
}

export interface DigestHealth {
  database: 'connected' | 'degraded';
  databaseLatencyMs: number;
  workerStatus: string;
  workerHeartbeatAgeSeconds: number | null;
  nextScheduledAttempt: string | null;
  backlog: { status: string; count: number }[];
  checkedAt: string;
}

export interface DailyDigestParts {
  advisory_id: string;
  advisory_title: string;
  dispatch_date: string;
  severity: string;
  finding_count: number;
  severity_counts: string;
  findings_summary: string;
  health_report: string;
  recipient_name: string;
}

const digestEscapeHtml = (value: string) =>
  String(value).replace(/[&<>"']/g, (ch) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]!,
  );

function normalizeDigestConfig(config: TemplateCustomization): TemplateCustomization {
  config = { ...DEFAULT_DAILY_DIGEST_CUSTOMIZATION, ...config };
  for (const key of [
    'fontColor',
    'headingColor',
    'accentColor',
    'canvasBg',
    'cardBg',
    'headerBg',
    'badgeStampColor',
  ] as const) {
    if (!/^#[0-9a-f]{3}(?:[0-9a-f]{3})?$/i.test(config[key]))
      config[key] = DEFAULT_DAILY_DIGEST_CUSTOMIZATION[key];
  }
  if (!['solid', 'dashed', 'none'].includes(config.borderStyle)) config.borderStyle = 'solid';
  if (!/^\d{1,3}(?:px|rem|%)$/.test(config.borderRadius)) config.borderRadius = '12px';
  config.badgeStampText = digestEscapeHtml(config.badgeStampText);
  config.classificationText = digestEscapeHtml(config.classificationText);
  return config;
}

export function compileDailyDigestTemplate(config: TemplateCustomization): string {
  config = normalizeDigestConfig(config);
  const fontCss = getFontFamilyCss(config.fontFamily);
  const headerHex = config.headerBg.slice(1);
  const expanded = headerHex.length === 3 ? [...headerHex].map((ch) => ch + ch).join('') : headerHex;
  const luminance = [0, 2, 4]
    .map((offset) => parseInt(expanded.slice(offset, offset + 2), 16) / 255)
    .map((channel) => (channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4))
    .reduce((sum, channel, index) => sum + channel * [0.2126, 0.7152, 0.0722][index], 0);
  const headerText = luminance > 0.179 ? '#0f172a' : '#ffffff';
  const headerMuted = luminance > 0.179 ? '#334155' : '#cbd5e1';
  const stampHtml = config.showStamp
    ? `<p style="margin:0 0 12px;font-size:11px;line-height:18px;letter-spacing:1.5px;font-weight:700;color:${config.badgeStampColor};">${config.badgeStampText}</p>`
    : '';
  const classificationBanner = config.showClassificationBanner
    ? `<tr><td style="padding:12px 28px;background:${config.canvasBg};color:${config.fontColor};font-size:10px;line-height:16px;letter-spacing:1px;text-align:center;">${config.classificationText}</td></tr>`
    : '';
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>Daily vulnerability digest</title>
<style>
  body,table,td,a { -webkit-text-size-adjust:100%; -ms-text-size-adjust:100%; }
  table,td { mso-table-lspace:0pt; mso-table-rspace:0pt; }
  table { border-collapse:collapse; }
  a { overflow-wrap:anywhere; word-break:breakword; }
  @media only screen and (max-width:600px) {
    .outer { padding:16px 8px !important; }
    .section { padding:24px 20px !important; }
    .digest-title { font-size:22px !important;line-height:28px !important; }
  }
</style>
</head>
<body style="margin:0;padding:0;background:${config.canvasBg};color:${config.fontColor};font-family:${digestEscapeHtml(fontCss)};">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;background:${config.canvasBg};">
<tr><td class="outer" align="center" style="padding:36px 16px;">
<!--[if mso]><table role="presentation" width="680" align="center"><tr><td><![endif]-->
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;max-width:680px;background:${config.cardBg};border:1px ${config.borderStyle} #cbd5e1;border-radius:${config.borderRadius};">
${classificationBanner}
 <tr><td class="section" style="padding:20px 32px;background:${config.headerBg};border-top:4px solid ${config.accentColor};">
 <p style="margin:0 0 12px;color:${headerMuted};font-size:10px;line-height:14px;font-weight:700;letter-spacing:2px;">VULNSTREAM / THREAT INTELLIGENCE</p>
 <p style="margin:0 0 6px;"><span style="display:inline-block;padding:4px 10px;background:#ffffff;color:#0f172a;font-size:10px;line-height:14px;letter-spacing:1px;font-weight:700;border-radius:4px;">{{severity}}</span></p>
 <h1 class="digest-title" style="margin:0 0 8px;font-size:24px;line-height:30px;font-weight:700;letter-spacing:-.25px;color:${headerText};">Daily Vulnerability Digest</h1>
 <p style="margin:0;font-size:11px;line-height:18px;color:${headerMuted};">{{advisory_id}}<br>Date: {{dispatch_date}}</p>
 </td></tr>
<tr><td class="section" style="padding:28px 32px 24px;font-size:14px;line-height:24px;color:${config.fontColor};">
${stampHtml}
<h2 style="margin:0 0 12px;color:${config.headingColor};font-size:16px;line-height:24px;font-weight:700;">Findings at a glance</h2>
<p style="margin:0 0 16px;font-size:14px;line-height:22px;color:${config.fontColor};">{{finding_count}} finding(s) reported today. {{severity_counts}}</p>
{{findings_summary}}
{{health_report}}
</td></tr>
<tr><td class="section" style="padding:20px 32px;border-top:1px solid #cbd5e1;font-size:11px;line-height:18px;color:${config.fontColor};">
<p style="margin:0 0 8px;font-weight:700;">BA Threat Intel · Daily Digest</p>
<p style="margin:0;">A daily summary of monitored vulnerability activity and operational health. Validate applicability and follow your approved change process before remediation. Sent to {{recipient_name}}.</p>
</td></tr>
</table>
<!--[if mso]></td></tr></table><![endif]-->
</td></tr></table>
</body>
</html>`;
}

export function renderDailyFindingSummary(
  findings: DigestFinding[],
  config: TemplateCustomization,
): string {
  const safe = normalizeDigestConfig(config);
  const fontCss = getFontFamilyCss(safe.fontFamily);
  if (!findings.length) {
    return `<p style="margin:0;font-family:${digestEscapeHtml(fontCss)};font-size:12px;line-height:20px;color:${safe.fontColor};">No findings in the last 24 hours.</p>`;
  }
  const bySeverity: Record<string, DigestFinding[]> = {};
  for (const finding of findings) (bySeverity[finding.severity] ||= []).push(finding);
  const parts = (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'] as const)
    .filter((s) => bySeverity[s]?.length)
    .map((s) => {
      const items = bySeverity[s];
      const list = items
        .slice(0, 25)
        .map(
          (f) =>
            `<li style="margin-bottom:2px"><strong>${digestEscapeHtml(f.cveId)}</strong> — ${digestEscapeHtml(f.assetName)}${f.vendor ? ` (${digestEscapeHtml(f.vendor)})` : ''}</li>`,
        )
        .join('');
      const extra =
        items.length > 25 ? `<li style="color:#71717a">…and ${items.length - 25} more</li>` : '';
      return `<h3 style="margin:16px 0 4px;font-family:${digestEscapeHtml(fontCss)};font-size:13px;font-weight:600;color:${safe.headingColor};">${s} (${items.length})</h3><ul style="font-family:${digestEscapeHtml(fontCss)};font-size:11px;line-height:20px;color:${safe.fontColor};margin:0 0 8px;padding-left:18px;list-style:disc">${list}${extra}</ul>`;
    });
  return parts.join('');
}

export function renderDailyHealthReport(
  health: DigestHealth | null,
  config: TemplateCustomization,
): string {
  if (!health) return '';
  const safe = normalizeDigestConfig(config);
  const fontCss = getFontFamilyCss(safe.fontFamily);
  const bodyRows = health.backlog
    .map(
      (row) =>
        `<tr><td style="padding:4px 8px;border:1px solid #27272a;font-family:${digestEscapeHtml(fontCss)};font-size:11px;">${digestEscapeHtml(row.status)}</td><td style="padding:4px 8px;border:1px solid #27272a;font-family:${digestEscapeHtml(fontCss)};font-size:11px;">${row.count}</td></tr>`,
    )
    .join('');
  const nextDelivery = health.nextScheduledAttempt
    ? new Date(health.nextScheduledAttempt).toISOString()
    : 'none pending';
  const workerAge =
    health.workerHeartbeatAgeSeconds !== null
      ? ` · ${health.workerHeartbeatAgeSeconds}s since heartbeat`
      : '';
  return `<h2 style="margin:24px 0 8px;font-family:${digestEscapeHtml(fontCss)};font-size:16px;font-weight:600;color:${safe.headingColor};">Operational health check</h2><table style="font-family:${digestEscapeHtml(fontCss)};font-size:11px;border-collapse:collapse;width:100%;margin-bottom:16px;color:${safe.fontColor};"><tr><td style="padding:4px 8px;border:1px solid #27272a">${digestEscapeHtml(health.database)} (${health.databaseLatencyMs} ms)</td></tr><tr><td style="padding:4px 8px;border:1px solid #27272a">Delivery worker</td><td style="padding:4px 8px;border:1px solid #27272a">${digestEscapeHtml(health.workerStatus)}${workerAge}</td></tr><tr><td style="padding:4px 8px;border:1px solid #27272a">Next scheduled delivery</td><td style="padding:4px 8px;border:1px solid #27272a">${digestEscapeHtml(nextDelivery)}</td></tr><tr><td style="padding:4px 8px;border:1px solid #27272a">Outbox backlog</td><td style="padding:4px 8px;border:1px solid #27272a">${bodyRows || 'idle'}</td></tr><tr><td style="padding:4px 8px;border:1px solid #27272a">Checked at</td><td style="padding:4px 8px;border:1px solid #27272a">${new Date(health.checkedAt).toISOString()}</td></tr></table>`;
}

export function renderDailyDigest(config: TemplateCustomization, parts: DailyDigestParts): string {
  const template = compileDailyDigestTemplate(config);
  return template
    .replace(/{{severity}}/g, digestEscapeHtml(parts.severity))
    .replace(/{{advisory_id}}/g, digestEscapeHtml(parts.advisory_id))
    .replace(/{{advisory_title}}/g, digestEscapeHtml(parts.advisory_title))
    .replace(/{{dispatch_date}}/g, digestEscapeHtml(parts.dispatch_date))
    .replace(/{{finding_count}}/g, String(parts.finding_count))
    .replace(/{{severity_counts}}/g, digestEscapeHtml(parts.severity_counts || '—'))
    .replace(/{{findings_summary}}/g, parts.findings_summary)
    .replace(/{{health_report}}/g, parts.health_report)
    .replace(/{{recipient_name}}/g, digestEscapeHtml(parts.recipient_name));
}
