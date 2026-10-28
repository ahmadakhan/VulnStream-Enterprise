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
  const section = (label: string) =>
    `<h2 style="margin:0 0 12px;color:${config.headingColor};font-size:16px;line-height:24px;font-weight:700;">${label}</h2>`;
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
  @media only screen and (max-width:600px) {
    .outer { padding:16px 8px !important; }
    .section { padding:24px 20px !important; }
    .advisory-title { font-size:24px !important;line-height:32px !important; }
  }
</style>
</head>
<body style="margin:0;padding:0;background:${config.canvasBg};color:${config.fontColor};font-family:${escapeHtml(fontCss)};">
<div style="display:none;font-size:1px;line-height:1px;max-height:0;max-width:0;opacity:0;overflow:hidden;mso-hide:all;">{{severity}} security advisory · {{advisory_title}}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;background:${config.canvasBg};">
<tr><td class="outer" align="center" style="padding:36px 16px;">
<!--[if mso]><table role="presentation" width="680" align="center"><tr><td><![endif]-->
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;max-width:680px;background:${config.cardBg};border:1px ${config.borderStyle} #cbd5e1;border-radius:${config.borderRadius};">
${classificationBanner}
<tr><td class="section" style="padding:32px;background:${config.headerBg};border-top:4px solid ${config.accentColor};">
<p style="margin:0 0 20px;color:${headerMuted};font-size:11px;line-height:18px;font-weight:700;letter-spacing:2px;">VULNSTREAM / THREAT INTELLIGENCE</p>
<p style="margin:0 0 12px;"><span style="display:inline-block;padding:5px 10px;background:#ffffff;color:#0f172a;font-size:11px;line-height:16px;letter-spacing:1px;font-weight:700;border-radius:4px;">{{severity}} PRIORITY</span></p>
<h1 class="advisory-title" style="margin:0 0 16px;font-size:28px;line-height:36px;font-weight:700;letter-spacing:-.5px;color:${headerText};">{{advisory_title}}</h1>
<p style="margin:0;font-size:12px;line-height:20px;color:${headerMuted};">{{advisory_id}}<br>Generated {{dispatch_date}}</p>
</td></tr>
<tr><td class="section" style="padding:28px 32px 24px;font-size:14px;line-height:24px;color:${config.fontColor};">
${stampHtml}
${section('Executive summary')}
<p style="margin:0;">{{executive_summary}}</p>
</td></tr>
<tr><td class="section" style="padding:24px 32px;border-top:1px solid #cbd5e1;font-size:14px;line-height:24px;color:${config.fontColor};">
${section('Affected products &amp; assets')}
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;font-size:13px;line-height:22px;color:${config.fontColor};">
<tr><td style="padding:0 0 6px;font-weight:700;color:${config.headingColor};">CVE identifiers</td></tr>
<tr><td style="padding:0 0 16px;overflow-wrap:anywhere;">{{cve_ids}}</td></tr>
<tr><td style="padding:0 0 6px;font-weight:700;color:${config.headingColor};">Monitored inventory</td></tr>
<tr><td style="padding:0;white-space:pre-line;">{{affected_systems}}</td></tr>
</table>
</td></tr>
<tr><td class="section" style="padding:24px 32px;border-top:1px solid #cbd5e1;font-size:14px;line-height:24px;color:${config.fontColor};">
${section('Recommended response')}
<div style="border-left:3px solid ${config.accentColor};padding:8px 0 8px 18px;white-space:pre-wrap;overflow-wrap:anywhere;">{{remediation_steps}}</div>
<p style="margin:20px 0 4px;font-size:12px;font-weight:700;color:${config.headingColor};">SOURCE ADVISORY</p>
<a href="{{vendor_link}}" style="color:${config.accentColor};font-size:13px;line-height:22px;text-decoration:underline;">{{vendor_link}}</a>
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
