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
  a { overflow-wrap:anywhere; word-break:breakword; }
  .ms-rteTableEvenCol-default { font-weight:700;color:${escapeHtml(config.headingColor)}; }
  @media only screen and (max-width:600px) {
    .outer { padding:16px 8px !important; }
    .ms-rteTableEvenCol-default { width:30% !important; }
  }
</style>
</head>
<body style="margin:0;padding:0;background:${config.canvasBg};color:${config.fontColor};font-family:${escapeHtml(fontCss)};">
<p>​​​​​​​​<br/></p>
<table class="ms-rteTable-default" cellspacing="0" style="width:100%;">
<tbody>

<tr class="ms-rteTableEvenRow-default">
<td class="ms-rteTableEvenCol-default" style="width:11%;">Vulnerability Name</td>
<td class="ms-rteTableOddCol-default">
${stampHtml}
{{advisory_title}}
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

${classificationBanner}

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
</body>
</html>`;
}
