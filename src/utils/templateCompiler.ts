import { TemplateCustomization } from '../types';

export const DEFAULT_TEMPLATE_CUSTOMIZATION: TemplateCustomization = {
  fontFamily: 'sans',
  fontColor: '#d4d4d8',
  headingColor: '#ffffff',
  accentColor: '#3b82f6',
  canvasBg: '#09090b',
  cardBg: '#18181b',
  headerBg: '#1e293b',
  badgeStampText: 'OFFICIAL SECURITY BULLETIN',
  badgeStampColor: '#ef4444',
  showStamp: true,
  showClassificationBanner: true,
  classificationText: 'TLP:AMBER+STRICT • AUTOMATED UNATTENDED NOTICE',
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
  for (const key of ['fontColor', 'headingColor', 'accentColor', 'canvasBg', 'cardBg', 'headerBg', 'badgeStampColor'] as const) {
    if (!/^#[0-9a-f]{3}(?:[0-9a-f]{3})?$/i.test(config[key])) config[key] = DEFAULT_TEMPLATE_CUSTOMIZATION[key];
  }
  if (!['solid', 'dashed', 'none'].includes(config.borderStyle)) config.borderStyle = 'solid';
  if (!/^\d{1,3}(?:px|rem|%)$/.test(config.borderRadius)) config.borderRadius = '12px';
  const escapeHtml = (value: string) => String(value).replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]!));
  config.badgeStampText = escapeHtml(config.badgeStampText);
  config.classificationText = escapeHtml(config.classificationText);
  const fontCss = getFontFamilyCss(config.fontFamily);

  const stampHtml = config.showStamp
    ? `
      <div class="badge-stamp" style="position: absolute; top: 18px; right: 24px; border: 2px dashed ${config.badgeStampColor}; color: ${config.badgeStampColor}; font-weight: 800; font-size: 11px; padding: 4px 10px; border-radius: 6px; text-transform: uppercase; letter-spacing: 0.1em; transform: rotate(-3deg); opacity: 0.95; font-family: ui-monospace, monospace;">
        ${config.badgeStampText}
      </div>`
    : '';

  const classificationBanner = config.showClassificationBanner
    ? `
      <div style="background: #111827; border-bottom: 1px solid #374151; color: #9ca3af; font-family: ui-monospace, monospace; font-size: 10px; text-align: center; padding: 6px; font-weight: 600; letter-spacing: 0.15em; text-transform: uppercase;">
        ${config.classificationText}
      </div>`
    : '';

  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Advisory</title>
  <style>
    html, body {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
      -webkit-font-smoothing: antialiased;
      overflow-x: hidden;
    }
    *, *:before, *:after {
      box-sizing: inherit;
    }
    body {
      font-family: ${fontCss};
      background-color: ${config.canvasBg};
      color: ${config.fontColor};
      padding: 24px 16px;
      word-wrap: break-word;
    }
    .wrapper {
      max-width: 660px;
      width: 100%;
      margin: 0 auto;
      background-color: ${config.cardBg};
      border: 1px ${config.borderStyle} #27272a;
      border-radius: ${config.borderRadius};
      overflow: hidden;
      position: relative;
      box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);
    }
    .header-box {
      background: ${config.headerBg};
      padding: 24px;
      border-bottom: 1px ${config.borderStyle} #27272a;
      position: relative;
    }
    .badge {
      display: inline-block;
      padding: 3px 8px;
      border-radius: 6px;
      font-weight: 700;
      font-size: 11px;
      background: rgba(0, 0, 0, 0.4);
      color: ${config.headingColor};
      border: 1px solid #3f3f46;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .content-box {
      padding: 24px;
    }
    h2 {
      color: ${config.headingColor};
      margin: 12px 0 4px 0;
      font-size: 19px;
      letter-spacing: -0.02em;
    }
    h3 {
      color: ${config.headingColor};
      font-size: 14px;
      margin: 22px 0 8px 0;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      border-bottom: 1px solid rgba(255, 255, 255, 0.08);
      padding-bottom: 4px;
    }
    .callout {
      background: rgba(0, 0, 0, 0.35);
      border-left: 3px solid ${config.accentColor};
      padding: 12px 14px;
      margin: 16px 0;
      border-radius: 4px;
      font-size: 13px;
      line-height: 1.45;
    }
    .mono {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      background: rgba(0, 0, 0, 0.4);
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 12px;
      border: 1px solid #3f3f46;
      color: ${config.headingColor};
    }
    .code-block {
      background: #09090b;
      border: 1px solid #27272a;
      border-radius: 8px;
      padding: 12px 14px;
      font-family: ui-monospace, monospace;
      font-size: 12px;
      line-height: 1.5;
      color: #a1a1aa;
      white-space: pre-wrap;
    }
    .footer {
      padding: 16px 24px;
      font-size: 11px;
      color: #71717a;
      border-top: 1px solid rgba(255, 255, 255, 0.08);
      background: rgba(0, 0, 0, 0.2);
      font-family: ui-monospace, monospace;
    }
    /* Sleek custom scrollbars */
    ::-webkit-scrollbar {
      width: 6px;
      height: 6px;
    }
    ::-webkit-scrollbar-track {
      background: rgba(0, 0, 0, 0.15);
    }
    ::-webkit-scrollbar-thumb {
      background: #3f3f46;
      border-radius: 4px;
    }
    ::-webkit-scrollbar-thumb:hover {
      background: #52525b;
    }
    @media (max-width: 580px) {
      body {
        padding: 12px 8px !important;
      }
      .wrapper {
        border-radius: 8px !important;
      }
      .header-box {
        padding: 16px !important;
      }
      .content-box {
        padding: 16px !important;
      }
      .badge-stamp {
        position: static !important;
        display: inline-block !important;
        margin-top: 8px !important;
        margin-bottom: 8px !important;
        transform: none !important;
      }
      h2 {
        font-size: 16px !important;
      }
      .code-block {
        font-size: 11px !important;
        padding: 10px !important;
      }
    }
  </style>
</head>
<body>
  <div class="wrapper">
    ${classificationBanner}
    <div class="header-box">
      ${stampHtml}
      <span class="badge">{{severity}}</span>
      <h2>{{advisory_id}}: {{advisory_title}}</h2>
      <p style="color: #94a3b8; font-size: 12px; margin: 4px 0 0 0;">
        Automated Notice • Dispatched at {{dispatch_date}}
      </p>
    </div>

    <div class="content-box">
      <div class="callout">
        This security bulletin was generated and dispatched automatically upon matching monitored product inventory. No human operator approval was required.
      </div>

      <h3>1. Executive Summary</h3>
      <p style="font-size: 13px; line-height: 1.55; margin: 0 0 16px 0;">
        {{executive_summary}}
      </p>

      <h3>2. Affected Products &amp; Monitored Assets</h3>
      <p style="font-size: 13px; margin: 6px 0;">
        <strong>Target CVE:</strong> <span class="mono">{{cve_ids}}</span>
      </p>
      <p style="font-size: 13px; margin: 6px 0;">
        <strong>Monitored Infrastructure:</strong> {{affected_systems}}
      </p>

      <h3>3. Autonomous Remediation Playbook</h3>
      <div class="code-block">
{{remediation_steps}}
      </div>

      <p style="margin-top: 18px; font-size: 13px;">
        <strong>Vendor Reference:</strong> 
        <a href="{{vendor_link}}" style="color: ${config.accentColor}; text-decoration: none; font-weight: 500;">{{vendor_link}}</a>
      </p>
    </div>

    <div class="footer">
      VulnStream Autonomous Intelligence • Zero-Touch Alerting Service
    </div>
  </div>
</body>
</html>`;
}
