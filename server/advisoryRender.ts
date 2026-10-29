import type { Advisory } from '../src/types/index.ts';

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f59e0b',
  MEDIUM: '#eab308',
  LOW: '#10b981',
  UNKNOWN: '#6b7280',
};
const SEVERITY_BADGE = (severity: string) => {
  const color = SEVERITY_COLORS[severity] || SEVERITY_COLORS.UNKNOWN;
  const label = severity || 'UNKNOWN';
  return `<span style="display:inline-block;padding:2px 10px;border-radius:4px;background:${color};color:#ffffff;font-size:11px;line-height:16px;font-weight:700;letter-spacing:0.5px;">${label}</span>`;
};

/**
 * Renders the operator-managed advisory template for one advisory view.
 *
 * A digest is rendered from a recipient-specific advisory view (a subset of the
 * findings in the combined advisory), so the rendered HTML can never disclose a
 * finding that the recipient is not subscribed to.
 */
export function renderAdvisory(template: string, advisory: Advisory): string {
  const escape = (v: string) =>
    v.replace(
      /[&<>"']/g,
      (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]!,
    );
  const values: Record<string, string> = {
    severity: advisory.severity,
    advisory_id: advisory.id,
    advisory_title: advisory.title,
    dispatch_date: new Date().toLocaleDateString('en-GB', {
      day: 'numeric',
      month: 'long',
      year: 'numeric',
    }),
    executive_summary: advisory.executiveSummary,
    cve_ids: advisory.cveIds.join(', '),
    affected_systems: advisory.affectedSystems.join('\n'),
    affected_systems_html: advisory.affectedSystems
      .map((sys: string) => `<li>${escape(sys)}</li>`)
      .join('\n'),
    remediation_steps: advisory.remediationInstructions,
    vendor_link: advisory.vendorLink || '',
    cve_id_links: advisory.cveIds
      .map(
        (cve: string) =>
          `<a href="https://nvd.nist.gov/vuln/detail/${escape(cve)}" target="_blank">${escape(cve)}</a>`,
      )
      .join(', '),
    cve_details: advisory.cveIds
      .map(
        (cve: string) =>
          `<div style="margin-bottom:12px;">
<span><a href="https://nvd.nist.gov/vuln/detail/${escape(cve)}" target="_blank" rel="noopener noreferrer" style="font-family:monospace;font-weight:600;color:${SEVERITY_COLORS[advisory.severity] || SEVERITY_COLORS.UNKNOWN};text-decoration:underline;">${escape(cve)}</a></span>
</div>
<ul style="margin:0 0 8px;padding-left:18px;font-size:12px;line-height:20px;">
<li style="margin-bottom:2px;"><strong>Severity:</strong> ${SEVERITY_BADGE(advisory.severity)}</li>
<li style="margin-bottom:2px;"><strong>Vendor Advisory:</strong> ${
            advisory.vendorLink
              ? `<a href="${escape(advisory.vendorLink)}" target="_blank" rel="noopener noreferrer">View source</a>`
              : '<span style="color:#94a3b8;">N/A</span>'
          }</li>
</ul>`,
      )
      .join('\n'),
    mitigation_steps: `<ul>
<li>Review and limit administrative access to trusted networks.</li>
<li>Monitor affected services for anomalous activity following the advisory window.</li>
<li>Apply compensating controls if vendor patches are not yet deployable.</li>
</ul>`,
    recommended_actions: `<ul>
<li>Inventory all affected systems identified in this advisory.</li>
<li>Apply vendor patches immediately following your change management process.</li>
<li>Validate backup, restore, and operational functionality after remediation.</li>
</ul>`,
  };
  const rawHtmlTokens = new Set([
    'cve_id_links',
    'cve_details',
    'affected_systems_html',
    'mitigation_steps',
    'recommended_actions',
  ]);
  return template.replace(/{{([a-z_]+)}}/g, (_, key) => {
    if (rawHtmlTokens.has(key)) return values[key] || '';
    return escape(values[key] || '');
  });
}
