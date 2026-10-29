import type { Advisory } from '../src/types/index.ts';

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
          `<div>
<span><a href="https://nvd.nist.gov/vuln/detail/${escape(cve)}" target="_blank">${escape(cve)}</a></span><br/>
<span>${escape(advisory.title)}</span>
</div>
<ul>
<li><strong>Severity:</strong> ${escape(advisory.severity)}</li>
<li><strong>Source Advisory:</strong> ${
            advisory.vendorLink
              ? `<a href="${escape(advisory.vendorLink)}" target="_blank">View vendor advisory</a>`
              : 'N/A'
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
