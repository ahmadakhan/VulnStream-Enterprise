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
    dispatch_date: new Date().toISOString(),
    executive_summary: advisory.executiveSummary,
    cve_ids: advisory.cveIds.join(', '),
    affected_systems: advisory.affectedSystems.join('\n'),
    remediation_steps: advisory.remediationInstructions,
    vendor_link: advisory.vendorLink || '',
  };
  return template.replace(/{{([a-z_]+)}}/g, (_, key) => escape(values[key] || ''));
}
