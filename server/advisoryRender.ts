import type { Advisory, ReviewEdits } from '../src/types/index.ts';

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f59e0b',
  MEDIUM: '#eab308',
  LOW: '#10b981',
  UNKNOWN: '#6b7280',
};
const SEVERITY_BADGE = (severity: string, suffix = '') => {
  const color = SEVERITY_COLORS[severity] || SEVERITY_COLORS.UNKNOWN;
  const label = severity || 'UNKNOWN';
  return `<span style="display:inline-block;padding:4px 10px;border-radius:4px;background:${color};color:#ffffff;font-size:11px;line-height:16px;font-weight:700;letter-spacing:0.5px;">${label}${suffix}</span>`;
};

/**
 * Validates that all required advisory fields needed by the email template
 * are populated. Called by renderAdvisory to prevent emails with empty
 * content from being queued for delivery.
 */
export function validateAdvisoryFields(advisory: Advisory): AdvisoryFieldValidation {
  const missingFields: string[] = [];
  if (!advisory.id || !advisory.id.trim()) missingFields.push('id');
  if (!advisory.title || !advisory.title.trim()) missingFields.push('title');
  if (!advisory.severity) missingFields.push('severity');
  if (!advisory.executiveSummary || !advisory.executiveSummary.trim())
    missingFields.push('executiveSummary');
  if (!advisory.remediationInstructions || !advisory.remediationInstructions.trim())
    missingFields.push('remediationInstructions');
  if (!advisory.affectedSystems || advisory.affectedSystems.length === 0)
    missingFields.push('affectedSystems');
  return { valid: missingFields.length === 0, missingFields };
}

export interface AdvisoryFieldValidation {
  valid: boolean;
  missingFields: string[];
}

/**
 * Renders the operator-managed advisory template for one advisory view.
 *
 * A digest is rendered from a recipient-specific advisory view (a subset of the
 * findings in the combined advisory), so the rendered HTML can never disclose a
 * finding that the recipient is not subscribed to.
 *
 * Throws if any required advisory field is empty, preventing emails with
 * missing content from being queued for delivery.
 */
export function renderAdvisory(template: string, advisory: Advisory): string {
  const validation = validateAdvisoryFields(advisory);
  if (!validation.valid) {
    throw new Error(
      `Cannot render advisory email with empty required fields: ${validation.missingFields.join(', ')}`,
    );
  }
  const escape = (v: string) =>
    v.replace(
      /[&<>"']/g,
      (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]!,
    );
  const edits: ReviewEdits = advisory.edits || {};
  const values: Record<string, string> = {
    severity: advisory.severity,
    advisory_id: advisory.id,
    advisory_title: advisory.title,
    dispatch_date: new Date().toLocaleString('en-GB', {
      day: 'numeric',
      month: 'long',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
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
    audience_notice: edits.audienceNotice
      ? escape(edits.audienceNotice).replace(/\n/g, '<br/>')
      : 'This advisory is being distributed to all recipients per the EVERYONE delivery policy.',
     reviewer_comment: edits.reviewerComment
       ? `<strong>Reviewer note${edits.reviewerName ? ` by ${escape(edits.reviewerName)}` : ''}</strong> ${escape(edits.reviewerComment).replace(/\n/g, '<br/>')}`
       : '',
     severity_badge: SEVERITY_BADGE(advisory.severity),
     severity_header_badge: SEVERITY_BADGE(advisory.severity, ' SEVERITY'),
   };
   const rawHtmlTokens = new Set([
     'cve_id_links',
     'cve_details',
     'affected_systems_html',
     'mitigation_steps',
     'recommended_actions',
     'audience_notice',
     'reviewer_comment',
     'severity_badge',
     'severity_header_badge',
   ]);
  return template.replace(/{{([a-z_]+)}}/g, (_, key) => {
    if (rawHtmlTokens.has(key)) return values[key] || '';
    return escape(values[key] || '');
  });
}
