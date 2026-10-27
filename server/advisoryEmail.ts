import type { Advisory } from '../src/types/index.ts';

const escapeHtml = (value: string) => value.replace(/[&<>"']/g, ch =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]!);

const stripCrlf = (value: string) => value.replace(/[\r\n]/g, ' ');

/** Advisory IDs carry the configured prefix and remain stable on retries/resends. */
export function advisoryEmail(advisory: Advisory, html?: string, detailLines?: string[]) {
  const safeId = stripCrlf(advisory.id);
  const safeSeverity = stripCrlf(advisory.severity);
  const safeTitle = stripCrlf(advisory.title);
  const escapedId = escapeHtml(advisory.id);
  if (html !== undefined && !html.includes(escapedId)) {
    const identity = `<p style="font-family:Arial,sans-serif;font-size:12px;color:#52525b;padding:12px 16px;">Advisory ID: <strong>${escapedId}</strong></p>`;
    html = /<body\b[^>]*>/i.test(html)
      ? html.replace(/<body\b[^>]*>/i, match => match + identity)
      : identity + html;
  }
  const details =
    detailLines && detailLines.length
      ? `\n\nFindings:\n${detailLines.map(stripCrlf).join('\n')}`
      : '';
  return {
    subject: `[${safeId}] [${safeSeverity}] ${safeTitle}`,
    text: `Advisory ID: ${advisory.id}\n\n${advisory.title}\n\nSeverity: ${advisory.severity}\n\nCVE IDs:\n${advisory.cveIds.join('\n')}\n\n${advisory.executiveSummary}\n\nAffected systems:\n${advisory.affectedSystems.join('\n')}${details}\n\n${advisory.remediationInstructions}${advisory.vendorLink ? `\n\nVendor advisory: ${advisory.vendorLink}` : ''}`,
    html,
  };
}
