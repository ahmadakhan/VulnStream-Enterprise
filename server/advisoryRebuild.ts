import type { Advisory, Finding, TemplateCustomization } from '../src/types/index.ts';
import { DEFAULT_TEMPLATE_CUSTOMIZATION, compileCustomizedTemplate } from '../src/utils/templateCompiler.ts';
import { get, type Db } from './db.ts';
import { advisoryEmail } from './advisoryEmail.ts';
import { renderAdvisory } from './advisoryRender.ts';

/** Rebuilt content must describe current findings, never an old rendered body. */
export function currentAdvisoryView(original: Advisory, findings: Finding[]): Advisory {
  const unique = (values: string[]) => [...new Set(values.filter(Boolean))].sort();
  const ranks: Advisory['severity'][] = ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  const links = unique(
    findings.flatMap((f) => [f.cve.remediation?.vendorAdvisoryRef || '', f.cve.remediation?.patchUrl || '']),
  );
  return {
    ...original,
    severity: findings.reduce(
      (severity, f) =>
        ranks.indexOf(f.cve.cvss.severity) > ranks.indexOf(severity) ? f.cve.cvss.severity : severity,
      'UNKNOWN' as Advisory['severity'],
    ),
    title: `Vulnerability notice: ${unique(findings.map((f) => f.cveId)).join(', ')}`,
    cveIds: unique(findings.map((f) => f.cveId)),
    findingIds: findings.map((f) => f.id),
    affectedSystems: unique(findings.map((f) => f.matchedAssetName)),
    executiveSummary: `${findings.length} current inventory correlation(s). Confirm applicability and consult the vendor before remediation.`,
    remediationInstructions:
      unique(
        findings.flatMap((f) => [
          ...(f.cve.remediation?.immediateActions || []),
          ...(f.cve.remediation?.workarounds || []),
          ...(f.cve.remediation?.stepByStep || []),
          f.cve.remediation?.patchUrl || '',
          f.cve.remediation?.vendorAdvisoryRef || '',
        ]),
      ).join('\n') || 'Consult the current vendor advisory for remediation guidance.',
    vendorLink: links[0] || '',
  };
}

export async function currentAdvisoryBody(db: Db, view: Advisory, findings: Finding[]) {
  const template = await get<{ templateCustomization?: TemplateCustomization }>(db, 'template', 'main');
  const html = renderAdvisory(
    compileCustomizedTemplate(template?.templateCustomization || DEFAULT_TEMPLATE_CUSTOMIZATION),
    view,
  );
  return advisoryEmail(
    view,
    html,
    findings.map(
      (f) =>
        `${f.cveId} | ${f.cve.cvss.severity}${f.cve.cisaKev?.isKev ? ' | CISA KEV' : ''} | ${f.matchedAssetName}`,
    ),
  );
}
