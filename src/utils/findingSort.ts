import type { Finding } from '../types';
import { formatDate } from './dateTime';

const timestamp = (value: string): number => {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : Number.NEGATIVE_INFINITY;
};

/** Newest published CVEs first; use the latest modification date to break ties. */
export function compareFindingsByRecency(a: Finding, b: Finding): number {
  const publishedA = timestamp(a.cve.publishedDate);
  const publishedB = timestamp(b.cve.publishedDate);
  if (publishedA !== publishedB) return publishedA > publishedB ? -1 : 1;
  const modifiedA = timestamp(a.cve.modifiedDate);
  const modifiedB = timestamp(b.cve.modifiedDate);
  if (modifiedA !== modifiedB) return modifiedA > modifiedB ? -1 : 1;
  return a.cveId.localeCompare(b.cveId) || a.id.localeCompare(b.id);
}

export function formatCveDate(value: string): string {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? formatDate(value) : '—';
}
