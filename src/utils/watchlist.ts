import type { WatchListItem } from '../types/index.ts';
import { buildStrictCpe23 } from '../data/vendorCatalog.ts';
import { parseCPE23 } from './cpeMatcher.ts';

export function orderWatchlist(items: WatchListItem[]): WatchListItem[] {
  return [...items].sort((a, b) => {
    const createdOrder = Date.parse(b.createdAt) - Date.parse(a.createdAt);
    return Number.isFinite(createdOrder) && createdOrder !== 0 ? createdOrder : a.id.localeCompare(b.id);
  });
}

export function editedWatchlistCpe(
  item: WatchListItem,
  fields: { cpeExpression: string; vendor: string; product: string; part: 'a' | 'o' | 'h'; version: string; targetHw: string },
): string {
  const original = parseCPE23(item.cpes[0] || '');
  const formChanged =
    fields.vendor.trim() !== (original.isValid ? original.vendor : item.vendor) ||
    fields.product.trim() !== (original.isValid ? original.product : item.product) ||
    fields.part !== (original.part === 'o' || original.part === 'h' ? original.part : 'a') ||
    fields.version !== (original.version || '*') ||
    fields.targetHw !== (original.isValid ? original.targetHw : item.targetHw || '*');

  return formChanged
    ? buildStrictCpe23(fields.part, fields.vendor, fields.product, fields.version, fields.targetHw)
    : fields.cpeExpression.trim();
}
