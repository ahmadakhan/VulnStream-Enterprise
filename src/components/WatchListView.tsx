import { PageHeading } from './PageHeading';
import React, { useState, useMemo, useEffect, useRef } from 'react';
import { useApp } from '../context/AppContext';
import { WatchListItem, NormalizedCVE, NvdCpeSearchResult } from '../types';
import {
  generateCPE23,
  parseCPE23,
  matchesWatchlistItem,
  matchVendorWithAliases,
  matchProductWithAliases,
} from '../utils/cpeMatcher';
import { formatDate as fmtDate } from '../utils/dateTime';
import {
  ENTERPRISE_VENDOR_CATALOG,
  getCatalogProductsForVendor,
  buildStrictCpe23,
  CatalogProduct,
} from '../data/vendorCatalog';
import {
  Server,
  Plus,
  Upload,
  Download,
  Trash2,
  Edit2,
  Search,
  X,
  Code,
  FlaskConical,
  CheckCircle2,
  AlertCircle,
  Check,
  Package,
  Loader2,
} from 'lucide-react';
import { Pagination } from './Pagination';
import { editedWatchlistCpe } from '../utils/watchlist';
import { CveLink } from './CveLink';
import { useDialogFocus } from '../hooks/useDialogFocus';
import './product-registration.css';

function ProductRegistrationDialog({
  children,
  onClose,
}: {
  children: React.ReactNode;
  onClose: () => void;
}) {
  const ref = useDialogFocus(onClose);
  return (
    <div
      ref={ref}
      role="dialog"
      aria-modal="true"
      aria-labelledby="product-registration-title"
      aria-describedby="product-registration-description"
      tabIndex={-1}
      className="product-registration-overlay"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div className="product-registration-dialog ui-panel">{children}</div>
    </div>
  );
}

export const WatchListView: React.FC = () => {
  const {
    watchlist,
    addWatchlistItem,
    updateWatchlistItem,
    toggleWatchlistItemActive,
    deleteWatchlistItem,
    bulkImportWatchlist,
    simulateCorrelation,
    searchNvdCpes,
    settings,
  } = useApp();

  // Primary view mode: Inventory vs Simulator Lab
  const [viewMode, setViewMode] = useState<'inventory' | 'simulator'>('inventory');

  const [searchTerm, setSearchTerm] = useState('');
  const [showAddModal, setShowAddModal] = useState(false);
  const [savingProduct, setSavingProduct] = useState(false);
  const [catalogQuery, setCatalogQuery] = useState('');
  const nvdSearchSequence = useRef(0);
  useEffect(() => {
    nvdSearchSequence.current++;
  }, [showAddModal]);
  useEffect(
    () => () => {
      nvdSearchSequence.current++;
    },
    [],
  );
  const [saveFeedback, setSaveFeedback] = useState<{ type: 'error' | 'success'; message: string } | null>(
    null,
  );
  const [deleteFeedback, setDeleteFeedback] = useState<{ type: 'error' | 'success'; message: string } | null>(
    null,
  );
  const [showBulkModal, setShowBulkModal] = useState(false);
  const [editingItem, setEditingItem] = useState<WatchListItem | null>(null);
  const [deletingAsset, setDeletingAsset] = useState<WatchListItem | null>(null);
  const [togglingAssetId, setTogglingAssetId] = useState<string | null>(null);

  // Pagination for inventory table
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);

  // Form State
  const [vendorInput, setVendorInput] = useState('');
  const [customProductInput, setCustomProductInput] = useState('');
  const [additionalProductInput, setAdditionalProductInput] = useState('');
  const [additionalCpes, setAdditionalCpes] = useState<string[]>([]);
  const [selectedProductIds, setSelectedProductIds] = useState<string[]>([]);
  const [cpePart, setCpePart] = useState<'a' | 'o' | 'h'>('a');
  const [versionInput, setVersionInput] = useState('*');
  const [targetHwInput, setTargetHwInput] = useState('*');
  const [assetTagInput, setAssetTagInput] = useState('');
  const [ownerGroupInput, setOwnerGroupInput] = useState('SecOps-Core');
  const [notesInput, setNotesInput] = useState('');
  const [purlInput, setPurlInput] = useState('');
  const [cpeExpressionInput, setCpeExpressionInput] = useState('');

  // Track auto-generated CPEs the user removes from the live preview, and
  // custom CPE 2.3 expressions the user adds manually.
  const [removedAutoCpes, setRemovedAutoCpes] = useState<Set<string>>(new Set());
  const [customAddedCpes, setCustomAddedCpes] = useState<string[]>([]);
  const [customCpeInput, setCustomCpeInput] = useState('');

  const [nvdSearchProduct, setNvdSearchProduct] = useState('');

  // NVD Verified CPE search
  const [nvdResults, setNvdResults] = useState<NvdCpeSearchResult[]>([]);
  const [nvdLoading, setNvdLoading] = useState(false);
  const [nvdError, setNvdError] = useState<string | null>(null);
  const [selectedNvdCpes, setSelectedNvdCpes] = useState<string[]>([]);
  const [nvdResultsFilter, setNvdResultsFilter] = useState('');

  const [bulkJsonText, setBulkJsonText] = useState('');
  const [bulkFeedback, setBulkFeedback] = useState<{ imported: number; errors: string[] } | null>(null);

  // -------------------------------------------------------------
  // Simulator State
  // -------------------------------------------------------------
  const [simPart, setSimPart] = useState<'a' | 'o' | 'h'>('a');
  const [simVendor, setSimVendor] = useState('paloaltonetworks');
  const [simProduct, setSimProduct] = useState('pan-os');
  const [simVersion, setSimVersion] = useState('10.2.3');
  const [simHw, setSimHw] = useState('any');
  const [simPurl, setSimPurl] = useState('');
  const [simResults, setSimResults] = useState<{
    testedAt: string;
    matchedCves: Array<{
      cve: NormalizedCVE;
      method: string;
      confidence: number;
      evidence: string;
      autoAction: string;
      suppressed: boolean;
      suppressionReason?: string;
    }>;
    totalScanned: number;
    ruleSummary: {
      cpeGenerated: string;
      aliasExpanded: boolean;
      intervalEvaluated: boolean;
      architectureFiltered: boolean;
    };
  } | null>(null);

  // Suggested catalog products for currently typed vendor
  const catalogProducts = useMemo(() => {
    return getCatalogProductsForVendor(vendorInput);
  }, [vendorInput]);

  const editedCpe = () =>
    editingItem
      ? editedWatchlistCpe(editingItem, {
          cpeExpression: cpeExpressionInput,
          vendor: vendorInput,
          product: customProductInput,
          part: cpePart,
          version: versionInput,
          targetHw: targetHwInput,
        })
      : cpeExpressionInput.trim();

  // Dynamically generated Strict CPE 2.3 expressions
  const generatedCpes = useMemo(() => {
    if (editingItem) {
      const cpe = editedCpe();
      const current = cpe
        ? [{ product: 'Current product', cpe, part: parseCPE23(cpe).part as 'a' | 'o' | 'h' }]
        : [];
      const additions = selectedProductIds.flatMap((id) => {
        const product = catalogProducts.find((entry) => entry.normalizedId === id);
        if (!product) return [];
        const addedCpe = buildStrictCpe23(
          product.part,
          vendorInput,
          product.normalizedId,
          versionInput,
          targetHwInput,
        );
        return editingItem.cpes.includes(addedCpe)
          ? []
          : [{ product: product.name, cpe: addedCpe, part: product.part }];
      });
      const customAddition = additionalProductInput.trim()
        ? [
            {
              product: additionalProductInput.trim(),
              cpe: buildStrictCpe23(
                cpePart,
                vendorInput,
                additionalProductInput,
                versionInput,
                targetHwInput,
              ),
              part: cpePart,
            },
          ]
        : [];
      const nvdAdditions = selectedNvdCpes
        .filter(
          (cpe) =>
            cpe &&
            !current.some((item) => item.cpe === cpe) &&
            !additions.some((item) => item.cpe === cpe) &&
            !customAddition.some((item) => item.cpe === cpe),
        )
        .map((cpe) => ({
          product: 'NVD verified',
          cpe,
          part: parseCPE23(cpe).part as 'a' | 'o' | 'h',
        }));
      return [...current, ...additions, ...customAddition, ...nvdAdditions].filter(
        (item) => !removedAutoCpes.has(item.cpe),
      );
    }
    const list: Array<{ product: string; cpe: string; part: 'a' | 'o' | 'h' }> = [];
    const v = vendorInput.trim() || 'vendor';

    if (selectedProductIds.length > 0) {
      for (const prodId of selectedProductIds) {
        const catProd = catalogProducts.find((p) => p.normalizedId === prodId);
        const prodName = catProd ? catProd.normalizedId : prodId;
        const part = catProd ? catProd.part : cpePart;
        const cpe = buildStrictCpe23(part, v, prodName, versionInput, targetHwInput);
        list.push({ product: catProd ? catProd.name : prodName, cpe, part });
      }
    }

    if (customProductInput.trim()) {
      const customP = customProductInput.trim();
      const cpe = buildStrictCpe23(cpePart, v, customP, versionInput, targetHwInput);
      list.push({ product: customP, cpe, part: cpePart });
    }

    if (list.length === 0 && (vendorInput.trim() || customProductInput.trim())) {
      const cpe = buildStrictCpe23(cpePart, v, 'software', versionInput, targetHwInput);
      list.push({ product: 'Standard Asset', cpe, part: cpePart });
    }

    const nvdAdditions = selectedNvdCpes
      .filter((cpe) => cpe && !list.some((item) => item.cpe === cpe))
      .map((cpe) => ({
        product: 'NVD verified',
        cpe,
        part: parseCPE23(cpe).part as 'a' | 'o' | 'h',
      }));

    return [
      ...list.filter((item) => !removedAutoCpes.has(item.cpe)),
      ...nvdAdditions,
      ...customAddedCpes.map((cpe) => {
        const parsed = parseCPE23(cpe);
        return {
          product: 'Custom',
          cpe,
          part: parsed.isValid ? (parsed.part as 'a' | 'o' | 'h') : cpePart,
        };
      }),
    ];
  }, [
    vendorInput,
    selectedProductIds,
    customProductInput,
    additionalProductInput,
    cpePart,
    versionInput,
    targetHwInput,
    catalogProducts,
    editingItem,
    cpeExpressionInput,
    selectedNvdCpes,
    removedAutoCpes,
    customAddedCpes,
  ]);

  const filteredAssets = watchlist.filter((item) => {
    const matchesSearch =
      item.assetTag.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.vendor.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.product.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.ownerGroup.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.cpes.some((c) => c.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (item.purls && item.purls.some((p) => p.toLowerCase().includes(searchTerm.toLowerCase())));

    return matchesSearch;
  });

  const paginatedAssets = filteredAssets.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  const handleOpenAdd = () => {
    setSaveFeedback(null);
    setCatalogQuery('');
    setVendorInput('');
    setCustomProductInput('');
    setAdditionalProductInput('');
    setAdditionalCpes([]);
    setSelectedProductIds([]);
    setCpePart('a');
    setVersionInput('*');
    setTargetHwInput('*');
    setAssetTagInput('');
    setOwnerGroupInput('SecOps-Core');
    setNotesInput('');
    setPurlInput('');
    setCpeExpressionInput('');
    setNvdSearchProduct('');
    setNvdResults([]);
    setNvdResultsFilter('');
    setNvdLoading(false);
    setNvdError(null);
    setSelectedNvdCpes([]);
    setRemovedAutoCpes(new Set());
    setCustomAddedCpes([]);
    setCustomCpeInput('');
    setEditingItem(null);
    setShowAddModal(true);
  };

  const handleOpenEdit = (item: WatchListItem) => {
    setSaveFeedback(null);
    setCatalogQuery('');
    const parsed = parseCPE23(item.cpes[0] || '');
    setVendorInput(parsed.isValid ? parsed.vendor : item.vendor);
    setCustomProductInput(parsed.isValid ? parsed.product : item.product);
    setAdditionalProductInput('');
    setAdditionalCpes(item.cpes.slice(1));
    setSelectedProductIds([]);
    setCpePart((parsed.part === 'o' || parsed.part === 'h' ? parsed.part : 'a') as 'a' | 'o' | 'h');
    setVersionInput(parsed.version || '*');
    setTargetHwInput(parsed.isValid ? parsed.targetHw : item.targetHw || '*');
    setAssetTagInput(item.assetTag);
    setOwnerGroupInput(item.ownerGroup);
    setNotesInput(item.notes || '');
    setPurlInput((item.purls || []).join('\n'));
    setCpeExpressionInput(item.cpes[0] || '');
    setNvdSearchProduct('');
    setNvdResults([]);
    setNvdResultsFilter('');
    setNvdLoading(false);
    setNvdError(null);
    setSelectedNvdCpes([]);
    setRemovedAutoCpes(new Set());
    setCustomAddedCpes([]);
    setCustomCpeInput('');
    setEditingItem(item);
    setShowAddModal(true);
  };

  const toggleSelectProduct = (prod: CatalogProduct) => {
    setSelectedProductIds((prev) => {
      if (prev.includes(prod.normalizedId)) {
        return prev.filter((id) => id !== prod.normalizedId);
      } else {
        return [...prev, prod.normalizedId];
      }
    });
  };

  const selectVendorQuick = (vendorName: string) => {
    nvdSearchSequence.current++;
    setVendorInput(vendorName);
    setSelectedProductIds([]);
    setSelectedNvdCpes([]);
    setNvdResults([]);
    setNvdError(null);
    setNvdLoading(false);
    setCatalogQuery('');
  };

  const nvdSearchProductTerm = useMemo(() => {
    const nvdSearch = nvdSearchProduct.trim();
    if (nvdSearch) return nvdSearch;
    const custom = customProductInput.trim();
    if (custom) return custom;
    if (selectedProductIds.length === 1) {
      const catProd = catalogProducts.find((p) => p.normalizedId === selectedProductIds[0]);
      return catProd ? catProd.name : '';
    }
    return '';
  }, [nvdSearchProduct, customProductInput, selectedProductIds, catalogProducts]);

  const dedupeCpes = (cpes: string[]): string[] => {
    const seen = new Set<string>();
    return cpes.filter((c) => {
      const key = c.toLowerCase();
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  };

  const handleNvdSearch = async () => {
    if (!vendorInput.trim()) return;
    const sequence = ++nvdSearchSequence.current;
    setNvdLoading(true);
    setNvdError(null);
    setNvdResults([]);
    setNvdResultsFilter('');
    try {
      const result = await searchNvdCpes(vendorInput.trim(), nvdSearchProductTerm, 50);
      if (sequence !== nvdSearchSequence.current) return;
      const found = result?.results || [];
      setNvdResults(found);
      if (found.length === 0)
        setNvdError('No verified CPEs found in the NVD dictionary for this vendor/product.');
    } catch (e) {
      if (sequence === nvdSearchSequence.current)
        setNvdError(e instanceof Error ? e.message : 'NVD CPE search failed');
    } finally {
      if (sequence === nvdSearchSequence.current) setNvdLoading(false);
    }
  };

  const addNvdCpe = (cpe: string) => {
    setSelectedNvdCpes((prev) => dedupeCpes([...prev, cpe]));
    setNvdResults((prev) => prev.filter((r) => r.cpeName !== cpe));
    setNvdError(null);
  };

  const removeNvdCpe = (cpe: string) => setSelectedNvdCpes((prev) => prev.filter((c) => c !== cpe));

  const filteredNvdResults = useMemo(() => {
    if (!nvdResultsFilter.trim()) return nvdResults;
    const q = nvdResultsFilter.toLowerCase().trim();
    return nvdResults.filter(
      (r) =>
        r.cpeName.toLowerCase().includes(q) ||
        r.vendor.toLowerCase().includes(q) ||
        r.product.toLowerCase().includes(q) ||
        (r.title ? r.title.toLowerCase().includes(q) : false),
    );
  }, [nvdResults, nvdResultsFilter]);

  const handleSaveProduct = async (e: React.FormEvent) => {
    e.preventDefault();
    if (savingProduct) return;
    setSavingProduct(true);
    try {
      setSaveFeedback(null);
      if (!vendorInput.trim()) {
        setSaveFeedback({ type: 'error', message: 'Enter a vendor before saving.' });
        return;
      }

      const purlList = purlInput
        .split('\n')
        .map((s) => s.trim())
        .filter(Boolean);

      // If editing existing single item
      if (editingItem) {
        const cpe = editedCpe();
        const parsedCpe = parseCPE23(cpe);
        if (!parsedCpe.isValid) {
          setSaveFeedback({ type: 'error', message: 'Enter a valid CPE 2.3 expression before saving.' });
          return;
        }

        const selectedCatalogProducts = selectedProductIds.map((id) =>
          catalogProducts.find((entry) => entry.normalizedId === id),
        );
        if (selectedCatalogProducts.some((product) => !product)) {
          setSaveFeedback({
            type: 'error',
            message:
              'The vendor changed after selection. Reselect the catalog products for the current vendor.',
          });
          return;
        }
        const productsToAdd = selectedCatalogProducts.flatMap((product, index) => {
          if (!product) return [];
          const addedCpe = buildStrictCpe23(
            product.part,
            vendorInput,
            product.normalizedId,
            versionInput,
            targetHwInput,
          );
          if (editingItem.cpes.includes(addedCpe) || addedCpe === cpe || removedAutoCpes.has(addedCpe))
            return [];
          return [
            {
              vendor: vendorInput.trim(),
              product: product.name,
              version: versionInput,
              cpes: [addedCpe],
              targetHw: targetHwInput !== '*' ? targetHwInput : undefined,
              assetTag: `${assetTagInput.trim() || editingItem.assetTag}-${index + 1}`,
              ownerGroup: ownerGroupInput.trim() || 'Unassigned',
              notes: notesInput.trim(),
              active: true,
            },
          ];
        });
        if (additionalProductInput.trim()) {
          const addedCpe = buildStrictCpe23(
            cpePart,
            vendorInput,
            additionalProductInput,
            versionInput,
            targetHwInput,
          );
          if (!editingItem.cpes.includes(addedCpe) && addedCpe !== cpe && !removedAutoCpes.has(addedCpe)) {
            productsToAdd.push({
              vendor: vendorInput.trim(),
              product: additionalProductInput.trim(),
              version: versionInput,
              cpes: [addedCpe],
              targetHw: targetHwInput !== '*' ? targetHwInput : undefined,
              assetTag: `${assetTagInput.trim() || editingItem.assetTag}-new`,
              ownerGroup: ownerGroupInput.trim() || 'Unassigned',
              notes: notesInput.trim(),
              active: true,
            });
          }
        }
        if (productsToAdd.length) {
          const imported = await bulkImportWatchlist(productsToAdd);
          if (!imported.success || imported.errors.length) {
            setSaveFeedback({
              type: 'error',
              message: imported.errors.join('; ') || 'Selected catalog products could not be added.',
            });
            return;
          }
        }

        const finalCpes = dedupeCpes([
          ...(removedAutoCpes.has(cpe) ? [] : [cpe]),
          ...additionalCpes.filter((c) => !removedAutoCpes.has(c)),
          ...selectedNvdCpes.filter((c) => !removedAutoCpes.has(c)),
          ...customAddedCpes,
        ]);
        if (finalCpes.length === 0) {
          setSaveFeedback({
            type: 'error',
            message: 'All auto-generated CPEs were removed. Add at least one product or CPE before saving.',
          });
          return;
        }
        const saved = await updateWatchlistItem({
          ...editingItem,
          vendor: parsedCpe.vendor,
          product: parsedCpe.product,
          version: parsedCpe.version,
          cpes: finalCpes,
          purls: purlList.length > 0 ? purlList : undefined,
          targetHw: parsedCpe.targetHw !== '*' ? parsedCpe.targetHw : undefined,
          assetTag: assetTagInput.trim() || editingItem.assetTag,
          ownerGroup: ownerGroupInput.trim() || 'Unassigned',
          notes: notesInput.trim(),
        });
        if (!saved) {
          setSaveFeedback({
            type: 'error',
            message: productsToAdd.length
              ? `Added ${productsToAdd.length} selected product(s), but could not save changes to the current asset.`
              : 'Could not save changes to the current asset.',
          });
          return;
        }
        setSaveFeedback({
          type: 'success',
          message: productsToAdd.length
            ? `Saved the asset and added ${productsToAdd.length} product(s).`
            : selectedProductIds.length
              ? 'Asset changes saved; the selected catalog product(s) were already attached to this asset.'
              : 'Asset changes saved.',
        });
        setShowAddModal(false);
        return;
      }

      // Creating new products (supports multi-products!)
      const productsToCreate: Array<{ name: string; normalizedId: string; part: 'a' | 'o' | 'h' }> = [];

      // Add selected catalog products
      for (const prodId of selectedProductIds) {
        const catProd = catalogProducts.find((p) => p.normalizedId === prodId);
        if (catProd) {
          const generatedCpe = buildStrictCpe23(
            catProd.part,
            vendorInput.trim(),
            catProd.normalizedId,
            versionInput,
            targetHwInput,
          );
          if (!removedAutoCpes.has(generatedCpe)) {
            productsToCreate.push({
              name: catProd.name,
              normalizedId: catProd.normalizedId,
              part: catProd.part,
            });
          }
        } else {
          const generatedCpe = buildStrictCpe23(
            cpePart,
            vendorInput.trim(),
            prodId,
            versionInput,
            targetHwInput,
          );
          if (!removedAutoCpes.has(generatedCpe)) {
            productsToCreate.push({ name: prodId, normalizedId: prodId, part: cpePart });
          }
        }
      }

      // Add custom product if entered
      if (customProductInput.trim()) {
        const generatedCpe = buildStrictCpe23(
          cpePart,
          vendorInput.trim(),
          customProductInput.trim().toLowerCase().replace(/\s+/g, '_'),
          versionInput,
          targetHwInput,
        );
        if (!removedAutoCpes.has(generatedCpe)) {
          productsToCreate.push({
            name: customProductInput.trim(),
            normalizedId: customProductInput.trim().toLowerCase().replace(/\s+/g, '_'),
            part: cpePart,
          });
        }
      }

      // If none selected, fallback to single entry
      if (productsToCreate.length === 0) {
        const fallbackCpe = buildStrictCpe23(
          cpePart,
          vendorInput.trim(),
          'software',
          versionInput,
          targetHwInput,
        );
        if (!removedAutoCpes.has(fallbackCpe)) {
          productsToCreate.push({
            name: 'Standard Asset',
            normalizedId: 'software',
            part: cpePart,
          });
        } else {
          setSaveFeedback({
            type: 'error',
            message: 'All auto-generated CPEs were removed. Add at least one product or CPE before saving.',
          });
          return;
        }
      }

      // Register all products into inventory
      const newItems = productsToCreate.map((p, idx) => {
        const cpe = buildStrictCpe23(p.part, vendorInput.trim(), p.normalizedId, versionInput, targetHwInput);
        const tagSuffix = productsToCreate.length > 1 ? `-${idx + 1}` : '';
        const baseTag =
          assetTagInput.trim() ||
          `${vendorInput.toUpperCase().slice(0, 4)}-${p.normalizedId.toUpperCase().slice(0, 6)}`;
        const isPrimary = idx === 0;

        return {
          vendor: vendorInput.trim(),
          product: p.name,
          cpes: isPrimary ? dedupeCpes([cpe, ...selectedNvdCpes, ...customAddedCpes]) : [cpe],
          purls: purlList.length > 0 ? purlList : undefined,
          targetHw: targetHwInput !== '*' ? targetHwInput : undefined,
          assetTag: `${baseTag}${tagSuffix}`,
          ownerGroup: ownerGroupInput.trim() || 'SecOps-Core',
          notes: notesInput.trim(),
          active: true,
        };
      });
      const result = await bulkImportWatchlist(newItems);
      if (!result.errors.length) setShowAddModal(false);
      else
        setSaveFeedback({
          type: 'error',
          message: `${result.imported} product(s) registered. ${result.errors.join(' ')}`,
        });
    } catch (error) {
      setSaveFeedback({
        type: 'error',
        message: error instanceof Error ? error.message : 'Could not save the product. Please retry.',
      });
    } finally {
      setSavingProduct(false);
    }
  };

  const handleBulkImport = async () => {
    try {
      const parsed = JSON.parse(bulkJsonText);
      const items = Array.isArray(parsed) ? parsed : [parsed];
      const validItems: Array<Omit<WatchListItem, 'id' | 'createdAt'>> = [];
      const errors: string[] = [];

      items.forEach((item: any, i: number) => {
        if (!item.vendor || !item.product) {
          errors.push(`Row ${i + 1}: Missing required vendor or product name.`);
          return;
        }

        const generatedCpe =
          item.cpes && item.cpes.length > 0
            ? item.cpes
            : [generateCPE23('a', item.vendor, item.product, item.version || '*')];

        validItems.push({
          vendor: item.vendor.trim(),
          product: item.product.trim(),
          cpes: generatedCpe,
          purls: item.purls || [],
          targetHw: item.targetHw || '*',
          assetTag: item.assetTag?.trim() || `BULK-${i + 1}-${Date.now().toString(36).toUpperCase()}`,
          ownerGroup: item.ownerGroup?.trim() || 'Imported-Inventory',
          notes: item.notes || 'Bulk imported product asset',
          active: item.active !== false,
        });
      });

      if (validItems.length > 0) {
        const result = await bulkImportWatchlist(validItems);
        if (result.errors.length) {
          setBulkFeedback(result);
          return;
        }
      }

      setBulkFeedback({
        imported: validItems.length,
        errors,
      });

      if (errors.length === 0) {
        setTimeout(() => {
          setShowBulkModal(false);
          setBulkJsonText('');
          setBulkFeedback(null);
        }, 1200);
      }
    } catch {
      setBulkFeedback({
        imported: 0,
        errors: ['Invalid JSON syntax. Ensure data is valid JSON array or object.'],
      });
    }
  };

  const handleExportJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(watchlist, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute(
      'download',
      `monitored-products-${new Date().toISOString().split('T')[0]}.json`,
    );
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  // Run Simulator Engine against the full server-side cache. The snapshot only
  // carries a capped recent slice, so evaluating it locally would silently miss
  // matches on a large installation.
  const runSimulation = async () => {
    const generatedCpe = generateCPE23(
      simPart,
      simVendor,
      simProduct,
      simVersion,
      simHw === 'any' ? '*' : simHw,
    );
    const result = await simulateCorrelation({
      vendor: simVendor,
      product: simProduct,
      version: simVersion,
      cpes: [generatedCpe],
      purls: simPurl ? [simPurl] : undefined,
      targetHw: simHw !== 'any' ? simHw : undefined,
      assetTag: 'SIM-PROD-01',
    });
    if (!result) return; // The context banner reports the request failure.
    const testedAt = new Date(result.testedAt);
    setSimResults({
      testedAt: Number.isNaN(testedAt.getTime()) ? result.testedAt : testedAt.toLocaleTimeString(),
      matchedCves: result.matchedCves,
      totalScanned: result.totalScanned,
      ruleSummary: {
        cpeGenerated: generatedCpe,
        aliasExpanded: result.aliasExpanded,
        intervalEvaluated: result.intervalEvaluated,
        architectureFiltered: simHw !== 'any',
      },
    });
  };

  return (
    <div className="space-y-6">
      {/* Header and View Mode Switcher */}
      <div className="ui-page-header">
        <PageHeading page="watchlist">
          Enterprise products tracked with automated strict CPE 2.3 expressions and supply-chain PURLs. All
          assets are protected with uniform autonomous detection.
        </PageHeading>

        {/* Dual Tab Mode Switcher */}
        <div className="ui-segmented flex items-center space-x-1 bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-200 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 p-1 rounded-xl shadow-sm">
          <button
            onClick={() => setViewMode('inventory')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition flex items-center space-x-1.5 ${
              viewMode === 'inventory'
                ? 'bg-zinc-800 text-zinc-100 dark:bg-zinc-800 dark:text-zinc-100 light:bg-white light:text-zinc-900 shadow-sm font-semibold'
                : 'text-zinc-400 hover:text-zinc-200 dark:text-zinc-400 dark:hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-900'
            }`}
          >
            <Server className="w-3.5 h-3.5" />
            <span>Monitored Products ({watchlist.length})</span>
          </button>
          <button
            onClick={() => {
              setViewMode('simulator');
              if (!simResults) void runSimulation();
            }}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition flex items-center space-x-1.5 ${
              viewMode === 'simulator'
                ? 'bg-zinc-800 text-zinc-100 dark:bg-zinc-800 dark:text-zinc-100 light:bg-white light:text-zinc-900 shadow-sm font-semibold'
                : 'text-zinc-400 hover:text-zinc-200 dark:text-zinc-400 dark:hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-900'
            }`}
          >
            <FlaskConical className="w-3.5 h-3.5 text-zinc-300 dark:text-zinc-300 light:text-zinc-600" />
            <span>Matching simulator</span>
          </button>
        </div>
      </div>

      {/* VIEW 1: Monitored Products Table */}
      {viewMode === 'simulator' && (
        <section className="rounded-xl border border-zinc-700 p-5 space-y-4">
          <h2 className="text-lg font-semibold">Matching Simulator</h2>
          <p className="text-sm text-zinc-400 dark:text-zinc-400 light:text-zinc-600">
            Uses the same correlation engine as the server against the current threat cache, across all dates.
            This preview does not save findings or send notifications.
          </p>
          <form
            className="grid gap-3 md:grid-cols-3"
            onSubmit={(e) => {
              e.preventDefault();
              void runSimulation();
            }}
          >
            <label className="text-sm">
              CPE part
              <select
                className="block w-full border border-zinc-600 rounded p-2 mt-1"
                value={simPart}
                onChange={(e) => setSimPart(e.target.value as 'a' | 'o' | 'h')}
              >
                <option value="a">Application</option>
                <option value="o">Operating system</option>
                <option value="h">Hardware</option>
              </select>
            </label>
            {(
              [
                ['Vendor', simVendor, setSimVendor],
                ['Product', simProduct, setSimProduct],
                ['Installed version', simVersion, setSimVersion],
                ['Architecture', simHw, setSimHw],
                ['Package URL (optional)', simPurl, setSimPurl],
              ] as const
            ).map(([label, value, setter]) => (
              <label key={label} className="text-sm">
                {label}
                <input
                  className="block w-full border border-zinc-600 rounded p-2 mt-1"
                  value={value}
                  onChange={(e) => setter(e.target.value)}
                  required={label !== 'Package URL (optional)'}
                />
              </label>
            ))}
            <button type="submit" className="rounded bg-blue-600 px-4 py-2 self-end">
              Check matches
            </button>
          </form>
          {simResults && (
            <div className="space-y-3" aria-live="polite">
              <p>
                {simResults.matchedCves.length} matches from {simResults.totalScanned} cached vulnerabilities
              </p>
              <code className="block break-all text-xs">{simResults.ruleSummary.cpeGenerated}</code>
              {simResults.matchedCves.length === 0 && (
                <p>No matching vulnerabilities in the current cache.</p>
              )}
              {simResults.matchedCves.map((result) => (
                <article key={result.cve.cveId} className="border border-zinc-700 rounded p-3">
                  <h3 className="font-semibold">
                    <CveLink cveId={result.cve.cveId} /> — {result.cve.title}
                  </h3>
                  <p>
                    {result.autoAction} · {result.method}
                  </p>
                  <p className="text-sm text-zinc-400 dark:text-zinc-400 light:text-zinc-600">
                    {result.evidence}
                  </p>
                </article>
              ))}
            </div>
          )}
        </section>
      )}

      {viewMode === 'inventory' && (
        <div className="space-y-4">
          {/* Action and Search Toolbar */}
          <div className="ui-panel bg-zinc-900/50 dark:bg-zinc-900/50 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl p-4 flex flex-wrap items-center justify-between gap-3 shadow-sm transition-colors">
            {/* Search Input */}
            <div className="relative w-full sm:w-80">
              <Search className="w-4 h-4 text-zinc-400 dark:text-zinc-400 light:text-zinc-600 absolute left-3 top-2.5" />
              <input
                type="text"
                placeholder="Search products by tag, vendor, product, or CPE..."
                value={searchTerm}
                onChange={(e) => {
                  setSearchTerm(e.target.value);
                  setCurrentPage(1);
                }}
                className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl pl-9 pr-3 py-2 text-xs text-zinc-100 dark:text-zinc-100 light:text-zinc-900 dark:placeholder-zinc-500 light:placeholder-zinc-400 focus:outline-none focus:border-zinc-600 transition"
              />
            </div>

            {/* Buttons */}
            <div className="monitored-inventory-actions flex items-center space-x-2">
              <button
                onClick={handleExportJson}
                className="text-xs px-3 py-1.5 rounded-xl bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 hover:bg-zinc-700 dark:hover:bg-zinc-700 light:hover:bg-zinc-300 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 border border-zinc-700 dark:border-zinc-700 light:border-zinc-300 font-medium transition flex items-center space-x-1"
                title="Export Monitored Products to JSON"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Export JSON</span>
              </button>
              <button
                onClick={() => setShowBulkModal(true)}
                className="text-xs px-3 py-1.5 rounded-xl bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 hover:bg-zinc-700 dark:hover:bg-zinc-700 light:hover:bg-zinc-300 text-zinc-200 dark:text-zinc-200 light:text-zinc-800 border border-zinc-700 dark:border-zinc-700 light:border-zinc-300 font-medium transition flex items-center space-x-1"
              >
                <Upload className="w-3.5 h-3.5" />
                <span>Bulk Import</span>
              </button>
              <button
                onClick={handleOpenAdd}
                className="text-xs px-3.5 py-1.5 rounded-xl bg-zinc-100 hover:bg-zinc-200 dark:bg-zinc-100 dark:hover:bg-zinc-200 light:bg-zinc-900 light:hover:bg-zinc-800 text-zinc-900 dark:text-zinc-900 light:text-zinc-50 font-semibold transition flex items-center space-x-1.5 shadow-sm"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Add Product</span>
              </button>
            </div>
          </div>

          {/* Products Table (Uniform Priority - No Exposure Tiering) */}
          <div className="ui-panel bg-zinc-900/50 dark:bg-zinc-900/50 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl overflow-hidden shadow-sm transition-colors">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-zinc-950/80 dark:bg-zinc-950/80 light:bg-zinc-100 border-b border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 text-zinc-400 dark:text-zinc-400 light:text-zinc-600 font-mono uppercase text-[11px]">
                  <tr>
                    <th className="py-3 px-4">Asset Tag / Host</th>
                    <th className="py-3 px-4">Vendor &amp; Product</th>
                    <th className="py-3 px-4">Strict CPE 2.3 Expression</th>
                    <th className="py-3 px-4">Arch / Context</th>
                    <th className="py-3 px-4">Custodian Group</th>
                    <th className="py-3 px-4">Protection Status</th>
                    <th className="py-3 px-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800/60 dark:divide-zinc-800/60 light:divide-zinc-200">
                  {paginatedAssets.length === 0 ? (
                    <tr>
                      <td
                        colSpan={7}
                        className="py-8 text-center text-zinc-500 dark:text-zinc-500 light:text-zinc-600 text-xs"
                      >
                        No matching monitored products found.
                      </td>
                    </tr>
                  ) : (
                    paginatedAssets.map((asset) => (
                      <tr
                        key={asset.id}
                        className="hover:bg-zinc-800/30 dark:hover:bg-zinc-800/30 light:hover:bg-zinc-50 transition"
                      >
                        {/* Asset Tag */}
                        <td className="py-3 px-4 font-mono font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900">
                          <div>{asset.assetTag}</div>
                          {asset.notes && (
                            <div className="text-[11px] text-zinc-400 dark:text-zinc-400 light:text-zinc-600 font-sans font-normal mt-0.5 line-clamp-1">
                              {asset.notes}
                            </div>
                          )}
                        </td>

                        {/* Vendor & Product */}
                        <td className="py-3 px-4">
                          <div className="font-medium text-zinc-200 dark:text-zinc-200 light:text-zinc-800">
                            {asset.vendor} /{' '}
                            <span className="text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-semibold">
                              {asset.product}
                            </span>
                          </div>
                          <div className="text-[10px] text-zinc-500 dark:text-zinc-500 light:text-zinc-600 font-mono mt-0.5">
                            Registered: {fmtDate(asset.createdAt, settings.timezone)}
                          </div>
                        </td>

                        {/* CPE Expressions */}
                        <td className="py-3 px-4 font-mono text-[11px] max-w-sm">
                          <div className="space-y-1">
                            {asset.cpes.slice(0, 2).map((cpe, idx) => (
                              <div
                                key={idx}
                                className="bg-zinc-950/80 dark:bg-zinc-950/80 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 px-2 py-0.5 rounded text-zinc-300 dark:text-zinc-300 light:text-zinc-800 truncate"
                                title={cpe}
                              >
                                {cpe}
                              </div>
                            ))}
                            {asset.purls && asset.purls.length > 0 && (
                              <div
                                className="bg-zinc-950/80 dark:bg-zinc-950/80 light:bg-zinc-100 border border-zinc-700/60 dark:border-zinc-700/60 light:border-zinc-300 px-2 py-0.5 rounded text-zinc-400 dark:text-zinc-400 light:text-zinc-700 truncate"
                                title={asset.purls.join(', ')}
                              >
                                {asset.purls[0]}
                              </div>
                            )}
                          </div>
                        </td>

                        {/* Arch / Context */}
                        <td className="py-3 px-4 font-mono text-[11px] text-zinc-400 dark:text-zinc-400 light:text-zinc-600">
                          <span className="bg-zinc-900 dark:bg-zinc-900 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 px-2 py-0.5 rounded">
                            {asset.targetHw || 'Unknown'}
                          </span>
                        </td>

                        {/* Custodian Group */}
                        <td className="py-3 px-4 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 font-mono text-[11px]">
                          {asset.ownerGroup}
                        </td>

                        {/* Matching status and enable / disable control */}
                        <td className="py-3 px-4">
                          <div className="flex items-center gap-2">
                            <span
                              className={`inline-flex items-center space-x-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-semibold border font-mono ${
                                asset.active
                                  ? 'bg-emerald-950/40 text-emerald-300 border-emerald-800/60'
                                  : 'bg-zinc-900 text-zinc-400 border-zinc-700 light:bg-zinc-100 light:text-zinc-600 light:border-zinc-300'
                              }`}
                            >
                              <span
                                className={`w-1.5 h-1.5 rounded-full ${asset.active ? 'bg-emerald-500' : 'bg-zinc-500'}`}
                              />
                              <span>
                                {asset.active
                                  ? settings.schedulerEnabled
                                    ? 'Matching enabled'
                                    : 'Manual matching'
                                  : 'Matching disabled'}
                              </span>
                            </span>
                            <button
                              type="button"
                              role="switch"
                              aria-checked={asset.active}
                              aria-label={`${asset.active ? 'Disable' : 'Enable'} vulnerability matching for ${asset.assetTag}`}
                              disabled={togglingAssetId === asset.id}
                              onClick={async () => {
                                setTogglingAssetId(asset.id);
                                try {
                                  await toggleWatchlistItemActive(asset.id);
                                } finally {
                                  setTogglingAssetId(null);
                                }
                              }}
                              className={`w-9 h-5 shrink-0 flex items-center rounded-full p-0.5 transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-500 disabled:opacity-60 ${
                                asset.active
                                  ? 'bg-emerald-600 justify-end'
                                  : 'bg-zinc-700 justify-start light:bg-zinc-300'
                              }`}
                              title={
                                asset.active
                                  ? 'Disable matching for this product'
                                  : 'Enable matching for this product'
                              }
                            >
                              <span className="w-4 h-4 rounded-full bg-white shadow-sm" />
                            </button>
                          </div>
                        </td>

                        {/* Actions */}
                        <td className="py-3 px-4 text-right">
                          <div className="flex items-center justify-end space-x-2">
                            <button
                              onClick={() => handleOpenEdit(asset)}
                              className="p-1.5 rounded-lg hover:bg-zinc-800 dark:hover:bg-zinc-800 light:hover:bg-zinc-200 text-zinc-400 hover:text-zinc-200 dark:hover:text-zinc-200 light:hover:text-zinc-900 transition"
                              title="Edit Product"
                            >
                              <Edit2 className="w-3.5 h-3.5" />
                            </button>
                            <button
                              onClick={() => setDeletingAsset(asset)}
                              className="p-1.5 rounded-lg hover:bg-zinc-800 dark:hover:bg-zinc-800 light:hover:bg-zinc-200 text-zinc-400 hover:text-rose-400 transition"
                              title="Delete Product"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>

            {/* Pagination Component */}
            <Pagination
              currentPage={currentPage}
              totalItems={filteredAssets.length}
              pageSize={pageSize}
              onPageChange={setCurrentPage}
              onPageSizeChange={setPageSize}
              pageSizeOptions={[10, 25, 50]}
            />
          </div>
        </div>
      )}

      {/* Register / Edit Product */}
      {showAddModal && (
        <ProductRegistrationDialog
          onClose={() => {
            if (!savingProduct) setShowAddModal(false);
          }}
        >
          <header className="registration-header">
            <span className="registration-header-icon">
              <Server size={23} strokeWidth={1.6} aria-hidden="true" />
            </span>
            <div>
              <p className="registration-eyebrow">Monitored inventory</p>
              <h2 id="product-registration-title">
                {editingItem ? 'Edit monitored product' : 'Register monitored products'}
              </h2>
              <p id="product-registration-description">
                Define ownership, select your products, and review their identifiers before saving.
              </p>
            </div>
            <button
              type="button"
              className="registration-close"
              aria-label="Close product registration"
              disabled={savingProduct}
              onClick={() => setShowAddModal(false)}
            >
              <X size={20} aria-hidden="true" />
            </button>
          </header>
          <form onSubmit={handleSaveProduct} className="registration-form" aria-busy={savingProduct}>
            <div className="registration-body">
              <fieldset
                className="registration-body-grid"
                disabled={savingProduct}
                aria-label="Monitored product details"
              >
                <div className="registration-fields">
                  <section className="registration-section">
                    <div className="registration-section-heading">
                      <span aria-hidden="true">01</span>
                      <div>
                        <h3>Asset details</h3>
                        <p>Required fields identify the system and the team responsible for it.</p>
                      </div>
                    </div>
                    {/* Asset Tag & Custodian Group */}
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                      <div>
                        <label
                          htmlFor="registration-asset-tag"
                          className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-1 font-mono"
                        >
                          Asset Tag / Host Prefix *
                        </label>
                        <input
                          id="registration-asset-tag"
                          type="text"
                          required
                          placeholder="e.g. CORP-APP-01"
                          value={assetTagInput}
                          onChange={(e) => setAssetTagInput(e.target.value)}
                          className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl p-2.5 text-zinc-100 dark:text-zinc-100 light:text-zinc-900 focus:border-zinc-600 focus:outline-none"
                        />
                      </div>
                      <div>
                        <label
                          htmlFor="registration-owner-group"
                          className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-1 font-mono"
                        >
                          Custodian Group *
                        </label>
                        <input
                          id="registration-owner-group"
                          type="text"
                          required
                          placeholder="e.g. SecOps-Core"
                          value={ownerGroupInput}
                          onChange={(e) => setOwnerGroupInput(e.target.value)}
                          className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl p-2.5 text-zinc-100 dark:text-zinc-100 light:text-zinc-900 focus:border-zinc-600 focus:outline-none"
                        />
                      </div>
                    </div>
                  </section>
                  <section className="registration-section">
                    <div className="registration-section-heading">
                      <span aria-hidden="true">02</span>
                      <div>
                        <h3>Vendor & products</h3>
                        <p>Select one or more catalog products, or enter a custom product.</p>
                      </div>
                    </div>
                    {/* Vendor Field with Quick Presets */}
                    <div>
                      <label
                        htmlFor="registration-vendor"
                        className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-1 font-mono"
                      >
                        Vendor Name *
                      </label>
                      <input
                        id="registration-vendor"
                        type="text"
                        required
                        placeholder="Search or enter a vendor, e.g. Microsoft"
                        value={vendorInput}
                        onChange={(e) => selectVendorQuick(e.target.value)}
                        className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl p-2.5 text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-medium focus:border-zinc-600 focus:outline-none"
                      />

                      {/* Popular Vendor Shortcuts */}
                      <div className="registration-vendor-shortcuts flex flex-wrap gap-1.5 mt-2">
                        <span className="text-[10px] text-zinc-500 dark:text-zinc-500 light:text-zinc-600 font-mono mr-1">
                          Popular vendors
                        </span>
                        {[
                          'Microsoft',
                          'Cisco',
                          'Fortinet',
                          'VMware',
                          'Veeam',
                          'Palo Alto Networks',
                          'Apache',
                          'Red Hat',
                          'Oracle',
                          'Google',
                          'F5',
                          'Linux Foundation',
                        ].map((v) => (
                          <button
                            key={v}
                            type="button"
                            onClick={() => selectVendorQuick(v)}
                            className="px-2 py-0.5 rounded-lg text-[10px] font-mono bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 hover:bg-zinc-800 dark:hover:bg-zinc-800 light:hover:bg-zinc-200 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 transition"
                          >
                            {v}
                          </button>
                        ))}
                      </div>
                    </div>
                    {/* Catalog Products for Vendor (MULTI-SELECT SUPPORT) */}
                    {catalogProducts.length > 0 && (
                      <div className="registration-catalog bg-zinc-950/70 dark:bg-zinc-950/70 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl p-3 space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="font-mono text-[11px] text-zinc-300 dark:text-zinc-300 light:text-zinc-800 font-semibold flex items-center gap-1.5">
                            <Package className="w-3.5 h-3.5 text-emerald-400" />
                            {vendorInput} catalog
                          </span>
                          <span className="text-[10px] font-mono text-zinc-500 dark:text-zinc-500 light:text-zinc-600">
                            {selectedProductIds.length} selected
                          </span>
                        </div>

                        <input
                          type="search"
                          className="registration-catalog-query"
                          aria-label="Filter catalog products"
                          placeholder="Find a product in this catalog…"
                          value={catalogQuery}
                          onChange={(event) => setCatalogQuery(event.target.value)}
                        />
                        <div className="registration-catalog-options grid grid-cols-1 sm:grid-cols-2 gap-2 max-h-48 overflow-y-auto pr-1">
                          {catalogProducts
                            .filter((prod) =>
                              `${prod.name} ${prod.normalizedId} ${prod.description}`
                                .toLowerCase()
                                .includes(catalogQuery.toLowerCase().trim()),
                            )
                            .map((prod) => {
                              const isSelected = selectedProductIds.includes(prod.normalizedId);
                              return (
                                <label
                                  key={prod.normalizedId}
                                  className={`registration-product-choice cursor-pointer p-2 rounded-lg border text-xs transition flex items-start space-x-2 select-none ${
                                    isSelected
                                      ? 'bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 border-zinc-600 dark:border-zinc-600 light:border-zinc-400 text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-medium'
                                      : 'bg-zinc-900/60 dark:bg-zinc-900/60 light:bg-white border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 text-zinc-400 dark:text-zinc-400 light:text-zinc-600 hover:border-zinc-700'
                                  }`}
                                >
                                  <input
                                    type="checkbox"
                                    checked={isSelected}
                                    onChange={() => toggleSelectProduct(prod)}
                                    aria-label={prod.name}
                                    className="mt-0.5 rounded border-zinc-700 dark:border-zinc-700 light:border-zinc-400 text-zinc-200 dark:text-zinc-200 light:text-zinc-800"
                                  />
                                  <div className="min-w-0 flex-1">
                                    <div className="flex items-center justify-between">
                                      <span className="truncate font-semibold">{prod.name}</span>
                                      <span className="text-[9px] font-mono uppercase px-1 rounded bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 text-zinc-400 dark:text-zinc-400 light:text-zinc-600">
                                        {prod.part === 'o' ? 'OS' : prod.part === 'h' ? 'HW' : 'APP'}
                                      </span>
                                    </div>
                                    <div className="text-[10px] text-zinc-500 dark:text-zinc-500 light:text-zinc-600 truncate mt-0.5">
                                      {prod.description}
                                    </div>
                                  </div>
                                </label>
                              );
                            })}
                        </div>
                        {catalogQuery &&
                          !catalogProducts.some((prod) =>
                            `${prod.name} ${prod.normalizedId} ${prod.description}`
                              .toLowerCase()
                              .includes(catalogQuery.toLowerCase().trim()),
                          ) && (
                            <p className="registration-helper" role="status">
                              No catalog products match. Try another name or enter a custom product below.
                            </p>
                          )}
                      </div>
                    )}
                    {/* Custom Product Input Field */}
                    <div>
                      <label
                        htmlFor="registration-custom-product"
                        className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-1 font-mono"
                      >
                        Custom product name
                      </label>
                      <input
                        id="registration-custom-product"
                        type="text"
                        placeholder="e.g. pan-os, custom-gateway, http_server"
                        value={customProductInput}
                        onChange={(e) => setCustomProductInput(e.target.value)}
                        className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl p-2.5 text-zinc-100 dark:text-zinc-100 light:text-zinc-900 focus:border-zinc-600 focus:outline-none"
                      />
                      <p className="registration-helper">
                        Optional. Add a product that is not listed in the catalog.
                      </p>
                    </div>
                  </section>
                  <section className="registration-section">
                    <div className="registration-section-heading">
                      <span aria-hidden="true">03</span>
                      <div>
                        <h3>Version & platform</h3>
                        <p>An exact installed version improves applicability matching.</p>
                      </div>
                    </div>
                    {/* CPE Attributes (Part, Version, Target HW) */}
                    <div className="grid grid-cols-3 gap-3">
                      <div>
                        <label
                          htmlFor="registration-part"
                          className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-1 font-mono"
                        >
                          CPE Part
                        </label>
                        <select
                          id="registration-part"
                          value={cpePart}
                          onChange={(e) => setCpePart(e.target.value as any)}
                          className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl p-2.5 text-zinc-100 dark:text-zinc-100 light:text-zinc-900 focus:border-zinc-600 focus:outline-none"
                        >
                          <option value="a">Application (a)</option>
                          <option value="o">Operating System (o)</option>
                          <option value="h">Hardware Device (h)</option>
                        </select>
                      </div>
                      <div>
                        <label
                          htmlFor="registration-version"
                          className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-1 font-mono"
                        >
                          Installed Version
                        </label>
                        <input
                          id="registration-version"
                          type="text"
                          placeholder="* or exact e.g. 10.2.3"
                          value={versionInput}
                          onChange={(e) => setVersionInput(e.target.value)}
                          className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl p-2.5 text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-mono focus:border-zinc-600 focus:outline-none"
                        />
                      </div>
                      <div>
                        <label
                          htmlFor="registration-architecture"
                          className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-1 font-mono"
                        >
                          Target Arch
                        </label>
                        <input
                          id="registration-architecture"
                          type="text"
                          placeholder="* or x86_64, aarch64"
                          value={targetHwInput}
                          onChange={(e) => setTargetHwInput(e.target.value)}
                          className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl p-2.5 text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-mono focus:border-zinc-600 focus:outline-none"
                        />
                      </div>
                    </div>
                    {editingItem && (
                      <div>
                        <label className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-1 font-mono">
                          CPE 2.3 Expression (editable)
                        </label>
                        <input
                          type="text"
                          required
                          aria-label="Editable CPE expression"
                          value={cpeExpressionInput}
                          onChange={(e) => setCpeExpressionInput(e.target.value)}
                          aria-invalid={!parseCPE23(editedCpe()).isValid}
                          className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl p-2.5 text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-mono focus:border-zinc-600 focus:outline-none"
                        />
                        {!parseCPE23(editedCpe()).isValid && (
                          <p className="mt-1 text-rose-400">
                            Enter a valid CPE 2.3 expression before saving.
                          </p>
                        )}
                        <p className="mt-1 text-zinc-500 dark:text-zinc-500 light:text-zinc-600">
                          Change the product fields or expression to update this asset. Select catalog
                          products above to add separate monitored products.
                        </p>
                      </div>
                    )}

                    {editingItem && additionalCpes.length > 0 && (
                      <div className="rounded-xl border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 p-3 space-y-2">
                        <div className="text-[11px] font-mono text-zinc-400 dark:text-zinc-400 light:text-zinc-600">
                          Additional CPEs currently attached to this asset. Remove any that should not be
                          monitored.
                        </div>
                        {additionalCpes.map((cpe, index) => (
                          <div key={`${cpe}-${index}`} className="flex items-center gap-2">
                            <code
                              className="min-w-0 flex-1 truncate text-xs text-zinc-300 dark:text-zinc-300 light:text-zinc-700"
                              title={cpe}
                            >
                              {cpe}
                            </code>
                            <button
                              type="button"
                              onClick={() =>
                                setAdditionalCpes((current) =>
                                  current.filter((_, cpeIndex) => cpeIndex !== index),
                                )
                              }
                              aria-label={`Remove additional CPE ${cpe}`}
                              className="shrink-0 rounded-lg p-1 text-zinc-500 dark:text-zinc-500 light:text-zinc-600 hover:bg-zinc-800 dark:hover:bg-zinc-800 light:hover:bg-zinc-200 hover:text-rose-400 transition"
                            >
                              <X className="h-4 w-4" />
                            </button>
                          </div>
                        ))}
                      </div>
                    )}

                    {editingItem && (
                      <div>
                        <label className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-1 font-mono">
                          Add Another Custom Product
                        </label>
                        <input
                          type="text"
                          placeholder="e.g. internal_gateway"
                          aria-label="Additional custom product"
                          value={additionalProductInput}
                          onChange={(e) => setAdditionalProductInput(e.target.value)}
                          className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl p-2.5 text-zinc-100 dark:text-zinc-100 light:text-zinc-900 focus:border-zinc-600 focus:outline-none"
                        />
                      </div>
                    )}
                    <p className="registration-helper">
                      Use * when a version or architecture is unknown. Version-specific matches may require
                      review.
                    </p>
                  </section>
                  <section className="registration-section">
                    <div className="registration-section-heading">
                      <span aria-hidden="true">04</span>
                      <div>
                        <h3>Find dictionary entries</h3>
                        <p>Look up published CPE identifiers for the selected vendor and product.</p>
                      </div>
                    </div>
                    {/* NVD Verified CPE 2.3 Search */}
                    <div className="registration-nvd space-y-3">
                      <div className="flex items-center justify-between gap-2">
                        <h3 className="registration-subheading">NVD CPE dictionary</h3>
                        <button
                          type="button"
                          onClick={handleNvdSearch}
                          disabled={nvdLoading || !vendorInput.trim()}
                          className="text-[10px] font-mono px-2.5 py-1 rounded-lg bg-sky-900/40 dark:bg-sky-900/40 light:bg-sky-100 border border-sky-800 dark:border-sky-800 light:border-sky-300 text-sky-300 dark:text-sky-300 light:text-sky-700 hover:bg-sky-900/60 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-1"
                        >
                          {nvdLoading ? (
                            <Loader2 className="w-3 h-3 animate-spin" />
                          ) : (
                            <Search className="w-3 h-3" />
                          )}
                          {nvdLoading ? 'Searching...' : 'Search NVD'}
                        </button>
                      </div>

                      {/* NVD Product Search Input */}
                      <div className="relative">
                        <Search className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-500 dark:text-zinc-500 light:text-zinc-600" />
                        <input
                          type="text"
                          placeholder="e.g. backup_and_replication, one, agent"
                          aria-label="Product to find in NVD"
                          value={nvdSearchProduct}
                          onChange={(e) => setNvdSearchProduct(e.target.value)}
                          className="w-full pl-8 bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl p-2 text-[11px] text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-mono focus:border-zinc-600 focus:outline-none"
                        />
                      </div>

                      <p className="text-[10px] text-zinc-500 dark:text-zinc-500 light:text-zinc-600">
                        Search the NIST dictionary for {vendorInput.trim() || 'vendor'}
                        {nvdSearchProductTerm && ` / ${nvdSearchProductTerm}`}. Add matching entries to the
                        product. Requests are subject to NVD rate limits.
                      </p>
                      {nvdError && (
                        <div
                          className="rounded-lg border border-rose-800 bg-rose-950/40 p-2 text-[10px] text-rose-300"
                          role="alert"
                        >
                          {nvdError}
                        </div>
                      )}
                      {nvdResults.length > 0 && (
                        <>
                          {/* Results Filter */}
                          <div className="relative">
                            <Search className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-500 dark:text-zinc-500 light:text-zinc-600" />
                            <input
                              type="text"
                              placeholder="Filter results by CPE, vendor, product, or title..."
                              aria-label="Filter NVD CPE results"
                              value={nvdResultsFilter}
                              onChange={(e) => setNvdResultsFilter(e.target.value)}
                              className="w-full pl-8 bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl p-2 text-[11px] text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-mono focus:border-zinc-600 focus:outline-none"
                            />
                          </div>
                          <div className="registration-nvd-results space-y-1.5 max-h-52 overflow-y-auto pr-1">
                            {filteredNvdResults.map((r) => {
                              const parsed = parseCPE23(r.cpeName);
                              const hasVersionWildcard = parsed.version === '*' || parsed.version === '?';
                              const hasArchWildcard = parsed.targetHw === '*' || parsed.targetHw === '?';
                              return (
                                <div
                                  key={r.cpeNameId || r.cpeName}
                                  className="registration-nvd-result bg-zinc-950/70 dark:bg-zinc-950/70 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-lg p-2 flex items-center justify-between"
                                >
                                  <div className="min-w-0 flex-1">
                                    {r.title && <p className="registration-result-title">{r.title}</p>}
                                    <code
                                      className="block text-[10px] text-zinc-300 dark:text-zinc-300 light:text-zinc-700 font-mono truncate"
                                      title={r.cpeName}
                                    >
                                      {r.cpeName}
                                    </code>
                                    <div className="text-[9px] text-zinc-500 dark:text-zinc-500 light:text-zinc-600 flex items-center gap-2 mt-0.5">
                                      <span className="flex items-center gap-1">
                                        {parsed.isValid ? (
                                          <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                                        ) : (
                                          <AlertCircle className="w-3 h-3 text-rose-400" />
                                        )}
                                        <span>{parsed.isValid ? 'Valid CPE 2.3' : 'Invalid CPE'}</span>
                                      </span>
                                      <span className="text-zinc-600 dark:text-zinc-600 light:text-zinc-700">
                                        ·
                                      </span>
                                      <span className="flex items-center gap-1">
                                        <span className="px-1 py-0.25 rounded bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 text-[8px] font-mono text-zinc-400 dark:text-zinc-400 light:text-zinc-600">
                                          ver:{' '}
                                          {hasVersionWildcard
                                            ? `${parsed.version} (wildcard)`
                                            : parsed.version}
                                        </span>
                                      </span>
                                      <span className="flex items-center gap-1">
                                        {r.vendor} / {r.product} · part {r.part}
                                      </span>
                                      <span className="flex items-center gap-1">
                                        arch{' '}
                                        {hasArchWildcard
                                          ? `${parsed.targetHw || '*'} (wildcard)`
                                          : parsed.targetHw || '*'}
                                      </span>
                                    </div>
                                  </div>
                                  <button
                                    type="button"
                                    onClick={() => addNvdCpe(r.cpeName)}
                                    disabled={!parsed.isValid}
                                    aria-label={`Add NVD CPE ${r.cpeName}`}
                                    className="shrink-0 ml-2 text-[10px] font-mono px-2 py-0.75 rounded bg-emerald-900/40 dark:bg-emerald-900/40 light:bg-emerald-100 border border-emerald-800 dark:border-emerald-800 light:border-emerald-300 text-emerald-300 dark:text-emerald-300 light:text-emerald-700 hover:bg-emerald-900/60"
                                  >
                                    Add
                                  </button>
                                </div>
                              );
                            })}
                          </div>
                          {filteredNvdResults.length === 0 && (
                            <p className="registration-helper" role="status">
                              No dictionary entries match this filter.
                            </p>
                          )}
                        </>
                      )}
                      {selectedNvdCpes.length > 0 && (
                        <div className="space-y-1">
                          <div className="text-[10px] font-mono text-zinc-400 dark:text-zinc-400 light:text-zinc-600">
                            Selected verified CPEs ({selectedNvdCpes.length}):
                          </div>
                          {selectedNvdCpes.map((cpe) => (
                            <div key={cpe} className="flex items-center gap-2">
                              <code
                                className="min-w-0 flex-1 truncate text-xs text-zinc-300 dark:text-zinc-300 light:text-zinc-700"
                                title={cpe}
                              >
                                {cpe}
                              </code>
                              <button
                                type="button"
                                onClick={() => removeNvdCpe(cpe)}
                                aria-label={`Remove verified CPE ${cpe}`}
                                className="shrink-0 rounded-lg p-1 text-zinc-500 dark:text-zinc-500 light:text-zinc-600 hover:bg-zinc-800 dark:hover:bg-zinc-800 light:hover:bg-zinc-200 hover:text-rose-400 transition"
                              >
                                <X className="h-3.5 w-3.5" />
                              </button>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </section>
                  <details className="registration-advanced">
                    <summary>
                      Additional identifiers &amp; notes <span>Optional</span>
                    </summary>
                    <div>
                      {/* Supply Chain PURL (Optional) */}
                      <div>
                        <label
                          htmlFor="registration-purls"
                          className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-1 font-mono"
                        >
                          Package URLs (PURL, Optional - One per line)
                        </label>
                        <textarea
                          id="registration-purls"
                          rows={2}
                          placeholder="e.g. pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
                          value={purlInput}
                          onChange={(e) => setPurlInput(e.target.value)}
                          className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl p-2.5 font-mono text-zinc-100 dark:text-zinc-100 light:text-zinc-900 focus:border-zinc-600 focus:outline-none"
                        />
                      </div>
                      {/* Operational Notes */}
                      <div>
                        <label
                          htmlFor="registration-notes"
                          className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-1 font-mono"
                        >
                          Deployment Notes
                        </label>
                        <input
                          id="registration-notes"
                          type="text"
                          placeholder="e.g. Core production infrastructure; continuous zero-human matching"
                          value={notesInput}
                          onChange={(e) => setNotesInput(e.target.value)}
                          className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl p-2.5 text-zinc-100 dark:text-zinc-100 light:text-zinc-900 focus:border-zinc-600 focus:outline-none"
                        />
                      </div>
                    </div>
                  </details>
                </div>
                <aside className="registration-preview" aria-label="Registration identifier preview">
                  {/* DYNAMIC REAL-TIME STRICT CPE 2.3 EXPRESSIONS PREVIEW BOX */}
                  <div className="registration-cpe-preview bg-zinc-950/90 dark:bg-zinc-950/90 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl p-3.5 space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-[11px] font-mono text-zinc-300 dark:text-zinc-300 light:text-zinc-800 font-bold uppercase tracking-wider flex items-center gap-1.5">
                        <Code className="w-3.5 h-3.5 text-sky-400" />
                        CPE preview
                      </span>
                      <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/50 px-2 py-0.5 rounded border border-emerald-800/60">
                        {generatedCpes.length} entries
                      </span>
                    </div>

                    <div className="registration-cpe-list space-y-1.5 max-h-36 overflow-y-auto">
                      {generatedCpes.map((item, idx) => (
                        <div
                          key={item.cpe}
                          className="bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-lg p-2 font-mono text-xs flex items-center justify-between text-zinc-200 dark:text-zinc-200 light:text-zinc-800 shadow-sm"
                        >
                          <div className="truncate mr-2">
                            <span className="text-[10px] text-zinc-500 dark:text-zinc-500 light:text-zinc-600 mr-1.5">
                              [{item.product}]
                            </span>
                            <span className="text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-semibold">
                              {item.cpe}
                            </span>
                          </div>
                          <div className="flex items-center gap-1 shrink-0">
                            <button
                              type="button"
                              onClick={() => {
                                if (item.product === 'Custom') {
                                  setCustomAddedCpes((c) => c.filter((c2) => c2 !== item.cpe));
                                } else {
                                  setRemovedAutoCpes((s) => {
                                    const next = new Set(s);
                                    next.add(item.cpe);
                                    return next;
                                  });
                                }
                              }}
                              aria-label={`Remove CPE ${item.cpe}`}
                              className="rounded-lg p-0.75 text-zinc-500 dark:text-zinc-500 light:text-zinc-600 hover:bg-zinc-800 dark:hover:bg-zinc-800 light:hover:bg-zinc-200 hover:text-rose-400 transition"
                              title={
                                item.product === 'Custom' ? 'Remove custom CPE' : 'Remove auto-generated CPE'
                              }
                            >
                              <X className="h-3.5 w-3.5" />
                            </button>
                            <span className="text-[9px] font-mono uppercase bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 text-zinc-400 px-1.5 py-0.2 rounded shrink-0">
                              {item.part}
                            </span>
                          </div>
                        </div>
                      ))}
                    </div>
                    {!generatedCpes.length && (
                      <div className="registration-preview-empty">
                        <Code size={24} aria-hidden="true" />
                        <p>Select a product to preview its CPE identifiers.</p>
                      </div>
                    )}
                    <p className="registration-helper">
                      Review these identifiers before saving. Dictionary entries are attached to the first
                      product when registering several products.
                    </p>
                  </div>
                  <label htmlFor="registration-manual-cpe">Add a CPE expression</label>
                  {/* Custom CPE 2.3 Expression Input */}
                  <div className="registration-manual-cpe flex gap-2">
                    <input
                      type="text"
                      placeholder="e.g. cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"
                      id="registration-manual-cpe"
                      value={customCpeInput}
                      onChange={(e) => setCustomCpeInput(e.target.value)}
                      className="flex-1 bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl p-2.5 text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-mono text-xs focus:border-zinc-600 focus:outline-none"
                    />
                    <button
                      type="button"
                      onClick={() => {
                        const trimmed = customCpeInput.trim();
                        if (trimmed && parseCPE23(trimmed).isValid && !customAddedCpes.includes(trimmed)) {
                          setCustomAddedCpes((c) => [...c, trimmed]);
                          setCustomCpeInput('');
                        }
                      }}
                      disabled={!customCpeInput.trim() || !parseCPE23(customCpeInput.trim()).isValid}
                      className="shrink-0 px-3 py-1.5 rounded-xl bg-sky-900/40 dark:bg-sky-900/40 light:bg-sky-100 border border-sky-800 dark:border-sky-800 light:border-sky-300 text-sky-300 dark:text-sky-300 light:text-sky-700 font-mono text-xs hover:bg-sky-900/60 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-1"
                    >
                      <Plus className="w-3 h-3" />
                      Add
                    </button>
                  </div>
                </aside>
              </fieldset>
            </div>
            <footer className="registration-footer">
              <div className="registration-footer-summary">
                <strong>{editingItem ? 'Review your changes' : 'Ready to register'}</strong>
                <span>
                  {generatedCpes.length} CPE {generatedCpes.length === 1 ? 'identifier' : 'identifiers'} in
                  the preview · Required fields marked *
                </span>
              </div>
              {/* Buttons */}
              {saveFeedback && (
                <div
                  role={saveFeedback.type === 'error' ? 'alert' : 'status'}
                  className={`rounded-lg border px-3 py-2 text-sm ${
                    saveFeedback.type === 'error'
                      ? 'border-rose-800 bg-rose-950/40 text-rose-300'
                      : 'border-emerald-800 bg-emerald-950/40 text-emerald-300'
                  }`}
                >
                  {saveFeedback.message}
                </div>
              )}
              <div className="registration-footer-actions">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  disabled={savingProduct}
                  className="px-3.5 py-1.5 rounded-xl bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 hover:bg-zinc-700 text-zinc-300 dark:text-zinc-300 light:text-zinc-800 transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={
                    savingProduct ||
                    !vendorInput.trim() ||
                    (Boolean(editingItem) && !parseCPE23(editedCpe()).isValid)
                  }
                  className="px-4 py-1.5 rounded-xl bg-zinc-100 hover:bg-zinc-200 dark:bg-zinc-100 dark:hover:bg-zinc-200 light:bg-zinc-900 light:hover:bg-zinc-800 text-zinc-900 dark:text-zinc-900 light:text-zinc-50 font-semibold transition disabled:opacity-50 shadow-sm"
                >
                  {savingProduct ? (
                    <>
                      <Loader2 size={15} className="animate-spin" aria-hidden="true" /> Saving…
                    </>
                  ) : editingItem ? (
                    selectedProductIds.length > 0 || additionalProductInput.trim() ? (
                      `Save Changes + Add ${selectedProductIds.length + (additionalProductInput.trim() ? 1 : 0)} Product(s)`
                    ) : (
                      'Save Changes'
                    )
                  ) : selectedProductIds.length > 1 ? (
                    `Register ${selectedProductIds.length} products`
                  ) : (
                    'Register Product'
                  )}
                </button>
              </div>
            </footer>
          </form>
        </ProductRegistrationDialog>
      )}

      {/* Bulk JSON Import Modal */}
      {showBulkModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="ui-panel bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-2xl w-full p-6 shadow-2xl relative">
            <button
              onClick={() => {
                setShowBulkModal(false);
                setBulkFeedback(null);
              }}
              className="absolute top-4 right-4 text-zinc-400 hover:text-zinc-200 dark:text-zinc-400 dark:hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-800"
            >
              <X className="w-5 h-5" />
            </button>

            <h2 className="text-base font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 mb-1 flex items-center gap-2">
              <Upload className="w-4 h-4 text-zinc-300 dark:text-zinc-300 light:text-zinc-700" />
              Bulk Product Asset Import (JSON)
            </h2>
            <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-4">
              Import up to 1,000 product records. Provide vendor, product, assetTag, and optional CPE 2.3
              expressions.
            </p>

            {bulkFeedback && (
              <div
                className={`p-3 rounded-xl text-xs mb-3 flex items-center gap-2 ${
                  bulkFeedback.errors.length === 0
                    ? 'bg-zinc-950 border border-emerald-800 text-emerald-300'
                    : 'bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-700 dark:border-zinc-700 light:border-zinc-300 text-zinc-300 dark:text-zinc-300 light:text-zinc-700'
                }`}
              >
                {bulkFeedback.errors.length === 0 ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                ) : (
                  <AlertCircle className="w-4 h-4 text-zinc-400 dark:text-zinc-400 light:text-zinc-600 shrink-0" />
                )}
                <span>
                  Successfully imported {bulkFeedback.imported} monitored products.
                  {bulkFeedback.errors.length > 0 && ` (${bulkFeedback.errors.join('; ')})`}
                </span>
              </div>
            )}

            <textarea
              rows={8}
              value={bulkJsonText}
              onChange={(e) => setBulkJsonText(e.target.value)}
              placeholder={`[\n  {\n    "vendor": "microsoft",\n    "product": "windows_server_2022",\n    "assetTag": "DC-PDC01",\n    "ownerGroup": "SecOps-Core"\n  }\n]`}
              className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl p-3 font-mono text-xs text-zinc-100 dark:text-zinc-100 light:text-zinc-900 focus:border-zinc-600 focus:outline-none leading-relaxed"
            />

            <div className="flex justify-end space-x-2 mt-4 pt-3 border-t border-zinc-800 dark:border-zinc-800 light:border-zinc-200 text-xs">
              <button
                onClick={() => {
                  setShowBulkModal(false);
                  setBulkFeedback(null);
                }}
                className="px-3 py-1.5 rounded-xl bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 hover:bg-zinc-700 text-zinc-300 dark:text-zinc-300 light:text-zinc-800"
              >
                Cancel
              </button>
              <button
                onClick={handleBulkImport}
                disabled={!bulkJsonText.trim()}
                className="px-4 py-1.5 rounded-xl bg-zinc-100 hover:bg-zinc-200 dark:bg-zinc-100 dark:hover:bg-zinc-200 light:bg-zinc-900 light:hover:bg-zinc-800 text-zinc-900 dark:text-zinc-900 light:text-zinc-50 font-semibold disabled:opacity-50"
              >
                Import Products
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Delete Product Confirmation Modal */}
      {deletingAsset && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="ui-panel bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-sm w-full p-6 shadow-2xl relative">
            <h3 className="text-sm font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 mb-2">
              Remove Monitored Product?
            </h3>
            <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 leading-relaxed mb-6">
              Are you sure you want to remove <strong>{deletingAsset.assetTag}</strong> (
              {deletingAsset.vendor} {deletingAsset.product})? Autonomous correlation and alerting for this
              product will cease immediately.
            </p>
            <div className="flex justify-end space-x-2">
              <button
                type="button"
                onClick={() => setDeletingAsset(null)}
                className="px-3 py-1.5 rounded-xl bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-100 hover:bg-zinc-700 dark:hover:bg-zinc-700 light:hover:bg-zinc-200 text-zinc-300 dark:text-zinc-300 light:text-zinc-700 text-xs font-medium"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={async () => {
                  const result = await deleteWatchlistItem(deletingAsset.id);
                  if (result) {
                    setDeleteFeedback({
                      type: 'success',
                      message: `Removed ${deletingAsset.vendor} ${deletingAsset.product} (${deletingAsset.assetTag}) from monitored inventory.`,
                    });
                    setTimeout(() => setDeleteFeedback(null), 5000);
                  } else {
                    setDeleteFeedback({
                      type: 'error',
                      message: 'Failed to remove product from inventory. Please try again.',
                    });
                  }
                  setDeletingAsset(null);
                }}
                className="px-3 py-1.5 rounded-xl bg-red-600 hover:bg-red-500 text-white text-xs font-semibold"
              >
                Remove Product
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
