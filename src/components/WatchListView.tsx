import React, { useState, useMemo } from 'react';
import { useApp } from '../context/AppContext';
import { WatchListItem, NormalizedCVE } from '../types';
import {
  generateCPE23,
  parseCPE23,
  matchesWatchlistItem,
  matchVendorWithAliases,
  matchProductWithAliases,
} from '../utils/cpeMatcher';
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
  ExternalLink,
  Zap,
  ArrowRight,
  Shield,
  Layers,
  Sparkles,
  Check,
  Package,
  Cpu,
} from 'lucide-react';
import { runVulnerabilityPipeline } from '../engine/pipelineEngine';
import { Pagination } from './Pagination';
import { editedWatchlistCpe } from '../utils/watchlist';

export const WatchListView: React.FC = () => {
  const {
    watchlist,
    addWatchlistItem,
    updateWatchlistItem,
    deleteWatchlistItem,
    bulkImportWatchlist,
    cveData,
    settings,
  } = useApp();

  // Primary view mode: Inventory vs Simulator Lab
  const [viewMode, setViewMode] = useState<'inventory' | 'simulator'>('inventory');

  const [searchTerm, setSearchTerm] = useState('');
  const [showAddModal, setShowAddModal] = useState(false);
  const [showBulkModal, setShowBulkModal] = useState(false);
  const [editingItem, setEditingItem] = useState<WatchListItem | null>(null);
  const [deletingAsset, setDeletingAsset] = useState<WatchListItem | null>(null);

  // Pagination for inventory table
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);

  // Form State
  const [vendorInput, setVendorInput] = useState('');
  const [customProductInput, setCustomProductInput] = useState('');
  const [selectedProductIds, setSelectedProductIds] = useState<string[]>([]);
  const [cpePart, setCpePart] = useState<'a' | 'o' | 'h'>('a');
  const [versionInput, setVersionInput] = useState('*');
  const [targetHwInput, setTargetHwInput] = useState('*');
  const [assetTagInput, setAssetTagInput] = useState('');
  const [ownerGroupInput, setOwnerGroupInput] = useState('SecOps-Core');
  const [notesInput, setNotesInput] = useState('');
  const [purlInput, setPurlInput] = useState('');
  const [cpeExpressionInput, setCpeExpressionInput] = useState('');

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

  const editedCpe = () => editingItem ? editedWatchlistCpe(editingItem, {
    cpeExpression: cpeExpressionInput,
    vendor: vendorInput,
    product: customProductInput,
    part: cpePart,
    version: versionInput,
    targetHw: targetHwInput,
  }) : cpeExpressionInput.trim();

  // Dynamically generated Strict CPE 2.3 expressions
  const generatedCpes = useMemo(() => {
    if (editingItem) {
      const cpe = editedCpe();
      return cpe
        ? [{ product: 'Edited CPE', cpe, part: cpePart }]
        : [];
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
      const cpe = buildStrictCpe23(cpePart, v, 'product', versionInput, targetHwInput);
      list.push({ product: 'product', cpe, part: cpePart });
    }

    return list;
  }, [
    vendorInput,
    selectedProductIds,
    customProductInput,
    cpePart,
    versionInput,
    targetHwInput,
    catalogProducts,
    editingItem,
    cpeExpressionInput,
    vendorInput,
    customProductInput,
    versionInput,
    targetHwInput,
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
    setVendorInput('');
    setCustomProductInput('');
    setSelectedProductIds([]);
    setCpePart('a');
    setVersionInput('*');
    setTargetHwInput('*');
    setAssetTagInput('');
    setOwnerGroupInput('SecOps-Core');
    setNotesInput('');
    setPurlInput('');
    setCpeExpressionInput('');
    setEditingItem(null);
    setShowAddModal(true);
  };

  const handleOpenEdit = (item: WatchListItem) => {
    const parsed = parseCPE23(item.cpes[0] || '');
    setVendorInput(parsed.isValid ? parsed.vendor : item.vendor);
    setCustomProductInput(parsed.isValid ? parsed.product : item.product);
    setSelectedProductIds([]);
    setCpePart((parsed.part === 'o' || parsed.part === 'h' ? parsed.part : 'a') as 'a' | 'o' | 'h');
    setVersionInput(parsed.version || '*');
    setTargetHwInput(parsed.isValid ? parsed.targetHw : item.targetHw || '*');
    setAssetTagInput(item.assetTag);
    setOwnerGroupInput(item.ownerGroup);
    setNotesInput(item.notes || '');
    setPurlInput((item.purls || []).join('\n'));
    setCpeExpressionInput(item.cpes[0] || '');
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
    setVendorInput(vendorName);
    setSelectedProductIds([]);
  };

  const handleSaveProduct = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!vendorInput.trim()) return;

    const purlList = purlInput
      .split('\n')
      .map((s) => s.trim())
      .filter(Boolean);

    // If editing existing single item
    if (editingItem) {
      const cpe = editedCpe();
      const parsedCpe = parseCPE23(cpe);
      if (!parsedCpe.isValid) return;
      const saved = await updateWatchlistItem({
        ...editingItem,
        vendor: parsedCpe.vendor,
        product: parsedCpe.product,
        version: parsedCpe.version,
        cpes: editingItem.cpes.length ? [cpe, ...editingItem.cpes.slice(1)] : [cpe],
        purls: purlList.length > 0 ? purlList : undefined,
        targetHw: parsedCpe.targetHw !== '*' ? parsedCpe.targetHw : undefined,
        assetTag: assetTagInput.trim() || editingItem.assetTag,
        ownerGroup: ownerGroupInput.trim() || 'Unassigned',
        notes: notesInput.trim(),
      });
      if (saved) setShowAddModal(false);
      return;
    }

    // Creating new products (supports multi-products!)
    const productsToCreate: Array<{ name: string; normalizedId: string; part: 'a' | 'o' | 'h' }> = [];

    // Add selected catalog products
    for (const prodId of selectedProductIds) {
      const catProd = catalogProducts.find((p) => p.normalizedId === prodId);
      if (catProd) {
        productsToCreate.push({ name: catProd.name, normalizedId: catProd.normalizedId, part: catProd.part });
      } else {
        productsToCreate.push({ name: prodId, normalizedId: prodId, part: cpePart });
      }
    }

    // Add custom product if entered
    if (customProductInput.trim()) {
      productsToCreate.push({
        name: customProductInput.trim(),
        normalizedId: customProductInput.trim().toLowerCase().replace(/\s+/g, '_'),
        part: cpePart,
      });
    }

    // If none selected, fallback to single entry
    if (productsToCreate.length === 0) {
      productsToCreate.push({
        name: 'Standard Asset',
        normalizedId: 'software',
        part: cpePart,
      });
    }

    // Register all products into inventory
    const newItems = productsToCreate.map((p, idx) => {
      const cpe = buildStrictCpe23(p.part, vendorInput.trim(), p.normalizedId, versionInput, targetHwInput);
      const tagSuffix = productsToCreate.length > 1 ? `-${idx + 1}` : '';
      const baseTag =
        assetTagInput.trim() ||
        `${vendorInput.toUpperCase().slice(0, 4)}-${p.normalizedId.toUpperCase().slice(0, 6)}`;

      return {
        vendor: vendorInput.trim(),
        product: p.name,
        cpes: [cpe],
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

  // Run Simulator Engine
  const runSimulation = () => {
    const generatedCpe = generateCPE23(
      simPart,
      simVendor,
      simProduct,
      simVersion,
      simHw === 'any' ? '*' : simHw,
    );
    const simulatedWatchItem: WatchListItem = {
      id: 'sim-test-01',
      vendor: simVendor,
      product: simProduct,
      version: simVersion,
      cpes: [generatedCpe],
      purls: simPurl ? [simPurl] : undefined,
      targetHw: simHw !== 'any' ? simHw : undefined,
      assetTag: 'SIM-PROD-01',
      ownerGroup: 'Simulation-Lab',
      active: true,
      createdAt: new Date().toISOString(),
    };

    const correlation = runVulnerabilityPipeline([], cveData, [simulatedWatchItem], [], [], {
      ...settings,
      scopeHours: 0,
    });
    const matchedCves = correlation.newFindings.map((finding) => ({
      cve: finding.cve,
      method: finding.matchingMethod,
      confidence: finding.notificationStatus === 'REVIEW_REQUIRED' ? 0 : 100,
      evidence: finding.matchingEvidence,
      autoAction: finding.notificationStatus === 'REVIEW_REQUIRED' ? 'REVIEW_REQUIRED' : 'MATCH_CONFIRMED',
      suppressed: false,
      suppressionReason: '',
    }));

    setSimResults({
      testedAt: new Date().toLocaleTimeString(),
      matchedCves,
      totalScanned: cveData.length,
      ruleSummary: {
        cpeGenerated: generatedCpe,
        aliasExpanded: false,
        intervalEvaluated: true,
        architectureFiltered: simHw !== 'any',
      },
    });
  };

  return (
    <div className="space-y-6">
      {/* Header and View Mode Switcher */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 tracking-tight flex items-center gap-2">
            <Server className="w-5 h-5 text-zinc-300 dark:text-zinc-300 light:text-zinc-700" />
            Monitored Product Inventory &amp; Matching Engine
          </h1>
          <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mt-1">
            Enterprise products tracked with automated strict CPE 2.3 expressions and supply-chain PURLs. All
            assets are protected with uniform autonomous detection.
          </p>
        </div>

        {/* Dual Tab Mode Switcher */}
        <div className="flex items-center space-x-1 bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-200 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 p-1 rounded-xl shadow-sm">
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
              if (!simResults) runSimulation();
            }}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition flex items-center space-x-1.5 ${
              viewMode === 'simulator'
                ? 'bg-zinc-800 text-zinc-100 dark:bg-zinc-800 dark:text-zinc-100 light:bg-white light:text-zinc-900 shadow-sm font-semibold'
                : 'text-zinc-400 hover:text-zinc-200 dark:text-zinc-400 dark:hover:text-zinc-200 light:text-zinc-600 light:hover:text-zinc-900'
            }`}
          >
            <FlaskConical className="w-3.5 h-3.5 text-zinc-300" />
            <span>Matching Simulator &amp; Rule Lab</span>
          </button>
        </div>
      </div>

      {/* VIEW 1: Monitored Products Table */}
      {viewMode === 'simulator' && (
        <section className="rounded-xl border border-zinc-700 p-5 space-y-4">
          <h2 className="text-lg font-semibold">Matching Simulator</h2>
          <p className="text-sm text-zinc-400">
            Uses the same correlation engine as the server against the current threat cache, across all dates.
            This preview does not save findings or send notifications.
          </p>
          <form
            className="grid gap-3 md:grid-cols-3"
            onSubmit={(e) => {
              e.preventDefault();
              runSimulation();
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
                    {result.cve.cveId} — {result.cve.title}
                  </h3>
                  <p>
                    {result.autoAction} · {result.method}
                  </p>
                  <p className="text-sm text-zinc-400">{result.evidence}</p>
                </article>
              ))}
            </div>
          )}
        </section>
      )}

      {viewMode === 'inventory' && (
        <div className="space-y-4">
          {/* Action and Search Toolbar */}
          <div className="bg-zinc-900/50 dark:bg-zinc-900/50 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl p-4 flex flex-wrap items-center justify-between gap-3 shadow-sm transition-colors">
            {/* Search Input */}
            <div className="relative w-full sm:w-80">
              <Search className="w-4 h-4 text-zinc-500 absolute left-3 top-2.5" />
              <input
                type="text"
                placeholder="Search products by tag, vendor, product, or CPE..."
                value={searchTerm}
                onChange={(e) => {
                  setSearchTerm(e.target.value);
                  setCurrentPage(1);
                }}
                className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl pl-9 pr-3 py-1.5 text-xs text-zinc-100 dark:text-zinc-100 light:text-zinc-900 placeholder-zinc-500 focus:outline-none focus:border-zinc-600 transition"
              />
            </div>

            {/* Buttons */}
            <div className="flex items-center space-x-2">
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
          <div className="bg-zinc-900/50 dark:bg-zinc-900/50 light:bg-white border border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 rounded-2xl overflow-hidden shadow-sm transition-colors">
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
                      <td colSpan={7} className="py-8 text-center text-zinc-500 text-xs">
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
                          <div className="text-[10px] text-zinc-500 font-mono mt-0.5">
                            Registered: {new Date(asset.createdAt).toLocaleDateString()}
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

                        {/* Protection Status (Uniform for all products) */}
                        <td className="py-3 px-4">
                          <span className="inline-flex items-center space-x-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-950/40 text-emerald-300 border border-emerald-800/60 font-mono">
                            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                            <span>
                              {asset.active
                                ? settings.schedulerEnabled
                                  ? 'Scheduled matching'
                                  : 'Manual matching'
                                : 'Inactive'}
                            </span>
                          </span>
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

      {/* Register / Edit Product Modal with Auto-Suggest and Multi-Products Support */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4 overflow-y-auto">
          <div className="bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-2xl w-full p-6 shadow-2xl relative my-8 max-h-[90vh] overflow-y-auto">
            <button
              onClick={() => setShowAddModal(false)}
              className="absolute top-4 right-4 text-zinc-500 hover:text-zinc-200 dark:hover:text-zinc-200 light:hover:text-zinc-900"
            >
              <X className="w-5 h-5" />
            </button>

            <h2 className="text-base font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 mb-1 flex items-center gap-2">
              <Server className="w-4 h-4 text-zinc-300 dark:text-zinc-300 light:text-zinc-700" />
              {editingItem ? 'Edit Monitored Product' : 'Register Monitored Products'}
            </h2>
            <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-4">
              Enter a vendor to automatically view its catalog products. Select multiple products or enter
              custom ones — Strict CPE 2.3 expressions generate live automatically.
            </p>

            <form onSubmit={handleSaveProduct} className="space-y-4 text-xs">
              {/* Asset Tag & Custodian Group */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-1 font-mono">
                    Asset Tag / Host Prefix *
                  </label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. CORP-APP-01"
                    value={assetTagInput}
                    onChange={(e) => setAssetTagInput(e.target.value)}
                    className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl p-2.5 text-zinc-100 dark:text-zinc-100 light:text-zinc-900 focus:border-zinc-600 focus:outline-none"
                  />
                </div>
                <div>
                  <label className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-1 font-mono">
                    Custodian Group *
                  </label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. SecOps-Core"
                    value={ownerGroupInput}
                    onChange={(e) => setOwnerGroupInput(e.target.value)}
                    className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl p-2.5 text-zinc-100 dark:text-zinc-100 light:text-zinc-900 focus:border-zinc-600 focus:outline-none"
                  />
                </div>
              </div>

              {/* Vendor Field with Quick Presets */}
              <div>
                <label className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-1 font-mono">
                  Vendor Name *
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Microsoft, Cisco, Fortinet, VMware, Palo Alto, Apache, Red Hat..."
                  value={vendorInput}
                  onChange={(e) => setVendorInput(e.target.value)}
                  className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl p-2.5 text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-medium focus:border-zinc-600 focus:outline-none"
                />

                {/* Popular Vendor Shortcuts */}
                <div className="flex flex-wrap gap-1.5 mt-2">
                  <span className="text-[10px] text-zinc-500 font-mono self-center mr-1">Quick Select:</span>
                  {[
                    'Microsoft',
                    'Cisco',
                    'Fortinet',
                    'VMware',
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
                <div className="bg-zinc-950/70 dark:bg-zinc-950/70 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl p-3 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-[11px] text-zinc-300 dark:text-zinc-300 light:text-zinc-800 font-semibold flex items-center gap-1.5">
                      <Package className="w-3.5 h-3.5 text-emerald-400" />
                      Select Catalog Products from {vendorInput} (Multi-Product Selection Supported):
                    </span>
                    <span className="text-[10px] font-mono text-zinc-500">
                      {selectedProductIds.length} Selected
                    </span>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 max-h-48 overflow-y-auto pr-1">
                    {catalogProducts.map((prod) => {
                      const isSelected = selectedProductIds.includes(prod.normalizedId);
                      return (
                        <div
                          key={prod.normalizedId}
                          onClick={() => toggleSelectProduct(prod)}
                          className={`cursor-pointer p-2 rounded-lg border text-xs transition flex items-start space-x-2 select-none ${
                            isSelected
                              ? 'bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 border-zinc-600 dark:border-zinc-600 light:border-zinc-400 text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-medium'
                              : 'bg-zinc-900/60 dark:bg-zinc-900/60 light:bg-white border-zinc-800/80 dark:border-zinc-800/80 light:border-zinc-200 text-zinc-400 dark:text-zinc-400 light:text-zinc-600 hover:border-zinc-700'
                          }`}
                        >
                          <input
                            type="checkbox"
                            checked={isSelected}
                            onChange={() => {}}
                            className="mt-0.5 rounded border-zinc-700 text-zinc-200 pointer-events-none"
                          />
                          <div className="min-w-0 flex-1">
                            <div className="flex items-center justify-between">
                              <span className="truncate font-semibold">{prod.name}</span>
                              <span className="text-[9px] font-mono uppercase px-1 rounded bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 text-zinc-400">
                                {prod.part === 'o' ? 'OS' : prod.part === 'h' ? 'HW' : 'APP'}
                              </span>
                            </div>
                            <div className="text-[10px] text-zinc-500 light:text-zinc-600 truncate mt-0.5">
                              {prod.description}
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Custom Product Input Field */}
              <div>
                <label className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-1 font-mono">
                  Custom Product Name (or add in-house software)
                </label>
                <input
                  type="text"
                  placeholder="e.g. pan-os, custom-gateway, http_server"
                  value={customProductInput}
                  onChange={(e) => setCustomProductInput(e.target.value)}
                  className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl p-2.5 text-zinc-100 dark:text-zinc-100 light:text-zinc-900 focus:border-zinc-600 focus:outline-none"
                />
              </div>

              {editingItem && (
                <div>
                  <label className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-1 font-mono">
                    CPE 2.3 Expression (editable)
                  </label>
                  <input
                    type="text"
                    required
                    value={cpeExpressionInput}
                    onChange={(e) => setCpeExpressionInput(e.target.value)}
                    aria-invalid={!parseCPE23(cpeExpressionInput.trim()).isValid}
                    className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl p-2.5 text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-mono focus:border-zinc-600 focus:outline-none"
                  />
                  {!parseCPE23(cpeExpressionInput.trim()).isValid && (
                    <p className="mt-1 text-rose-400">Enter a valid CPE 2.3 expression before saving.</p>
                  )}
                  <p className="mt-1 text-zinc-500">
                    This expression is used for matching; its vendor, product, version, and target hardware are saved with the asset.
                  </p>
                </div>
              )}

              {/* CPE Attributes (Part, Version, Target HW) */}
              <div className="grid grid-cols-3 gap-3">
                <div>
                  <label className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-1 font-mono">
                    CPE Part
                  </label>
                  <select
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
                  <label className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-1 font-mono">
                    Installed Version
                  </label>
                  <input
                    type="text"
                    placeholder="* or exact e.g. 10.2.3"
                    value={versionInput}
                    onChange={(e) => setVersionInput(e.target.value)}
                    className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl p-2.5 text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-mono focus:border-zinc-600 focus:outline-none"
                  />
                </div>
                <div>
                  <label className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-1 font-mono">
                    Target Arch
                  </label>
                  <input
                    type="text"
                    placeholder="* or x86_64, aarch64"
                    value={targetHwInput}
                    onChange={(e) => setTargetHwInput(e.target.value)}
                    className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl p-2.5 text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-mono focus:border-zinc-600 focus:outline-none"
                  />
                </div>
              </div>

              {/* DYNAMIC REAL-TIME STRICT CPE 2.3 EXPRESSIONS PREVIEW BOX */}
              <div className="bg-zinc-950/90 dark:bg-zinc-950/90 light:bg-zinc-100 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl p-3.5 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-mono text-zinc-300 dark:text-zinc-300 light:text-zinc-800 font-bold uppercase tracking-wider flex items-center gap-1.5">
                    <Code className="w-3.5 h-3.5 text-sky-400" />
                    Auto-Generated Strict CPE 2.3 Expressions (Updates Live):
                  </span>
                  <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/50 px-2 py-0.5 rounded border border-emerald-800/60">
                    Live Auto-Synthesized
                  </span>
                </div>

                <div className="space-y-1.5 max-h-36 overflow-y-auto">
                  {generatedCpes.map((item, idx) => (
                    <div
                      key={idx}
                      className="bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-lg p-2 font-mono text-xs flex items-center justify-between text-zinc-200 dark:text-zinc-200 light:text-zinc-800 shadow-sm"
                    >
                      <div className="truncate mr-2">
                        <span className="text-[10px] text-zinc-500 mr-1.5">[{item.product}]</span>
                        <span className="text-zinc-100 dark:text-zinc-100 light:text-zinc-900 font-semibold">
                          {item.cpe}
                        </span>
                      </div>
                      <span className="text-[9px] font-mono uppercase bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 text-zinc-400 px-1.5 py-0.2 rounded shrink-0">
                        {item.part}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Supply Chain PURL (Optional) */}
              <div>
                <label className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-1 font-mono">
                  Package URLs (PURL, Optional - One per line)
                </label>
                <textarea
                  rows={2}
                  placeholder="e.g. pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
                  value={purlInput}
                  onChange={(e) => setPurlInput(e.target.value)}
                  className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl p-2.5 font-mono text-zinc-100 dark:text-zinc-100 light:text-zinc-900 focus:border-zinc-600 focus:outline-none"
                />
              </div>

              {/* Operational Notes */}
              <div>
                <label className="block text-zinc-400 dark:text-zinc-400 light:text-zinc-600 mb-1 font-mono">
                  Deployment Notes
                </label>
                <input
                  type="text"
                  placeholder="e.g. Core production infrastructure; continuous zero-human matching"
                  value={notesInput}
                  onChange={(e) => setNotesInput(e.target.value)}
                  className="w-full bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-50 border border-zinc-800 dark:border-zinc-800 light:border-zinc-300 rounded-xl p-2.5 text-zinc-100 dark:text-zinc-100 light:text-zinc-900 focus:border-zinc-600 focus:outline-none"
                />
              </div>

              {/* Buttons */}
              <div className="flex justify-end space-x-2 pt-3 border-t border-zinc-800 dark:border-zinc-800 light:border-zinc-200">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-3.5 py-1.5 rounded-xl bg-zinc-800 dark:bg-zinc-800 light:bg-zinc-200 hover:bg-zinc-700 text-zinc-300 dark:text-zinc-300 light:text-zinc-800 transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={!vendorInput.trim() || (Boolean(editingItem) && !parseCPE23(cpeExpressionInput.trim()).isValid)}
                  className="px-4 py-1.5 rounded-xl bg-zinc-100 hover:bg-zinc-200 dark:bg-zinc-100 dark:hover:bg-zinc-200 light:bg-zinc-900 light:hover:bg-zinc-800 text-zinc-900 dark:text-zinc-900 light:text-zinc-50 font-semibold transition disabled:opacity-50 shadow-sm"
                >
                  {editingItem
                    ? 'Save Changes'
                    : selectedProductIds.length > 1
                      ? `Register All (${selectedProductIds.length}) Products`
                      : 'Register Product'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Bulk JSON Import Modal */}
      {showBulkModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-2xl w-full p-6 shadow-2xl relative">
            <button
              onClick={() => {
                setShowBulkModal(false);
                setBulkFeedback(null);
              }}
              className="absolute top-4 right-4 text-zinc-500 hover:text-zinc-200 dark:hover:text-zinc-200 light:hover:text-zinc-900"
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
                    : 'bg-zinc-950 border border-zinc-700 text-zinc-300'
                }`}
              >
                {bulkFeedback.errors.length === 0 ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                ) : (
                  <AlertCircle className="w-4 h-4 text-zinc-400 shrink-0" />
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
          <div className="bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-sm w-full p-6 shadow-2xl relative">
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
                onClick={() => {
                  deleteWatchlistItem(deletingAsset.id);
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
