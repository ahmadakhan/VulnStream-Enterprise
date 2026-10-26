import { PageHeading } from './PageHeading';
import React, { useState, useMemo } from 'react';
import { useApp } from '../context/AppContext';
import { NormalizedCVE, ThreatSearchHit, ThreatSearchResponse } from '../types';
import {
  ENTERPRISE_VENDOR_CATALOG,
  getCatalogProductsForVendor,
  CatalogVendor,
  CatalogProduct,
} from '../data/vendorCatalog';
import {
  Search,
  X,
  Download,
  Copy,
  Check,
  Loader2,
  Flame,
  Database,
  AlertCircle,
} from 'lucide-react';
import { copyText } from '../utils/clipboard';
import { CveLink } from './CveLink';

const dateFormatter = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' });
const formatDate = (value: string) => {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '—' : dateFormatter.format(date);
};

const severityTone = (severity: NormalizedCVE['cvss']['severity']) => {
  switch (severity) {
    case 'CRITICAL':
      return 'border-rose-500/30 bg-rose-500/10 text-rose-300 light:text-rose-800';
    case 'HIGH':
      return 'border-orange-500/30 bg-orange-500/10 text-orange-300 light:text-orange-800';
    case 'MEDIUM':
      return 'border-amber-500/30 bg-amber-500/10 text-amber-300 light:text-amber-800';
    case 'LOW':
      return 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300 light:text-emerald-800';
    default:
      return 'border-zinc-700/60 bg-zinc-800/60 text-zinc-400 light:border-zinc-300 light:bg-zinc-100 light:text-zinc-600';
  }
};

const sourceTone = (source: ThreatSearchHit['source']) => {
  switch (source) {
    case 'NVD_API':
      return 'border-blue-500/30 bg-blue-500/10 text-blue-300 light:text-blue-800';
    case 'KEYWORD_FALLBACK':
      return 'border-teal-500/30 bg-teal-500/10 text-teal-300 light:text-teal-800';
  }
};

export const ThreatIntelligenceSearch: React.FC = () => {
  const { searchThreatIntelligence } = useApp();
  const [vendorQuery, setVendorQuery] = useState('');
  const [vendorSelected, setVendorSelected] = useState('');
  const [productSelected, setProductSelected] = useState('');
  const [customProduct, setCustomProduct] = useState('');
  const [useCustomProduct, setUseCustomProduct] = useState(false);
  const [resultLimit, setResultLimit] = useState(50);

  const [results, setResults] = useState<ThreatSearchHit[] | null>(null);
  const [totalResults, setTotalResults] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copiedJson, setCopiedJson] = useState(false);

  const vendorOptions = useMemo(() => {
    if (!vendorQuery.trim()) return ENTERPRISE_VENDOR_CATALOG;
    const q = vendorQuery.trim().toLowerCase();
    return ENTERPRISE_VENDOR_CATALOG.filter(
      (v) =>
        v.name.toLowerCase().includes(q) ||
        v.normalizedId.toLowerCase().includes(q) ||
        v.aliases.some((a) => a.toLowerCase().includes(q)),
    );
  }, [vendorQuery]);

  const productOptions = useMemo(() => {
    if (!vendorSelected) return [];
    return getCatalogProductsForVendor(vendorSelected);
  }, [vendorSelected]);

  const selectedVendorName = useMemo(() => {
    if (!vendorSelected) return '';
    return ENTERPRISE_VENDOR_CATALOG.find((v) => v.normalizedId === vendorSelected)?.name || vendorSelected;
  }, [vendorSelected]);

  const selectedProductName = useMemo(() => {
    if (useCustomProduct) return customProduct.trim();
    if (!vendorSelected || !productSelected) return '';
    return getCatalogProductsForVendor(vendorSelected).find((p) => p.normalizedId === productSelected)?.name || productSelected;
  }, [vendorSelected, productSelected, useCustomProduct, customProduct]);

  const effectiveVendor = vendorSelected || '';
  const effectiveProduct = useCustomProduct
    ? customProduct.trim()
    : productSelected || '';

  const canSearch = effectiveVendor && effectiveProduct;

  const handleSearch = async () => {
    if (!canSearch) return;
    setLoading(true);
    setError(null);
    setResults(null);
    setCopiedJson(false);
    try {
      const resp: ThreatSearchResponse = await searchThreatIntelligence(
        effectiveVendor,
        effectiveProduct,
        resultLimit,
      );
      setResults(resp.hits);
      setTotalResults(resp.totalResults);
      if (resp.rateLimited) {
        setError('NVD rate limit reached. The NVD API has a limited request budget; retry in a few seconds.');
      }
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : 'Search failed. Check your NVD API key configuration and network connectivity.',
      );
    } finally {
      setLoading(false);
    }
  };

  const handleDownloadJson = () => {
    if (!results) return;
    const payload = {
      vendor: effectiveVendor,
        product: selectedProductName || effectiveProduct,
      totalResults: totalResults,
      hits: results.map((h) => ({
        cveId: h.cve.cveId,
        title: h.cve.title,
        description: h.cve.description,
        severity: h.cve.cvss.severity,
        score: h.cve.cvss.score,
        publishedDate: h.cve.publishedDate,
        modifiedDate: h.cve.modifiedDate,
        cweIds: h.cve.cwe,
        matchingCpes: h.matchingCpes,
        source: h.source,
        references: [],
      })),
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `threat-intel-${effectiveVendor}-${effectiveProduct}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleCopyAll = async () => {
    if (!results) return;
    const cveIds = results.map((h) => h.cve.cveId).join('\n');
    const success = await copyText(cveIds);
    setCopiedJson(success);
    setTimeout(() => setCopiedJson(false), 2000);
  };

  const sortedResults = useMemo(() => {
    if (!results) return [];
    return [...results].sort((a, b) => {
      const sa = scoreValue(a.cve);
      const sb = scoreValue(b.cve);
      return sb - sa;
    });
  }, [results]);

  function scoreValue(cve: NormalizedCVE): number {
    if (cve.cvss.severity === 'CRITICAL') return 1000;
    if (cve.cvss.severity === 'HIGH') return 900;
    if (cve.cvss.severity === 'MEDIUM') return 500;
    if (cve.cvss.severity === 'LOW') return 200;
    if (cve.cisaKev.isKev) return 50;
    return 0;
  }

  const resetSearch = () => {
    setVendorSelected('');
    setProductSelected('');
    setCustomProduct('');
    setUseCustomProduct(false);
    setVendorQuery('');
    setResults(null);
    setTotalResults(0);
    setError(null);
    setCopiedJson(false);
  };

  return (
    <div className="space-y-6">
      <PageHeading
        page="threat-intelligence-search"
        title="Threat Intelligence Search"
        children={
          <span className="text-sm text-zinc-400 light:text-zinc-600">
            Search the NVD CVE database for vulnerabilities affecting a specific vendor and product.
            Results are matched against verified CPE 2.3 dictionary entries and can be exported for remediation planning.
          </span>
        }
      />

      <div className="rounded-lg border border-zinc-800/80 dark:border-zinc-800 light:border-zinc-200 bg-zinc-900/50 dark:bg-zinc-900 light:bg-zinc-50 p-4">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 items-end">
          <div className="md:col-span-1">
            <label className="block text-xs font-medium text-zinc-400 light:text-zinc-600 mb-1">
              Vendor
            </label>
            <div className="relative">
              <input
                type="text"
                value={vendorQuery}
                onChange={(e) => setVendorQuery(e.target.value)}
                onFocus={() => !vendorSelected && setVendorQuery('')}
                placeholder="Start typing a vendor..."
                className="w-full px-3 py-2 text-sm bg-zinc-800 dark:bg-zinc-800 light:bg-white light:border light:border-zinc-300 text-zinc-100 light:text-zinc-900 rounded-md focus:outline-none focus:ring-1 focus:ring-blue-500 placeholder-zinc-500"
              />
              {vendorQuery && !vendorSelected && (
                <div className="absolute z-10 mt-1 w-full max-h-48 overflow-y-auto bg-zinc-800 dark:bg-zinc-800 light:bg-white light:border light:border-zinc-300 rounded-md shadow-lg">
                  {vendorOptions.length === 0 ? (
                    <div className="px-3 py-2 text-sm text-zinc-400 light:text-zinc-600">
                      No matching vendors found
                    </div>
                  ) : (
                    vendorOptions.map((v: CatalogVendor) => (
                      <button
                        key={v.normalizedId}
                        type="button"
                        onClick={() => {
                          setVendorSelected(v.normalizedId);
                          setVendorQuery('');
                          setProductSelected('');
                          setUseCustomProduct(false);
                        }}
                        className="w-full text-left px-3 py-2 text-sm hover:bg-zinc-700/50 dark:hover:bg-zinc-700 light:hover:bg-zinc-100 text-zinc-200 light:text-zinc-800 first:rounded-t-md last:rounded-b-md"
                      >
                        <div className="font-medium">{v.name}</div>
                        {v.aliases.length > 0 && (
                          <div className="text-xs text-zinc-500 light:text-zinc-600">
                            aliases: {v.aliases.join(', ')}
                          </div>
                        )}
                      </button>
                    ))
                  )}
                </div>
              )}
              {vendorSelected && (
                <button
                  type="button"
                  onClick={() => {
                    setVendorSelected('');
                    setVendorQuery('');
                    setProductSelected('');
                    setUseCustomProduct(false);
                  }}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-300"
                  aria-label="Clear vendor"
                >
                  <X size={14} />
                </button>
              )}
            </div>
          </div>

          {!useCustomProduct && vendorSelected && (
            <div className="md:col-span-1">
              <label className="block text-xs font-medium text-zinc-400 light:text-zinc-600 mb-1">
                Product
              </label>
              <div className="relative">
                <select
                  value={productSelected}
                  onChange={(e) => {
                    setProductSelected(e.target.value);
                  }}
                  className="w-full px-3 py-2 text-sm bg-zinc-800 dark:bg-zinc-800 light:bg-white light:border light:border-zinc-300 text-zinc-100 light:text-zinc-900 rounded-md focus:outline-none focus:ring-1 focus:ring-blue-500"
                >
                  <option value="">Select a product</option>
                  {productOptions.length === 0 ? (
                    <option value="" disabled>
                      No catalog products for this vendor
                    </option>
                  ) : (
                    productOptions.map((p: CatalogProduct) => (
                      <option key={p.normalizedId} value={p.normalizedId}>
                        {p.name} ({p.part})
                      </option>
                    ))
                  )}
                </select>
              </div>
            </div>
          )}

          {vendorSelected && (
            <div className="md:col-span-1">
              <label className="block text-xs font-medium text-zinc-400 light:text-zinc-600 mb-1">
                Or manual product
              </label>
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  value={customProduct}
                  onChange={(e) => setCustomProduct(e.target.value)}
                  placeholder="Enter product name"
                  className="flex-1 px-3 py-2 text-sm bg-zinc-800 dark:bg-zinc-800 light:bg-white light:border light:border-zinc-300 text-zinc-100 light:text-zinc-900 rounded-md focus:outline-none focus:ring-1 focus:ring-blue-500 placeholder-zinc-500"
                />
                <button
                  type="button"
                  onClick={() => {
                    const useCustom = !useCustomProduct;
                    setUseCustomProduct(useCustom);
                    setProductSelected('');
                  }}
                  className={`px-2 py-2 rounded-md text-xs font-medium transition-colors ${
                    useCustomProduct
                      ? 'bg-blue-500/20 text-blue-300 light:text-blue-800 border border-blue-500/30'
                      : 'bg-zinc-700/50 text-zinc-300 light:text-zinc-600 border border-zinc-700/50 hover:bg-zinc-600/50'
                  }`}
                  aria-pressed={useCustomProduct}
                >
                  Use
                </button>
              </div>
            </div>
          )}

          <div className="md:col-span-1">
            <label className="block text-xs font-medium text-zinc-400 light:text-zinc-600 mb-1">
              Max results
            </label>
            <input
              type="number"
              min={1}
              max={200}
              value={resultLimit}
              onChange={(e) => setResultLimit(Math.max(1, Math.min(200, parseInt(e.target.value, 10) || 1)))}
              className="w-full px-3 py-2 text-sm bg-zinc-800 dark:bg-zinc-800 light:bg-white light:border light:border-zinc-300 text-zinc-100 light:text-zinc-900 rounded-md focus:outline-none focus:ring-1 focus:ring-blue-500"
            />
          </div>

          {!vendorSelected && (
            <div className="md:col-span-4">
              <label className="block text-xs font-medium text-zinc-400 light:text-zinc-600 mb-1">
                Or type a vendor name directly
              </label>
              <input
                type="text"
                value={vendorQuery}
                onChange={(e) => {
                  setVendorQuery(e.target.value);
                  if (e.target.value.trim() && !vendorSelected) {
                    setVendorSelected(e.target.value.trim());
                  }
                  if (!e.target.value.trim()) {
                    setVendorSelected('');
                    setProductSelected('');
                    setUseCustomProduct(true);
                  }
                }}
                placeholder="Type vendor name (e.g. apache) and press Enter..."
                className="w-full px-3 py-2 text-sm bg-zinc-800 dark:bg-zinc-800 light:bg-white light:border light:border-zinc-300 text-zinc-100 light:text-zinc-900 rounded-md focus:outline-none focus:ring-1 focus:ring-blue-500 placeholder-zinc-500"
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && vendorQuery.trim()) {
                    setVendorSelected(vendorQuery.trim());
                    setVendorQuery('');
                    setUseCustomProduct(true);
                  }
                }}
              />
            </div>
          )}

          <div className="md:col-span-4 flex justify-end gap-3">
            {(results || error) && (
              <button
                type="button"
                onClick={resetSearch}
                className="px-3 py-2 text-sm text-zinc-400 light:text-zinc-600 hover:text-zinc-200 light:hover:text-zinc-900 transition-colors"
              >
                <X size={16} className="inline mr-1" />
                Reset
              </button>
            )}
            <button
              type="button"
              onClick={handleSearch}
              disabled={!canSearch || loading}
              className="px-4 py-2 bg-blue-500/15 border border-blue-400/30 text-blue-300 light:text-blue-800 rounded-md font-medium hover:bg-blue-500/25 disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex items-center gap-2"
            >
              {loading ? <Loader2 size={16} className="animate-spin" /> : <Search size={16} />}
              Search threat feeds
            </button>
          </div>
        </div>
      </div>

      {error && !loading && (
        <div className="rounded-md border border-rose-500/30 bg-rose-500/10 p-3 flex items-start gap-2">
          <AlertCircle className="h-4 w-4 text-rose-400 light:text-rose-800 flex-shrink-0 mt-0.5" />
          <span className="text-sm text-rose-300 light:text-rose-800">{error}</span>
        </div>
      )}

      {results && results.length > 0 && (
        <div className="rounded-lg border border-zinc-800/80 dark:border-zinc-800 light:border-zinc-200 bg-zinc-900/50 dark:bg-zinc-900 light:bg-zinc-50">
          <div className="p-3 border-b border-zinc-800/80 dark:border-zinc-800 light:border-zinc-200 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <span className="text-sm text-zinc-400 light:text-zinc-600">
                Found <strong className="text-zinc-200 light:text-zinc-900">{results.length}</strong> vulnerabilities
                {totalResults > results.length && (
                  <span className="text-zinc-500 light:text-zinc-600">
                    {' '}
                    (showing first {results.length} of {totalResults})
                  </span>
                )}
                {vendorSelected && (
                  <span className="text-zinc-500 light:text-zinc-600">
                    {' '}
                    for {selectedVendorName} / {selectedProductName || effectiveProduct}
                  </span>
                )}
              </span>
            </div>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={handleCopyAll}
                className="p-1.5 text-zinc-400 light:text-zinc-600 hover:text-zinc-200 light:hover:text-zinc-900 rounded transition-colors"
                title="Copy all CVE IDs"
              >
                {copiedJson ? <Check size={16} className="text-green-400" /> : <Copy size={16} />}
              </button>
              <button
                type="button"
                onClick={handleDownloadJson}
                className="p-1.5 text-zinc-400 light:text-zinc-600 hover:text-zinc-200 light:hover:text-zinc-900 rounded transition-colors"
                title="Download results as JSON"
              >
                <Download size={16} />
              </button>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-zinc-800/80 dark:border-zinc-800 light:border-zinc-200">
                  <th className="px-4 py-2 text-left text-xs font-medium text-zinc-500 light:text-zinc-600 uppercase tracking-wider">CVE</th>
                  <th className="px-4 py-2 text-left text-xs font-medium text-zinc-500 light:text-zinc-600 uppercase tracking-wider">Severity</th>
                  <th className="px-4 py-2 text-left text-xs font-medium text-zinc-500 light:text-zinc-600 uppercase tracking-wider">CVSS</th>
                  <th className="px-4 py-2 text-left text-xs font-medium text-zinc-500 light:text-zinc-600 uppercase tracking-wider">KEV</th>
                  <th className="px-4 py-2 text-left text-xs font-medium text-zinc-500 light:text-zinc-600 uppercase tracking-wider">Matched CPE</th>
                  <th className="px-4 py-2 text-left text-xs font-medium text-zinc-500 light:text-zinc-600 uppercase tracking-wider">Source</th>
                  <th className="px-4 py-2 text-left text-xs font-medium text-zinc-500 light:text-zinc-600 uppercase tracking-wider">Published</th>
                </tr>
              </thead>
              <tbody>
                {sortedResults.map((hit: ThreatSearchHit) => {
                  const cve = hit.cve;
                  const scored = cve.cvss.version !== 'UNKNOWN';
                  return (
                    <tr
                      key={cve.cveId}
                      className="transition hover:bg-zinc-800/30 light:hover:bg-zinc-50 border-b border-zinc-800/40 dark:border-zinc-800/40 light:border-zinc-200/40"
                    >
                      <td className="px-4 py-3 min-w-[220px]">
                        <div className="flex items-center gap-2">
                          <CveLink cveId={cve.cveId} className="whitespace-nowrap" />
                          {cve.cisaKev.isKev && (
                            <span
                              className="inline-flex items-center gap-0.5 rounded-full border border-amber-500/30 bg-amber-500/10 px-1.5 py-0.5 font-mono text-[10px] font-medium text-amber-300 light:text-amber-800"
                              title="Listed in the CISA Known Exploited Vulnerabilities catalog"
                            >
                              <Flame className="h-3 w-3" aria-hidden="true" />
                              KEV
                            </span>
                          )}
                        </div>
                        <div className="mt-0.5 line-clamp-2 max-w-xs text-xs text-zinc-400 light:text-zinc-600">
                          {cve.title || 'No title provided'}
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <span
                          className={`rounded border px-1.5 py-0.5 font-mono text-[10px] font-medium ${severityTone(cve.cvss.severity)}`}
                        >
                          {cve.cvss.severity}
                        </span>
                      </td>
                      <td className="px-4 py-3 font-mono">
                        {scored ? cve.cvss.score.toFixed(1) : 'Unscored'}
                      </td>
                      <td className="px-4 py-3">
                        {cve.cisaKev.isKev ? (
                          <span className="text-xs text-amber-300 light:text-amber-800">Yes</span>
                        ) : (
                          <span className="text-xs text-zinc-500 light:text-zinc-600">—</span>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        {hit.matchingCpes.length > 0 ? (
                          <div className="space-y-0.5">
                            {hit.matchingCpes.slice(0, 2).map((cpe: string) => (
                              <code
                                key={cpe}
                                className="block text-[10px] font-mono text-zinc-500 light:text-zinc-600 truncate max-w-[200px]"
                                title={cpe}
                              >
                                {cpe}
                              </code>
                            ))}
                            {hit.matchingCpes.length > 2 && (
                              <span className="text-[10px] text-zinc-500 light:text-zinc-600">
                                +{hit.matchingCpes.length - 2} more
                              </span>
                            )}
                          </div>
                        ) : (
                          <span className="text-xs text-zinc-500 light:text-zinc-600">—</span>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <span
                          className={`inline-flex items-center gap-1 rounded-full border px-1.5 py-0.5 font-mono text-[10px] font-medium ${sourceTone(hit.source)}`}
                        >
                          {hit.source === 'NVD_API' ? 'Exact CPE' : 'Keyword match'}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-sm text-zinc-300 light:text-zinc-800">
                        {formatDate(cve.publishedDate)}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {results && results.length === 0 && !error && (
        <div className="rounded-lg border border-zinc-800/80 dark:border-zinc-800 light:border-zinc-200 bg-zinc-900/50 dark:bg-zinc-900 light:bg-zinc-50 p-8 text-center">
          <Database className="mx-auto h-10 w-10 text-zinc-600 light:text-zinc-400 mb-3" />
          <p className="text-sm text-zinc-400 light:text-zinc-600">
            No vulnerabilities found for the selected vendor and product.
          </p>
          <p className="text-xs text-zinc-500 light:text-zinc-600 mt-1">
            The NVD CPE dictionary did not return any matching CVEs. Try a different vendor or product spelling.
          </p>
        </div>
      )}

      {loading && (
        <div className="rounded-lg border border-zinc-800/80 dark:border-zinc-800 light:border-zinc-200 bg-zinc-900/50 dark:bg-zinc-900 light:bg-zinc-50 p-8 text-center">
          <Loader2 className="mx-auto h-6 w-6 text-blue-400 animate-spin mb-2" />
          <p className="text-sm text-zinc-400 light:text-zinc-600">
            Searching the NVD CVE database...
          </p>
          <p className="text-xs text-zinc-500 light:text-zinc-600 mt-1">
            This may take a few seconds depending on NVD rate limits.
          </p>
        </div>
      )}
    </div>
  );
};
